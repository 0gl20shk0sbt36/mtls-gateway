package relay

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"mtls-gateway/internal/certsource"
	"mtls-gateway/internal/eventlog"
	"mtls-gateway/internal/i18n"
)

// Manager 中继管理入口: 外壳(CLI/WebUI/GUI)唯一接口。
// 持有当前 RelayConfig 并持久化到磁盘; 提供 HTTP 管理 API 及便捷方法。
type Manager struct {
	relay          *Relay
	cfgPath        string
	mu             sync.Mutex
	cfg            RelayConfig
	noPersist      bool   // 只改内存、不落盘 (临时会话)
	serverOverride string // --server 覆盖的发现端点
	webUIOnce      sync.Once
	webUI          *eventlog.Logger // WebUI 界面事件日志(客户端侧, 单独文件)
}

// NewManager 创建管理入口。加载已有配置(若无则用默认)。
func NewManager(relay *Relay, cfgPath string) (*Manager, error) {
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		return nil, err
	}
	m := &Manager{relay: relay, cfgPath: cfgPath, cfg: cfg}
	return m, nil
}

// Config 返回当前配置的拷贝(顶层 Tunnels 切片复制; Tunnel.Routes 为值类型内嵌切片,
// 由调用方约定只读 — 变更走 AddTunnel/DelTunnel)
func (m *Manager) Config() RelayConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.cfg
	out.Tunnels = append([]Tunnel(nil), m.cfg.Tunnels...)
	return out
}

// Save 将当前配置落盘 (noPersist 时跳过)
func (m *Manager) Save() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.noPersist {
		return nil
	}
	return SaveConfig(m.cfgPath, m.cfg)
}

// SetNoPersist 切换是否落盘 (true=WebUI/API 改动只改内存)
func (m *Manager) SetNoPersist(v bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.noPersist = v
}

// SetServerAddr 覆盖服务端发现端点 (--server; 供 Discover 与按服务建隧道)
func (m *Manager) SetServerAddr(addr string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.serverOverride = addr
}

// AddTunnel 新增或覆盖隧道并持久化 (noPersist 时仅内存)
func (m *Manager) AddTunnel(t Tunnel) error {
	m.mu.Lock()
	m.cfg.UpsertTunnel(t)
	cfg := m.cfg
	np := m.noPersist
	m.mu.Unlock()
	if !np {
		if err := SaveConfig(m.cfgPath, cfg); err != nil {
			return err
		}
	}
	m.reloadTunnels()
	return nil
}

// reloadTunnels 把当前配置同步到运行时(增删立即生效)
func (m *Manager) reloadTunnels() {
	if err := m.relay.Reload(m.Config()); err != nil {
		log.Printf("reload tunnels: %v", err)
	}
}

// DelTunnel 删除隧道(整个服务)并持久化 (noPersist 时仅内存); 立即停掉运行时
func (m *Manager) DelTunnel(id string) (bool, error) {
	m.mu.Lock()
	ok := m.cfg.DelTunnel(id)
	cfg := m.cfg
	np := m.noPersist
	m.mu.Unlock()
	if !ok {
		return false, nil
	}
	if !np {
		if err := SaveConfig(m.cfgPath, cfg); err != nil {
			return true, err
		}
	}
	m.reloadTunnels()
	return true, nil
}

// Start 按当前配置启动中继
func (m *Manager) Start() error {
	cfg := m.Config()
	return m.relay.Start(cfg)
}

// Reload 按当前配置增量应用隧道集变更
func (m *Manager) Reload() error {
	cfg := m.Config()
	return m.relay.Reload(cfg)
}

// Stop 停止中继
func (m *Manager) Stop() { m.relay.Stop() }

// Status 当前隧道状态
func (m *Manager) Status() []TunnelStatus { return m.relay.Status() }

// ListCerts 当前可用证书 (供用户选择)
func (m *Manager) ListCerts() ([]certsource.IdentityMeta, error) { return m.relay.ListCertMeta() }

// Services 从服务端 /info 拉取可用服务 (供外壳选择)
func (m *Manager) Services() ([]ServiceInfo, error) { return m.relay.Discover() }

// ServicesForCert 用指定证书做服务发现 — 建隧道时用所选证书, 避免误用证书源第一枚
// lang: 请求语言(zh/en; 空=进程默认)
func (m *Manager) ServicesForCert(certID, lang string) ([]ServiceInfo, error) {
	return m.relay.DiscoverWithCertOf(certID, lang)
}

// —— 服务端管理桥 (证书管理台用; 需 admin 证书) ——

func (m *Manager) adminAddr() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg.AdminAddr
}

// adminClientFor 用 certID 加载证书(可带密码), 构建设往服务端 admin 端点的客户端
func (m *Manager) adminClientFor(certID, password string) (*AdminClient, error) {
	addr := m.adminAddr()
	if addr == "" {
		return nil, fmt.Errorf("admin_addr not set in relay config")
	}
	cert, err := m.relay.LoadCertWithPassword(certID, password)
	if err != nil {
		return nil, err
	}
	return NewAdminClient(addr, cert, m.relay.rootCAs), nil
}

func (m *Manager) AdminVerify(certID, password string) error {
	ac, err := m.adminClientFor(certID, password)
	if err != nil {
		return err
	}
	return ac.Verify()
}

// VerifyResult 验证结果: 用所选证书调 /info 拿服务 + 探测是否 admin
type VerifyResult struct {
	Services []ServiceInfo `json:"services"`
	Admin    bool          `json:"admin"`
}

// Verify 登录/验证: 加载证书 → /info 发现服务(证明证书已登记) + admin 探活(解锁管理)
func (m *Manager) Verify(certID, password string) (*VerifyResult, error) {
	cert, err := m.relay.LoadCertWithPassword(certID, password)
	if err != nil {
		return nil, err
	}
	svcs, err := m.relay.DiscoverWithCert(cert)
	if err != nil {
		return nil, fmt.Errorf("info: %w", err)
	}
	res := &VerifyResult{Services: svcs}
	if addr := m.adminAddr(); addr != "" {
		if err := NewAdminClient(addr, cert, m.relay.rootCAs).Verify(); err == nil {
			res.Admin = true
		}
	}
	return res, nil
}
func (m *Manager) AdminIssue(certID, password string, req IssueRequest) (*IssueResponse, error) {
	ac, err := m.adminClientFor(certID, password)
	if err != nil {
		return nil, err
	}
	return ac.Issue(req)
}
func (m *Manager) AdminRevoke(certID, password, serial string) error {
	ac, err := m.adminClientFor(certID, password)
	if err != nil {
		return err
	}
	return ac.Revoke(serial)
}

// AdminConfig 服务端配置总览 (mode + mappings + services)
func (m *Manager) AdminConfig(certID, password string) (json.RawMessage, error) {
	ac, err := m.adminClientFor(certID, password)
	if err != nil {
		return nil, err
	}
	return ac.Cfg()
}

// AdminSetConfig 整体替换服务端配置
func (m *Manager) AdminSetConfig(certID, password string, body json.RawMessage) (json.RawMessage, error) {
	ac, err := m.adminClientFor(certID, password)
	if err != nil {
		return nil, err
	}
	return ac.SetConfig(body)
}

// AdminMapping 通道 CRUD 透传 (method: POST/PUT/DELETE)
func (m *Manager) AdminMapping(certID, password, method, id string, body json.RawMessage) (json.RawMessage, error) {
	ac, err := m.adminClientFor(certID, password)
	if err != nil {
		return nil, err
	}
	return ac.Mapping(method, id, body)
}

// AdminService 服务 CRUD 透传 (method: POST/PUT/DELETE)
func (m *Manager) AdminService(certID, password, method, name string, body json.RawMessage) (json.RawMessage, error) {
	ac, err := m.adminClientFor(certID, password)
	if err != nil {
		return nil, err
	}
	return ac.Service(method, name, body)
}

// AdminListCerts 拉取服务端全部证书(供吊销下拉)
func (m *Manager) AdminListCerts(certID, password string) (json.RawMessage, error) {
	ac, err := m.adminClientFor(certID, password)
	if err != nil {
		return nil, err
	}
	return ac.List()
}

// AdminMappings 拉取服务端全部映射(供签发时选用途)
func (m *Manager) AdminMappings(certID, password string) ([]ServiceInfo, error) {
	ac, err := m.adminClientFor(certID, password)
	if err != nil {
		return nil, err
	}
	return ac.ListMappings()
}

// BuildServiceTunnels 依据服务端服务定义生成一条服务级隧道(含全部通道的本地路由)。
// locals: 通道 listen → 本地路由 (缺省 = 通道 listen 原样, 含冒号)
// lang: 错误语言(zh/en; 空=进程默认)
func (m *Manager) BuildServiceTunnels(svc ServiceInfo, locals map[string]string, certID, lang string) (Tunnel, error) {
	l := m.relay.L
	if lang == "en" || lang == "zh" {
		l = i18n.New(lang)
	}
	t := Tunnel{Service: svc.Name, CertID: certID, Enabled: true}
	for _, ch := range svc.Channels {
		local := ""
		if locals != nil {
			local = locals[ch.Listen]
		}
		if local == "" {
			local = ch.Listen // 默认本地路由 = 服务端通道内容一致 (含冒号与路径)
		}
		t.Routes = append(t.Routes, TunnelRoute{Channel: ch.Listen, Local: local})
	}
	if len(t.Routes) == 0 {
		return Tunnel{}, l.E("errNoChannels", svc.Name)
	}
	return t, nil
}

// reqL 按请求 X-Lang 返回错误字典(空=进程默认)
func (m *Manager) reqL(r *http.Request) *i18n.L {
	if lang := r.Header.Get("X-Lang"); lang == "en" || lang == "zh" {
		return i18n.New(lang)
	}
	return m.relay.L
}

// webUILogger 懒创建 WebUI 事件日志(从配置 webui_log_file; 空=禁用)
func (m *Manager) webUILogger() *eventlog.Logger {
	cfg := m.Config()
	if cfg.WebUILogFile == "" {
		return nil
	}
	m.webUIOnce.Do(func() {
		maxSize := cfg.WebUILogMaxSizeMB
		if maxSize <= 0 {
			maxSize = 10
		}
		maxFiles := cfg.WebUILogMaxFiles
		if maxFiles < 0 {
			maxFiles = 5
		}
		l, err := eventlog.New(cfg.WebUILogFile, maxSize, maxFiles)
		if err != nil {
			log.Printf("webui log: %v (禁用)", err)
			return
		}
		m.webUI = l
	})
	return m.webUI
}

// Handler 返回管理 HTTP handler (仅 bind loopback)
func (m *Manager) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, m.Status())
	})

	mux.HandleFunc("GET /api/certs", func(w http.ResponseWriter, r *http.Request) {
		metas, err := m.ListCerts()
		if err != nil {
			writeErr(w, r, err)
			return
		}
		writeJSON(w, metas)
	})

	// POST /api/verify — 登录/验证: /info 服务 + admin 探活 (需先选证书)
	mux.HandleFunc("POST /api/verify", func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			CertID  string `json:"cert_id"`
			LoadPwd string `json:"load_pwd,omitempty"`
		}
		if !decodeJSON(w, r, &b) {
			return
		}
		res, err := m.Verify(b.CertID, b.LoadPwd)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		writeJSON(w, res)
	})

	// GET /api/services — 从服务端 /info 拉取可用服务(供选择)
	mux.HandleFunc("GET /api/services", func(w http.ResponseWriter, r *http.Request) {
		svcs, err := m.Services()
		if err != nil {
			writeErr(w, r, err)
			return
		}
		writeJSON(w, svcs)
	})

	// —— 管理桥 (证书管理台; 先选 admin 证书验证解锁) ——
	type adminVerifyReq struct {
		CertID  string `json:"cert_id"`
		LoadPwd string `json:"load_pwd,omitempty"` // 加载加密 admin 证书用
	}
	type adminIssueReq struct {
		CertID  string `json:"cert_id"`
		LoadPwd string `json:"load_pwd,omitempty"` // 加载用; IssueRequest.Password=新证书 p12 密码
		IssueRequest
	}
	type adminRevokeReq struct {
		CertID  string `json:"cert_id"`
		LoadPwd string `json:"load_pwd,omitempty"`
		Serial  string `json:"serial"`
	}
	mux.HandleFunc("POST /api/admin/verify", func(w http.ResponseWriter, r *http.Request) {
		var b adminVerifyReq
		if !decodeJSON(w, r, &b) {
			return
		}
		if err := m.AdminVerify(b.CertID, b.LoadPwd); err != nil {
			writeErr(w, r, err)
			return
		}
		writeJSON(w, map[string]any{"ok": true})
	})
	mux.HandleFunc("POST /api/admin/issue", func(w http.ResponseWriter, r *http.Request) {
		var b adminIssueReq
		if !decodeJSON(w, r, &b) {
			return
		}
		resp, err := m.AdminIssue(b.CertID, b.LoadPwd, b.IssueRequest)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		writeJSON(w, resp)
	})
	// POST /api/admin/certs — 服务端证书列表(吊销下拉)
	mux.HandleFunc("POST /api/admin/certs", func(w http.ResponseWriter, r *http.Request) {
		var b adminVerifyReq
		if !decodeJSON(w, r, &b) {
			return
		}
		raw, err := m.AdminListCerts(b.CertID, b.LoadPwd)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(raw)
	})
	// POST /api/admin/mappings — 全部映射(签发选用途)
	mux.HandleFunc("POST /api/admin/mappings", func(w http.ResponseWriter, r *http.Request) {
		var b adminVerifyReq
		if !decodeJSON(w, r, &b) {
			return
		}
		ms, err := m.AdminMappings(b.CertID, b.LoadPwd)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		writeJSON(w, map[string]any{"mappings": ms})
	})
	mux.HandleFunc("POST /api/admin/revoke", func(w http.ResponseWriter, r *http.Request) {
		var b adminRevokeReq
		if !decodeJSON(w, r, &b) {
			return
		}
		if err := m.AdminRevoke(b.CertID, b.LoadPwd, b.Serial); err != nil {
			writeErr(w, r, err)
			return
		}
		writeJSON(w, map[string]any{"ok": true})
	})

	// POST /api/admin/config — 服务端配置总览(mode+mappings+services)
	mux.HandleFunc("POST /api/admin/config", func(w http.ResponseWriter, r *http.Request) {
		var b adminVerifyReq
		if !decodeJSON(w, r, &b) {
			return
		}
		raw, err := m.AdminConfig(b.CertID, b.LoadPwd)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(raw)
	})
	// PUT /api/admin/config — 整体替换服务端配置(批量保存)
	mux.HandleFunc("PUT /api/admin/config", func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			CertID  string          `json:"cert_id"`
			LoadPwd string          `json:"load_pwd"`
			Body    json.RawMessage `json:"body"`
		}
		if !decodeJSON(w, r, &b) {
			return
		}
		raw, err := m.AdminSetConfig(b.CertID, b.LoadPwd, b.Body)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(raw)
	})
	// POST /api/admin/mapping — 通道 CRUD 透传 {cert_id, load_pwd, method, id?, mapping}
	mux.HandleFunc("POST /api/admin/mapping", func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			CertID  string          `json:"cert_id"`
			LoadPwd string          `json:"load_pwd"`
			Method  string          `json:"method"`
			ID      string          `json:"id"`
			Mapping json.RawMessage `json:"mapping"`
		}
		if !decodeJSON(w, r, &b) {
			return
		}
		raw, err := m.AdminMapping(b.CertID, b.LoadPwd, b.Method, b.ID, b.Mapping)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(raw)
	})
	// POST /api/admin/service — 服务 CRUD 透传 {cert_id, load_pwd, method, name?, service}
	mux.HandleFunc("POST /api/admin/service", func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			CertID  string          `json:"cert_id"`
			LoadPwd string          `json:"load_pwd"`
			Method  string          `json:"method"`
			Name    string          `json:"name"`
			Service json.RawMessage `json:"service"`
		}
		if !decodeJSON(w, r, &b) {
			return
		}
		raw, err := m.AdminService(b.CertID, b.LoadPwd, b.Method, b.Name, b.Service)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(raw)
	})

	mux.HandleFunc("GET /api/config", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, m.Config())
	})

	// POST /api/tunnels  (body: {service, locals:{channel:local}, cert_id}) — 为服务所有通道建隧道
	mux.HandleFunc("POST /api/tunnels", func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			Service string            `json:"service"`
			Locals  map[string]string `json:"locals"`
			CertID  string            `json:"cert_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			writeErr(w, r, err)
			return
		}
		if b.Service == "" || b.CertID == "" {
			writeErr(w, r, m.reqL(r).E("errNeedSvcCert"))
			return
		}
		svcs, err := m.ServicesForCert(b.CertID, r.Header.Get("X-Lang"))
		if err != nil {
			writeErr(w, r, err)
			return
		}
		var svc *ServiceInfo
		for i := range svcs {
			if svcs[i].Name == b.Service {
				svc = &svcs[i]
				break
			}
		}
		if svc == nil {
			writeErr(w, r, m.reqL(r).E("errSvcNotFound", b.Service))
			return
		}
		t, err := m.BuildServiceTunnels(*svc, b.Locals, b.CertID, r.Header.Get("X-Lang"))
		if err != nil {
			writeErr(w, r, err)
			return
		}
		if err := m.AddTunnel(t); err != nil {
			writeErr(w, r, err)
			return
		}
		writeJSON(w, map[string]any{"ok": true, "service": t.Service, "count": len(t.Routes)})
		})

	// DELETE /api/tunnels/{id}
	mux.HandleFunc("DELETE /api/tunnels/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/tunnels/")
		if id == "" {
			writeErr(w, r, m.reqL(r).E("errNeedTunnelID"))
			return
		}
		ok, err := m.DelTunnel(id)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": ok})
	})

	// POST /api/start | /api/stop | /api/reload
	mux.HandleFunc("POST /api/start", func(w http.ResponseWriter, r *http.Request) {
		if err := m.Start(); err != nil {
			writeErr(w, r, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /api/stop", func(w http.ResponseWriter, r *http.Request) {
		m.Stop()
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /api/reload", func(w http.ResponseWriter, r *http.Request) {
		if err := m.Reload(); err != nil {
			writeErr(w, r, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})

	// 包装: 记录每个 WebUI/API 操作事件(短时大量, 单独文件)
	inner := mux
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := eventlog.NewStatusWriter(w)
		start := time.Now()
		inner.ServeHTTP(sw, r)
		if lg := m.webUILogger(); lg != nil {
			lg.Write(eventlog.Event{
				Type:     "webui",
				Method:   r.Method,
				Path:     r.URL.Path,
				Status:   sw.Status(),
				BytesIn:  r.ContentLength,
				BytesOut: sw.Bytes(),
				Msg:      time.Since(start).Round(time.Millisecond).String(),
			})
		}
	})
}

func (m *Manager) ConfigPath() string { return m.cfgPath }

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// writeErr 输出错误响应; 已知错误按请求语言(X-Lang)翻译, 其余原样;
// 按错误语义映射状态码(4xx 客户端错误, 5xx 服务端错误)
func writeErr(w http.ResponseWriter, r *http.Request, err error) {
	msg := err.Error()
	if r != nil {
		if lang := r.Header.Get("X-Lang"); lang == "en" || lang == "zh" {
			msg = localizeKnown(lang, err).Error()
		}
	}
	code := http.StatusInternalServerError
	switch {
	case strings.Contains(msg, "bad request"):
		code = http.StatusBadRequest
	case strings.Contains(msg, "required"), strings.Contains(msg, "必填"), strings.Contains(msg, "不能为空"),
		strings.Contains(msg, "格式"), strings.Contains(msg, "invalid"), strings.Contains(msg, "非法"),
		strings.Contains(msg, "已存在"), strings.Contains(msg, "禁止同名"):
		code = http.StatusBadRequest
	case strings.Contains(msg, "not found"), strings.Contains(msg, "未找到"), strings.Contains(msg, "不存在"):
		code = http.StatusNotFound
	case strings.Contains(msg, "forbidden"), strings.Contains(msg, "无权"), strings.Contains(msg, "拒绝"),
		strings.Contains(msg, "未声明"), strings.Contains(msg, "保留字"), strings.Contains(msg, "禁"):
		code = http.StatusForbidden
	}
	w.WriteHeader(code) // 保持 JSON 响应体(前端 api() 依赖)
	writeJSON(w, map[string]string{"error": msg})
}

// decodeJSON 解码请求体; 失败写 400 并返回 false
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeErr(w, r, fmt.Errorf("bad request: %v", err))
		return false
	}
	return true
}

// localizeKnown 已知错误按语言兜底翻译(所有 API 错误出口)
func localizeKnown(lang string, err error) error {
	if err == nil {
		return nil
	}
	l := i18n.New("zh")
	if lang == "en" {
		l = i18n.New("en")
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "private key needs password"), strings.Contains(s, "failed to parse private key"):
		return l.E("errPwdNeeded", errCertName(s))
	case strings.Contains(s, "decryption password incorrect"), strings.Contains(s, "password incorrect"):
		return l.E("errBadPwd", errCertName(s))
	case strings.Contains(s, "expired certificate"), strings.Contains(s, "certificate has expired"):
		return l.E("errExpired")
	case strings.Contains(s, "no certificates in source"), strings.Contains(s, "no client cert"):
		return l.E("errNoCert")
	case strings.Contains(s, "admin_addr not set"):
		return l.E("errNoAdminAddr")
	case strings.Contains(s, "server address not configured"):
		return l.E("errNoServerAddr")
	case strings.Contains(s, "name and purposes required"):
		return l.E("errNameRequired")
	case strings.Contains(s, "already exists"):
		n := 0
		if m := regexp.MustCompile(`\((\d+) record`).FindStringSubmatch(s); len(m) == 2 {
			n, _ = strconv.Atoi(m[1])
		}
		return l.E("errNameExists", errCertName(s), n)
	case strings.Contains(s, "missing listen"):
		return l.E("errMapNoListen")
	case strings.Contains(s, "missing id"):
		return l.E("errMapMissingID")
	case strings.Contains(s, "duplicate listen"):
		return l.E("errListenDup", tailName(s))
	case strings.Contains(s, "duplicate service name"):
		return l.E("errSvcExists", tailName(s))
	case strings.Contains(s, "has no channels"):
		return l.E("errNoChannels", tailName(s))
	case strings.Contains(s, "immutable"):
		return l.E("errImmutable")
	case strings.Contains(s, "forbidden"):
		return l.E("errDenied")
	case strings.Contains(s, "not found"):
		return l.E("errNotFound", errCertName(s))
	}
	return err
}

// errCertName 从错误消息提取证书名("decrypt key admin"/"cert admin not found"/"private key needs password: admin")
func errCertName(s string) string {
	for _, pat := range []string{`decrypt key ([^:\s]+)`, `private key needs password: (\S+)`, `cert (\S+) not found`, `certificate name (\S+) already exists`} {
		if m := regexp.MustCompile(pat).FindStringSubmatch(s); len(m) == 2 {
			return m[1]
		}
	}
	return tailName(s)
}

// tailName 取错误消息最后一段(: 之后)
func tailName(s string) string {
	if i := strings.LastIndex(s, ": "); i >= 0 {
		return s[i+2:]
	}
	return s
}
