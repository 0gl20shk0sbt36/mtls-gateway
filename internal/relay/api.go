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

	"mtls-gateway/internal/api"
	"mtls-gateway/internal/certsource"
	"mtls-gateway/internal/eventlog"
	"mtls-gateway/internal/i18n"
)

// maxBodyBytes 管理 API 请求体上限(防内存耗尽)
const maxBodyBytes = 4 << 20

// Manager 中继管理入口: 外壳(CLI/WebUI/GUI)唯一接口。
// 持有当前 RelayConfig 并持久化到磁盘; 提供 HTTP 管理 API 及便捷方法。
type Manager struct {
	relay          *Relay
	cfgPath        string
	mu             sync.Mutex
	cfg            RelayConfig
	noPersist      bool             // 只改内存、不落盘 (临时会话)
	serverOverride string           // --server 覆盖的发现端点(Config()/reloadTunnels 应用; 不落盘, adminAddr 不用)
	webUIMu        sync.Mutex       // 保护 webUI 懒创建(失败不缓存: 下次请求重试)
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
	if m.serverOverride != "" {
		out.ServerAddr = m.serverOverride // --server 覆盖(发现/隧道拨号用; 保存走 m.cfg 原值)
	}
	out.Tunnels = append([]Tunnel(nil), m.cfg.Tunnels...)
	for i := range out.Tunnels {
		out.Tunnels[i].Routes = append([]TunnelRoute(nil), m.cfg.Tunnels[i].Routes...) // 内层深拷贝
	}
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

// SetServerAddr 覆盖服务端发现端点 (--server): 仅影响 Config()/reloadTunnels(发现/隧道拨号),
// 不落盘; admin 桥(签发/吊销/验证)仍走独立 admin_addr, 不可混用。
func (m *Manager) SetServerAddr(addr string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.serverOverride = addr
}

// SettingsPatch 连接设置的部分更新(指针=该字段要改; nil=不动)
type SettingsPatch struct {
	ServerAddr *string `json:"server_addr"`
	AdminAddr  *string `json:"admin_addr"`
	ListenHost *string `json:"listen_host"`
	ServerCA   *string `json:"server_ca"`
	CertDir    *string `json:"cert_dir"` // 客户端证书源: 空=系统证书库; 非空=目录文件源
	Lang       *string `json:"lang"`
}

// certSourceFromConfig 依据 cert_dir 构建证书源: 空=系统证书库, 非空=目录文件源(dir)。
// 用于管理 API 热更新 (UpdateSettings 换源)。
func certSourceFromConfig(certDir string) (certsource.Source, error) {
	if certDir == "" {
		return certsource.OpenSystem()
	}
	return certsource.New(certsource.Dir, certDir)
}

// ResolveCertSource 启动时决定证书源: 配置 cert_dir 优先于 CLI 参数(配置即权威)。
// certDir 非空 = 目录文件源; 空 = 回落 CLI 参数 (-source / -source-arg)。
func ResolveCertSource(flagType, flagArg, certDir string) (certsource.Source, error) {
	if certDir != "" {
		return certsource.New(certsource.Dir, certDir)
	}
	return certsource.New(certsource.SourceType(flagType), flagArg)
}

// UpdateSettings 更新连接设置并热应用: 落盘(noPersist 除外) + lang 立即生效 + 重建隧道
// (Reload 应用 server_addr/listen_host/server_ca; admin_addr 由 adminAddr() 每次读取, 改 cfg 即生效;
// cert_dir 变更先构建新证书源(失败则整体失败), 再热替换 relay 来源)
func (m *Manager) UpdateSettings(p SettingsPatch) error {
	// 证书源变更: 先构建新源(锁外; 失败则整体失败, 不改 cfg 不落盘)
	var newSrc certsource.Source
	if p.CertDir != nil && m.relay != nil {
		s, err := certSourceFromConfig(*p.CertDir)
		if err != nil {
			return fmt.Errorf("cert source: %w", err)
		}
		newSrc = s
	}
	// 锁内改内存 cfg(记录旧值: 应用失败回滚用 — 半提交修复: 先应用后落盘)
	m.mu.Lock()
	oldCfg := m.cfg
	if p.ServerAddr != nil {
		m.cfg.ServerAddr = *p.ServerAddr
	}
	if p.AdminAddr != nil {
		m.cfg.AdminAddr = *p.AdminAddr
	}
	if p.ListenHost != nil {
		m.cfg.ListenHost = *p.ListenHost
	}
	if p.ServerCA != nil {
		m.cfg.ServerCAFile = *p.ServerCA
	}
	if p.CertDir != nil {
		m.cfg.CertDir = *p.CertDir
	}
	if p.Lang != nil {
		m.cfg.Lang = *p.Lang
	}
	cfg := m.cfg
	tuns := m.cfg.Tunnels
	if tuns == nil {
		tuns = []Tunnel{}
	}
	cfg.Tunnels = append([]Tunnel{}, tuns...) // 从非 nil 空数组开始 append, 保持 "tunnels": [] 而非 null
	np := m.noPersist
	m.mu.Unlock()

	// 先应用 relay(可能失败: SetServerCA 失败 → 回滚内存 cfg, 不落盘 — 避免"配置已持久化但未生效"半提交)
	if m.relay != nil {
		if p.Lang != nil {
			m.relay.SetLang(*p.Lang)
		}
		if p.ServerCA != nil {
			if err := m.relay.SetServerCA(*p.ServerCA); err != nil {
				m.mu.Lock()
				m.cfg = oldCfg // 回滚(未落盘, 磁盘保持旧值)
				m.mu.Unlock()
				return fmt.Errorf("set server_ca: %w", err)
			}
		}
		if p.CertDir != nil {
			m.relay.SetSource(newSrc) // 热换源: 清证书缓存, 按当前 server_ca 重新过滤
		}
	}
	if !np {
		if err := SaveConfig(m.cfgPath, cfg); err != nil {
			return fmt.Errorf("persist config: %w", err)
		}
	}
	// server_addr / listen_host / server_ca / cert_dir 变更 → Reload 重建隧道(热生效)
	if p.ServerAddr != nil || p.ListenHost != nil || p.ServerCA != nil || p.CertDir != nil {
		return m.reloadTunnels()
	}
	return nil
}

// AddTunnel 新增或覆盖隧道并持久化 (noPersist 时仅内存)
func (m *Manager) AddTunnel(t Tunnel) error {
	m.mu.Lock()
	m.cfg.UpsertTunnel(t)
	cfg := m.cfg
	cfg.Tunnels = append([]Tunnel(nil), m.cfg.Tunnels...) // 深拷贝: 防锁外 marshal 与并发修改竞态
	np := m.noPersist
	m.mu.Unlock()
	if !np {
		if err := SaveConfig(m.cfgPath, cfg); err != nil {
			log.Printf("config saved in memory but disk write failed: %v (restart will lose changes)", err)
		}
	}
	if err := m.reloadTunnels(); err != nil {
		return err // 隧道启动失败如实上报(不再谎报成功)
	}
	return nil
}

// reloadTunnels 把当前配置同步到运行时(增删立即生效); 返回错误供调用方上报
func (m *Manager) reloadTunnels() error {
	if m.relay == nil {
		return nil // 无 relay 后端(测试/纯配置模式)
	}
	if err := m.relay.Reload(m.Config()); err != nil {
		if err == errNotStarted {
			return nil // relay 未启动: 配置已保存, Start 时生效, 不算错误
		}
		return err
	}
	return nil
}

// DelTunnel 删除隧道(整个服务)并持久化 (noPersist 时仅内存); 立即停掉运行时
func (m *Manager) DelTunnel(id string) (bool, error) {
	m.mu.Lock()
	ok := m.cfg.DelTunnel(id)
	cfg := m.cfg
	cfg.Tunnels = append([]Tunnel(nil), m.cfg.Tunnels...) // 深拷贝: 防锁外 marshal 与并发修改竞态
	np := m.noPersist
	m.mu.Unlock()
	if !ok {
		return false, nil
	}
	if !np {
		if err := SaveConfig(m.cfgPath, cfg); err != nil {
			log.Printf("config saved in memory but disk write failed: %v (restart will lose changes)", err)
		}
	}
	if err := m.reloadTunnels(); err != nil { // 落盘失败也同步运行时(内存权威, 与 AddTunnel 一致); 失败上报
		return true, err
	}
	return true, nil
}

// Start 按当前配置启动中继
func (m *Manager) Start() error {
	cfg := m.Config()
	return m.relay.Start(cfg)
}

// StartWith 用给定配置启动(不读内存 cfg): 供 --server 等覆盖值注入(否则 Start 会用配置文件值覆盖)
func (m *Manager) StartWith(cfg RelayConfig) error {
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
	// 注意: serverOverride(--server) 是【发现端点】覆盖, 不是 admin 端点 —
	// admin 桥(签发/吊销/验证)必须走独立的 admin_addr, 混用会导致管理功能打到 /info 假成功
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
	return NewAdminClient(addr, cert, m.relay.rootCAsCopy()), nil
}

// withAdmin 建立 admin 客户端并执行 fn(管理桥样板收敛 M3)。
// 失败(无 admin_addr/证书加载失败)返回零值+err; 成功后关闭客户端。
func withAdmin[T any](m *Manager, certID, password string, fn func(*AdminClient) (T, error)) (T, error) {
	var zero T
	ac, err := m.adminClientFor(certID, password)
	if err != nil {
		return zero, err
	}
	defer ac.Close()
	return fn(ac)
}

// withAdminErr 同 withAdmin, 供只返回 error 的管理桥操作使用。
func withAdminErr(m *Manager, certID, password string, fn func(*AdminClient) error) error {
	_, err := withAdmin(m, certID, password, func(ac *AdminClient) (struct{}, error) {
		return struct{}{}, fn(ac)
	})
	return err
}

func (m *Manager) AdminVerify(certID, password string) error {
	return withAdminErr(m, certID, password, func(ac *AdminClient) error { return ac.Verify() })
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
		ac := NewAdminClient(addr, cert, m.relay.rootCAsCopy())
		if err := ac.Verify(); err == nil {
			res.Admin = true
		}
		ac.Close()
	}
	return res, nil
}
func (m *Manager) AdminIssue(certID, password string, req IssueRequest) (*IssueResponse, error) {
	return withAdmin(m, certID, password, func(ac *AdminClient) (*IssueResponse, error) { return ac.Issue(req) })
}
func (m *Manager) AdminRevoke(certID, password, serial string) error {
	return withAdminErr(m, certID, password, func(ac *AdminClient) error { return ac.Revoke(serial) })
}

// AdminConfig 服务端配置总览 (mode + mappings + services)
func (m *Manager) AdminConfig(certID, password string) (json.RawMessage, error) {
	return withAdmin(m, certID, password, func(ac *AdminClient) (json.RawMessage, error) { return ac.Cfg() })
}

// AdminSetConfig 整体替换服务端配置
func (m *Manager) AdminSetConfig(certID, password string, body json.RawMessage) (json.RawMessage, error) {
	return withAdmin(m, certID, password, func(ac *AdminClient) (json.RawMessage, error) { return ac.SetConfig(body) })
}

// AdminMapping 通道 CRUD 透传 (method: POST/PUT/DELETE)
func (m *Manager) AdminMapping(certID, password, method, id string, body json.RawMessage) (json.RawMessage, error) {
	return withAdmin(m, certID, password, func(ac *AdminClient) (json.RawMessage, error) { return ac.Mapping(method, id, body) })
}

// AdminService 服务 CRUD 透传 (method: POST/PUT/DELETE)
func (m *Manager) AdminService(certID, password, method, name string, body json.RawMessage) (json.RawMessage, error) {
	return withAdmin(m, certID, password, func(ac *AdminClient) (json.RawMessage, error) { return ac.Service(method, name, body) })
}

// AdminListCerts 拉取服务端全部证书(供吊销下拉)
func (m *Manager) AdminListCerts(certID, password string) (json.RawMessage, error) {
	return withAdmin(m, certID, password, func(ac *AdminClient) (json.RawMessage, error) { return ac.List() })
}

// AdminMappings 拉取服务端全部映射(供签发时选用途)
func (m *Manager) AdminMappings(certID, password string) ([]MappingInfo, error) {
	return withAdmin(m, certID, password, func(ac *AdminClient) ([]MappingInfo, error) { return ac.ListMappings() })
}

// BuildServiceTunnels 依据服务端服务定义生成一条服务级隧道(含全部通道的本地路由)。
// locals: 通道 listen → 本地路由 (缺省 = 通道 listen 原样, 含冒号)
// lang: 错误语言(zh/en; 空=进程默认)
func (m *Manager) BuildServiceTunnels(svc ServiceInfo, locals map[string]string, certID, lang string) (Tunnel, error) {
	l := m.relay.lang() // 锁内读(SetLang 并发写, 防 data race)
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
	return m.relay.lang()
}

// webUILogger 懒创建 WebUI 事件日志(从配置 webui_log_file; 空=禁用)。
// 创建失败不永久禁用(sync.Once 毒化): 配置文件写权限修复后下次请求重试。
func (m *Manager) webUILogger() *eventlog.Logger {
	cfg := m.Config()
	if cfg.WebUILogFile == "" {
		return nil
	}
	m.webUIMu.Lock()
	defer m.webUIMu.Unlock()
	if m.webUI != nil {
		return m.webUI
	}
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
		log.Printf("webui log: %v (本次不记录, 下次请求重试)", err)
		return nil
	}
	m.webUI = l
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

	mux.HandleFunc("GET /api/settings", func(w http.ResponseWriter, r *http.Request) {
		cfg := m.Config()
		writeJSON(w, map[string]any{
			"server_addr": cfg.ServerAddr,
			"admin_addr":  cfg.AdminAddr,
			"listen_host": cfg.ListenHost,
			"server_ca":   cfg.ServerCAFile,
			"cert_dir":    cfg.CertDir,
			"lang":        cfg.Lang,
		})
	})
	mux.HandleFunc("PUT /api/settings", func(w http.ResponseWriter, r *http.Request) {
		var p SettingsPatch
		if !decodeJSON(w, r, &p) { // 含 MaxBytesReader 4MB 上限(此前直接 Decode 绕过限流 — 测试审计发现)
			return
		}
		if err := m.UpdateSettings(p); err != nil {
			writeErr(w, r, err)
			return
		}
		writeJSON(w, map[string]any{"ok": true})
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
		if !decodeJSON(w, r, &b) {
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
// 状态码判定顺序: ① 管理桥错误内嵌的 "HTTP NNN"(权威) → ② 原始错误关键字(本地化译文措辞变化会错标)
func writeErr(w http.ResponseWriter, r *http.Request, err error) {
	raw := err.Error()
	msg := raw
	if r != nil {
		if lang := r.Header.Get("X-Lang"); lang == "en" || lang == "zh" {
			msg = localizeKnown(lang, err).Error()
		}
	}
	code := http.StatusInternalServerError
	// ① 优先解析管理桥错误里的真实状态码: "admin POST /x: HTTP 400: ..."(正则仅匹配 4xx/5xx)
	if m := reHTTPStatus.FindStringSubmatch(raw); len(m) == 2 {
		if c, e := strconv.Atoi(m[1]); e == nil {
			code = c
		}
	} else {
		// ② 关键字回退: 复用服务端共享权威表(api.StatusFromKeywords), 消除两处映射漂移
		code = api.StatusFromKeywords(raw)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8") // 先设头再 WriteHeader
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// decodeJSON 解码请求体; 失败写 400 并返回 false
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes) // 4MB 上限
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeErr(w, r, fmt.Errorf("bad request: %v", err))
		return false
	}
	return true
}

// 错误串提取正则(包级预编译; 每正则单捕获组, len(m)==2 判定)
var (
	reErrName       = regexp.MustCompile(`decrypt key (\S+)`)
	reErrNamePwd    = regexp.MustCompile(`private key needs password: (\S+)`)
	reErrNameCert   = regexp.MustCompile(`cert (\S+) not found`)
	reErrNameExist  = regexp.MustCompile(`certificate name (\S+) already exists`)
	reErrNameExist2 = regexp.MustCompile(`name (\S+) already exists`)
	reErrNameParse  = regexp.MustCompile(`parse (?:pem )?keypair (\S+):`)
	reErrRecord     = regexp.MustCompile(`\((\d+) record`)
	reHTTPStatus    = regexp.MustCompile(`HTTP ([45]\d{2})`)
)

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
		if m := reErrRecord.FindStringSubmatch(s); len(m) == 2 {
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
	case strings.Contains(s, "admin cert required"), strings.Contains(s, "admin required"):
		return l.E("errAdminDenied")
	case strings.Contains(s, "forbidden"):
		return l.E("errDenied")
	case strings.Contains(s, "not found"):
		return l.E("errNotFound", errCertName(s))
	case strings.Contains(s, "not registered"):
		return l.E("errNotFound", errCertName(s))
	case strings.Contains(s, "status=revoked"):
		return l.E("errRevoked") // 模板无 %s, 不传参
	case strings.Contains(s, "expired"):
		return l.E("errExpired") // 模板无 %s, 不传参
	}
	return err
}

// errCertName 从错误消息提取证书名("decrypt key admin"/"cert admin not found"/"private key needs password: admin")
func errCertName(s string) string {
	for _, re := range []*regexp.Regexp{reErrName, reErrNamePwd, reErrNameCert, reErrNameExist, reErrNameExist2, reErrNameParse} {
		if m := re.FindStringSubmatch(s); len(m) == 2 {
			// reErrName 用 \S+ 会连尾部冒号一起捕获("admin:" / "C:\x.pem:"), 去掉之
			return strings.TrimSuffix(m[1], ":")
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
