package relay

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"mtls-gateway/internal/certsource"
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

// Config 返回当前配置的副本
func (m *Manager) Config() RelayConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg
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
	return nil
}

// DelTunnel 删除隧道并持久化 (noPersist 时仅内存)
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

// BuildServiceTunnels 依据服务端服务定义生成该服务所有通道的隧道。
// locals: 通道 listen → 本地路由 (缺省 = 通道 listen 原样, 含冒号)
func (m *Manager) BuildServiceTunnels(svc ServiceInfo, locals map[string]string, certID string) ([]Tunnel, error) {
	var out []Tunnel
	for _, ch := range svc.Channels {
		local := ""
		if locals != nil {
			local = locals[ch.Listen]
		}
		if local == "" {
			local = ch.Listen // 默认本地路由 = 服务端通道内容一致 (含冒号与路径)
		}
		out = append(out, Tunnel{
			Service: svc.Name,
			Channel: ch.Listen,
			Local:   local,
			CertID:  certID,
			Enabled: true,
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("service %s has no channels", svc.Name)
	}
	return out, nil
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
			writeErr(w, err)
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
		json.NewDecoder(r.Body).Decode(&b)
		res, err := m.Verify(b.CertID, b.LoadPwd)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, res)
	})

	// GET /api/services — 从服务端 /info 拉取可用服务(供选择)
	mux.HandleFunc("GET /api/services", func(w http.ResponseWriter, r *http.Request) {
		svcs, err := m.Services()
		if err != nil {
			writeErr(w, err)
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
		json.NewDecoder(r.Body).Decode(&b)
		if err := m.AdminVerify(b.CertID, b.LoadPwd); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, map[string]any{"ok": true})
	})
	mux.HandleFunc("POST /api/admin/issue", func(w http.ResponseWriter, r *http.Request) {
		var b adminIssueReq
		json.NewDecoder(r.Body).Decode(&b)
		resp, err := m.AdminIssue(b.CertID, b.LoadPwd, b.IssueRequest)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, resp)
	})
	// POST /api/admin/certs — 服务端证书列表(吊销下拉)
	mux.HandleFunc("POST /api/admin/certs", func(w http.ResponseWriter, r *http.Request) {
		var b adminVerifyReq
		json.NewDecoder(r.Body).Decode(&b)
		raw, err := m.AdminListCerts(b.CertID, b.LoadPwd)
		if err != nil {
			writeErr(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(raw)
	})
	// POST /api/admin/mappings — 全部映射(签发选用途)
	mux.HandleFunc("POST /api/admin/mappings", func(w http.ResponseWriter, r *http.Request) {
		var b adminVerifyReq
		json.NewDecoder(r.Body).Decode(&b)
		ms, err := m.AdminMappings(b.CertID, b.LoadPwd)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, map[string]any{"mappings": ms})
	})
	mux.HandleFunc("POST /api/admin/revoke", func(w http.ResponseWriter, r *http.Request) {
		var b adminRevokeReq
		json.NewDecoder(r.Body).Decode(&b)
		if err := m.AdminRevoke(b.CertID, b.LoadPwd, b.Serial); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, map[string]any{"ok": true})
	})

	// POST /api/admin/config — 服务端配置总览(mode+mappings+services)
	mux.HandleFunc("POST /api/admin/config", func(w http.ResponseWriter, r *http.Request) {
		var b adminVerifyReq
		json.NewDecoder(r.Body).Decode(&b)
		raw, err := m.AdminConfig(b.CertID, b.LoadPwd)
		if err != nil {
			writeErr(w, err)
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
		json.NewDecoder(r.Body).Decode(&b)
		raw, err := m.AdminSetConfig(b.CertID, b.LoadPwd, b.Body)
		if err != nil {
			writeErr(w, err)
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
		json.NewDecoder(r.Body).Decode(&b)
		raw, err := m.AdminMapping(b.CertID, b.LoadPwd, b.Method, b.ID, b.Mapping)
		if err != nil {
			writeErr(w, err)
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
		json.NewDecoder(r.Body).Decode(&b)
		raw, err := m.AdminService(b.CertID, b.LoadPwd, b.Method, b.Name, b.Service)
		if err != nil {
			writeErr(w, err)
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
			writeErr(w, err)
			return
		}
		if b.Service == "" || b.CertID == "" {
			writeErr(w, fmt.Errorf("service and cert_id required"))
			return
		}
		svcs, err := m.Services()
		if err != nil {
			writeErr(w, err)
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
			writeErr(w, fmt.Errorf("service not found on server: %s", b.Service))
			return
		}
		tunnels, err := m.BuildServiceTunnels(*svc, b.Locals, b.CertID)
		if err != nil {
			writeErr(w, err)
			return
		}
		for _, t := range tunnels {
			if err := m.AddTunnel(t); err != nil {
				writeErr(w, err)
				return
			}
		}
		writeJSON(w, map[string]any{"ok": true, "count": len(tunnels)})
	})

	// DELETE /api/tunnels/{id}
	mux.HandleFunc("DELETE /api/tunnels/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/tunnels/")
		if id == "" {
			writeErr(w, fmt.Errorf("missing tunnel id"))
			return
		}
		ok, err := m.DelTunnel(id)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": ok})
	})

	// POST /api/start | /api/stop | /api/reload
	mux.HandleFunc("POST /api/start", func(w http.ResponseWriter, r *http.Request) {
		if err := m.Start(); err != nil {
			writeErr(w, err)
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
			writeErr(w, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})

	return mux
}

func (m *Manager) ConfigPath() string { return m.cfgPath }

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	w.WriteHeader(http.StatusInternalServerError) // 失败必须非 2xx, 否则前端无法区分
	writeJSON(w, map[string]string{"error": err.Error()})
}
