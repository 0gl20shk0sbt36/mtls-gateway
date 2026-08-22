// handler.go: 中继管理 HTTP 路由层(外壳/WebUI 的唯一接口)。
// 与 api.go(业务方法) / httperr.go(错误出口) 分离 — 路由骨架独立成文件,
// GUI 接入时只动本文件即可增删端点。
package relay

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"mtls-gateway/internal/eventlog"
	"mtls-gateway/internal/i18n"
)

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
