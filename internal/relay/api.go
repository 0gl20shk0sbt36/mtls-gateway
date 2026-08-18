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
	relay   *Relay
	cfgPath string
	mu      sync.Mutex
	cfg     RelayConfig
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

// Save 将当前配置落盘
func (m *Manager) Save() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return SaveConfig(m.cfgPath, m.cfg)
}

// AddTunnel 新增或覆盖隧道并持久化
func (m *Manager) AddTunnel(t Tunnel) error {
	m.mu.Lock()
	m.cfg.UpsertTunnel(t)
	cfg := m.cfg
	m.mu.Unlock()
	if err := SaveConfig(m.cfgPath, cfg); err != nil {
		return err
	}
	return nil
}

// DelTunnel 删除隧道并持久化
func (m *Manager) DelTunnel(id string) (bool, error) {
	m.mu.Lock()
	ok := m.cfg.DelTunnel(id)
	cfg := m.cfg
	m.mu.Unlock()
	if !ok {
		return false, nil
	}
	if err := SaveConfig(m.cfgPath, cfg); err != nil {
		return true, err
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

	mux.HandleFunc("GET /api/config", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, m.Config())
	})

	// POST /api/tunnels  (body: Tunnel json) — 新增/覆盖
	mux.HandleFunc("POST /api/tunnels", func(w http.ResponseWriter, r *http.Request) {
		var t Tunnel
		if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
			writeErr(w, err)
			return
		}
		if err := m.AddTunnel(t); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
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
	writeJSON(w, map[string]string{"error": err.Error()})
}
