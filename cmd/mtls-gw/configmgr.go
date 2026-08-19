// 服务端配置管理: 模式(mutable/ephemeral/immutable) + 通道/服务 CRUD + 热重载 + TOML 落盘(带备份)
package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/BurntSushi/toml"

	"mtls-gateway/internal/proxy"
)

// ConfigManager 持有可变的配置 + 路由器; 所有读写都过它(管理 API / 热重载)
type ConfigManager struct {
	mu     sync.Mutex
	path   string
	mode   string // mutable | ephemeral | immutable
	cfg    Config
	router *proxy.Router
}

func NewConfigManager(path string, cfg Config, router *proxy.Router) *ConfigManager {
	return &ConfigManager{path: path, mode: cfg.ConfigMode, cfg: cfg, router: router}
}

func (m *ConfigManager) Mode() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mode
}

func (m *ConfigManager) AdminRole() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg.AdminRole
}

func (m *ConfigManager) Router() *proxy.Router {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.router
}

func (m *ConfigManager) Mappings() []proxy.Mapping {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg.Mappings
}

func (m *ConfigManager) Services() []proxy.ServiceCfg {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg.Services
}

func (m *ConfigManager) checkWritable() error {
	if m.mode == "immutable" {
		return fmt.Errorf("config is immutable (read-only): 修改被服务端拒绝")
	}
	return nil
}

// rebuild 用当前 cfg 重建路由器(热重载); 失败回滚
func (m *ConfigManager) rebuild() error {
	r, err := proxy.NewRouter(m.cfg.Mappings, m.cfg.Services)
	if err != nil {
		return err
	}
	m.router = r
	return nil
}

// persist 落盘 (ephemeral 跳过; mutable 先备份再写)
func (m *ConfigManager) persist() error {
	if m.mode == "ephemeral" {
		return nil
	}
	if err := copyFile(m.path, m.path+".bak-"+time.Now().Format("20060102-150405")); err != nil {
		log.Printf("config backup failed: %v (仍继续写入)", err)
	}
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(m.cfg); err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	return os.WriteFile(m.path, buf.Bytes(), 0o600)
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o600)
}

// ---- 通道 (mappings) ----

func (m *ConfigManager) AddMapping(mm proxy.Mapping) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkWritable(); err != nil {
		return err
	}
	m.cfg.Mappings = append(m.cfg.Mappings, mm)
	if err := m.rebuild(); err != nil {
		m.cfg.Mappings = m.cfg.Mappings[:len(m.cfg.Mappings)-1]
		return err
	}
	return m.persist()
}

func (m *ConfigManager) UpdateMapping(id string, mm proxy.Mapping) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkWritable(); err != nil {
		return err
	}
	old := m.cfg.Mappings
	found := false
	for i := range m.cfg.Mappings {
		if m.cfg.Mappings[i].ID == id {
			m.cfg.Mappings[i] = mm
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("mapping %q not found", id)
	}
	if err := m.rebuild(); err != nil {
		m.cfg.Mappings = old
		return err
	}
	return m.persist()
}

func (m *ConfigManager) DeleteMapping(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkWritable(); err != nil {
		return err
	}
	old := m.cfg.Mappings
	out := m.cfg.Mappings[:0]
	for _, mm := range m.cfg.Mappings {
		if mm.ID != id {
			out = append(out, mm)
		}
	}
	if len(out) == len(m.cfg.Mappings) {
		return fmt.Errorf("mapping %q not found", id)
	}
	m.cfg.Mappings = out
	if err := m.rebuild(); err != nil {
		m.cfg.Mappings = old
		return err
	}
	return m.persist()
}

// ---- 服务 (services) ----

func (m *ConfigManager) AddService(s proxy.ServiceCfg) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkWritable(); err != nil {
		return err
	}
	m.cfg.Services = append(m.cfg.Services, s)
	if err := m.rebuild(); err != nil {
		m.cfg.Services = m.cfg.Services[:len(m.cfg.Services)-1]
		return err
	}
	return m.persist()
}

func (m *ConfigManager) UpdateService(name string, s proxy.ServiceCfg) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkWritable(); err != nil {
		return err
	}
	old := m.cfg.Services
	found := false
	for i := range m.cfg.Services {
		if m.cfg.Services[i].Name == name {
			m.cfg.Services[i] = s
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("service %q not found", name)
	}
	if err := m.rebuild(); err != nil {
		m.cfg.Services = old
		return err
	}
	return m.persist()
}

func (m *ConfigManager) DeleteService(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkWritable(); err != nil {
		return err
	}
	old := m.cfg.Services
	out := m.cfg.Services[:0]
	for _, s := range m.cfg.Services {
		if s.Name != name {
			out = append(out, s)
		}
	}
	if len(out) == len(m.cfg.Services) {
		return fmt.Errorf("service %q not found", name)
	}
	m.cfg.Services = out
	if err := m.rebuild(); err != nil {
		m.cfg.Services = old
		return err
	}
	return m.persist()
}
