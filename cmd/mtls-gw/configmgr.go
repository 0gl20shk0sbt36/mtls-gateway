// 服务端配置管理: 模式(mutable/ephemeral/immutable) + 通道/服务 CRUD + 热重载 + TOML 落盘(带备份)
package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/BurntSushi/toml"

	"mtls-gateway/internal/i18n"
	"mtls-gateway/internal/proxy"
)

// ConfigManager 持有可变的配置 + 路由器; 所有读写都过它(管理 API / 热重载)
type ConfigManager struct {
	mu     sync.Mutex
	path   string
	mode   string // mutable | ephemeral | immutable
	cfg    Config
	router *proxy.Router
	L      *i18n.L // 错误消息语言(zh/en, 默认 zh)
}

func NewConfigManager(path string, cfg Config, router *proxy.Router) *ConfigManager {
	return &ConfigManager{path: path, mode: cfg.ConfigMode, cfg: cfg, router: router, L: i18n.New(cfg.Lang)}
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

func (m *ConfigManager) Roles() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg.Roles
}

func (m *ConfigManager) checkWritable() error {
	if m.mode == "immutable" {
		return m.L.E("errImmutable")
	}
	return nil
}

// rebuild 用当前 cfg 重建路由器(热重载); 失败回滚
func (m *ConfigManager) rebuild() error {
	old := m.router
	r, err := proxy.NewRouter(m.cfg.Mappings, m.cfg.Services, m.cfg.Roles)
	if err != nil {
		return err
	}
	if old != nil {
		old.Close() // 释放旧路由的 idle 连接(热重载不累积 Transport)
	}
	m.router = r
	return nil
}

// persist 落盘 (ephemeral 跳过; mutable 先备份再写; 原子替换 + 备份限量)
func (m *ConfigManager) persist() error {
	if m.mode == "ephemeral" {
		return nil
	}
	if err := copyFile(m.path, m.path+".bak-"+time.Now().Format("20060102-150405")); err != nil {
		log.Printf("config backup failed: %v (仍继续写入)", err)
	}
	// 备份限量: 只留最近 5 份, 防无限累积
	pruneBackups(m.path, 5)
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(m.cfg); err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	// 原子替换: 临时文件 + rename, 避免写一半崩溃损坏配置
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("write tmp config: %w", err)
	}
	if err := os.Rename(tmp, m.path); err != nil {
		return fmt.Errorf("replace config: %w", err)
	}
	return nil
}

// pruneBackups 清理超过 maxKeep 份的 .bak-* 备份(保留最新的)
func pruneBackups(path string, maxKeep int) {
	matches, err := filepath.Glob(path + ".bak-*")
	if err != nil {
		return
	}
	if len(matches) <= maxKeep {
		return
	}
	sort.Strings(matches) // 时间戳命名, 字典序=时间序
	for _, old := range matches[:len(matches)-maxKeep] {
		os.Remove(old)
	}
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o600)
}

// ReplaceAll 整体替换 mappings+services+roles (批量编辑保存; 校验失败回滚)
func (m *ConfigManager) ReplaceAll(ms []proxy.Mapping, ss []proxy.ServiceCfg, roles []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkWritable(); err != nil {
		return err
	}
	oldM, oldS, oldR := m.cfg.Mappings, m.cfg.Services, m.cfg.Roles
	m.cfg.Mappings, m.cfg.Services, m.cfg.Roles = ms, ss, roles
	if err := m.rebuild(); err != nil {
		m.cfg.Mappings, m.cfg.Services, m.cfg.Roles = oldM, oldS, oldR
		return err
	}
	return m.persist()
}

// ---- 角色 (roles 声明列表) ----

func (m *ConfigManager) AddRole(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkWritable(); err != nil {
		return err
	}
	if name == "any" {
		return fmt.Errorf("any 是内置保留字, 禁止声明")
	}
	if !proxy.ValidRoleName(name) {
		return fmt.Errorf("bad role name %q (只允许字母/数字/下划线/连字符)", name)
	}
	for _, r := range m.cfg.Roles {
		if r == name {
			return fmt.Errorf("role %q 已声明", name)
		}
	}
	old := m.cfg.Roles
	m.cfg.Roles = append(m.cfg.Roles, name)
	if err := m.rebuild(); err != nil {
		m.cfg.Roles = old
		return err
	}
	return m.persist()
}

func (m *ConfigManager) DeleteRole(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkWritable(); err != nil {
		return err
	}
	if name == "any" {
		return fmt.Errorf("any 是内置保留字, 不可删除")
	}
	// 被服务引用时禁止删除
	for _, s := range m.cfg.Services {
		for _, r := range s.Roles {
			if r == name {
				return fmt.Errorf("role %q 仍被服务 %s 引用, 先改服务再删", name, s.Name)
			}
		}
	}
	old := m.cfg.Roles
	out := m.cfg.Roles[:0]
	for _, r := range m.cfg.Roles {
		if r != name {
			out = append(out, r)
		}
	}
	if len(out) == len(m.cfg.Roles) {
		return fmt.Errorf("role %q 未声明", name)
	}
	m.cfg.Roles = out
	if err := m.rebuild(); err != nil {
		m.cfg.Roles = old
		return err
	}
	return m.persist()
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
