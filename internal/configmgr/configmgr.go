// Package configmgr 配置管理: 模式 + 通道/服务 CRUD + 热重载 + TOML 落盘(带备份)。
// 网关与 mtls-admin 管理进程共用: 网关用 ReloadFromDisk(重读文件); 管理进程用 CRUD(改内存+落盘)。
package configmgr

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

	"mtls-gateway/internal/atomicfile"
	"mtls-gateway/internal/config"
	"mtls-gateway/internal/errs"
	"mtls-gateway/internal/i18n"
	"mtls-gateway/internal/proxy"
	"mtls-gateway/internal/types"
)

// ConfigManager 持有可变的配置 + 路由器; 所有读写都过它(管理 API / 热重载)
type ConfigManager struct {
	mu     sync.Mutex
	path   string
	mode   string // mutable | ephemeral | immutable
	cfg    config.Config
	router *proxy.Router
	L      *i18n.L // 错误消息语言(zh/en, 默认 zh)
}

// New 创建配置管理器: 持有配置 + 路由器, 模式与错误语言跟随 cfg。
// path=配置文件路径(落盘与 ReloadFromDisk 用); router=初始路由器(启动时构建)。
func New(path string, cfg config.Config, router *proxy.Router) *ConfigManager {
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
	return append([]proxy.Mapping(nil), m.cfg.Mappings...) // 深拷贝, 防外部改动/竞态
}

func (m *ConfigManager) Services() []proxy.ServiceCfg {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]proxy.ServiceCfg, len(m.cfg.Services))
	for i := range m.cfg.Services {
		out[i] = m.cfg.Services[i]
		out[i].Roles = append([]string(nil), m.cfg.Services[i].Roles...)
		out[i].Channels = append([]string(nil), m.cfg.Services[i].Channels...)
	}
	return out
}

func (m *ConfigManager) Roles() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.cfg.Roles...)
}

// ConfigPath 返回配置文件路径(ReloadFromDisk / 测试用)
func (m *ConfigManager) ConfigPath() string { return m.path }

func (m *ConfigManager) checkWritable() error {
	if m.mode == config.ModeImmutable {
		return errs.WithKind(m.L.E("errImmutable"), errs.KindImmutable)
	}
	return nil
}

// rebuild 用当前 cfg 重建路由器(热重载); 失败回滚
func (m *ConfigManager) rebuild() error {
	// admin_role 禁入业务服务 roles: 启动校验之外, 热更新路径(AddService/UpdateService/ReplaceAll)同样拦截
	for _, s := range m.cfg.Services {
		for _, r := range s.Roles {
			if r == m.cfg.AdminRole {
				return errs.New(errs.KindBadRequest, "service %s roles 里不允许出现内置管理角色 %q", s.Name, m.cfg.AdminRole)
			}
		}
	}
	// admin_role 禁入 roles 声明列表: 与 config.Parse/AddRole 三处对称 —
	// 此前 ReplaceAll 直接把请求 roles 赋给 m.cfg.Roles 绕过此校验, 可持久化网关
	// 拒绝加载的配置(内存/磁盘分叉 + 网关重启拒载 + 提权不变量绕过, pro 深度审计抓出)
	for _, r := range m.cfg.Roles {
		if r == m.cfg.AdminRole {
			return errs.New(errs.KindBadRequest, "admin_role %q 禁止出现在 roles 声明列表(提权风险)", m.cfg.AdminRole)
		}
	}
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

// ReloadFromDisk 重读配置文件并全量热重载(管理进程改配置后经 /admin/reload 调用)。
// 先解析+校验+构建新 router, 再原子替换(mode/Lang 同步); 任一步失败保持旧配置继续服务(失败不切换)。
// 安全字段(admin_role/require_ip_bind/tls_min_version)不热重载 — 网关 auth.New 启动固化,
// 接受新值会造成"配置校验按新值、授权闸门按旧值"分叉(S-2, pro 前瞻审计): 旧 admin 证书
// 会 stale-open 直到重启。检测到任一变更 → 拒绝 reload 并报错, 迫使运维重启两进程。
func (m *ConfigManager) ReloadFromDisk() error {
	cfg, err := config.Parse(m.path)
	if err != nil {
		return fmt.Errorf("reload config: %w", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if cfg.AdminRole != m.cfg.AdminRole ||
		cfg.RequireIPBindResolved() != m.cfg.RequireIPBindResolved() ||
		cfg.TLSMinVersion != m.cfg.TLSMinVersion {
		return errs.New(errs.KindBadRequest,
			"reload 拒绝: admin_role/require_ip_bind/tls_min_version 变更需重启两个进程(网关授权闸门启动固化, 热重载不同步)")
	}
	r, err := proxy.NewRouter(cfg.Mappings, cfg.Services, cfg.Roles)
	if err != nil {
		return fmt.Errorf("reload config: %w", err)
	}
	if m.router != nil {
		m.router.Close()
	}
	m.cfg, m.router, m.mode = cfg, r, cfg.ConfigMode
	m.L = i18n.New(cfg.Lang)
	return nil
}

// mutate 统一 CRUD 骨架: 检查可写 → apply 修改 cfg → rebuild 新 router → persist 落盘。
// 任一步失败整体回滚, 保证内存与磁盘一致(不留半态):
//   - apply 失败: 不 rollback(约定: apply 返回错误时 cfg 未被修改, 由 apply 自己保证);
//   - rebuild 失败: rollback 恢复 cfg(旧 router 未被触碰, 无需重建);
//   - persist 失败: rollback 恢复 cfg + rebuild 回旧 router(磁盘没写成, 内存必须还原)。
//
// 这是 2026-08-21 22:18 生产事件(内存 services 变空、重启才恢复)的根因修复:
// 落盘失败时内存不回滚, 导致内存/磁盘分叉。
func (m *ConfigManager) mutate(apply func() error, rollback func()) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkWritable(); err != nil {
		return err
	}
	if err := apply(); err != nil {
		return err
	}
	if err := m.rebuild(); err != nil {
		rollback()
		return err
	}
	if err := m.persist(); err != nil {
		rollback()
		m.rebuild() // 恢复旧 router(旧状态必然合法, 忽略错误)
		return fmt.Errorf("persist config: %w", err)
	}
	return nil
}

// persist 落盘 (ephemeral 跳过; mutable 先备份再写; 原子替换 + 备份限量)
func (m *ConfigManager) persist() error {
	if m.mode == config.ModeEphemeral {
		return nil
	}
	// D-3(pro 前瞻审计): 全量重写会丢失配置文件中未建模的键/注释 — 落盘前告警,
	// 让运维在升级/手改配置后知道哪些内容将被抹掉(不拒绝: 可用性优先, 备份已留)。
	if len(m.cfg.Undecoded) > 0 {
		log.Printf("⚠️ 配置文件含未建模键 %v, 本次落盘将丢失(如需保留请先升级二进制或手动合并)", m.cfg.Undecoded)
	}
	if err := copyFile(m.path, m.path+".bak-"+time.Now().Format("20060102-150405.000000000")); err != nil {
		log.Printf("config backup failed: %v (仍继续写入)", err)
	}
	// 备份限量: 只留最近 5 份, 防无限累积
	pruneBackups(m.path, 5)
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(m.cfg); err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	// 原子替换(CreateTemp 唯一临时文件 + rename): 抽 internal/atomicfile 与 relay.SaveConfig 共用
	if err := atomicfile.WriteFile(m.path, buf.Bytes()); err != nil {
		return fmt.Errorf("persist config: %w", err)
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

// ReplaceAll 整体替换 mappings+services+roles (批量编辑保存; 任一步失败回滚)
func (m *ConfigManager) ReplaceAll(ms []proxy.Mapping, ss []proxy.ServiceCfg, roles []string) error {
	var oldM []proxy.Mapping
	var oldS []proxy.ServiceCfg
	var oldR []string
	return m.mutate(func() error {
		oldM, oldS, oldR = m.cfg.Mappings, m.cfg.Services, m.cfg.Roles
		m.cfg.Mappings, m.cfg.Services, m.cfg.Roles = ms, ss, roles
		return nil
	}, func() {
		m.cfg.Mappings, m.cfg.Services, m.cfg.Roles = oldM, oldS, oldR
	})
}

// ---- 角色 (roles 声明列表) ----

func (m *ConfigManager) AddRole(name string) error {
	var old []string
	return m.mutate(func() error {
		if name == "any" {
			return errs.New(errs.KindBadRequest, "any 是内置保留字, 禁止声明")
		}
		if name == "null" {
			return errs.New(errs.KindBadRequest, "null 是内置保留字(匿名访问), 禁止声明")
		}
		if name == m.cfg.AdminRole {
			return errs.New(errs.KindBadRequest, "内置管理角色 %q 禁止声明为普通角色", name)
		}
		if !types.ValidRoleName(name) {
			return errs.New(errs.KindBadRequest, "bad role name %q (只允许字母/数字/下划线/连字符)", name)
		}
		for _, r := range m.cfg.Roles {
			if r == name {
				return errs.New(errs.KindConflict, "role %q 已声明", name)
			}
		}
		old = m.cfg.Roles
		m.cfg.Roles = append(m.cfg.Roles, name)
		return nil
	}, func() {
		m.cfg.Roles = old
	})
}

func (m *ConfigManager) DeleteRole(name string) error {
	var old []string
	return m.mutate(func() error {
		if name == "any" {
			return errs.New(errs.KindBadRequest, "any 是内置保留字, 不可删除")
		}
		// 被服务引用时禁止删除
		for _, s := range m.cfg.Services {
			for _, r := range s.Roles {
				if r == name {
					return errs.New(errs.KindConflict, "role %q 仍被服务 %s 引用, 先改服务再删", name, s.Name)
				}
			}
		}
		old = append([]string(nil), m.cfg.Roles...) // 深拷贝(回滚用, [:0] 复用会污染 old)
		out := m.cfg.Roles[:0]
		for _, r := range m.cfg.Roles {
			if r != name {
				out = append(out, r)
			}
		}
		if len(out) == len(m.cfg.Roles) {
			return errs.New(errs.KindBadRequest, "role %q 未声明", name)
		}
		m.cfg.Roles = out
		return nil
	}, func() {
		m.cfg.Roles = old
	})
}

// ---- 通道 (mappings) ----

func (m *ConfigManager) AddMapping(mm proxy.Mapping) error {
	return m.mutate(func() error {
		m.cfg.Mappings = append(m.cfg.Mappings, mm)
		return nil
	}, func() {
		m.cfg.Mappings = m.cfg.Mappings[:len(m.cfg.Mappings)-1]
	})
}

func (m *ConfigManager) UpdateMapping(id string, mm proxy.Mapping) error {
	var old []proxy.Mapping
	return m.mutate(func() error {
		old = append([]proxy.Mapping(nil), m.cfg.Mappings...) // 深拷贝(回滚用)
		found := false
		for i := range m.cfg.Mappings {
			if m.cfg.Mappings[i].ID == id {
				m.cfg.Mappings[i] = mm
				found = true
				break
			}
		}
		if !found {
			return errs.New(errs.KindNotFound, "mapping %q not found", id)
		}
		return nil
	}, func() {
		m.cfg.Mappings = old
	})
}

func (m *ConfigManager) DeleteMapping(id string) error {
	var old []proxy.Mapping
	return m.mutate(func() error {
		old = append([]proxy.Mapping(nil), m.cfg.Mappings...) // 深拷贝(回滚用)
		out := m.cfg.Mappings[:0]
		for _, mm := range m.cfg.Mappings {
			if mm.ID != id {
				out = append(out, mm)
			}
		}
		if len(out) == len(m.cfg.Mappings) {
			return errs.New(errs.KindNotFound, "mapping %q not found", id)
		}
		m.cfg.Mappings = out
		return nil
	}, func() {
		m.cfg.Mappings = old
	})
}

// ---- 服务 (services) ----

func (m *ConfigManager) AddService(s proxy.ServiceCfg) error {
	return m.mutate(func() error {
		m.cfg.Services = append(m.cfg.Services, s)
		return nil
	}, func() {
		m.cfg.Services = m.cfg.Services[:len(m.cfg.Services)-1]
	})
}

func (m *ConfigManager) UpdateService(name string, s proxy.ServiceCfg) error {
	var old []proxy.ServiceCfg
	return m.mutate(func() error {
		old = append([]proxy.ServiceCfg(nil), m.cfg.Services...) // 深拷贝(回滚用)
		found := false
		for i := range m.cfg.Services {
			if m.cfg.Services[i].Name == name {
				m.cfg.Services[i] = s
				found = true
				break
			}
		}
		if !found {
			return errs.New(errs.KindNotFound, "service %q not found", name)
		}
		return nil
	}, func() {
		m.cfg.Services = old
	})
}

func (m *ConfigManager) DeleteService(name string) error {
	var old []proxy.ServiceCfg
	return m.mutate(func() error {
		old = append([]proxy.ServiceCfg(nil), m.cfg.Services...) // 深拷贝(回滚用)
		out := m.cfg.Services[:0]
		for _, s := range m.cfg.Services {
			if s.Name != name {
				out = append(out, s)
			}
		}
		if len(out) == len(m.cfg.Services) {
			return errs.New(errs.KindNotFound, "service %q not found", name)
		}
		m.cfg.Services = out
		return nil
	}, func() {
		m.cfg.Services = old
	})
}
