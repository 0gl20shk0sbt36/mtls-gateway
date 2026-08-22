// Package config 共享配置定义与解析(mtls-gw 网关 与 mtls-admin 管理进程共用)。
//
// 管理服务拆分后, 网关与管理进程启动时指定同一配置文件:
//   - 网关: 读业务字段(bind_host/db/ca/server_cert/mappings/services/roles/log)
//   - 管理: 读管理字段(db/ca/ca_key/cert_dir/sock_path/admin_listen/签发参数/log)
//
// 各自忽略无关字段; Parse 做全量校验(两进程一致)。
package config

import (
	"fmt"
	"net"

	"github.com/BurntSushi/toml"

	"mtls-gateway/internal/auth"
	"mtls-gateway/internal/logging"
	"mtls-gateway/internal/proxy"
)

// 配置模式常量(哨兵, 防拼写漂移 — 可读性审计)
const (
	ModeMutable   = "mutable"
	ModeEphemeral = "ephemeral"
	ModeImmutable = "immutable"
)

// Config 配置文件结构 (TOML)
type Config struct {
	BindHost      string             `toml:"bind_host"`       // 全局绑定地址 (默认 0.0.0.0)
	DB            string             `toml:"db"`              // SQLite 数据库路径
	ConfigMode    string             `toml:"config_mode"`     // mutable | ephemeral | immutable
	Lang          string             `toml:"lang"`            // 错误消息语言: zh | en (默认 zh)
	AdminRole     string             `toml:"admin_role"`      // 内置管理角色名 (默认 mtls-superadmin)
	PwdLength     int                `toml:"pwd_length"`      // 自动生成 p12 密码长度
	KeyType       string             `toml:"key_type"`        // 签发密钥: rsa | ecdsa
	KeyBits       int                `toml:"key_bits"`        // rsa:2048/3072/4096; ecdsa:256/384/521
	TLSMinVersion string             `toml:"tls_min_version"` // "1.2" | "1.3"
	AdminListen   string             `toml:"admin_listen"`    // 管理 API TCP (mtls-admin 进程; 需 admin_role 证书)
	InfoListen    string             `toml:"info_listen"`     // /info 发现端口(网关); 空=关
	ReloadListen  string             `toml:"reload_listen"`   // 网关 /admin/reload 端口(管理进程调用); 空=与 info 同端口合并
	CA            string             `toml:"ca"`
	CAKey         string             `toml:"ca_key"`
	ServerCert    string             `toml:"server_cert"`
	ServerKey     string             `toml:"server_key"`
	CertDir       string             `toml:"cert_dir"`
	SockPath      string             `toml:"sock_path"`
	Org           string             `toml:"org"`          // 证书 O 字段
	OU            string             `toml:"ou"`           // 证书 OU 字段
	DefaultDays   int                `toml:"default_days"` // 普通证书默认天数
	AdminDays     int                `toml:"admin_days"`   // 管理角色证书默认天数
	RequireIPBind *bool              `toml:"require_ip_bind"`
	LogFile       string             `toml:"log_file"`        // 事件日志(系统/配置/证书操作); 空=默认分平台路径
	AccessLogFile string             `toml:"access_log_file"` // 访问日志(大量, 单独文件); 空=默认分平台路径
	StdoutLogFile string             `toml:"stdout_log_file"` // 标准日志(终端+文件双写: 认证/隧道/错误等 log.Printf); 空=默认分平台路径
	LogMaxSizeMB  int                `toml:"log_max_size"`    // 单文件上限 MB (默认 10)
	LogMaxFiles   int                `toml:"log_max_files"`   // 保留历史份数 (默认 5)
	Roles         []string           `toml:"roles"`           // 角色声明列表(服务 roles / 签发 purposes 必须在此声明)
	Mappings      []proxy.Mapping    `toml:"mappings"`        // 通道: id + listen(:port[/path]) + target
	Services      []proxy.ServiceCfg `toml:"services"`        // 服务注册: name + channels + roles
	// —— 管理进程专属(mtls-admin; 网关忽略) ——
	GatewayReloadAddr string `toml:"gateway_reload_addr"` // 网关 /admin/reload 地址(如 100.104.135.63:9444); 空=变更后不自动 reload
	ReloadCert        string `toml:"reload_cert"`         // 调网关 reload 的 admin 客户端证书(pem)
	ReloadKey         string `toml:"reload_key"`          // 调网关 reload 的 admin 客户端私钥(pem)
}

// RequireIPBindResolved 返回实际 IP 绑定要求 (默认 true)
func (c *Config) RequireIPBindResolved() bool {
	if c.RequireIPBind == nil {
		return true
	}
	return *c.RequireIPBind
}

// DefaultConfig 返回默认配置
func DefaultConfig() Config {
	return Config{
		BindHost:      "0.0.0.0",
		DB:            "/var/lib/mtls-gw/mtls-gw.db",
		ConfigMode:    ModeMutable,
		AdminRole:     auth.DefaultAdminRole,
		PwdLength:     16,
		KeyType:       "rsa",
		KeyBits:       2048,
		TLSMinVersion: "1.2",
		CA:            "/etc/mtls-gw/ca.crt",
		CAKey:         "/etc/mtls-gw/ca.key",
		ServerCert:    "/etc/mtls-gw/server.crt",
		ServerKey:     "/etc/mtls-gw/server.key",
		CertDir:       "/var/lib/mtls-gw/certs",
		SockPath:      "/run/mtls-gw.sock",
		Org:           "mtls-gw",
		OU:            "device",
		DefaultDays:   365,
		AdminDays:     30,
		LogFile:       logging.DefaultPath("mtls-gw", "events.log"), // 事件日志: 分平台默认(Windows=exe 目录/mtls-gw / Linux=用户缓存)
		AccessLogFile: logging.DefaultPath("mtls-gw", "access.log"), // 访问日志: 分平台默认
		StdoutLogFile: logging.DefaultPath("mtls-gw", "stdout.log"), // 标准日志(终端+文件双写): 分平台默认
		LogMaxSizeMB:  10,
		LogMaxFiles:   5,
		Roles:         []string{},
		Mappings:      []proxy.Mapping{},
		Services:      []proxy.ServiceCfg{},
	}
}

// Parse 解析配置文件 + 完整校验, 返回 error(启动 fatal 包装 / reload 直接返回)。
// 文件不存在也返回错误 — reload 时配置文件缺失必须报错, 不得静默用默认值清空运行中路由。
func Parse(path string) (Config, error) {
	cfg := DefaultConfig()
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return cfg, err
	}
	if cfg.AdminRole == "" {
		cfg.AdminRole = auth.DefaultAdminRole
	}
	if cfg.AdminRole == "any" {
		return cfg, fmt.Errorf("admin_role 不能是保留字 \"any\"(会导致任意 any 证书获得管理权限)")
	}
	if cfg.AdminRole == "null" {
		return cfg, fmt.Errorf("admin_role 不能是保留字 \"null\"(匿名访问哨兵, 语义冲突)")
	}
	if !proxy.ValidRoleName(cfg.AdminRole) {
		return cfg, fmt.Errorf("bad admin_role %q (只允许字母/数字/下划线/连字符)", cfg.AdminRole)
	}
	// admin_role 不得出现在 roles 声明列表: 该角色证书自动获得管理权限(IsAdmin 字符串相等),
	// 若声明为普通角色则对应证书全部提权 — 必须唯一保留给管理用途。
	for _, r := range cfg.Roles {
		if r == cfg.AdminRole {
			return cfg, fmt.Errorf("admin_role %q 禁止出现在 roles 声明列表(提权风险)", cfg.AdminRole)
		}
	}
	switch cfg.ConfigMode {
	case "", ModeMutable, ModeEphemeral, ModeImmutable:
		if cfg.ConfigMode == "" {
			cfg.ConfigMode = ModeMutable
		}
	default:
		return cfg, fmt.Errorf("bad config_mode %q (mutable|ephemeral|immutable)", cfg.ConfigMode)
	}
	// 校验: 内置管理角色不得出现在业务服务 roles 里
	for _, s := range cfg.Services {
		for _, r := range s.Roles {
			if r == cfg.AdminRole {
				return cfg, fmt.Errorf("service %s roles 里不允许出现内置管理角色 %q", s.Name, cfg.AdminRole)
			}
		}
	}
	// 校验: 签发密钥组合
	switch cfg.KeyType {
	case "", "rsa":
		if cfg.KeyBits != 0 && cfg.KeyBits != 2048 && cfg.KeyBits != 3072 && cfg.KeyBits != 4096 {
			return cfg, fmt.Errorf("bad key_bits %d for rsa (2048/3072/4096)", cfg.KeyBits)
		}
	case "ecdsa":
		if cfg.KeyBits != 0 && cfg.KeyBits != 256 && cfg.KeyBits != 384 && cfg.KeyBits != 521 {
			return cfg, fmt.Errorf("bad key_bits %d for ecdsa (256/384/521)", cfg.KeyBits)
		}
	default:
		return cfg, fmt.Errorf("bad key_type %q (rsa|ecdsa)", cfg.KeyType)
	}
	// 角色声明列表校验: 命名合法 + 去重 + 内置保留字 (服务 roles 校验在 NewRouter)
	seen := map[string]bool{}
	for _, r := range cfg.Roles {
		if r == "null" {
			return cfg, fmt.Errorf("角色 %q 是内置保留字(匿名路由哨兵), 禁止在 roles 声明列表中声明", r)
		}
		if r == "any" {
			return cfg, fmt.Errorf("角色 %q 是内置保留字(服务声明里直接写 any 即对任意证书开放), 禁止在 roles 声明列表中声明", r)
		}
		if !proxy.ValidRoleName(r) {
			return cfg, fmt.Errorf("bad role name %q (只允许字母/数字/下划线/连字符)", r)
		}
		if seen[r] {
			return cfg, fmt.Errorf("duplicate role %q", r)
		}
		seen[r] = true
	}
	return cfg, nil
}

// ResolveListen 把 ":port" 落到 bindHost (绝对地址原样返回)。
// 用 net.JoinHostPort 拼接: bind_host="::"(IPv6) 时 ":9444" → "[::]:9444"(原字符串拼接产出非法的 ":::9444")。
func ResolveListen(bindHost, spec string) string {
	if spec == "" {
		return ""
	}
	if spec[0] == ':' {
		return net.JoinHostPort(bindHost, spec[1:])
	}
	return spec
}
