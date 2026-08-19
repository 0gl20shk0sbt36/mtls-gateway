// mtls-gw: mTLS 反向代理网关 + 证书管理 (v4)
//
// 模型: mappings(通道) + services(服务注册) + roles(证书角色) 三表联动。
// 服务端参数只有一个: -config <配置文件> (TOML)。
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"mtls-gateway/internal/api"
	"mtls-gateway/internal/auth"
	"mtls-gateway/internal/db"
	"mtls-gateway/internal/proxy"
)

func main() {
	cfgPath = flag.String("config", "/etc/mtls-gw/config.toml", "配置文件路径")
	flag.Parse()

	// 配置加载
	cfg := loadConfig(*cfgPath)

	// 目录
	if err := os.MkdirAll(filepath.Dir(cfg.DB), 0o700); err != nil {
		log.Fatalf("mkdir db dir: %v", err)
	}

	// 数据库
	store, err := db.Open(cfg.DB)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer store.Close()
	log.Printf("db loaded: %d certs", len(store.List()))

	// 认证器 (requireIPBind/admin_role/tls_min_version 来自配置)
	requireIPBind := cfg.RequireIPBindResolved()
	gateway, err := auth.New(store, cfg.CA, cfg.ServerCert, cfg.ServerKey, requireIPBind, cfg.AdminRole, cfg.TLSMinVersion)
	if err != nil {
		log.Fatalf("auth: %v", err)
	}

	// 映射 + 服务注册 → 路由器 (listen 判重 / 通道引用校验在此报错)
	router, err := proxy.NewRouter(cfg.Mappings, cfg.Services)
	if err != nil {
		log.Fatalf("invalid config: %v", err)
	}
	log.Printf("mappings: %d services: %d on ports %v", len(cfg.Mappings), len(cfg.Services), router.Listens())

	bindHost := cfg.BindHost
	if bindHost == "" {
		bindHost = "0.0.0.0"
	}

	// ===== 网关主服务 (TCP mTLS): 每入口端口一个监听, 端口内按路径最长前缀匹配 =====
	for _, port := range router.Listens() {
		port := port
		go func() {
			addr := net.JoinHostPort(bindHost, port)
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				log.Fatalf("listen %s: %v", addr, err)
			}
			log.Printf("mtls gateway listening on %s (mTLS)", addr)
			srv := &http.Server{Handler: gatewayHandler(gateway, router, port)}
			if err := srv.Serve(tlsListener(ln, gateway.ServerTLSConfig())); err != nil {
				log.Fatalf("gateway serve %s: %v", addr, err)
			}
		}()
	}

	// ===== /info 服务发现 (无需 admin; 已登记设备证书即可; 按证书角色过滤服务) =====
	if infoListen := resolveListen(bindHost, cfg.InfoListen); infoListen != "" {
		go func() {
			ln, err := net.Listen("tcp", infoListen)
			if err != nil {
				log.Fatalf("info listen %s: %v", infoListen, err)
			}
			log.Printf("mtls /info listening on %s (registered cert only)", infoListen)
			infoSrv := &http.Server{Handler: infoHandler(gateway, router)}
			if err := infoSrv.Serve(tlsListener(ln, gateway.ServerTLSConfig())); err != nil {
				log.Fatalf("info serve: %v", err)
			}
		}()
	}

	// 管理 API
	mgr, err := api.NewManager(store, cfg.CA, cfg.CAKey, cfg.CertDir, cfg.SockPath, api.CertTemplate{
		Org:         cfg.Org,
		OU:          cfg.OU,
		DefaultDays: cfg.DefaultDays,
		AdminDays:   cfg.AdminDays,
	}, cfg.AdminRole, cfg.KeyType, cfg.KeyBits, cfg.PwdLength)
	if err != nil {
		log.Fatalf("manager: %v", err)
	}

	// ===== Unix socket 管理通道 (本机直接 admin) =====
	go func() {
		if err := mgr.ServeUnixSocket(); err != nil {
			log.Printf("unix socket: %v", err)
		}
	}()

	// ===== 管理 API TCP (远程 Web, 需 admin_role 证书) =====
	if admListen := resolveListen(bindHost, cfg.AdminListen); admListen != "" {
		go func() {
			ln, err := net.Listen("tcp", admListen)
			if err != nil {
				log.Fatalf("admin listen: %v", err)
			}
			log.Printf("admin api listening on %s (mTLS, admin cert required)", admListen)
			admSrv := &http.Server{Handler: adminHandler(gateway, mgr, router)}
			if err := admSrv.Serve(tlsListener(ln, gateway.ServerTLSConfig())); err != nil {
				log.Fatalf("admin serve: %v", err)
			}
		}()
	}

	select {}
}

// gatewayHandler 网关主 handler: 认证 → 按路径选映射(最长匹配) → 按引用服务的 roles 授权 → 转发
func gatewayHandler(gw *auth.Gateway, router *proxy.Router, port string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec, err := gw.Authorize(r)
		if err != nil {
			auth.AuthLog("", auth.RemoteIP(r), "", false)
			http.Error(w, "forbidden: "+err.Error(), http.StatusForbidden)
			return
		}
		remote := auth.RemoteIP(r)

		rt := router.Match(port, r.URL.Path)
		if rt == nil {
			http.Error(w, "no route for "+r.URL.Path, http.StatusNotFound)
			return
		}
		if !rt.Allows(rec.Purposes) {
			auth.AuthLog(rt.Listen(), remote, rec.Serial, false)
			http.Error(w, "no access to "+rt.Listen(), http.StatusForbidden)
			return
		}
		auth.AuthLog(rt.Listen(), remote, rec.Serial, true)
		proxy.SanitizeHeader(r)
		router.Serve(rt, w, r)
	})
}

// infoHandler /info: 无需 admin; 已登记证书即可; 返回该证书可访问的服务(按角色过滤)
func infoHandler(gw *auth.Gateway, router *proxy.Router) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec, err := gw.Authorize(r)
		if err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"services": router.ServicesAllowed(rec.Purposes)})
	})
}

// resolveListen 把 ":port" 落到 bindHost (绝对地址原样返回)
func resolveListen(bindHost, spec string) string {
	if spec == "" {
		return ""
	}
	if spec[0] == ':' {
		return bindHost + spec
	}
	return spec
}

// adminHandler 管理 TCP handler: 认证 + 只允许 admin_role
func adminHandler(gw *auth.Gateway, mgr *api.Manager, router *proxy.Router) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec, err := gw.Authorize(r)
		if err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if !gw.IsAdmin(rec) {
			http.Error(w, "admin cert required", http.StatusForbidden)
			return
		}
		r.Header.Set("X-Auth-Purpose", gw.AdminRole)
		if r.URL.Path == "/admin/mappings" && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"mappings": router.Routes()})
			return
		}
		mgr.HTTPHandler().ServeHTTP(w, r)
	})
}

// tlsListener 包装 TCP listener 为 TLS
func tlsListener(ln net.Listener, tlsCfg *tls.Config) net.Listener {
	return tls.NewListener(ln, tlsCfg)
}

// Config 配置文件结构 (TOML)
type Config struct {
	BindHost      string             `toml:"bind_host"`       // 全局绑定地址 (默认 0.0.0.0)
	DB            string             `toml:"db"`              // SQLite 数据库路径
	AdminRole     string             `toml:"admin_role"`      // 内置管理角色名 (默认 mtls-superadmin)
	PwdLength     int                `toml:"pwd_length"`      // 自动生成 p12 密码长度
	KeyType       string             `toml:"key_type"`        // 签发密钥: rsa | ecdsa
	KeyBits       int                `toml:"key_bits"`        // rsa:2048/3072/4096; ecdsa:256/384/521
	TLSMinVersion string             `toml:"tls_min_version"` // "1.2" | "1.3"
	AdminListen   string             `toml:"admin_listen"`    // 管理 API TCP (需 admin_role 证书)
	InfoListen    string             `toml:"info_listen"`     // /info 发现端口; 空=关
	CA            string             `toml:"ca"`
	CAKey         string             `toml:"ca_key"`
	ServerCert    string             `toml:"server_cert"`
	ServerKey     string             `toml:"server_key"`
	CertDir       string             `toml:"cert_dir"`
	SockPath      string             `toml:"sock_path"`
	Org           string             `toml:"org"`           // 证书 O 字段
	OU            string             `toml:"ou"`            // 证书 OU 字段
	DefaultDays   int                `toml:"default_days"`  // 普通证书默认天数
	AdminDays     int                `toml:"admin_days"`    // 管理角色证书默认天数
	RequireIPBind *bool              `toml:"require_ip_bind"`
	Mappings      []proxy.Mapping    `toml:"mappings"` // 通道: id + listen(:port[/path]) + target
	Services      []proxy.ServiceCfg `toml:"services"` // 服务注册: name + channels + roles
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
		Mappings:      []proxy.Mapping{},
		Services:      []proxy.ServiceCfg{},
	}
}

func loadConfig(path string) Config {
	cfg := DefaultConfig()
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		log.Printf("config %s: %v (使用默认值)", path, err)
	}
	if cfg.AdminRole == "" {
		cfg.AdminRole = auth.DefaultAdminRole
	}
	// 校验: 内置管理角色不得出现在业务服务 roles 里
	for _, s := range cfg.Services {
		for _, r := range s.Roles {
			if r == cfg.AdminRole {
				log.Fatalf("service %s roles 里不允许出现内置管理角色 %q", s.Name, cfg.AdminRole)
			}
		}
	}
	// 校验: 签发密钥组合
	switch cfg.KeyType {
	case "", "rsa":
		if cfg.KeyBits != 0 && cfg.KeyBits != 2048 && cfg.KeyBits != 3072 && cfg.KeyBits != 4096 {
			log.Fatalf("bad key_bits %d for rsa (2048/3072/4096)", cfg.KeyBits)
		}
	case "ecdsa":
		if cfg.KeyBits != 0 && cfg.KeyBits != 256 && cfg.KeyBits != 384 && cfg.KeyBits != 521 {
			log.Fatalf("bad key_bits %d for ecdsa (256/384/521)", cfg.KeyBits)
		}
	default:
		log.Fatalf("bad key_type %q (rsa|ecdsa)", cfg.KeyType)
	}
	return cfg
}

var cfgPath = flag.String("config", "/etc/mtls-gw/config.toml", "配置文件路径")
var _ = strings.TrimSpace
var _ = time.Now
