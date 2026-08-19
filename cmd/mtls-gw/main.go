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

	// 配置管理器 (模式 + CRUD + 热重载 + 落盘)
	cm := NewConfigManager(*cfgPath, cfg, router)
	log.Printf("config mode: %s", cm.Mode())

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
			srv := &http.Server{Handler: gatewayHandler(gateway, cm, port)}
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
			infoSrv := &http.Server{Handler: infoHandler(gateway, cm)}
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
			admSrv := &http.Server{Handler: adminHandler(gateway, mgr, cm)}
			if err := admSrv.Serve(tlsListener(ln, gateway.ServerTLSConfig())); err != nil {
				log.Fatalf("admin serve: %v", err)
			}
		}()
	}

	select {}
}

// gatewayHandler 网关主 handler: 认证 → 按路径选映射(最长匹配) → 按引用服务的 roles 授权 → 转发
// 路由器每次从 ConfigManager 取(支持热重载)
func gatewayHandler(gw *auth.Gateway, cm *ConfigManager, port string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec, err := gw.Authorize(r)
		if err != nil {
			auth.AuthLog("", auth.RemoteIP(r), "", false)
			http.Error(w, "forbidden: "+err.Error(), http.StatusForbidden)
			return
		}
		remote := auth.RemoteIP(r)

		router := cm.Router()
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
func infoHandler(gw *auth.Gateway, cm *ConfigManager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec, err := gw.Authorize(r)
		if err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"services": cm.Router().ServicesAllowed(rec.Purposes)})
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
// 提供: 证书签发/吊销 (mgr) + 通道/服务/角色 CRUD (cm, 尊重 config_mode)
func adminHandler(gw *auth.Gateway, mgr *api.Manager, cm *ConfigManager) http.Handler {
	mux := http.NewServeMux()

	// 配置总览(UI 用): 模式 + 通道 + 服务
	mux.HandleFunc("GET /admin/config", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"mode":     cm.Mode(),
			"mappings": cm.Mappings(),
			"services": cm.Services(),
		})
	})

	// 通道 CRUD
	mux.HandleFunc("GET /admin/mappings", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"mappings": cm.Mappings()})
	})
	mux.HandleFunc("POST /admin/mappings", func(w http.ResponseWriter, r *http.Request) {
		var m proxy.Mapping
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := cm.AddMapping(m); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]any{"ok": true})
	})
	mux.HandleFunc("PUT /admin/mappings", func(w http.ResponseWriter, r *http.Request) {
		var m proxy.Mapping
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := cm.UpdateMapping(r.URL.Query().Get("id"), m); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]any{"ok": true})
	})
	mux.HandleFunc("DELETE /admin/mappings", func(w http.ResponseWriter, r *http.Request) {
		if err := cm.DeleteMapping(r.URL.Query().Get("id")); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]any{"ok": true})
	})

	// 服务 CRUD
	mux.HandleFunc("GET /admin/services", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"services": cm.Services()})
	})
	mux.HandleFunc("POST /admin/services", func(w http.ResponseWriter, r *http.Request) {
		var s proxy.ServiceCfg
		if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := cm.AddService(s); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]any{"ok": true})
	})
	mux.HandleFunc("PUT /admin/services", func(w http.ResponseWriter, r *http.Request) {
		var s proxy.ServiceCfg
		if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := cm.UpdateService(r.URL.Query().Get("name"), s); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]any{"ok": true})
	})
	mux.HandleFunc("DELETE /admin/services", func(w http.ResponseWriter, r *http.Request) {
		if err := cm.DeleteService(r.URL.Query().Get("name")); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]any{"ok": true})
	})

	// 证书管理 (mgr)
	mux.Handle("/", mgr.HTTPHandler())

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
		mux.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// tlsListener 包装 TCP listener 为 TLS
func tlsListener(ln net.Listener, tlsCfg *tls.Config) net.Listener {
	return tls.NewListener(ln, tlsCfg)
}

// Config 配置文件结构 (TOML)
type Config struct {
	BindHost      string             `toml:"bind_host"`       // 全局绑定地址 (默认 0.0.0.0)
	DB            string             `toml:"db"`              // SQLite 数据库路径
	ConfigMode    string             `toml:"config_mode"`     // mutable(改后落盘) | ephemeral(仅内存) | immutable(只读)
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
		ConfigMode:    "mutable",
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
	switch cfg.ConfigMode {
	case "", "mutable", "ephemeral", "immutable":
		if cfg.ConfigMode == "" {
			cfg.ConfigMode = "mutable"
		}
	default:
		log.Fatalf("bad config_mode %q (mutable|ephemeral|immutable)", cfg.ConfigMode)
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
