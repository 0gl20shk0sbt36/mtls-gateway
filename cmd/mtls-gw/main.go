// mtls-gw — 通用 mTLS 网关核心 daemon
// 功能:
//  1. TCP mTLS 监听: 验证客户端证书(CA) → IP 预检(SAN vs 来源) → 内存表授权(serial)
//  2. 按授权用途路由到后端服务(反代, 改写 Host 为 loopback)
//  3. 管理 API: Unix socket(本机直接 admin) + TCP 远程(admin 证书)
//  4. SQLite 持久化, 内存为权威
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

	"mtls-gateway/internal/api"
	"mtls-gateway/internal/auth"
	"mtls-gateway/internal/db"
	"mtls-gateway/internal/proxy"
)

func main() {
	var (
		cfgPath     = flag.String("config", "/etc/mtls-gw/config.json", "配置文件路径")
		dbPath      = flag.String("db", "/var/lib/mtls-gw/mtls-gw.db", "SQLite 数据库路径")
		caPath      = flag.String("ca", "", "CA 证书路径 (覆盖 config)")
		serverCert  = flag.String("server-cert", "", "网关 TLS 证书 (覆盖 config)")
		serverKey   = flag.String("server-key", "", "网关 TLS 私钥 (覆盖 config)")
		caKeyPath   = flag.String("ca-key", "", "CA 私钥 (签发用, 覆盖 config)")
		certDir     = flag.String("cert-dir", "", "签发证书输出目录 (覆盖 config)")
		sockPath    = flag.String("sock", "", "Unix socket 路径 (覆盖 config)")
		adminListen = flag.String("admin-listen", "", "管理 API TCP 监听 (覆盖 config)")
	)
	flag.Parse()

	// 配置加载
	cfg := loadConfig(*cfgPath)

	// flag 覆盖 (默认值通用化, 实际路径由配置/flag 指定)
	ca := firstNonEmpty(*caPath, cfg.CA, "/etc/mtls-gw/ca.crt")
	sCert := firstNonEmpty(*serverCert, cfg.ServerCert, "/etc/mtls-gw/server.crt")
	sKey := firstNonEmpty(*serverKey, cfg.ServerKey, "/etc/mtls-gw/server.key")
	caKey := firstNonEmpty(*caKeyPath, cfg.CAKey, "/etc/mtls-gw/ca.key")
	cDir := firstNonEmpty(*certDir, cfg.CertDir, "/var/lib/mtls-gw/certs")
	sock := firstNonEmpty(*sockPath, cfg.SockPath, "/run/mtls-gw.sock")
	admListen := firstNonEmpty(*adminListen, cfg.AdminListen, "")

	// 目录
	if err := os.MkdirAll(filepath.Dir(*dbPath), 0o700); err != nil {
		log.Fatalf("mkdir db dir: %v", err)
	}

	// 数据库
	store, err := db.Open(*dbPath)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer store.Close()
	log.Printf("db loaded: %d certs", len(store.List()))

	// 认证器 (requireIPBind: 默认 true, 配置 require_ip_bind=false 关闭 IP 绑定)
	requireIPBind := cfg.RequireIPBindResolved()
	gateway, err := auth.New(store, ca, sCert, sKey, requireIPBind)
	if err != nil {
		log.Fatalf("auth: %v", err)
	}

	// 映射路由 (mappings) → 路由器; listen 重复在此报错
	router, err := proxy.NewRouter(cfg.Mappings)
	if err != nil {
		log.Fatalf("invalid mappings: %v", err)
	}
	log.Printf("mappings: %d on ports %v", len(cfg.Mappings), router.Listens())

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

	// ===== /info 服务发现 (无需 admin; 已登记设备证书即可) =====
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
	mgr, err := api.NewManager(store, ca, caKey, cDir, sock, api.CertTemplate{
		Org:         cfg.Org,
		OU:          cfg.OU,
		DefaultDays: cfg.DefaultDays,
		AdminDays:   cfg.AdminDays,
	})
	if err != nil {
		log.Fatalf("manager: %v", err)
	}

	// ===== Unix socket 管理通道 (本机直接 admin) =====
	go func() {
		if err := mgr.ServeUnixSocket(); err != nil {
			log.Printf("unix socket: %v", err)
		}
	}()

	// ===== 管理 API TCP (远程 Web, 需 admin 证书) =====
	if admListen != "" {
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

// gatewayHandler 网关主 handler: 认证 → 按路径选映射(最长匹配) → 按映射 services 授权 → 转发
func gatewayHandler(gw *auth.Gateway, router *proxy.Router, port string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. 认证 + 授权 (IP 预检 + 内存表) → 证书身份记录
		rec, err := gw.Authorize(r)
		if err != nil {
			auth.AuthLog("", auth.RemoteIP(r), "", false)
			http.Error(w, "forbidden: "+err.Error(), http.StatusForbidden)
			return
		}
		remote := auth.RemoteIP(r)

		// 2. 按路径选映射 (最长前缀, 本端口内)
		rt := router.Match(port, r.URL.Path)
		if rt == nil {
			http.Error(w, "no route for "+r.URL.Path, http.StatusNotFound)
			return
		}

		// 3. 证书用途必须被该映射的 services 允许 (或 any)
		if !rt.Allows(rec.Purposes) {
			auth.AuthLog(rt.Listen(), remote, rec.Serial, false)
			http.Error(w, "no access to "+rt.Listen(), http.StatusForbidden)
			return
		}

		// 4. 前缀替换并转发
		auth.AuthLog(rt.Listen(), remote, rec.Serial, true)
		proxy.SanitizeHeader(r)
		router.Serve(rt, w, r)
	})
}

// infoHandler /info: 无需 admin; 已登记证书即可; 返回的是该证书可访问的映射 (按用途过滤)
func infoHandler(gw *auth.Gateway, router *proxy.Router) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec, err := gw.Authorize(r)
		if err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"mappings": router.AllowedRoutes(rec.Purposes)})
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

// adminHandler 管理 TCP handler: 认证 + 只允许 admin 用途
func adminHandler(gw *auth.Gateway, mgr *api.Manager, router *proxy.Router) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec, err := gw.Authorize(r)
		if err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if !rec.HasPurpose(auth.PurposeAdmin) {
			http.Error(w, "admin cert required", http.StatusForbidden)
			return
		}
		r.Header.Set("X-Auth-Purpose", auth.PurposeAdmin)
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

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// Config 配置文件结构
type Config struct {
	BindHost      string          `json:"bind_host"`    // 全局绑定地址 (默认 0.0.0.0)
	AdminListen   string          `json:"admin_listen"` // 管理 API TCP (需 admin 证书)
	InfoListen    string          `json:"info_listen"`  // /info 发现端口 (已登记证书即可); 空=关
	CA            string          `json:"ca"`
	CAKey         string          `json:"ca_key"`
	ServerCert    string          `json:"server_cert"`
	ServerKey     string          `json:"server_key"`
	CertDir       string          `json:"cert_dir"`
	SockPath      string          `json:"sock_path"`
	Org           string          `json:"org"`             // 证书 O 字段 (默认 "mtls-gw")
	OU            string          `json:"ou"`              // 证书 OU 字段 (默认 "device")
	DefaultDays   int             `json:"default_days"`    // 默认有效期天数 (默认 365)
	AdminDays     int             `json:"admin_days"`      // admin 用途默认天数 (默认 30)
	RequireIPBind *bool           `json:"require_ip_bind"` // IP 绑定 (nil=默认 true)
	Mappings      []proxy.Mapping `json:"mappings"`        // 映射服务定义: listen(:port[/path]) → target + services
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
		BindHost:    "0.0.0.0",
		CA:          "/etc/mtls-gw/ca.crt",
		CAKey:       "/etc/mtls-gw/ca.key",
		ServerCert:  "/etc/mtls-gw/server.crt",
		ServerKey:   "/etc/mtls-gw/server.key",
		CertDir:     "/var/lib/mtls-gw/certs",
		SockPath:    "/run/mtls-gw.sock",
		Org:         "mtls-gw",
		OU:          "device",
		DefaultDays: 365,
		AdminDays:   30,
		Mappings:    []proxy.Mapping{},
	}
}

func loadConfig(path string) Config {
	cfg := DefaultConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("no config at %s, using defaults", path)
		return cfg
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Printf("bad config %s: %v", path, err)
	}
	return cfg
}
