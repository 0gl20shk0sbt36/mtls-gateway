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
		cfgPath       = flag.String("config", "/etc/mtls-gw/config.json", "配置文件路径")
		dbPath        = flag.String("db", "/var/lib/mtls-gw/mtls-gw.db", "SQLite 数据库路径")
		caPath        = flag.String("ca", "", "CA 证书路径 (覆盖 config)")
		serverCert    = flag.String("server-cert", "", "网关 TLS 证书 (覆盖 config)")
		serverKey     = flag.String("server-key", "", "网关 TLS 私钥 (覆盖 config)")
		caKeyPath     = flag.String("ca-key", "", "CA 私钥 (签发用, 覆盖 config)")
		certDir       = flag.String("cert-dir", "", "签发证书输出目录 (覆盖 config)")
		sockPath      = flag.String("sock", "", "Unix socket 路径 (覆盖 config)")
		adminListen   = flag.String("admin-listen", "", "管理 API TCP 监听 (覆盖 config)")
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

	// 后端路由 (用途 → 后端地址)
	backends := []proxy.Backend{}
	for purpose, bc := range cfg.Backends {
		backends = append(backends, proxy.Backend{Purpose: purpose, Target: bc.Target})
	}
	router := proxy.NewRouter(backends)
	log.Printf("routes: %v", router.Purposes())

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

	// ===== 网关主服务 (TCP mTLS): 每个用途一个端口 =====
	// 每个 backend 配置了 listen 就单独开一个端口, 该端口只服务对应用途
	// (证书 Purposes 必须包含该用途才能通过, 否则 403)
	for purpose, bc := range cfg.Backends {
		bc := bc
		purpose := purpose
		if bc.Listen == "" {
			continue // 未配 listen 的用途不开独立端口
		}
		go func() {
			ln, err := net.Listen("tcp", bc.Listen)
			if err != nil {
				log.Fatalf("listen %s (purpose=%s): %v", bc.Listen, purpose, err)
			}
			log.Printf("mtls gateway [%s] listening on %s (mTLS)", purpose, bc.Listen)
			srv := &http.Server{Handler: gatewayHandler(gateway, router, mgr, purpose)}
			if err := srv.Serve(tlsListener(ln, gateway.ServerTLSConfig())); err != nil {
				log.Fatalf("gateway [%s] serve: %v", purpose, err)
			}
		}()
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
			admSrv := &http.Server{Handler: adminHandler(gateway, mgr)}
			if err := admSrv.Serve(tlsListener(ln, gateway.ServerTLSConfig())); err != nil {
				log.Fatalf("admin serve: %v", err)
			}
		}()
	}

	select {}
}

// gatewayHandler 网关主 handler: 认证 → 校验端口用途权限 → 路由
// portPurpose: 本监听端口的用途 (如 "dsh"); 证书 Purposes 必须包含它
func gatewayHandler(gw *auth.Gateway, router *proxy.Router, mgr *api.Manager, portPurpose string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. 认证 + 授权 (IP 预检 + 内存表) → 证书身份记录
		rec, err := gw.Authorize(r)
		if err != nil {
			auth.AuthLog("", auth.RemoteIP(r), "", false)
			http.Error(w, "forbidden: "+err.Error(), http.StatusForbidden)
			return
		}
		remote := auth.RemoteIP(r)
		serial := rec.Serial

		// 2. 端口用途校验: 证书必须有本端口的用途权限
		//    (管理 API 只走独立 admin 端口 9444 + Unix socket, 不在业务端口)
		if !rec.HasPurpose(portPurpose) {
			auth.AuthLog(portPurpose, remote, serial, false)
			http.Error(w, "no access to purpose: "+portPurpose, http.StatusForbidden)
			return
		}

		// 4. 路由到本端口对应的后端
		auth.AuthLog(portPurpose, remote, serial, true)
		proxy.SanitizeHeader(r)
		router.Handler(portPurpose).ServeHTTP(w, r)
	})
}

// adminHandler 管理 TCP handler: 认证 + 只允许 admin 用途
func adminHandler(gw *auth.Gateway, mgr *api.Manager) http.Handler {
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
	Listen      string            `json:"listen"`
	AdminListen string            `json:"admin_listen"`
	CA          string            `json:"ca"`
	CAKey       string            `json:"ca_key"`
	ServerCert  string            `json:"server_cert"`
	ServerKey   string            `json:"server_key"`
	CertDir     string            `json:"cert_dir"`
	SockPath    string            `json:"sock_path"`
	Org          string            `json:"org"`             // 证书 O 字段 (默认 "mtls-gw")
	OU           string            `json:"ou"`              // 证书 OU 字段 (默认 "device")
	DefaultDays  int               `json:"default_days"`    // 默认有效期天数 (默认 365)
	AdminDays    int               `json:"admin_days"`      // admin 用途默认天数 (默认 30)
	RequireIPBind *bool            `json:"require_ip_bind"` // IP 绑定 (nil=默认 true; false=允许不绑 IP 证书)
	Backends     map[string]BackendCfg `json:"backends"`    // purpose → 后端配置
}

// BackendCfg 一个后端的配置
type BackendCfg struct {
	Target string `json:"target"` // 后端地址 http://127.0.0.1:3080
	Listen string `json:"listen"` // 该用途的独立监听地址 (如 "0.0.0.0:9443"); 空=不单独开端口
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
		Listen:      "0.0.0.0:9443",
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
		Backends:    map[string]BackendCfg{},
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
