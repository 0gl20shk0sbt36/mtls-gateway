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
	"strings"

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
		gatewayListen = flag.String("listen", "", "网关监听地址 (覆盖 config)")
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
	gwListen := firstNonEmpty(*gatewayListen, cfg.Listen, "0.0.0.0:9443")
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

	// 认证器
	gateway, err := auth.New(store, ca, sCert, sKey)
	if err != nil {
		log.Fatalf("auth: %v", err)
	}

	// 后端路由 (用途 → 后端地址)
	backends := []proxy.Backend{}
	for purpose, target := range cfg.Backends {
		backends = append(backends, proxy.Backend{Purpose: purpose, Target: target})
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

	// ===== 网关主服务 (TCP mTLS): 认证 + 路由 =====
	go func() {
		ln, err := net.Listen("tcp", gwListen)
		if err != nil {
			log.Fatalf("listen %s: %v", gwListen, err)
		}
		log.Printf("mtls gateway listening on %s (mTLS)", gwListen)
		srv := &http.Server{Handler: gatewayHandler(gateway, router, mgr)}
		if err := srv.Serve(tlsListener(ln, gateway.ServerTLSConfig())); err != nil {
			log.Fatalf("gateway serve: %v", err)
		}
	}()

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

// gatewayHandler 网关主 handler: 认证 → 按用途路由
func gatewayHandler(gw *auth.Gateway, router *proxy.Router, mgr *api.Manager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. 认证 + 授权 (IP 预检 + 内存表)
		purpose, err := gw.Authorize(r)
		if err != nil {
			auth.AuthLog("", auth.RemoteIP(r), "", false)
			http.Error(w, "forbidden: "+err.Error(), http.StatusForbidden)
			return
		}
		remote := auth.RemoteIP(r)
		serial := ""
		if len(r.TLS.PeerCertificates) > 0 {
			serial = r.TLS.PeerCertificates[0].SerialNumber.String()
		}

		// 2. 管理路径 (需要 admin 用途) — 用 /admin/ 前缀, /api/ 留给后端业务
		if strings.HasPrefix(r.URL.Path, "/admin/") {
			if !auth.IsAdminPurpose(purpose) {
				auth.AuthLog(purpose, remote, serial, false)
				http.Error(w, "admin required", http.StatusForbidden)
				return
			}
			auth.AuthLog(purpose, remote, serial, true)
			r.Header.Set("X-Auth-Purpose", purpose)
			mgr.HTTPHandler().ServeHTTP(w, r)
			return
		}

		// 3. 普通服务: 按用途路由
		if !router.HasPurpose(purpose) {
			auth.AuthLog(purpose, remote, serial, false)
			http.Error(w, "no backend for purpose: "+purpose, http.StatusNotFound)
			return
		}
		auth.AuthLog(purpose, remote, serial, true)
		proxy.SanitizeHeader(r)
		router.Handler(purpose).ServeHTTP(w, r)
	})
}

// adminHandler 管理 TCP handler: 认证 + 只允许 admin 用途
func adminHandler(gw *auth.Gateway, mgr *api.Manager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		purpose, err := gw.Authorize(r)
		if err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if !auth.IsAdminPurpose(purpose) {
			http.Error(w, "admin cert required", http.StatusForbidden)
			return
		}
		r.Header.Set("X-Auth-Purpose", purpose)
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
	Org         string            `json:"org"`          // 证书 O 字段 (默认 "mtls-gw")
	OU          string            `json:"ou"`           // 证书 OU 字段 (默认 "device")
	DefaultDays int               `json:"default_days"` // 默认有效期天数 (默认 365)
	AdminDays   int               `json:"admin_days"`   // admin 用途默认天数 (默认 30)
	Backends    map[string]string `json:"backends"`     // purpose → target
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
		Backends:    map[string]string{},
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
