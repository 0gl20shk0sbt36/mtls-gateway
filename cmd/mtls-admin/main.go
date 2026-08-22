// mtls-admin — 独立管理进程(管理服务拆分阶段 2)。
//
// 与 mtls-gw 网关读同一 config.toml, 各取所需字段。职责:
//   - SQLite DB 写者(签发/吊销落库)
//   - CA 私钥持有(证书签发/吊销)
//   - 配置管理(configmgr: 改内存 + TOML 落盘 + 校验)
//   - 管理 API: Unix socket(本机 CLI) + admin_listen TCP(mTLS, admin 证书)
//
// 变更(签发/吊销/配置)后调网关 POST /admin/reload 全量热重载(配置 gateway_reload_addr)。
// 网关是纯只读消费者(仅加载时读), 本进程是唯一写者, 两者不同时操作同一文件。
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"mtls-gateway/internal/api"
	"mtls-gateway/internal/auth"
	"mtls-gateway/internal/config"
	"mtls-gateway/internal/configmgr"
	"mtls-gateway/internal/db"
	"mtls-gateway/internal/eventlog"
	"mtls-gateway/internal/i18n"
	"mtls-gateway/internal/proxy"
)

// version 由 release 构建经 -ldflags "-X main.version=..." 注入; 默认 "dev"
var version = "dev"

// 管理端口超时: 与网关一致(WriteTimeout 不限制, IdleTimeout 300s)
const (
	gwWriteTimeout = 0 * time.Second
	gwIdleTimeout  = 300 * time.Second
)

func main() {
	configPath := flag.String("config", "/etc/mtls-gw/config.toml", "配置文件路径(与网关同一份)")
	flag.Parse()

	cfg, err := config.Parse(*configPath)
	if err != nil {
		log.Fatalf("config %s: %v (配置文件错误, 拒绝启动)", *configPath, err)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.DB), 0o700); err != nil {
		log.Fatalf("mkdir db dir: %v", err)
	}

	// 日志: 事件(JSON) + 标准输出(文本, 终端+文件双写)
	evLog, err := eventlog.New(cfg.LogFile, cfg.LogMaxSizeMB, cfg.LogMaxFiles)
	if err != nil {
		log.Printf("event log: %v (禁用)", err)
	}
	defer func() {
		if evLog != nil {
			evLog.Close()
		}
	}()
	stdLog, err := eventlog.NewText(cfg.StdoutLogFile, cfg.LogMaxSizeMB, cfg.LogMaxFiles)
	if err != nil {
		log.Printf("stdout log: %v (仅终端)", err)
	}
	defer func() {
		if stdLog != nil {
			stdLog.Close()
		}
	}()
	if stdLog != nil {
		log.SetOutput(io.MultiWriter(os.Stderr, stdLog.TextWriter()))
	}
	log.Printf("mtls-admin %s starting", version)

	// DB(唯一写者: 签发/吊销落库)
	store, err := db.Open(cfg.DB)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer store.Close()
	log.Printf("db loaded: %d certs", len(store.List()))

	// 认证器(admin 端口 mTLS 保护: 客户端证书链验证 + 内存查表)
	gw, err := auth.New(store, cfg.CA, cfg.ServerCert, cfg.ServerKey, cfg.RequireIPBindResolved(), cfg.AdminRole, cfg.TLSMinVersion)
	if err != nil {
		log.Fatalf("auth: %v", err)
	}

	// 配置管理(改内存 + TOML 落盘; router 仅校验用, 不 Serve)
	cm := configmgr.New(*configPath, cfg, nil)

	// 管理 API(签发/吊销/列表/p12)
	mgr, err := api.NewManager(store, cfg.CA, cfg.CAKey, cfg.CertDir, cfg.SockPath, api.CertTemplate{
		Org:         cfg.Org,
		OU:          cfg.OU,
		DefaultDays: cfg.DefaultDays,
		AdminDays:   cfg.AdminDays,
	}, cfg.AdminRole, cfg.KeyType, cfg.KeyBits, cfg.PwdLength, cfg.Roles)
	if err != nil {
		log.Fatalf("manager: %v", err)
	}
	mgr.SetDeclaredRoles(cfg.Roles)

	// 网关 reload 客户端(可选): 变更后调网关 /admin/reload 热重载
	var rc *reloadClient
	if cfg.GatewayReloadAddr != "" {
		rc, err = newReloadClient(cfg)
		if err != nil {
			log.Fatalf("reload client: %v", err)
		}
		log.Printf("gateway reload: %s (变更后自动热重载)", cfg.GatewayReloadAddr)
	}

	if evLog != nil {
		evLog.Write(eventlog.Event{Type: "start", Msg: "mtls-admin 启动"})
	}

	h := adminHandler(gw, mgr, cm, evLog, rc)

	// ===== Unix socket 管理通道 (本机直接 admin, CLI 用) =====
	go func() {
		if err := mgr.ServeUnixSocket(); err != nil {
			log.Printf("unix socket: %v", err)
		}
	}()

	// ===== 管理 API TCP (Web 面板/远程, 需 admin_role 证书) =====
	adminListen := config.ResolveListen(cfg.BindHost, cfg.AdminListen)
	if adminListen != "" {
		ln, err := net.Listen("tcp", adminListen)
		if err != nil {
			log.Fatalf("admin listen %s: %v", adminListen, err)
		}
		log.Printf("admin api listening on %s (mTLS, admin cert required)", adminListen)
		srv := &http.Server{
			Handler:           h,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      gwWriteTimeout,
			IdleTimeout:       gwIdleTimeout,
		}
		go func() {
			if err := srv.Serve(tls.NewListener(ln, gw.ServerTLSConfig())); err != nil && err != http.ErrServerClosed {
				log.Fatalf("admin serve: %v", err)
			}
		}()
	}

	// 优雅退出
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("shutting down...")
	if evLog != nil {
		evLog.Write(eventlog.Event{Type: "stop", Msg: "mtls-admin 停止"})
	}
}

// reloadClient 调网关 POST /admin/reload(admin 证书 mTLS)触发全量热重载
type reloadClient struct {
	addr string // host:port
	cli  *http.Client
}

func newReloadClient(cfg config.Config) (*reloadClient, error) {
	if cfg.ReloadCert == "" || cfg.ReloadKey == "" {
		return nil, fmt.Errorf("gateway_reload_addr 已配置但缺 reload_cert/reload_key(admin 客户端证书)")
	}
	cert, err := tls.LoadX509KeyPair(cfg.ReloadCert, cfg.ReloadKey)
	if err != nil {
		return nil, fmt.Errorf("load reload cert: %w", err)
	}
	caPEM, err := os.ReadFile(cfg.CA)
	if err != nil {
		return nil, fmt.Errorf("read ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("parse ca pem")
	}
	return &reloadClient{
		addr: cfg.GatewayReloadAddr,
		cli: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{cert}},
			},
		},
	}, nil
}

// Trigger 调网关 /admin/reload; 失败仅记日志(管理侧已落盘, 下次变更/手动 reload 可收敛)
func (c *reloadClient) Trigger() {
	if c == nil {
		return
	}
	resp, err := c.cli.Post("https://"+c.addr+"/admin/reload", "application/json", nil)
	if err != nil {
		log.Printf("gateway reload: %v (管理侧已落盘, 可稍后重试)", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("gateway reload: HTTP %d (管理侧已落盘)", resp.StatusCode)
		return
	}
	log.Printf("gateway reload: ok")
}

// —— 管理 handler(admin 证书保护): 证书管理(api.Manager) + 配置 CRUD(configmgr, 落盘后调网关 reload) ——

func adminHandler(gw *auth.Gateway, mgr *api.Manager, cm *configmgr.ConfigManager, ev *eventlog.Logger, rc *reloadClient) http.Handler {
	mux := http.NewServeMux()

	cfgChanged := func(msg string) {
		if ev != nil {
			ev.Write(eventlog.Event{Type: "config_change", Msg: msg})
		}
	}
	// 配置变更落盘后触发网关 reload(管理进程是配置写者, 网关只读消费者)
	changed := func(msg string) {
		cfgChanged(msg)
		rc.Trigger()
	}

	// 配置总览
	mux.HandleFunc("GET /admin/config", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"mode":       cm.Mode(),
			"admin_role": cm.AdminRole(),
			"roles":      cm.Roles(),
			"mappings":   cm.Mappings(),
			"services":   cm.Services(),
		})
	})
	// 整体替换保存
	mux.HandleFunc("POST /admin/config", func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			Mappings []proxy.Mapping    `json:"mappings"`
			Services []proxy.ServiceCfg `json:"services"`
			Roles    []string           `json:"roles"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			gwErr(w, r, err)
			return
		}
		if err := cm.ReplaceAll(b.Mappings, b.Services, b.Roles); err != nil {
			gwErr(w, r, err)
			return
		}
		changed(fmt.Sprintf("批量保存配置: mappings=%d services=%d roles=%d", len(b.Mappings), len(b.Services), len(b.Roles)))
		writeJSON(w, map[string]any{"ok": true})
	})

	// 角色 CRUD
	mux.HandleFunc("POST /admin/roles", func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			Name string `json:"name"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			gwErr(w, r, err)
			return
		}
		if err := cm.AddRole(b.Name); err != nil {
			gwErr(w, r, err)
			return
		}
		changed("新增角色 " + b.Name)
		writeJSON(w, map[string]any{"ok": true})
	})
	mux.HandleFunc("DELETE /admin/roles", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if err := cm.DeleteRole(name); err != nil {
			gwErr(w, r, err)
			return
		}
		changed("删除角色 " + name)
		writeJSON(w, map[string]any{"ok": true})
	})

	// 通道 CRUD
	mux.HandleFunc("GET /admin/mappings", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"mappings": cm.Mappings()})
	})
	mux.HandleFunc("POST /admin/mappings", func(w http.ResponseWriter, r *http.Request) {
		var m proxy.Mapping
		r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			gwErr(w, r, err)
			return
		}
		if err := cm.AddMapping(m); err != nil {
			gwErr(w, r, err)
			return
		}
		changed(fmt.Sprintf("新增通道 id=%s listen=%s target=%s", m.ID, m.Listen, m.Target))
		writeJSON(w, map[string]any{"ok": true})
	})
	mux.HandleFunc("PUT /admin/mappings", func(w http.ResponseWriter, r *http.Request) {
		var m proxy.Mapping
		r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			gwErr(w, r, err)
			return
		}
		if err := cm.UpdateMapping(r.URL.Query().Get("id"), m); err != nil {
			gwErr(w, r, err)
			return
		}
		changed(fmt.Sprintf("修改通道 id=%s listen=%s", r.URL.Query().Get("id"), m.Listen))
		writeJSON(w, map[string]any{"ok": true})
	})
	mux.HandleFunc("DELETE /admin/mappings", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if err := cm.DeleteMapping(id); err != nil {
			gwErr(w, r, err)
			return
		}
		changed("删除通道 id=" + id)
		writeJSON(w, map[string]any{"ok": true})
	})

	// 服务 CRUD
	mux.HandleFunc("GET /admin/services", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"services": cm.Services()})
	})
	mux.HandleFunc("POST /admin/services", func(w http.ResponseWriter, r *http.Request) {
		var s proxy.ServiceCfg
		r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
		if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
			gwErr(w, r, err)
			return
		}
		if err := cm.AddService(s); err != nil {
			gwErr(w, r, err)
			return
		}
		changed(fmt.Sprintf("新增服务 name=%s channels=%v roles=%v", s.Name, s.Channels, s.Roles))
		writeJSON(w, map[string]any{"ok": true})
	})
	mux.HandleFunc("PUT /admin/services", func(w http.ResponseWriter, r *http.Request) {
		var s proxy.ServiceCfg
		r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
		if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
			gwErr(w, r, err)
			return
		}
		if err := cm.UpdateService(r.URL.Query().Get("name"), s); err != nil {
			gwErr(w, r, err)
			return
		}
		changed(fmt.Sprintf("修改服务 name=%s channels=%v roles=%v", s.Name, s.Channels, s.Roles))
		writeJSON(w, map[string]any{"ok": true})
	})
	mux.HandleFunc("DELETE /admin/services", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if err := cm.DeleteService(name); err != nil {
			gwErr(w, r, err)
			return
		}
		changed("删除服务 name=" + name)
		writeJSON(w, map[string]any{"ok": true})
	})

	// 证书管理(api.Manager 现成) + 兜底
	mux.Handle("/", mgr.HTTPHandler())

	// 外层: admin 证书授权
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

// gwErrLang 按请求 X-Lang 返回错误字典(默认 zh)
func gwErrLang(r *http.Request) *i18n.L {
	if lang := r.Header.Get("X-Lang"); lang == "en" || lang == "zh" {
		return i18n.New(lang)
	}
	return i18n.New("zh")
}

// gwErr 输出错误(状态码复用 api.ErrStatus; errImmutable 按请求语言重翻)
func gwErr(w http.ResponseWriter, r *http.Request, err error) {
	msg := err.Error()
	l := gwErrLang(r)
	if localized := l.E("errImmutable").Error(); msg == i18n.New("zh").S("errImmutable") || msg == i18n.New("en").S("errImmutable") || msg == localized {
		msg = localized
	}
	http.Error(w, msg, api.ErrStatus(err))
}
