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
	"mtls-gateway/internal/logging"
	"mtls-gateway/internal/permissioncheck"
	"mtls-gateway/internal/proxy"
)

// version 由 release 构建经 -ldflags "-X main.version=..." 注入; 默认 "dev"
var version = "dev"

// 管理端口超时: 与网关一致(WriteTimeout 不限制, IdleTimeout 300s)
const (
	gwWriteTimeout = 0 * time.Second
	gwIdleTimeout  = 300 * time.Second
	// maxBodyBytes 管理 API 请求体上限(防内存耗尽)
	maxBodyBytes = 4 << 20
)

func main() {
	configPath := flag.String("config", "/etc/mtls-gw/config.toml", "配置文件路径(与网关同一份)")
	flag.Parse()

	cfg, err := config.Parse(*configPath)
	if err != nil {
		log.Fatalf("config %s: %v (配置文件错误, 拒绝启动)", *configPath, err)
	}
	// 保留原始 cfg 供 configmgr 使用: 下方日志路径替换只影响本进程日志 —
	// 若替换后的路径进 configmgr, persist() 会把 admin 组件路径写回共享 config.toml,
	// 网关下次启动继承该路径 → 日志重新合流(滚动竞态回归 + 用户配置被污染)。
	origCfg := cfg
	// 日志路径与网关分离(同一 config 的 log_file 等字段指向网关路径时 —
	// 双进程各自滚动同一文件会 rename 竞态互相覆盖; 强制改用 mtls-admin 组件路径)。
	// 注意: 显式配置的共享路径同样被替换 — 双进程共享一份 config, 该字段无法表达
	// 每进程路径, 共享路径本身就是滚动竞态源, 组件化分离是安全默认。
	adminLog := logging.DefaultPath("mtls-admin", "events.log")
	if cfg.LogFile != adminLog {
		log.Printf("日志: events %q → %q (mtls-admin 组件路径, 与网关分离避免滚动竞态)", cfg.LogFile, adminLog)
		cfg.LogFile = adminLog
	}
	adminAccess := logging.DefaultPath("mtls-admin", "access.log")
	if cfg.AccessLogFile != adminAccess {
		log.Printf("日志: access %q → %q (mtls-admin 组件路径)", cfg.AccessLogFile, adminAccess)
		cfg.AccessLogFile = adminAccess
	}
	adminStdout := logging.DefaultPath("mtls-admin", "stdout.log")
	if cfg.StdoutLogFile != adminStdout {
		log.Printf("日志: stdout %q → %q (mtls-admin 组件路径)", cfg.StdoutLogFile, adminStdout)
		cfg.StdoutLogFile = adminStdout
	}
	if err := os.MkdirAll(filepath.Dir(cfg.DB), 0o700); err != nil {
		log.Fatalf("mkdir db dir: %v", err)
	}

	// 启动前权限预检(Linux): 管理进程是唯一写者(DB/CA 签发/配置落盘) —
	// 检查 CA 私钥/reload 客户端证书(mode&0o007==0 禁 world)/DB/签发目录/socket/配置目录。
	// 防 22:18 类"目录不可写带病运行"(签发目录只读 → 临时目录创建失败、配置落盘失败)。
	if permissioncheck.Report(permissioncheck.Check(permissioncheck.AdminNeeds(cfg, *configPath)), cfg.LogFile) {
		os.Exit(1)
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
	// 用原始 cfg(日志路径未被替换): 落盘不污染共享配置
	cm := configmgr.New(*configPath, origCfg, nil)

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
	// 审计事件在 Manager 内部触发(签发/吊销成功), 双通道(unix socket/TCP)统一留痕 —
	// 证书操作是最高价值审计项, 不能只靠 TCP wrapper(CLI 走 unix socket 会绕过)
	mgr.SetAudit(func(kind, msg string) {
		if evLog != nil {
			evLog.Write(eventlog.Event{Type: kind, Msg: msg})
		}
	})

	// 网关 reload 客户端(可选): 变更后调网关 /admin/reload 热重载。
	// 配置错误(缺 reload_cert/key 等)降级为警告并禁用自动 reload —
	// 自动 reload 是增强项, 不应因它瘫痪证书管理/签发(证书管理仍可用, 稍后手动 reload 即可)。
	var rc *reloadClient
	if cfg.GatewayReloadAddr != "" {
		rc, err = newReloadClient(cfg)
		if err != nil {
			log.Printf("gateway reload 客户端配置错误: %v (自动 reload 禁用; 变更后需手动调网关 /admin/reload)", err)
			rc = nil
		} else {
			log.Printf("gateway reload: %s (变更后自动热重载)", cfg.GatewayReloadAddr)
		}
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

// Trigger 调网关 /admin/reload; 返回是否成功(失败由调用方写事件留痕, 管理侧已落盘可重试)
func (c *reloadClient) Trigger() bool {
	if c == nil {
		return false
	}
	resp, err := c.cli.Post("https://"+c.addr+"/admin/reload", "application/json", nil)
	if err != nil {
		log.Printf("gateway reload: %v (管理侧已落盘, 可稍后重试)", err)
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("gateway reload: HTTP %d (管理侧已落盘)", resp.StatusCode)
		return false
	}
	log.Printf("gateway reload: ok")
	return true
}

// —— 管理 handler(admin 证书保护): 证书管理(api.Manager) + 配置 CRUD(configmgr, 落盘后调网关 reload) ——

func adminHandler(gw *auth.Gateway, mgr *api.Manager, cm *configmgr.ConfigManager, ev *eventlog.Logger, rc *reloadClient) http.Handler {
	mux := http.NewServeMux()

	cfgChanged := func(msg string) {
		if ev != nil {
			ev.Write(eventlog.Event{Type: "config_change", Msg: msg})
		}
	}
	// 配置变更落盘后触发网关 reload(管理进程是配置写者, 网关只读消费者);
	// 并同步签发校验的角色集(否则新增角色后签发仍报"未声明", 需重启才生效)
	changed := func(msg string) {
		cfgChanged(msg)
		mgr.SetDeclaredRoles(cm.Roles()) // 角色 CRUD/config 批量保存后刷新签发校验集
		if rc != nil && !rc.Trigger() {
			// reload 失败可见: 网关内存副本停留旧状态(吊销不生效/新证书不可用), 必须留痕
			cfgChanged("⚠️ 网关 reload 失败: " + msg + " (网关仍用旧内存副本, 请检查 gateway_reload_addr/reload 证书)")
		}
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
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
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
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
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
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
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
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
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
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
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
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
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

	// 证书管理(api.Manager 现成): 审计事件(cert_issue/cert_revoke)已下沉到 Manager 内部
	// (SetAudit), unix socket 与 TCP 双通道统一留痕, 这里直接挂载即可。
	mux.Handle("/", mgr.HTTPHandler())

	// 外层: admin 证书授权(认证失败留痕 — 管理面不能是日志盲区)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec, err := gw.Authorize(r)
		if err != nil {
			cfgChanged("管理面认证失败: " + r.Method + " " + r.URL.Path)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if !gw.IsAdmin(rec) {
			cfgChanged(fmt.Sprintf("管理面拒绝非 admin 证书 %s(%s): %s %s", rec.Name, rec.Serial, r.Method, r.URL.Path))
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
