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
	"context"
	"crypto/tls"
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
	"mtls-gateway/internal/httpshared"
	"mtls-gateway/internal/i18n"
	"mtls-gateway/internal/logging"
	"mtls-gateway/internal/permissioncheck"
	"mtls-gateway/internal/proxy"
)

// version 由 release 构建经 -ldflags "-X main.version=..." 注入; 默认 "dev"
var version = "dev"

// 管理端口超时: 与网关共享 httpshared 常量(WriteTimeout 不限制, IdleTimeout 300s)

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
	// 预检前创建日志目录(与 DB 目录一致): 组件路径目录可能不存在(新机器),
	// 不创建则权限预检对缺失目录报 ENOENT → 管理进程无法首次启动。
	for _, p := range []string{cfg.LogFile, cfg.AccessLogFile, cfg.StdoutLogFile} {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			log.Fatalf("mkdir log dir: %v", err)
		}
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
	// 启动即构建 router(与网关一致): 坏映射(重复 listen/坏引用/角色未声明)两进程同样拒绝启动
	// — 此前 mtls-admin 不校验, 网关拒启而管理进程照常启动, 两进程不对称(flash 审计抓出)
	router, err := proxy.NewRouter(origCfg.Mappings, origCfg.Services, origCfg.Roles)
	if err != nil {
		log.Fatalf("config 路由校验: %v (与网关一致, 拒绝启动)", err)
	}
	cm := configmgr.New(*configPath, origCfg, router)

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
	var rc *httpshared.ReloadClient
	if cfg.GatewayReloadAddr != "" {
		rc, err = httpshared.NewReloadClient(cfg.GatewayReloadAddr, cfg.ReloadCert, cfg.ReloadKey, cfg.CA)
		if err != nil {
			log.Printf("gateway reload 客户端配置错误: %v (自动 reload 禁用; 变更后需手动调网关 /admin/reload)", err)
			rc = nil
		} else {
			log.Printf("gateway reload: %s (变更后自动热重载)", cfg.GatewayReloadAddr)
		}
	}
	// 证书变更(签发/吊销)后触发网关 reload: 网关是只读消费者, 不自动感知 DB 变更 —
	// 不 reload 则新签发证书对网关不可见、吊销仍放行(管理拆分数据流的必接环节)。
	mgr.SetPostChange(func() {
		if rc != nil && !rc.Trigger() {
			log.Printf("⚠️ 证书变更后网关 reload 失败(网关仍用旧内存副本, 请检查 gateway_reload_addr/reload 证书)")
			if evLog != nil {
				evLog.Write(eventlog.Event{Type: "config_change", Msg: "⚠️ 证书变更后网关 reload 失败(网关仍用旧内存副本)"})
			}
		}
	})

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
	var srv *http.Server
	adminListen := config.ResolveListen(cfg.BindHost, cfg.AdminListen)
	if adminListen != "" {
		ln, err := net.Listen("tcp", adminListen)
		if err != nil {
			log.Fatalf("admin listen %s: %v", adminListen, err)
		}
		log.Printf("admin api listening on %s (mTLS, admin cert required)", adminListen)
		srv = &http.Server{
			Handler:           h,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      httpshared.WriteTimeout,
			IdleTimeout:       httpshared.IdleTimeout,
		}
		go func() {
			if err := srv.Serve(tls.NewListener(ln, gw.ServerTLSConfig())); err != nil && err != http.ErrServerClosed {
				log.Fatalf("admin serve: %v", err)
			}
		}()
	}

	// 优雅退出: SIGINT/SIGTERM → 关闭 TCP admin server(5s 内等进行中的签发/p12 请求完成,
	// 与网关一致; unix socket 随进程退出关闭, CLI 操作短平快不受影响) — flash 审计抓出此前无优雅退出
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("shutting down...")
	if evLog != nil {
		evLog.Write(eventlog.Event{Type: "stop", Msg: "mtls-admin 停止"})
	}
	if srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}
}

// reloadClient 已移至 internal/httpshared(ReloadClient) — 网关 reload 客户端,
// 跨进程共享(管理进程 + 未来 GUI 服务端复用)。

// —— 管理 handler(admin 证书保护): 证书管理(api.Manager) + 配置 CRUD(configmgr, 落盘后调网关 reload) ——

func adminHandler(gw *auth.Gateway, mgr *api.Manager, cm *configmgr.ConfigManager, ev *eventlog.Logger, rc *httpshared.ReloadClient) http.Handler {
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
		httpshared.WriteJSON(w, map[string]any{
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
		r.Body = http.MaxBytesReader(w, r.Body, httpshared.MaxBodyBytes)
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			gwErr(w, r, err)
			return
		}
		if err := cm.ReplaceAll(b.Mappings, b.Services, b.Roles); err != nil {
			gwErr(w, r, err)
			return
		}
		changed(fmt.Sprintf("批量保存配置: mappings=%d services=%d roles=%d", len(b.Mappings), len(b.Services), len(b.Roles)))
		httpshared.WriteJSON(w, map[string]any{"ok": true})
	})

	// 角色 CRUD
	mux.HandleFunc("POST /admin/roles", func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			Name string `json:"name"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, httpshared.MaxBodyBytes)
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			gwErr(w, r, err)
			return
		}
		if err := cm.AddRole(b.Name); err != nil {
			gwErr(w, r, err)
			return
		}
		changed("新增角色 " + b.Name)
		httpshared.WriteJSON(w, map[string]any{"ok": true})
	})
	mux.HandleFunc("DELETE /admin/roles", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if err := cm.DeleteRole(name); err != nil {
			gwErr(w, r, err)
			return
		}
		changed("删除角色 " + name)
		httpshared.WriteJSON(w, map[string]any{"ok": true})
	})

	// 通道 CRUD
	mux.HandleFunc("GET /admin/mappings", func(w http.ResponseWriter, r *http.Request) {
		httpshared.WriteJSON(w, map[string]any{"mappings": cm.Mappings()})
	})
	mux.HandleFunc("POST /admin/mappings", func(w http.ResponseWriter, r *http.Request) {
		var m proxy.Mapping
		r.Body = http.MaxBytesReader(w, r.Body, httpshared.MaxBodyBytes)
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			gwErr(w, r, err)
			return
		}
		if err := cm.AddMapping(m); err != nil {
			gwErr(w, r, err)
			return
		}
		changed(fmt.Sprintf("新增通道 id=%s listen=%s target=%s", m.ID, m.Listen, m.Target))
		httpshared.WriteJSON(w, map[string]any{"ok": true})
	})
	mux.HandleFunc("PUT /admin/mappings", func(w http.ResponseWriter, r *http.Request) {
		var m proxy.Mapping
		r.Body = http.MaxBytesReader(w, r.Body, httpshared.MaxBodyBytes)
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			gwErr(w, r, err)
			return
		}
		if err := cm.UpdateMapping(r.URL.Query().Get("id"), m); err != nil {
			gwErr(w, r, err)
			return
		}
		changed(fmt.Sprintf("修改通道 id=%s listen=%s", r.URL.Query().Get("id"), m.Listen))
		httpshared.WriteJSON(w, map[string]any{"ok": true})
	})
	mux.HandleFunc("DELETE /admin/mappings", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if err := cm.DeleteMapping(id); err != nil {
			gwErr(w, r, err)
			return
		}
		changed("删除通道 id=" + id)
		httpshared.WriteJSON(w, map[string]any{"ok": true})
	})

	// 服务 CRUD
	mux.HandleFunc("GET /admin/services", func(w http.ResponseWriter, r *http.Request) {
		httpshared.WriteJSON(w, map[string]any{"services": cm.Services()})
	})
	mux.HandleFunc("POST /admin/services", func(w http.ResponseWriter, r *http.Request) {
		var s proxy.ServiceCfg
		r.Body = http.MaxBytesReader(w, r.Body, httpshared.MaxBodyBytes)
		if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
			gwErr(w, r, err)
			return
		}
		if err := cm.AddService(s); err != nil {
			gwErr(w, r, err)
			return
		}
		changed(fmt.Sprintf("新增服务 name=%s channels=%v roles=%v", s.Name, s.Channels, s.Roles))
		httpshared.WriteJSON(w, map[string]any{"ok": true})
	})
	mux.HandleFunc("PUT /admin/services", func(w http.ResponseWriter, r *http.Request) {
		var s proxy.ServiceCfg
		r.Body = http.MaxBytesReader(w, r.Body, httpshared.MaxBodyBytes)
		if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
			gwErr(w, r, err)
			return
		}
		if err := cm.UpdateService(r.URL.Query().Get("name"), s); err != nil {
			gwErr(w, r, err)
			return
		}
		changed(fmt.Sprintf("修改服务 name=%s channels=%v roles=%v", s.Name, s.Channels, s.Roles))
		httpshared.WriteJSON(w, map[string]any{"ok": true})
	})
	mux.HandleFunc("DELETE /admin/services", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if err := cm.DeleteService(name); err != nil {
			gwErr(w, r, err)
			return
		}
		changed("删除服务 name=" + name)
		httpshared.WriteJSON(w, map[string]any{"ok": true})
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

// localizeErrImmutable 仅 errImmutable 按请求语言重翻; 其余 configmgr/proxy 的
// CRUD 错误是硬编码中文, 完整 i18n 接入属后续工作(结构化错误改造时统一)。
func localizeErrImmutable(lang string, err error) error {
	msg := err.Error()
	zh := i18n.New("zh").S("errImmutable")
	en := i18n.New("en").S("errImmutable")
	if msg == zh || msg == en || msg == i18n.New(lang).S("errImmutable") {
		return i18n.New(lang).E("errImmutable")
	}
	return err
}

// gwErr 输出管理 API 错误(JSON 信封 + 状态码): 统一出口收敛到 httpshared.ErrWriter,
// 状态码复用 api.ErrStatus(服务端权威表), 本地化仅覆盖 errImmutable。
var gwErr = httpshared.ErrWriter{
	Status:   api.ErrStatus,
	Localize: localizeErrImmutable,
}.Write
