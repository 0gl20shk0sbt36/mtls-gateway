// mtls-gw: mTLS 反向代理网关(纯数据面: 认证 + 路由 + 转发; 管理功能在独立 mtls-admin 进程)
//
// 模型: mappings(通道) + services(服务注册) + roles(证书角色) 三表联动。
// 服务端参数只有一个: -config <配置文件> (TOML)。
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
	"strings"
	"syscall"
	"time"

	"mtls-gateway/internal/api"
	"mtls-gateway/internal/auth"
	"mtls-gateway/internal/config"
	"mtls-gateway/internal/configmgr"
	"mtls-gateway/internal/db"
	"mtls-gateway/internal/eventlog"
	"mtls-gateway/internal/httpshared"
	"mtls-gateway/internal/pathutil"
	"mtls-gateway/internal/permissioncheck"
	"mtls-gateway/internal/proxy"
)

// version 由 release 构建经 -ldflags "-X main.version=..." 注入; 默认 "dev"
var version = "dev"

// 转发超时参数(全部 http.Server 共用; 防回归常量, 单测断言):
//   - WriteTimeout: 0(不限制) — 绝对时限会在响应中途强关连接, 即使流式响应持续输出也会到点被切。
//     LLM/SSE 长流式响应(如 DSH 对话)总时长可远超 60s, 原 60s 表现为"每次发送消息的第一次发送超时"。
//     frp 对照: frp 隧道转发只设 ReadHeaderTimeout, 不设 WriteTimeout/IdleTimeout, 连接生命周期交对端。
//   - IdleTimeout: 300s — keep-alive 空闲上限(对齐浏览器连接池习惯); 过短(60s)会让浏览器复用已被关闭的死连接。
//
// 常量本体在 internal/httpshared(与 mtls-admin 共享, 防两进程漂移)。

func main() {
	var gateway *auth.Gateway // 供监听 handler 使用(在 auth.New 处赋值)
	// 监听注册表(O-1, pro 前瞻审计): 启动注册, reload 动态增删业务端口, 优雅退出全关。
	reg := newListenerRegistry()
	cfgPath = flag.String("config", "/etc/mtls-gw/config.toml", "配置文件路径")
	flag.Parse()

	// 配置加载
	cfg := loadConfig(*cfgPath)

	// 目录
	if err := os.MkdirAll(filepath.Dir(cfg.DB), 0o700); err != nil {
		log.Fatalf("mkdir db dir: %v", err)
	}
	// 预检前创建日志目录(与 DB 目录一致): 默认分平台路径目录可能不存在(新机器),
	// 不创建则权限预检对缺失目录报 ENOENT → 网关无法首次启动。
	for _, p := range []string{cfg.LogFile, cfg.AccessLogFile, cfg.StdoutLogFile} {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			log.Fatalf("mkdir log dir: %v", err)
		}
	}

	// 启动前权限预检(Linux): 网关读路径(CA/服务器证书/私钥/DB/日志)权限不足 → 拒绝启动。
	// 防 2026-08-21 22:18 类事件带病运行; 密钥文件要求 mode&0o007==0(禁 world 可读)。
	// 失败时 stderr 必有输出; 尝试写事件日志(日志无权限则跳过)。
	if permissioncheck.Report(permissioncheck.Check(permissioncheck.GatewayNeeds(cfg)), cfg.LogFile) {
		os.Exit(1)
	}

	// 数据库
	store, err := db.Open(cfg.DB)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer store.Close()
	log.Printf("mtls-gw %s starting", version)
	log.Printf("db loaded: %d certs", len(store.List()))
	// 启动时检查证书重名(禁止同名规则同样约束存量数据): 同名 >1 条 → 拒绝启动
	{
		byName := map[string][]db.CertRecord{}
		for _, r := range store.List() {
			byName[r.Name] = append(byName[r.Name], r)
		}
		for name, recs := range byName {
			if len(recs) > 1 {
				var serials []string
				for _, r := range recs {
					serials = append(serials, r.Serial)
				}
				log.Fatalf("证书重名: %q 有 %d 条记录 %v, 禁止同名; 请吊销并清理多余记录后重启", name, len(recs), serials)
			}
		}
	}

	// 认证器 (requireIPBind/admin_role/tls_min_version 来自配置)
	requireIPBind := cfg.RequireIPBindResolved()
	gateway, err = auth.New(store, cfg.CA, cfg.ServerCert, cfg.ServerKey, requireIPBind, cfg.AdminRole, cfg.TLSMinVersion)
	if err != nil {
		log.Fatalf("auth: %v", err)
	}
	// 映射 + 服务注册 → 路由器 (listen 判重 / 通道引用校验 / 角色声明校验在此报错)
	router, err := proxy.NewRouter(cfg.Mappings, cfg.Services, cfg.Roles)
	if err != nil {
		log.Fatalf("invalid config: %v", err)
	}
	log.Printf("mappings: %d services: %d on ports %v", len(cfg.Mappings), len(cfg.Services), router.Listens())

	// 配置管理器 (模式 + CRUD + 热重载 + 落盘)
	cm := configmgr.New(*cfgPath, cfg, router)
	log.Printf("config mode: %s", cm.Mode())

	// 事件日志(系统) + 访问日志(大量, 单独文件); 各自滚动
	evLog, err := eventlog.New(cfg.LogFile, cfg.LogMaxSizeMB, cfg.LogMaxFiles)
	if err != nil {
		log.Printf("event log: %v (禁用)", err)
	}
	defer func() {
		if evLog != nil {
			evLog.Close()
		}
	}()
	accLog, err := eventlog.New(cfg.AccessLogFile, cfg.LogMaxSizeMB, cfg.LogMaxFiles)
	if err != nil {
		log.Printf("access log: %v (禁用)", err)
	}
	defer func() {
		if accLog != nil {
			accLog.Close()
		}
	}()
	// 标准日志(认证/启动/隧道/错误等 log.Printf): 终端 + 文件双写(文本滚动文件)
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
		log.SetOutput(io.MultiWriter(os.Stderr, stdLog.TextWriter())) // 双写: 终端(systemd journal) + stdout.log
	}
	if evLog != nil {
		evLog.Write(eventlog.Event{Type: "start", Msg: "mtls-gw 启动"})
	}

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
			reg.add("gw:"+port, ln, gatewayHandler(gateway, cm, port, accLog), "gateway", "mTLS", gateway.ServerTLSConfig())
		}()
	}

	// ===== /info 服务发现 (已登记设备证书即可; 匿名返回 CA 供引导) =====
	// ===== /admin/reload (管理进程调用, 全量热重载) =====
	// 网关管理面仅剩 reload(其余管理功能在独立 mtls-admin 进程, 绑 admin_listen);
	// 网关用独立 reload_listen 端口, 未配置时与 info 同端口(/info + /admin/reload 路径区分)。
	infoListen := config.ResolveListen(bindHost, cfg.InfoListen)
	reloadListen := config.ResolveListen(bindHost, cfg.ReloadListen)
	if reloadListen == "" {
		reloadListen = infoListen // 默认与 /info 合并(兼容旧 info+admin 合并配置形态)
	}
	merged := infoListen != "" && reloadListen != "" && infoListen == reloadListen

	if merged {
		// 合并端口: /info(匿名引导) + /admin/reload(admin 证书) 同端口路径区分
		go func() {
			ln, err := net.Listen("tcp", reloadListen)
			if err != nil {
				log.Fatalf("merged listen: %v", err)
			}
			reg.add("merged", ln, mergedHandler(gateway, cm, accLog, evLog, reg, bindHost), "info+reload", "merged: /info anonymous, /admin/reload mTLS", gateway.ServerTLSConfig())
		}()
	} else {
		if infoListen != "" {
			go func() {
				ln, err := net.Listen("tcp", infoListen)
				if err != nil {
					log.Fatalf("info listen %s: %v", infoListen, err)
				}
				reg.add("info", ln, infoHandler(gateway, cm, accLog), "/info", "registered cert only", gateway.ServerTLSConfig())
			}()
		}
		if reloadListen != "" {
			go func() {
				ln, err := net.Listen("tcp", reloadListen)
				if err != nil {
					log.Fatalf("reload listen %s: %v", reloadListen, err)
				}
				reg.add("reload", ln, adminHandler(gateway, cm, evLog, reg, bindHost, accLog), "/admin/reload", "mTLS, admin cert required", gateway.ServerTLSConfig())
			}()
		}
	}

	// 优雅退出: SIGINT/SIGTERM 关闭全部 http.Server 并等 store 落盘
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit
	log.Println("shutting down...")
	if evLog != nil {
		evLog.Write(eventlog.Event{Type: "stop", Msg: "mtls-gw 停止"})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, s := range reg.all() {
		s.Shutdown(ctx)
	}
}

// accessEvent 组装访问事件(元数据, 不记录数据内容; 含来源 IP 与耗时供取证/排查)
func accessEvent(rec *db.CertRecord, channel, method, path string, status int, in, out int64, remote string, dur time.Duration) eventlog.Event {
	return eventlog.Event{
		Type:       "access",
		Cert:       rec.Name,
		Serial:     rec.Serial,
		Role:       strings.Join(rec.Purposes, ","),
		Channel:    channel,
		Method:     method,
		Path:       path,
		Status:     status,
		BytesIn:    in,
		BytesOut:   out,
		Remote:     remote,
		DurationMS: dur.Milliseconds(),
	}
}

// gatewayHandler 网关主 handler: 认证 → 按路径选映射(最长匹配) → 按引用服务的 roles 授权 → 转发
// 路由器每次从 ConfigManager 取(支持热重载); 访问/拒绝事件写 accLog
func gatewayHandler(gw *auth.Gateway, cm *configmgr.ConfigManager, port string, acc *eventlog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := eventlog.NewStatusWriter(w)

		// 匹配前规范化请求路径: 防 /admin/../secret 命中 /admin 映射后逃逸 target 前缀
		// (dot-segment 只清替换结果不够 — 匹配用的是原始路径)
		r.URL.Path = pathutil.CleanDotSegments(r.URL.Path)
		router := cm.Router()
		rt := router.Match(port, r.URL.Path)
		if rt == nil {
			if acc != nil {
				acc.Write(eventlog.Event{Type: "deny", Channel: ":" + port, Method: r.Method, Path: r.URL.Path, Status: 404, Msg: "no route"})
			}
			http.Error(sw, "no route for "+r.URL.Path, http.StatusNotFound)
			return
		}
		remote := auth.RemoteIP(r)

		// null 路由: 匿名放行(不需要证书; 任意来源可访问, 由部署方确保端口暴露面)
		if rt.AllowsNull() {
			auth.AuthLog(rt.Listen(), remote, "(anonymous)", true)
			rt.ApplyHeaders(r, proxy.HeaderVars{RemoteIP: remote}) // 默认防伪造基线 + mapping.headers(证书变量为空)
			router.Serve(rt, sw, r)
			if acc != nil {
				code := sw.Status()
				if code == 0 {
					code = http.StatusOK
				}
				acc.Write(accessEvent(&db.CertRecord{Name: "(anonymous)"}, rt.Listen(), r.Method, r.URL.Path, code, r.ContentLength, sw.Bytes(), remote, time.Since(start)))
			}
			return
		}

		// 非 null 路由: 需要证书 + 授权
		rec, err := gw.Authorize(r)
		if err != nil {
			auth.AuthLog("", remote, "", false)
			if acc != nil {
				acc.Write(eventlog.Event{Type: "deny", Channel: ":" + port, Method: r.Method, Path: r.URL.Path, Status: 403, Msg: err.Error()})
			}
			http.Error(sw, "forbidden", http.StatusForbidden) // 脱敏: 细节仅写事件日志
			return
		}

		if !rt.Allows(rec.Purposes) {
			auth.AuthLog(rt.Listen(), remote, rec.Serial, false)
			if acc != nil {
				acc.Write(eventlog.Event{Type: "deny", Cert: rec.Name, Serial: rec.Serial, Role: strings.Join(rec.Purposes, ","), Channel: rt.Listen(), Method: r.Method, Path: r.URL.Path, Status: 403, Msg: "no access"})
			}
			http.Error(sw, "no access to "+rt.Listen(), http.StatusForbidden)
			return
		}
		auth.AuthLog(rt.Listen(), remote, rec.Serial, true)
		rt.ApplyHeaders(r, proxy.HeaderVars{ // 默认防伪造基线 + mapping.headers(证书变量注入)
			CertName:   rec.Name,
			CertSerial: rec.Serial,
			CertRoles:  strings.Join(rec.Purposes, ","),
			RemoteIP:   remote,
		})
		router.Serve(rt, sw, r)
		if acc != nil {
			code := sw.Status()
			if code == 0 {
				code = http.StatusOK // 未写头时记 200(Hijack 已记 101)
			}
			acc.Write(accessEvent(rec, rt.Listen(), r.Method, r.URL.Path, code, r.ContentLength, sw.Bytes(), remote, time.Since(start)))
		}
	})
}

// mergedHandler 合并端口(info_listen == reload_listen)的路径分发:
// /info 匿名可达(引导), /admin/* 必须 admin 证书 — 前缀匹配安全语义可测(pro 深度审计提示,
// 若 /admin 前缀匹配写错则 reload 暴露给匿名, 是安全事故且需测试拦截)。
func mergedHandler(gw *auth.Gateway, cm *configmgr.ConfigManager, accLog, evLog *eventlog.Logger,
	reg *listenerRegistry, bindHost string) http.Handler {
	mm := http.NewServeMux()
	mm.HandleFunc("/info", infoHandler(gw, cm, accLog).ServeHTTP)
	mm.Handle("/admin/", adminHandler(gw, cm, evLog, reg, bindHost, accLog)) // 尾部斜杠=前缀匹配(/admin/*)
	return mm
}

// infoHandler /info: 匿名引导(null)或已登记证书; 无证书时返回 CA(供客户端过滤证书源), 有证书时附带可访问服务列表
func infoHandler(gw *auth.Gateway, cm *configmgr.ConfigManager, acc *eventlog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := eventlog.NewStatusWriter(w)
		remote := auth.RemoteIP(r)
		rec, err := gw.Authorize(r)
		if err != nil {
			// 有证书但认证失败(吊销/未登记) → 403; 仅真匿名(无证书)才返回 CA 引导
			if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
				if acc != nil {
					acc.Write(eventlog.Event{Type: "deny", Channel: "/info", Method: r.Method, Path: r.URL.Path, Status: 403, Msg: err.Error()})
				}
				http.Error(sw, "forbidden", http.StatusForbidden)
				return
			}
		}
		var services []proxy.ServiceInfo
		name := "(anonymous)"
		if err == nil {
			services = cm.Router().ServicesAllowed(rec.Purposes)
			name = rec.Name
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(sw).Encode(map[string]any{
			"ca":       string(gw.CAPEM()),
			"services": services,
		})
		if acc != nil {
			code := sw.Status()
			if code == 0 {
				code = http.StatusOK
			}
			acc.Write(accessEvent(&db.CertRecord{Name: name}, "/info", r.Method, r.URL.Path, code, r.ContentLength, sw.Bytes(), remote, time.Since(start)))
		}
	})
}

// adminHandler 管理 TCP handler: 认证 + 只允许 admin_role
// gwErr 输出管理端点错误(JSON 信封 + 状态码 + kind): 与 mtls-admin 共用
// httpshared.ErrWriter 统一出口 — 状态码走 api.ErrStatus(errs.Kind 结构化优先),
// errImmutable 按 X-Lang 重翻, kind 随信封上传; 消除旧"分散三处"漂移。
var gwErr = httpshared.ErrWriter{
	Status:   api.ErrStatus,
	Localize: httpshared.LocalizeErrImmutable,
	Kind:     httpshared.KindOfErr,
}.Write

// adminHandler 网关管理端点(管理服务拆分后仅剩 reload):
//   - POST /admin/reload — 全量热重载(DB + 配置) + 业务端口集合热 diff(O-1),
//     由独立 mtls-admin 进程调用(admin 证书)
//
// 其余管理功能(签发/吊销/配置 CRUD)已拆分至 mtls-admin 进程, 网关不再提供。
func adminHandler(gw *auth.Gateway, cm *configmgr.ConfigManager, ev *eventlog.Logger,
	reg *listenerRegistry, bindHost string, acc *eventlog.Logger) http.Handler {
	mux := http.NewServeMux()

	// 记配置变更事件
	cfgChanged := func(msg string) {
		if ev != nil {
			ev.Write(eventlog.Event{Type: "config_change", Msg: msg})
		}
	}

	// GET /admin/health — 探活 + 版本回传(O-2, pro 前瞻审计): 升级/排障时对比
	// 网关与 mtls-admin 版本是否一致(版本不匹配时 config 校验可能分叉)。
	mux.HandleFunc("GET /admin/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"status": "ok", "version": version})
	})

	// POST /admin/reload — 全量热重载(DB + 配置): 管理进程改完 DB/配置后调用。
	// 先 DB 后配置, 各自原子替换; 任一失败返回错误(成功侧已生效, 失败侧保持旧副本, 可重试)。
	// admin 证书保护(外层统一 Authorize + IsAdmin)。
	// POST /admin/reload — 全量热重载(DB + 配置) + 端口集合热 diff。
	// 顺序(D-1, pro 前瞻审计): 先 ValidateReload 预检(解析+安全字段+构建 router),
	// 失败则 DB 也不动 — 避免"DB 已换新、配置保持旧"的混合态; 再 DB → 配置原子替换;
	// 最后 diff 业务端口: 新增即监听, 删除即关闭(不再需要重启网关)。
	mux.HandleFunc("POST /admin/reload", func(w http.ResponseWriter, r *http.Request) {
		oldPorts := reg.gatewayPorts() // reload 前实际监听的业务端口
		if err := cm.ValidateReload(); err != nil {
			gwErr(w, r, err) // 预检失败: DB 不动, 整体保持旧状态
			return
		}
		if err := gw.Reload(); err != nil {
			gwErr(w, r, fmt.Errorf("db reload: %w", err))
			return
		}
		if err := cm.ReloadFromDisk(); err != nil {
			gwErr(w, r, err)
			return
		}
		cfgChanged("热重载: DB + 配置(管理进程触发)")
		// O-1: 业务端口集合热 diff — 新增端口立即监听, 删除端口立即关闭
		added, removed := diffPorts(oldPorts, cm.Router().Listens())
		for _, port := range added {
			if err := reg.addGatewayPort(bindHost, port, gatewayHandler(gw, cm, port, acc), gw.ServerTLSConfig()); err != nil {
				msg := fmt.Sprintf("热重载: 新增端口 %s 监听失败: %v (需重启网关)", port, err)
				log.Printf("%s", msg)
				cfgChanged(msg)
			}
		}
		for _, port := range removed {
			reg.remove("gw:" + port)
		}
		if len(added) > 0 || len(removed) > 0 {
			msg := fmt.Sprintf("热重载: 业务端口变更 +%v -%v (动态生效)", added, removed)
			log.Printf("%s", msg)
			cfgChanged(msg)
		}
		writeJSON(w, map[string]any{"ok": true, "added": added, "removed": removed})
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec, err := gw.Authorize(r)
		if err != nil {
			// 管理面认证失败留痕(业务面有 access log, 管理面不能是盲区)
			if ev != nil {
				ev.Write(eventlog.Event{Type: "deny", Channel: "/admin/reload", Method: r.Method, Path: r.URL.Path, Status: 403, Msg: "admin auth failed"})
			}
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if !gw.IsAdmin(rec) {
			if ev != nil {
				ev.Write(eventlog.Event{Type: "deny", Cert: rec.Name, Serial: rec.Serial, Channel: "/admin/reload", Method: r.Method, Path: r.URL.Path, Status: 403, Msg: "admin cert required"})
			}
			http.Error(w, "admin cert required", http.StatusForbidden)
			return
		}
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

// loadConfig 启动时加载配置; 解析/语义错误或文件缺失一律拒绝启动
// (静默用默认值可能带错安全配置, 且掩盖 systemd 配置路径笔误 — 与 mtls-admin 一致)。
func loadConfig(path string) config.Config {
	cfg, err := config.Parse(path)
	if err != nil {
		log.Fatalf("config %s: %v (配置文件错误/缺失, 拒绝启动)", path, err)
	}
	return cfg
}

var cfgPath *string
