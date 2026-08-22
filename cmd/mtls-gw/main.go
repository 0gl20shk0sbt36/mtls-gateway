// mtls-gw: mTLS 反向代理网关 + 证书管理 (v4)
//
// 模型: mappings(通道) + services(服务注册) + roles(证书角色) 三表联动。
// 服务端参数只有一个: -config <配置文件> (TOML)。
package main

import (
	"bufio"
	"bytes"
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
	"sync"
	"syscall"
	"time"

	"mtls-gateway/internal/api"
	"mtls-gateway/internal/auth"
	"mtls-gateway/internal/config"
	"mtls-gateway/internal/db"
	"mtls-gateway/internal/eventlog"
	"mtls-gateway/internal/i18n"
	"mtls-gateway/internal/pathutil"
	"mtls-gateway/internal/proxy"
)

// version 由 release 构建经 -ldflags "-X main.version=..." 注入; 默认 "dev"
var version = "dev"

// 转发超时参数(全部 http.Server 共用; 防回归常量, 单测断言):
//   - WriteTimeout: 0(不限制) — 绝对时限会在响应中途强关连接, 即使流式响应持续输出也会到点被切。
//     LLM/SSE 长流式响应(如 DSH 对话)总时长可远超 60s, 原 60s 表现为"每次发送消息的第一次发送超时"。
//     frp 对照: frp 隧道转发只设 ReadHeaderTimeout, 不设 WriteTimeout/IdleTimeout, 连接生命周期交对端。
//   - IdleTimeout: 300s — keep-alive 空闲上限(对齐浏览器连接池习惯); 过短(60s)会让浏览器复用已被关闭的死连接。
const (
	gwWriteTimeout = 0 * time.Second   // 不限制响应写时限(长流式/SSE 刚需)
	gwIdleTimeout  = 300 * time.Second // keep-alive 空闲上限
)

func main() {
	var servers []*http.Server // 优雅退出时关闭
	var serversMu sync.Mutex
	cfgPath = flag.String("config", "/etc/mtls-gw/config.toml", "配置文件路径")
	flag.Parse()

	// 配置加载
	cfg := loadConfig(*cfgPath)

	// 目录
	if err := os.MkdirAll(filepath.Dir(cfg.DB), 0o700); err != nil {
		log.Fatalf("mkdir db dir: %v", err)
	}

	// 启动前权限预检(Linux): 配置引用的全部文件/目录权限不足 → 拒绝启动。
	// 防 2026-08-21 22:18 类事件(配置目录不可写导致落盘/备份静默失败、内存与磁盘分叉)带病运行。
	// 失败时 stderr 必有输出; 尝试写事件日志(日志无权限则跳过)。
	if fails := checkStartupPaths(cfg); len(fails) > 0 {
		reportStartupFailures(cfg, fails)
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
	gateway, err := auth.New(store, cfg.CA, cfg.ServerCert, cfg.ServerKey, requireIPBind, cfg.AdminRole, cfg.TLSMinVersion)
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
	cm := NewConfigManager(*cfgPath, cfg, router)
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
			log.Printf("mtls gateway listening on %s (mTLS)", addr)
			srv := &http.Server{
				Handler:           gatewayHandler(gateway, cm, port, accLog),
				ReadHeaderTimeout: 10 * time.Second,
				ReadTimeout:       30 * time.Second,
				// WriteTimeout: 流式响应(SSE/LLM token 流)可能持续数分钟,
				// 60s 会在 LLM 生成中途强制切断连接(表现: 消息超时一次, 重发命中缓存即好)。
				// 禁用写超时(单用户内网环境, 挂连接风险可接受); 反代侧 ResponseHeaderTimeout 仍保护响应头
				WriteTimeout: gwWriteTimeout,
				IdleTimeout:  gwIdleTimeout,
			}
			serversMu.Lock()
			servers = append(servers, srv)
			serversMu.Unlock()
			if err := srv.Serve(tlsListener(ln, gateway.ServerTLSConfig())); err != nil && err != http.ErrServerClosed {
				log.Fatalf("gateway serve %s: %v", addr, err)
			}
		}()
	}

	// ===== /info 服务发现 (已登记设备证书即可; 匿名返回 CA 供引导) =====
	infoListen := config.ResolveListen(bindHost, cfg.InfoListen)
	admListen := config.ResolveListen(bindHost, cfg.AdminListen)
	merged := infoListen != "" && admListen != "" && infoListen == admListen // 同端口合并: /info + /admin 路径区分
	if infoListen != "" && !merged {
		go func() {
			ln, err := net.Listen("tcp", infoListen)
			if err != nil {
				log.Fatalf("info listen %s: %v", infoListen, err)
			}
			log.Printf("mtls /info listening on %s (registered cert only)", infoListen)
			infoSrv := &http.Server{
				Handler:           infoHandler(gateway, cm, accLog),
				ReadHeaderTimeout: 10 * time.Second,
				ReadTimeout:       30 * time.Second,
				WriteTimeout:      gwWriteTimeout,
				IdleTimeout:       gwIdleTimeout,
			}
			serversMu.Lock()
			servers = append(servers, infoSrv)
			serversMu.Unlock()
			if err := infoSrv.Serve(tlsListener(ln, gateway.ServerTLSConfig())); err != nil && err != http.ErrServerClosed {
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
	}, cfg.AdminRole, cfg.KeyType, cfg.KeyBits, cfg.PwdLength, cfg.Roles)
	if err != nil {
		log.Fatalf("manager: %v", err)
	}
	mgr.SetDeclaredRoles(cfg.Roles)

	// ===== Unix socket 管理通道 (本机直接 admin) =====
	go func() {
		if err := mgr.ServeUnixSocket(); err != nil {
			log.Printf("unix socket: %v", err)
		}
	}()

	// ===== 管理 API TCP (远程 Web, 需 admin_role 证书) =====
	if admListen != "" {
		if merged {
			// 合并端口: /info(匿名引导) + /admin/*(admin 证书) 同端口路径区分
			mm := http.NewServeMux()
			mm.HandleFunc("/info", infoHandler(gateway, cm, accLog).ServeHTTP)
			mm.Handle("/admin/", adminHandler(gateway, mgr, cm, evLog)) // 尾部斜杠=前缀匹配(/admin/*)
			go func() {
				ln, err := net.Listen("tcp", admListen)
				if err != nil {
					log.Fatalf("merged listen: %v", err)
				}
				log.Printf("mtls info+admin listening on %s (merged: /info anonymous, /admin mTLS)", admListen)
				admSrv := &http.Server{
					Handler:           mm,
					ReadHeaderTimeout: 10 * time.Second,
					ReadTimeout:       30 * time.Second,
					WriteTimeout:      gwWriteTimeout,
					IdleTimeout:       gwIdleTimeout,
				}
				serversMu.Lock()
				servers = append(servers, admSrv)
				serversMu.Unlock()
				if err := admSrv.Serve(tlsListener(ln, gateway.ServerTLSConfig())); err != nil && err != http.ErrServerClosed {
					log.Fatalf("merged serve: %v", err)
				}
			}()
		} else {
			go func() {
				ln, err := net.Listen("tcp", admListen)
				if err != nil {
					log.Fatalf("admin listen: %v", err)
				}
				log.Printf("admin api listening on %s (mTLS, admin cert required)", admListen)
				admSrv := &http.Server{
					Handler:           adminHandler(gateway, mgr, cm, evLog),
					ReadHeaderTimeout: 10 * time.Second,
					ReadTimeout:       30 * time.Second,
					WriteTimeout:      gwWriteTimeout,
					IdleTimeout:       gwIdleTimeout,
				}
				serversMu.Lock()
				servers = append(servers, admSrv)
				serversMu.Unlock()
				if err := admSrv.Serve(tlsListener(ln, gateway.ServerTLSConfig())); err != nil && err != http.ErrServerClosed {
					log.Fatalf("admin serve: %v", err)
				}
			}()
		}
	}

	// 优雅退出: SIGINT/SIGTERM 关闭全部 http.Server 并等 store 落盘
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit
	log.Println("shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serversMu.Lock()
	snapshot := append([]*http.Server(nil), servers...)
	serversMu.Unlock()
	for _, s := range snapshot {
		s.Shutdown(ctx)
	}
}

// statusWriter 包装 ResponseWriter: 记录状态码与响应字节数(访问日志用)
// 实现 Hijacker/Flusher/ReaderFrom: 透传底层能力, 否则 WebSocket 升级(101)与流式响应被破坏
type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *statusWriter) WriteHeader(c int) {
	if w.status != 0 {
		return // 幂等: 只记首次(与 eventlog.StatusWriter 一致)
	}
	w.status = c
	w.ResponseWriter.WriteHeader(c)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return n, err
}

// Hijack 透传(WebSocket/升级必需)
func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying ResponseWriter does not support hijacking")
	}
	if w.status == 0 {
		w.status = http.StatusSwitchingProtocols // 升级连接: 访问日志记 101(与 eventlog 侧一致)
	}
	return hj.Hijack()
}

// Flush 透传(流式响应)
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// ReadFrom 透传(io.Copy 优化)
func (w *statusWriter) ReadFrom(r io.Reader) (int64, error) {
	if rf, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		n, err := rf.ReadFrom(r)
		w.bytes += n
		if w.status == 0 {
			w.status = http.StatusOK
		}
		return n, err
	}
	n, err := io.Copy(struct{ io.Writer }{w}, r)
	return n, err
}

// accessEvent 组装访问事件(元数据, 不记数据内容)
func accessEvent(rec *db.CertRecord, channel, method, path string, status int, in, out int64) eventlog.Event {
	ev := eventlog.Event{
		Type:     "access",
		Cert:     rec.Name,
		Serial:   rec.Serial,
		Role:     strings.Join(rec.Purposes, ","),
		Channel:  channel,
		Method:   method,
		Path:     path,
		Status:   status,
		BytesIn:  in,
		BytesOut: out,
	}
	return ev
}

// gatewayHandler 网关主 handler: 认证 → 按路径选映射(最长匹配) → 按引用服务的 roles 授权 → 转发
// 路由器每次从 ConfigManager 取(支持热重载); 访问/拒绝事件写 accLog
func gatewayHandler(gw *auth.Gateway, cm *ConfigManager, port string, acc *eventlog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w}

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
				code := sw.status
				if code == 0 {
					code = http.StatusOK
				}
				acc.Write(accessEvent(&db.CertRecord{Name: "(anonymous)"}, rt.Listen(), r.Method, r.URL.Path, code, r.ContentLength, sw.bytes))
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
			code := sw.status
			if code == 0 {
				code = http.StatusOK // 未写头时记 200(Hijack 已记 101)
			}
			acc.Write(accessEvent(rec, rt.Listen(), r.Method, r.URL.Path, code, r.ContentLength, sw.bytes))
		}
	})
}

// infoHandler /info: 无需 admin; 已登记证书即可; 返回该证书可访问的服务(按角色过滤)
// infoHandler /info: 匿名引导(null)或已登记证书; 无证书时返回 CA(供客户端过滤证书源), 有证书时附带可访问服务列表
func infoHandler(gw *auth.Gateway, cm *ConfigManager, acc *eventlog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w}
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
			code := sw.status
			if code == 0 {
				code = http.StatusOK
			}
			acc.Write(accessEvent(&db.CertRecord{Name: name}, "/info", r.Method, r.URL.Path, code, r.ContentLength, sw.bytes))
		}
	})
}

// adminHandler 管理 TCP handler: 认证 + 只允许 admin_role
// gwErrLang 按请求 X-Lang 返回错误字典(默认 zh)
func gwErrLang(r *http.Request) *i18n.L {
	if lang := r.Header.Get("X-Lang"); lang == "en" || lang == "zh" {
		return i18n.New(lang)
	}
	return i18n.New("zh")
}

// gwErr 输出错误; 状态码复用 api.ErrStatus(不再固定 400)。
// 注意: 目前仅 errImmutable 按请求语言重翻; 其余 configmgr/proxy 的 CRUD 错误是硬编码中文,
// 完整 i18n 接入属后续工作。错误本地化/状态码机制分散三处(此处 + relay.localizeKnown + api.StatusFromKeywords),
// 新增错误串时需同步对应处, 否则状态码或翻译会静默漂移。
func gwErr(w http.ResponseWriter, r *http.Request, err error) {
	msg := err.Error()
	l := gwErrLang(r)
	if localized := l.E("errImmutable").Error(); msg == i18n.New("zh").S("errImmutable") || msg == i18n.New("en").S("errImmutable") || msg == localized {
		msg = localized
	}
	http.Error(w, msg, api.ErrStatus(err))
}

// 提供: 证书签发/吊销 (mgr) + 通道/服务/角色 CRUD (cm, 尊重 config_mode)
func adminHandler(gw *auth.Gateway, mgr *api.Manager, cm *ConfigManager, ev *eventlog.Logger) http.Handler {
	mux := http.NewServeMux()

	// 记配置变更事件
	cfgChanged := func(msg string) {
		if ev != nil {
			ev.Write(eventlog.Event{Type: "config_change", Msg: msg})
		}
	}

	// 配置总览(UI 用): 模式 + 通道 + 服务 + 角色
	mux.HandleFunc("GET /admin/config", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"mode":       cm.Mode(),
			"admin_role": cm.AdminRole(),
			"roles":      cm.Roles(),
			"mappings":   cm.Mappings(),
			"services":   cm.Services(),
		})
	})

	// POST /admin/reload — 全量热重载(DB + 配置): 管理进程改完 DB/配置后调用。
	// 先 DB 后配置, 各自原子替换; 任一失败返回错误(成功侧已生效, 失败侧保持旧副本, 可重试)。
	// admin 证书保护(adminHandler 外层统一 Authorize + IsAdmin)。
	mux.HandleFunc("POST /admin/reload", func(w http.ResponseWriter, r *http.Request) {
		if err := gw.Reload(); err != nil {
			gwErr(w, r, fmt.Errorf("db reload: %w", err))
			return
		}
		if err := cm.ReloadFromDisk(); err != nil {
			gwErr(w, r, err)
			return
		}
		cfgChanged("热重载: DB + 配置(管理进程触发)")
		writeJSON(w, map[string]any{"ok": true})
	})

	// 整体替换保存 (批量编辑)
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
		mgr.SetDeclaredRoles(cm.Roles())
		cfgChanged(fmt.Sprintf("批量保存配置: mappings=%d services=%d roles=%d", len(b.Mappings), len(b.Services), len(b.Roles)))
		writeJSON(w, map[string]any{"ok": true})
	})

	// 角色声明列表 CRUD
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
		mgr.SetDeclaredRoles(cm.Roles())
		cfgChanged("新增角色 " + b.Name)
		writeJSON(w, map[string]any{"ok": true})
	})
	mux.HandleFunc("DELETE /admin/roles", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if err := cm.DeleteRole(name); err != nil {
			gwErr(w, r, err)
			return
		}
		mgr.SetDeclaredRoles(cm.Roles())
		cfgChanged("删除角色 " + name)
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
		cfgChanged(fmt.Sprintf("新增通道 id=%s listen=%s target=%s", m.ID, m.Listen, m.Target))
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
		cfgChanged(fmt.Sprintf("修改通道 id=%s listen=%s", r.URL.Query().Get("id"), m.Listen))
		writeJSON(w, map[string]any{"ok": true})
	})
	mux.HandleFunc("DELETE /admin/mappings", func(w http.ResponseWriter, r *http.Request) {
		if err := cm.DeleteMapping(r.URL.Query().Get("id")); err != nil {
			gwErr(w, r, err)
			return
		}
		cfgChanged("删除通道 id=" + r.URL.Query().Get("id"))
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
		cfgChanged(fmt.Sprintf("新增服务 name=%s channels=%v roles=%v", s.Name, s.Channels, s.Roles))
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
		cfgChanged(fmt.Sprintf("修改服务 name=%s channels=%v roles=%v", s.Name, s.Channels, s.Roles))
		writeJSON(w, map[string]any{"ok": true})
	})
	mux.HandleFunc("DELETE /admin/services", func(w http.ResponseWriter, r *http.Request) {
		if err := cm.DeleteService(r.URL.Query().Get("name")); err != nil {
			gwErr(w, r, err)
			return
		}
		cfgChanged("删除服务 name=" + r.URL.Query().Get("name"))
		writeJSON(w, map[string]any{"ok": true})
	})

	// 证书管理 (mgr) — 包装记录签发/吊销事件(带对象详情)
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w}
		msg := ""
		if r.URL.Path == "/admin/certs/revoke" || r.URL.Path == "/admin/certs/issue" {
			if b, err := io.ReadAll(io.LimitReader(r.Body, 4<<20)); err == nil { // 限 4MB
				r.Body = io.NopCloser(bytes.NewReader(b)) // 恢复 body 供下游解析
				var rb struct {
					Serial   string   `json:"serial"`
					Name     string   `json:"name"`
					Purposes []string `json:"purposes"`
				}
				if json.Unmarshal(b, &rb) == nil {
					if r.URL.Path == "/admin/certs/revoke" && rb.Serial != "" {
						msg = "吊销证书 serial=" + rb.Serial
					}
					if r.URL.Path == "/admin/certs/issue" {
						msg = fmt.Sprintf("签发证书 name=%s purposes=%v", rb.Name, rb.Purposes)
					}
				}
			}
		}
		mgr.HTTPHandler().ServeHTTP(sw, r)
		if ev != nil && sw.status >= 200 && sw.status < 400 {
			switch r.URL.Path {
			case "/admin/certs/issue":
				if msg == "" {
					msg = "签发证书"
				}
				ev.Write(eventlog.Event{Type: "cert_issue", Msg: msg})
			case "/admin/certs/revoke":
				if msg == "" {
					msg = "吊销证书"
				}
				ev.Write(eventlog.Event{Type: "cert_revoke", Msg: msg})
			}
		}
	}))

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

// loadConfig 启动时加载配置; 解析/语义错误拒绝启动(静默用默认值可能带错安全配置)
func loadConfig(path string) config.Config {
	cfg, err := config.Parse(path)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("config %s 不存在 (使用默认值)", path)
			return config.DefaultConfig()
		}
		log.Fatalf("config %s: %v (配置文件错误, 拒绝启动)", path, err)
	}
	return cfg
}

var cfgPath *string
