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

	"github.com/BurntSushi/toml"

	"mtls-gateway/internal/api"
	"mtls-gateway/internal/auth"
	"mtls-gateway/internal/db"
	"mtls-gateway/internal/eventlog"
	"mtls-gateway/internal/i18n"
	"mtls-gateway/internal/pathutil"
	"mtls-gateway/internal/proxy"
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

	// 数据库
	store, err := db.Open(cfg.DB)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer store.Close()
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
				WriteTimeout:      60 * time.Second,
				IdleTimeout:       60 * time.Second,
			}
			serversMu.Lock()
			servers = append(servers, srv)
			serversMu.Unlock()
			if err := srv.Serve(tlsListener(ln, gateway.ServerTLSConfig())); err != nil && err != http.ErrServerClosed {
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
			infoSrv := &http.Server{
				Handler:           infoHandler(gateway, cm, accLog),
				ReadHeaderTimeout: 10 * time.Second,
				ReadTimeout:       30 * time.Second,
				WriteTimeout:      60 * time.Second,
				IdleTimeout:       60 * time.Second,
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
	if admListen := resolveListen(bindHost, cfg.AdminListen); admListen != "" {
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
				WriteTimeout:      60 * time.Second,
				IdleTimeout:       60 * time.Second,
			}
			serversMu.Lock()
			servers = append(servers, admSrv)
			serversMu.Unlock()
			if err := admSrv.Serve(tlsListener(ln, gateway.ServerTLSConfig())); err != nil && err != http.ErrServerClosed {
				log.Fatalf("admin serve: %v", err)
			}
		}()
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
		rec, err := gw.Authorize(r)
		if err != nil {
			auth.AuthLog("", auth.RemoteIP(r), "", false)
			if acc != nil {
				acc.Write(eventlog.Event{Type: "deny", Channel: ":" + port, Method: r.Method, Path: r.URL.Path, Status: 403, Msg: err.Error()})
			}
			http.Error(sw, "forbidden", http.StatusForbidden) // 脱敏: 细节仅写事件日志
			return
		}
		remote := auth.RemoteIP(r)

		// 匹配前规范化请求路径: 防 /admin/../secret 命中 /admin 映射后逃逸 target 前缀
		// (dot-segment 只清替换结果不够 — 匹配用的是原始路径)
		r.URL.Path = pathutil.CleanDotSegments(r.URL.Path)
		router := cm.Router()
		rt := router.Match(port, r.URL.Path)
		if rt == nil {
			if acc != nil {
				acc.Write(eventlog.Event{Type: "deny", Cert: rec.Name, Serial: rec.Serial, Role: strings.Join(rec.Purposes, ","), Channel: ":" + port, Method: r.Method, Path: r.URL.Path, Status: 404, Msg: "no route"})
			}
			http.Error(sw, "no route for "+r.URL.Path, http.StatusNotFound)
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
		proxy.SanitizeHeader(r)
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
func infoHandler(gw *auth.Gateway, cm *ConfigManager, acc *eventlog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w}
		rec, err := gw.Authorize(r)
		if err != nil {
			if acc != nil {
				acc.Write(eventlog.Event{Type: "deny", Channel: "/info", Method: r.Method, Path: r.URL.Path, Status: 403, Msg: err.Error()})
			}
			http.Error(sw, "forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(sw).Encode(map[string]any{"services": cm.Router().ServicesAllowed(rec.Purposes)})
		if acc != nil {
			code := sw.status
			if code == 0 {
				code = http.StatusOK // 兜底(与 gatewayHandler 一致)
			}
			acc.Write(accessEvent(rec, "/info", r.Method, r.URL.Path, code, r.ContentLength, sw.bytes))
		}
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
// gwErrLang 按请求 X-Lang 返回错误字典(默认 zh)
func gwErrLang(r *http.Request) *i18n.L {
	if lang := r.Header.Get("X-Lang"); lang == "en" || lang == "zh" {
		return i18n.New(lang)
	}
	return i18n.New("zh")
}

// gwErr 输出错误; 已知错误(immutable)按请求语言重翻, 其余原样
func gwErr(w http.ResponseWriter, r *http.Request, err error) {
	msg := err.Error()
	if msg == i18n.New("zh").S("errImmutable") || msg == i18n.New("en").S("errImmutable") {
		msg = gwErrLang(r).E("errImmutable").Error()
	}
	http.Error(w, msg, http.StatusBadRequest)
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

// Config 配置文件结构 (TOML)
type Config struct {
	BindHost      string             `toml:"bind_host"`       // 全局绑定地址 (默认 0.0.0.0)
	DB            string             `toml:"db"`              // SQLite 数据库路径
	ConfigMode    string             `toml:"config_mode"`     // mutable | ephemeral | immutable
	Lang          string             `toml:"lang"`            // 错误消息语言: zh | en (默认 zh)
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
	Org           string             `toml:"org"`          // 证书 O 字段
	OU            string             `toml:"ou"`           // 证书 OU 字段
	DefaultDays   int                `toml:"default_days"` // 普通证书默认天数
	AdminDays     int                `toml:"admin_days"`   // 管理角色证书默认天数
	RequireIPBind *bool              `toml:"require_ip_bind"`
	LogFile       string             `toml:"log_file"`        // 事件日志(系统/配置/证书操作); 空=关
	AccessLogFile string             `toml:"access_log_file"` // 访问日志(大量, 单独文件); 空=关
	LogMaxSizeMB  int                `toml:"log_max_size"`    // 单文件上限 MB (默认 10)
	LogMaxFiles   int                `toml:"log_max_files"`   // 保留历史份数 (默认 5)
	Roles         []string           `toml:"roles"`           // 角色声明列表(服务 roles / 签发 purposes 必须在此声明)
	Mappings      []proxy.Mapping    `toml:"mappings"`        // 通道: id + listen(:port[/path]) + target
	Services      []proxy.ServiceCfg `toml:"services"`        // 服务注册: name + channels + roles
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
		LogMaxSizeMB:  10,
		LogMaxFiles:   5,
		Roles:         []string{},
		Mappings:      []proxy.Mapping{},
		Services:      []proxy.ServiceCfg{},
	}
}

func loadConfig(path string) Config {
	cfg := DefaultConfig()
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		if os.IsNotExist(err) {
			log.Printf("config %s 不存在 (使用默认值)", path)
		} else {
			// 解析/语义错误: 静默用默认值可能带错 CA/证书/权限配置启动, 属安全风险
			log.Fatalf("config %s: %v (配置文件错误, 拒绝启动)", path, err)
		}
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
	// 角色声明列表校验: 命名合法 + 去重 (服务 roles 校验在 NewRouter)
	seen := map[string]bool{}
	for _, r := range cfg.Roles {
		if !proxy.ValidRoleName(r) {
			log.Fatalf("bad role name %q (只允许字母/数字/下划线/连字符)", r)
		}
		if seen[r] {
			log.Fatalf("duplicate role %q", r)
		}
		seen[r] = true
	}
	return cfg
}

var cfgPath *string
