// mtls-relay — 客户端 mTLS 中继层 daemon (客户端侧网关)。
//
// 单实例, 同时监听并转发所有配置的隧道(端口); 每条隧道将本地明文连接
// 用 mTLS 客户端证书转发到服务端 mtls-gw 网关后端端口。
// 提供本地管理 API (loopback), 供外壳 (CLI/WebUI/GUI) 调用。
package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"mtls-gateway/internal/certsource"
	"mtls-gateway/internal/relay"
	"mtls-gateway/internal/relayweb"
)

// version 由 release 构建经 -ldflags "-X main.version=..." 注入; 默认 "dev"
var version = "dev"

func main() {
	// 便携式: 默认配置文件放 exe 同目录(config.json), 不写用户文件夹; 显式 -config 优先
	defCfg := "config.json"
	if exe, err := os.Executable(); err == nil {
		defCfg = filepath.Join(filepath.Dir(exe), "config.json")
	}
	var (
		configPath  = flag.String("config", defCfg, "配置 JSON 路径 (默认 exe 同目录 config.json)")
		adminListen = flag.String("listen-admin", "127.0.0.1:18081", "本地管理 API 监听 (loopback)")
		source      = flag.String("source", "system", "证书来源: system|dir|file")
		sourceArg   = flag.String("source-arg", "", "dir=目录路径 / file=文件路径 (system 忽略)")
		filterOrg   = flag.String("filter-org", "", "只展示该 org 签发的证书 (空=不过滤; 如 CA 的 O=yyx 则传 yyx)")
		showAll     = flag.Bool("show-all", false, "显示全部证书 (跳过 org 过滤)")
		noWeb       = flag.Bool("no-web", false, "不启动管理 HTTP (纯中继, 无 WebUI/API)")
		allowRemote = flag.Bool("allow-remote", false, "允许管理 API 监听非 loopback (⚠️ 无鉴权, 仅可信网络)")
		server      = flag.String("server", "", "覆盖服务端发现端点 (临时, 不写入配置)")
		noWrite     = flag.Bool("no-write", false, "WebUI/API 改动只改内存, 不写回 -config 文件")
	)
	flag.Parse()

	cfgPath := expandHome(*configPath)

	// 证书来源: 预加载配置, 配置 cert_dir 优先于 -source 参数(配置即权威)
	preCfg, err := relay.LoadConfig(cfgPath)
	if err != nil {
		log.Fatalf("config %s: %v", cfgPath, err)
	}
	src, err := relay.ResolveCertSource(*source, *sourceArg, preCfg.CertDir)
	if err != nil {
		log.Fatalf("cert source: %v", err)
	}
	certsource.ApplyGwFilter(src, *filterOrg, *showAll)

	// 中继核心 + 管理
	r := relay.New(cfgPath, src)
	mgr, err := relay.NewManager(r, cfgPath)
	if err != nil {
		log.Fatalf("manager: %v", err)
	}
	// 首次启动: 配置文件不存在 → 自动生成默认配置模板(用户编辑后重启生效)
	if created, cerr := relay.EnsureDefaultConfig(cfgPath); cerr != nil {
		log.Printf("生成默认配置文件失败: %v (继续用内存默认配置)", cerr)
	} else if created {
		log.Printf("已生成默认配置文件 %s; 请填写 server_addr / admin_addr(或经 WebUI 配置)后重启", cfgPath)
	}
	// 错误消息语言(配置 lang; 默认 zh)
	if cfg := mgr.Config(); cfg.Lang != "" {
		r.SetLang(cfg.Lang)
	}

	// 临时会话开关 (--no-write / --server)
	if *noWrite {
		mgr.SetNoPersist(true)
	}
	if *server != "" {
		r.SetServerAddr(*server)   // 覆盖发现端点(relay 层)
		mgr.SetServerAddr(*server) // Manager 层: Config()/reloadTunnels 应用(Reload 不回退)
	}

	// 若已有启用的隧道配置, 启动即运行
	cfg := mgr.Config()
	cfgServerAddr := cfg.ServerAddr
	if *server != "" {
		cfgServerAddr = *server
		cfg.ServerAddr = *server // 注入 StartWith: Start 会用配置文件值覆盖, 必须显式传
	}
	r.SetServerAddr(cfgServerAddr) // 让 Discover(/api/services) 在未 Start 时也能用
	if err := r.SetServerCA(cfg.ServerCAFile); err != nil {
		log.Fatalf("server_ca: %v", err) // 配置的 CA 不可用 → 拒绝启动(防 MITM)
	}
	// 无条件启动核心(0 隧道也可): 否则空配置下 WebUI 添加隧道无法 Reload 启动
	if err := mgr.StartWith(cfg); err != nil {
		log.Printf("start: %v", err)
	} else {
		log.Printf("relay started: %d tunnel(s)", countEnabled(cfg.Tunnels))
	}

	// 管理 HTTP server (提供管理 API + WebUI 面板); --no-web 或空 listen 则不起 (纯中继)
	var srv *http.Server
	if !*noWeb && *adminListen != "" {
		// 安全: 管理 API 无鉴权 — 默认强制 loopback; 非 loopback 需显式 --allow-remote
		if !isLoopbackAddr(*adminListen) && !*allowRemote {
			log.Fatalf("管理 API 监听 %s 非 loopback 且未指定 --allow-remote — 拒绝启动 (管理面无鉴权)", *adminListen)
		}
		if !isLoopbackAddr(*adminListen) {
			log.Printf("⚠️ 管理 API 监听 %s 非 loopback — 无鉴权, 局域网可访问, 请仅在可信网络使用", *adminListen)
		}
		ln, err := net.Listen("tcp", *adminListen)
		if err != nil {
			log.Fatalf("admin listen %s: %v", *adminListen, err)
		}
		srv = &http.Server{
			Handler:           relayweb.NewHandler(mgr, *allowRemote),
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		go func() {
			log.Printf("mtls-relay admin api + webui on %s", *adminListen)
			if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
				log.Fatalf("admin serve: %v", err)
			}
		}()
	}

	// 优雅退出
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("shutting down...")
	mgr.Stop()
	if srv != nil {
		srv.Close()
	}
}

func expandHome(p string) string {
	if len(p) < 2 || p[0] != '~' {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	if p == "~" {
		return home
	}
	return home + p[1:]
}

func countEnabled(ts []relay.Tunnel) int {
	n := 0
	for _, t := range ts {
		if t.Enabled {
			n++
		}
	}
	return n
}

// isLoopbackAddr 判断监听地址是否为回环(127.0.0.1 / ::1 / localhost)
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
