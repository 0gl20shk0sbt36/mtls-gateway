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
	"syscall"
	"time"

	"mtls-gateway/internal/certsource"
	"mtls-gateway/internal/relay"
	"mtls-gateway/internal/relayweb"
)

func main() {
	var (
		configPath  = flag.String("config", "~/.mtls-relay/config.json", "配置 JSON 路径")
		adminListen = flag.String("listen-admin", "127.0.0.1:18081", "本地管理 API 监听 (loopback)")
		source      = flag.String("source", "system", "证书来源: system|dir|file")
		sourceArg   = flag.String("source-arg", "", "dir=目录路径 / file=文件路径 (system 忽略)")
		filterOrg   = flag.String("filter-org", "mtls-gw", "只展示该 org 签发的证书 (空=不过滤)")
		showAll     = flag.Bool("show-all", false, "显示全部证书 (跳过 org 过滤)")
		noWeb       = flag.Bool("no-web", false, "不启动管理 HTTP (纯中继, 无 WebUI/API)")
		server      = flag.String("server", "", "覆盖服务端发现端点 (临时, 不写入配置)")
		noWrite     = flag.Bool("no-write", false, "WebUI/API 改动只改内存, 不写回 -config 文件")
	)
	flag.Parse()

	cfgPath := expandHome(*configPath)

	// 证书来源
	src, err := certsource.New(certsource.SourceType(*source), *sourceArg)
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
	// 错误消息语言(配置 lang; 默认 zh)
	if cfg := mgr.Config(); cfg.Lang != "" {
		r.SetLang(cfg.Lang)
	}

	// 临时会话开关 (--no-write / --server)
	if *noWrite {
		mgr.SetNoPersist(true)
	}
	if *server != "" {
		r.SetServerAddr(*server)
		mgr.SetServerAddr(*server)
	}

	// 若已有启用的隧道配置, 启动即运行
	cfg := mgr.Config()
	cfgServerAddr := cfg.ServerAddr
	if *server != "" {
		cfgServerAddr = *server
	}
	r.SetServerAddr(cfgServerAddr)   // 让 Discover(/api/services) 在未 Start 时也能用
	r.SetServerCA(cfg.ServerCAFile)  // 证书验证根的加载
	if len(cfg.Tunnels) > 0 {
		if n := countEnabled(cfg.Tunnels); n > 0 {
			if err := mgr.Start(); err != nil {
				log.Printf("start on boot: %v", err)
			} else {
				log.Printf("relay started on boot: %d tunnel(s)", n)
			}
		}
	}

	// 管理 HTTP server (提供管理 API + WebUI 面板); --no-web 或空 listen 则不起 (纯中继)
	var srv *http.Server
	if !*noWeb && *adminListen != "" {
		ln, err := net.Listen("tcp", *adminListen)
		if err != nil {
			log.Fatalf("admin listen %s: %v", *adminListen, err)
		}
		srv = &http.Server{
			Handler:           relayweb.NewHandler(mgr),
			ReadHeaderTimeout: 10 * time.Second,
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
