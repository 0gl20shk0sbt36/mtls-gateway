// mtls-relay-cli — mtls-relay 管理 CLI (daemon 的客户端, 经本地管理 API).
//
// 用法:
//
//	mtls-relay-cli [--admin 127.0.0.1:18081] certs
//	mtls-relay-cli [--admin ...] tunnel add --service <svc> --cert <certID> [--route "ch=local,..."]
//	mtls-relay-cli [--admin ...] tunnel del <id>
//	mtls-relay-cli [--admin ...] tunnel list
//	mtls-relay-cli [--admin ...] reload | start | stop | status | config
//	mtls-relay-cli [--admin ...] start | stop
//	mtls-relay-cli [--admin ...] status
//	mtls-relay-cli [--admin ...] config
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// version 由 release 构建经 -ldflags "-X main.version=..." 注入; 默认 "dev"
var version = "dev"

var adminAddr = "127.0.0.1:18081"

func main() {
	// 全局 --admin (须在子命令前; 支持 --admin=<addr> 形式 — flash 低危项)
	args := []string{}
	for i := 0; i < len(os.Args); i++ {
		switch {
		case os.Args[i] == "--admin" && i+1 < len(os.Args):
			adminAddr = os.Args[i+1]
			i++
			continue
		case strings.HasPrefix(os.Args[i], "--admin="):
			adminAddr = strings.TrimPrefix(os.Args[i], "--admin=")
			continue
		}
		args = append(args, os.Args[i])
	}
	os.Args = args
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	cmd := os.Args[1]
	rest := os.Args[2:]
	switch cmd {
	case "certs":
		certs()
	case "tunnel":
		tunnel(rest)
	case "reload":
		must(post("/api/reload", nil))
	case "start":
		must(post("/api/start", nil))
	case "stop":
		must(post("/api/stop", nil))
	case "status":
		status()
	case "config":
		config()
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "未知命令: %s\n", cmd)
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Println(`mtls-relay-cli — mtls-relay 管理 CLI (daemon 的客户端)
用法:
  mtls-relay-cli [--admin 127.0.0.1:18081] certs
  mtls-relay-cli [--admin ...] tunnel add --service <svc> --cert <certID> [--route "ch=local,..."]
  mtls-relay-cli [--admin ...] tunnel del <id>
  mtls-relay-cli [--admin ...] tunnel list
  mtls-relay-cli [--admin ...] reload | start | stop
  mtls-relay-cli [--admin ...] status | config`)
}

func client() *http.Client {
	return &http.Client{Timeout: 15 * time.Second}
}

func url(path string) string { return "http://" + adminAddr + path }

// do 发请求(method + 可选 JSON body)并读响应体; 非 200 返回带 body 的错误。get/post/deleteT 的共用实现
func do(method, path string, body any) ([]byte, error) {
	var rdr io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, url(path), rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return b, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return b, nil
}

func get(path string) ([]byte, error) {
	return do("GET", path, nil)
}

func post(path string, body any) error {
	_, err := do("POST", path, body)
	return err
}

func must(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		os.Exit(1)
	}
}

func deleteT(path string) error {
	_, err := do("DELETE", path, nil)
	return err
}

func certs() {
	b, err := get("/api/certs")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	var metas []map[string]any
	if err := json.Unmarshal(b, &metas); err != nil {
		fmt.Fprintln(os.Stderr, "解析响应失败:", err)
		os.Exit(1)
	}
	if len(metas) == 0 {
		fmt.Println("(无可用证书)")
		return
	}
	fmt.Printf("%-56s %-24s %-20s %s\n", "ID", "CN", "有效至", "来源")
	for _, m := range metas {
		fmt.Printf("%-56s %-24s %-20s %v\n", m["id"], m["common_name"], m["valid_until"], m["found_in"])
	}
}

func tunnel(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "用法: tunnel add|del|list")
		os.Exit(1)
	}
	sub := args[0]
	switch sub {
	case "add":
		tunnelAdd(args[1:])
	case "del":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "用法: tunnel del <id>")
			os.Exit(1)
		}
		must(deleteT("/api/tunnels/" + args[1]))
		fmt.Println("已删除隧道:", args[1])
	case "list":
		tunnelList()
	default:
		fmt.Fprintln(os.Stderr, "未知子命令:", sub)
		os.Exit(1)
	}
}

// tunnelAdd v4 模型: 按服务建隧道(服务端通道 → 本地路由)
func tunnelAdd(args []string) {
	fs := flag.NewFlagSet("tunnel add", flag.ExitOnError)
	service := fs.String("service", "", "服务名 (服务端 /info 所列)")
	cert := fs.String("cert", "", "证书 ID (certs 子命令所列)")
	route := fs.String("route", "", "本地路由覆盖: 通道=本地 (如 ':29991=:39991'; 可逗号分隔多个)")
	fs.Parse(args)

	if *service == "" || *cert == "" {
		fmt.Fprintln(os.Stderr, "必须提供 --service --cert")
		os.Exit(1)
	}
	locals := map[string]string{}
	if *route != "" {
		for _, pair := range strings.Split(*route, ",") {
			kv := strings.SplitN(pair, "=", 2)
			if len(kv) == 2 {
				locals[kv[0]] = kv[1]
			}
		}
	}
	body := map[string]any{"service": *service, "cert_id": *cert, "locals": locals}
	must(post("/api/tunnels", body))
	fmt.Println("已保存服务隧道:", *service, "(已自动重载生效)")
}

func tunnelList() {
	cfgB, err := get("/api/config")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	var cfg struct {
		ListenHost string `json:"listen_host"`
		Tunnels    []struct {
			Service string `json:"service"`
			CertID  string `json:"cert_id"`
			Enabled bool   `json:"enabled"`
			Routes  []struct {
				Channel string `json:"channel"`
				Local   string `json:"local"`
			} `json:"routes"`
		} `json:"tunnels"`
	}
	if err := json.Unmarshal(cfgB, &cfg); err != nil {
		fmt.Fprintln(os.Stderr, "解析失败:", err)
		os.Exit(1)
	}
	if len(cfg.Tunnels) == 0 {
		fmt.Println("(无隧道)")
		return
	}
	fmt.Printf("%-14s %-10s %-14s %-14s %s\n", "SERVICE", "ENABLED", "CHANNEL", "LOCAL", "CERT")
	for _, t := range cfg.Tunnels {
		if len(t.Routes) == 0 {
			fmt.Printf("%-14s %-10v %-14s %-14s %s\n", t.Service, t.Enabled, "-", "-", t.CertID)
			continue
		}
		for _, r := range t.Routes {
			fmt.Printf("%-14s %-10v %-14s %-14s %s\n", t.Service, t.Enabled, r.Channel, r.Local, t.CertID)
		}
	}
}

func status() {
	b, err := get("/api/status")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	var sts []map[string]any
	if err := json.Unmarshal(b, &sts); err != nil {
		fmt.Fprintln(os.Stderr, "解析失败:", err)
		os.Exit(1)
	}
	if len(sts) == 0 {
		fmt.Println("(中继未运行 / 无活动隧道)")
		return
	}
	fmt.Printf("%-14s %-14s %-8s %-10s %-12s %-12s %s\n", "SERVICE", "LOCAL", "ACTIVE", "RUNNING", "BYTES_IN", "BYTES_OUT", "LAST_ERR")
	for _, s := range sts {
		fmt.Printf("%-14s %-14v %-8v %-10v %-12v %-12v %v\n",
			s["service"], s["local"], s["active_conns"], s["running"], s["bytes_in"], s["bytes_out"], s["last_error"])
	}
}

func config() {
	b, err := get("/api/config")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, b, "", "  "); err != nil {
		fmt.Println(string(b))
		return
	}
	fmt.Println(pretty.String())
}
