// mtls-relay-cli — mtls-relay 管理 CLI (daemon 的客户端, 经本地管理 API).
//
// 用法:
//
//	mtls-relay-cli [--admin 127.0.0.1:18081] certs
//	mtls-relay-cli [--admin ...] tunnel add --id t1 --local 18080 --remote gw:9443 \
//	                     --cert <certID> [--server-name X] [--purpose P]
//	mtls-relay-cli [--admin ...] tunnel del <id>
//	mtls-relay-cli [--admin ...] tunnel list
//	mtls-relay-cli [--admin ...] reload
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

var adminAddr = "127.0.0.1:18081"

func main() {
	// 全局 --admin (须在子命令前)
	args := []string{}
	for i := 0; i < len(os.Args); i++ {
		if os.Args[i] == "--admin" && i+1 < len(os.Args) {
			adminAddr = os.Args[i+1]
			i++
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
  mtls-relay-cli [--admin ...] tunnel add --id t1 --local 18080 --remote gw:9443 --cert <ID> [--server-name X] [--purpose P]
  mtls-relay-cli [--admin ...] tunnel del <id>
  mtls-relay-cli [--admin ...] tunnel list
  mtls-relay-cli [--admin ...] reload | start | stop
  mtls-relay-cli [--admin ...] status | config`)
}

func client() *http.Client {
	return &http.Client{Timeout: 15 * time.Second}
}

func url(path string) string { return "http://" + adminAddr + path }

func get(path string) ([]byte, error) {
	resp, err := client().Get(url(path))
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

func post(path string, body any) error {
	var rdr io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		rdr = bytes.NewReader(data)
	}
	resp, err := client().Post(url(path), "application/json", rdr)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

func must(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		os.Exit(1)
	}
}

func deleteT(path string) error {
	req, _ := http.NewRequest("DELETE", url(path), nil)
	resp, err := client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
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

func tunnelAdd(args []string) {
	fs := flag.NewFlagSet("tunnel add", flag.ExitOnError)
	id := fs.String("id", "", "隧道 ID")
	local := fs.Int("local", 0, "本地监听端口")
	remote := fs.String("remote", "", "远端网关后端 host:port")
	cert := fs.String("cert", "", "证书 ID (certs 子命令所列)")
	serverName := fs.String("server-name", "", "TLS SNI (可选)")
	purpose := fs.String("purpose", "", "用途 (记录用, 可选)")
	fs.Parse(args)

	if *local == 0 || *remote == "" || *cert == "" {
		fmt.Fprintln(os.Stderr, "必须提供 --local --remote --cert")
		os.Exit(1)
	}
	if *id == "" {
		*id = fmt.Sprintf("t%d", *local)
	}
	body := map[string]any{
		"id": *id, "local_port": *local, "remote_addr": *remote,
		"cert_id": *cert, "server_name": *serverName,
		"purpose": *purpose, "enabled": true,
	}
	must(post("/api/tunnels", body))
	fmt.Println("已保存隧道:", *id, "(执行 reload 生效; start 首次启动)")
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
			ID         string `json:"id"`
			LocalPort  int    `json:"local_port"`
			RemoteAddr string `json:"remote_addr"`
			Purpose    string `json:"purpose"`
			CertID     string `json:"cert_id"`
			Enabled    bool   `json:"enabled"`
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
	fmt.Printf("%-8s %-8s %-24s %-12s %s\n", "ID", "LOCAL", "REMOTE", "PURPOSE", "CERT")
	for _, t := range cfg.Tunnels {
		fmt.Printf("%-8s %-8d %-24s %-12s %s\n", t.ID, t.LocalPort, t.RemoteAddr, t.Purpose, t.CertID)
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
	fmt.Printf("%-8s %-8s %-10s %-14s %-10s %s\n", "ID", "LOCAL", "ACTIVE", "BYTES_IN", "BYTES_OUT", "LAST_ERR")
	for _, s := range sts {
		fmt.Printf("%-8s %-8v %-10v %-14v %-10v %v\n",
			s["id"], s["local_port"], s["active_conns"], s["bytes_in"], s["bytes_out"], s["last_error"])
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
