// mtls-gw-cli — mtls-gw 管理 CLI (瘦客户端, 调 Unix socket API)
// 用法:
//
//	mtls-gw-cli issue <name> --purpose dsh --ts-ip 100.x.y.z [--days 365]
//	mtls-gw-cli revoke <serial>
//	mtls-gw-cli list
//	mtls-gw-cli health
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"mtls-gateway/internal/i18n"
)

var sockPath = "/run/mtls-gw.sock"
var lang = i18n.Detect() // 系统语言检测 (LC_ALL > LC_MESSAGES > LANG > zh)

func main() {
	// 全局 --sock 参数 (必须在子命令前)
	newArgs := []string{}
	for i := 0; i < len(os.Args); i++ {
		if os.Args[i] == "--sock" && i+1 < len(os.Args) {
			sockPath = os.Args[i+1]
			i++ // 跳过值
			continue
		}
		newArgs = append(newArgs, os.Args[i])
	}
	os.Args = newArgs
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "issue":
		issue(args)
	case "revoke":
		revoke(args)
	case "list":
		list()
	case "health":
		health()
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "%s\n", i18n.T(lang, "unknown_command", cmd))
		usage()
		os.Exit(1)
	}
}

func usage() {
	if lang == i18n.En {
		fmt.Println(`mtls-gw-cli — management CLI (talks to the core daemon over a Unix socket)
usage:
  mtls-gw-cli issue <name> --purpose <admin|dsh|...> --ts-ip <100.x.y.z> [--days N] [--password P]
  mtls-gw-cli revoke <serial>
  mtls-gw-cli list
  mtls-gw-cli health
  mtls-gw-cli --sock <path> ...  specify socket path`)
		return
	}
	fmt.Println(`mtls-gw-cli — 管理 CLI (经 Unix socket 调核心进程)
用法:
  mtls-gw-cli issue <name> --purpose <admin|dsh|...> --ts-ip <100.x.y.z> [--days N] [--password P]
  mtls-gw-cli revoke <serial>
  mtls-gw-cli list
  mtls-gw-cli health
  mtls-gw-cli --sock <path> ...  指定 socket 路径`)
}

// do 经 Unix socket 发请求(method + 可选 JSON body); httpPost/httpGet 的共用实现
func do(method, path string, body any) (*http.Response, error) {
	var rdr io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, "http://unix"+path, rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", sockPath)
			},
			Dial: func(_, _ string) (net.Conn, error) {
				return net.Dial("unix", sockPath)
			},
		},
		Timeout: 30 * time.Second,
	}
	return client.Do(req)
}

// httpPost 经 Unix socket 发 JSON 请求
func httpPost(path string, body any) (*http.Response, error) {
	return do("POST", path, body)
}

func httpGet(path string) (*http.Response, error) {
	return do("GET", path, nil)
}

func issue(args []string) {
	// 支持 flag 在前或后: 手动分离位置参数, 但 flag 的值紧跟 flag 不能拆散
	// 已知 flag: --purpose <v> --ts-ip <v> --days <v> --password <v>
	needValue := map[string]bool{"--purpose": true, "--ts-ip": true, "--days": true, "--password": true}
	positional := []string{}
	flagArgs := []string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) > 0 && a[0] == '-' {
			flagArgs = append(flagArgs, a)
			if needValue[a] && i+1 < len(args) {
				flagArgs = append(flagArgs, args[i+1])
				i++
			}
		} else {
			positional = append(positional, a)
		}
	}
	flagArgs = append(flagArgs, positional...)
	fs := flag.NewFlagSet("issue", flag.ExitOnError)
	purpose := fs.String("purpose", "", "用途: admin|dsh|... 可逗号分隔多值 (如 dsh,vaultwarden)")
	tsIP := fs.String("ts-ip", "", "绑定 TS IP (写入证书 SAN)")
	days := fs.Int("days", 0, "有效期天数(0=服务端默认: admin→AdminDays, 其他→DefaultDays)")
	password := fs.String("password", "", "p12 密码 (默认自动生成)")
	fs.Parse(flagArgs)

	name := fs.Arg(0)
	if name == "" || *purpose == "" {
		fmt.Fprintln(os.Stderr, "用法: mtls-gw-cli issue <name> --purpose <p> [--ts-ip <ip>] [--days N]")
		os.Exit(1)
	}
	resp, err := httpPost("/admin/certs/issue", map[string]any{
		"name": name, "purposes": strings.Split(*purpose, ","), "ts_ip": *tsIP, "days": *days, "password": *password,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", i18n.T(lang, "issue_failed", err, sockPath))
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		var e map[string]any
		json.NewDecoder(resp.Body).Decode(&e)
		fmt.Fprintf(os.Stderr, "%s\n", i18n.T(lang, "issue_error", e))
		os.Exit(1)
	}
	var out struct {
		Serial      string   `json:"serial"`
		P12Password string   `json:"p12_password"`
		Expires     string   `json:"expires"`
		Warnings    []string `json:"warnings"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	fmt.Println(i18n.T(lang, "issue_success"))
	// 警告优先显示 (按语言翻译)
	for _, w := range i18n.TranslateWarnings(lang, out.Warnings) {
		fmt.Println("⚠", w)
	}
	fmt.Println(i18n.T(lang, "serial", out.Serial))
	fmt.Println(i18n.T(lang, "p12_password", out.P12Password))
	fmt.Println(i18n.T(lang, "expires", out.Expires))
	fmt.Println(i18n.T(lang, "cert_dir", "/var/lib/mtls-gw/certs/"+name+"/"))
}

func revoke(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "用法: mtls-gw-cli revoke <serial>")
		os.Exit(1)
	}
	serial := args[0]
	resp, err := httpPost("/admin/certs/revoke", map[string]string{"serial": serial})
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", i18n.T(lang, "revoke_failed", err))
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		fmt.Fprintf(os.Stderr, "%s\n", i18n.T(lang, "revoke_error", resp.StatusCode))
		os.Exit(1)
	}
	fmt.Println(i18n.T(lang, "revoked", serial))
}

func list() {
	resp, err := httpGet("/admin/certs")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", i18n.T(lang, "list_failed", err))
		os.Exit(1)
	}
	defer resp.Body.Close()
	var certs []map[string]any
	json.NewDecoder(resp.Body).Decode(&certs)
	if len(certs) == 0 {
		fmt.Println(i18n.T(lang, "no_certs"))
		return
	}
	fmt.Println(i18n.T(lang, "list_header", "SERIAL", "NAME", "PURPOSES", "TS_IP", "STATUS", "EXPIRES"))
	for _, c := range certs {
		// purposes 是 JSON 数组 → 转逗号分隔显示
		purposes := ""
		if ps, ok := c["purposes"].([]any); ok {
			parts := []string{}
			for _, p := range ps {
				parts = append(parts, fmt.Sprint(p))
			}
			purposes = strings.Join(parts, ",")
		}
		fmt.Printf("%-12s %-20s %-16s %-16s %-10s %v\n",
			c["serial"], c["name"], purposes, c["ts_ip"], c["status"], c["expires_at"])
	}
}

func health() {
	resp, err := httpGet("/admin/health")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", i18n.T(lang, "health_failed", err))
		os.Exit(1)
	}
	defer resp.Body.Close()
	fmt.Println(i18n.T(lang, "core_ok"))
}
