package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// mtls-relay-cli 子进程黑盒测试: 编译二进制 + 起 HTTP 假 daemon + exec 跑各命令, 断言退出码与输出。

var binPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "mtls-relay-cli-test")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	binPath = filepath.Join(dir, "mtls-relay-cli")
	if runtime.GOOS == "windows" {
		binPath += ".exe" // go build -o 在 Windows 自动追加 .exe, exec 路径须带扩展名(windows-test 抓出)
	}
	cmd := exec.Command("go", "build", "-o", binPath, ".")
	cmd.Dir = "."
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %v\n%s", err, out)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func runCLI(t *testing.T, adminAddr string, args ...string) (string, string, int) {
	t.Helper()
	full := append([]string{"--admin", adminAddr}, args...)
	cmd := exec.Command(binPath, full...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("run %v: %v", args, err)
		}
	}
	return stdout.String(), stderr.String(), code
}

func TestCLICerts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/certs" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		fmt.Fprint(w, `[{"id":"dev-a","common_name":"dev-a","valid_until":"2027-01-01","found_in":"dir"}]`)
	}))
	defer srv.Close()

	stdout, _, code := runCLI(t, strings.TrimPrefix(srv.URL, "http://"), "certs")
	if code != 0 {
		t.Fatalf("certs exit=%d", code)
	}
	if !strings.Contains(stdout, "dev-a") {
		t.Errorf("certs 应显示 dev-a: %s", stdout)
	}
}

func TestCLITunnelAdd(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/tunnels" || r.Method != "POST" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		json.NewDecoder(r.Body).Decode(&gotBody)
		fmt.Fprint(w, `{"service":"svc-a","count":1}`)
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	stdout, _, code := runCLI(t, addr, "tunnel", "add", "--service", "svc-a", "--cert", "dev-a", "--route", ":46991=:47991,:46991/admin=:47991/admin")
	if code != 0 {
		t.Fatalf("tunnel add exit=%d", code)
	}
	if gotBody["service"] != "svc-a" || gotBody["cert_id"] != "dev-a" {
		t.Errorf("body = %v", gotBody)
	}
	locals, _ := gotBody["locals"].(map[string]any)
	if len(locals) != 2 {
		t.Errorf("locals 应有 2 条路由: %v", gotBody["locals"])
	}
	if !strings.Contains(stdout, "svc-a") {
		t.Errorf("stdout 应含服务名: %s", stdout)
	}
}

func TestCLITunnelDel(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	_, _, code := runCLI(t, addr, "tunnel", "del", "t1")
	if code != 0 {
		t.Fatalf("tunnel del exit=%d", code)
	}
	if gotMethod != "DELETE" || gotPath != "/api/tunnels/t1" {
		t.Errorf("del 应 DELETE /api/tunnels/t1, got %s %s", gotMethod, gotPath)
	}
}

func TestCLIReloadStartStop(t *testing.T) {
	var gotPaths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPaths = append(gotPaths, r.URL.Path)
		fmt.Fprint(w, `{}`)
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	for _, sub := range []string{"reload", "start", "stop"} {
		_, _, code := runCLI(t, addr, sub)
		if code != 0 {
			t.Fatalf("%s exit=%d", sub, code)
		}
	}
	want := []string{"/api/reload", "/api/start", "/api/stop"}
	for i, p := range want {
		if gotPaths[i] != p {
			t.Errorf("第 %d 个请求 = %s, want %s", i, gotPaths[i], p)
		}
	}
}

func TestCLIStatusConfig(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/status":
			fmt.Fprint(w, `[{"service":"svc-a","local":":47991","running":true}]`)
		case "/api/config":
			fmt.Fprint(w, `{"server_addr":"gw:9499","tunnels":[]}`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	if _, _, code := runCLI(t, addr, "status"); code != 0 {
		t.Fatalf("status exit=%d", code)
	}
	stdout, _, code := runCLI(t, addr, "config")
	if code != 0 {
		t.Fatalf("config exit=%d", code)
	}
	if !strings.Contains(stdout, "gw:9499") {
		t.Errorf("config 应含 server_addr: %s", stdout)
	}
}

func TestCLITunnelAddMissingArgs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("缺参数不应发请求")
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	_, stderr, code := runCLI(t, addr, "tunnel", "add")
	if code != 1 {
		t.Fatalf("缺参数应退出码 1, got %d", code)
	}
	if stderr == "" {
		t.Error("stderr 应有提示")
	}
}

func TestCLIUnknownCommand(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	_, _, code := runCLI(t, addr, "bogus")
	if code != 1 {
		t.Fatalf("未知命令应退出码 1, got %d", code)
	}
}

// 审计补: --admin=<addr> 等号形式
func TestCLIAdminEqualsForm(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `[]`)
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	cmd := exec.Command(binPath, "--admin="+addr, "certs")
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("--admin= 等号形式应可用: %v (%s)", err, stderr.String())
	}
}
