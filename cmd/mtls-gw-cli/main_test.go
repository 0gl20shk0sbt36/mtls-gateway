package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// mtls-gw-cli 子进程黑盒测试: 编译二进制 + 起 unix socket 假 daemon + exec 跑各命令, 断言退出码与输出。

var binPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "mtls-gw-cli-test")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	binPath = filepath.Join(dir, "mtls-gw-cli")
	if runtime.GOOS == "windows" {
		binPath += ".exe" // go build -o 在 Windows 自动追加 .exe, exec 路径须带扩展名(windows-test 抓出)
	}
	cmd := exec.Command("go", "build", "-o", binPath, ".")
	cmd.Dir = "." // 在 cmd/mtls-gw-cli 包目录编译
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %v\n%s", err, out)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// startUnixSock 起一个 unix socket HTTP 假 daemon, 返回 socket 路径 + 关闭函数
func startUnixSock(t *testing.T, handler http.Handler) (string, func()) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "gw.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.Listener = ln
	srv.Start()
	return sock, func() { srv.Close() }
}

// runCLI 跑 mtls-gw-cli 子命令, 返回 (stdout, stderr, exitCode)
func runCLI(t *testing.T, sock string, args ...string) (string, string, int) {
	t.Helper()
	full := append([]string{"--sock", sock}, args...)
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

func TestCLIIssueSuccess(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/certs/issue" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body["name"] != "dev-a" {
			t.Errorf("name = %v", body["name"])
		}
		if ps, ok := body["purposes"].([]any); !ok || len(ps) != 2 || ps[0] != "dsh" {
			t.Errorf("purposes = %v", body["purposes"])
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"serial":"SERIAL123","p12_password":"PW123","expires":"2027-01-01"}`)
	})
	sock, closeFn := startUnixSock(t, handler)
	defer closeFn()

	stdout, stderr, code := runCLI(t, sock, "issue", "dev-a", "--purpose", "dsh,vaultwarden", "--days", "30")
	if code != 0 {
		t.Fatalf("issue exit=%d stderr=%s", code, stderr)
	}
	for _, want := range []string{"SERIAL123", "PW123", "2027-01-01"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout 应含 %q: %s", want, stdout)
		}
	}
}

func TestCLIIssueServerError(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		fmt.Fprint(w, `{"error":"bad request"}`)
	})
	sock, closeFn := startUnixSock(t, handler)
	defer closeFn()

	_, stderr, code := runCLI(t, sock, "issue", "dev-a", "--purpose", "dsh")
	if code != 1 {
		t.Fatalf("issue 应退出码 1, got %d", code)
	}
	if stderr == "" {
		t.Error("stderr 应有错误提示")
	}
}

func TestCLIRevoke(t *testing.T) {
	var gotSerial string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/certs/revoke" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		gotSerial = body["serial"]
		fmt.Fprint(w, `{}`)
	})
	sock, closeFn := startUnixSock(t, handler)
	defer closeFn()

	stdout, _, code := runCLI(t, sock, "revoke", "SERIAL-ABC")
	if code != 0 {
		t.Fatalf("revoke exit=%d", code)
	}
	if gotSerial != "SERIAL-ABC" {
		t.Errorf("serial = %q", gotSerial)
	}
	if !strings.Contains(stdout, "SERIAL-ABC") {
		t.Errorf("stdout 应含 serial: %s", stdout)
	}
}

func TestCLIListEmpty(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[]`)
	})
	sock, closeFn := startUnixSock(t, handler)
	defer closeFn()

	stdout, _, code := runCLI(t, sock, "list")
	if code != 0 {
		t.Fatalf("list exit=%d", code)
	}
	if !strings.Contains(stdout, "无证书") && !strings.Contains(stdout, "no certs") {
		t.Errorf("空列表应提示无证书: %s", stdout)
	}
}

func TestCLIListRows(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[{"serial":"S1","name":"dev-a","purposes":["dsh","vault"],"ts_ip":"100.64.0.1","status":"enabled","expires_at":"2027-01-01"}]`)
	})
	sock, closeFn := startUnixSock(t, handler)
	defer closeFn()

	stdout, _, code := runCLI(t, sock, "list")
	if code != 0 {
		t.Fatalf("list exit=%d", code)
	}
	if !strings.Contains(stdout, "dev-a") || !strings.Contains(stdout, "dsh,vault") {
		t.Errorf("list 应显示名称与逗号分隔用途: %s", stdout)
	}
}

func TestCLIHealth(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/health" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		fmt.Fprint(w, `{"ok":true}`)
	})
	sock, closeFn := startUnixSock(t, handler)
	defer closeFn()

	_, _, code := runCLI(t, sock, "health")
	if code != 0 {
		t.Fatalf("health exit=%d", code)
	}
}

func TestCLIUnknownCommand(t *testing.T) {
	sock, closeFn := startUnixSock(t, http.NotFoundHandler())
	defer closeFn()

	_, stderr, code := runCLI(t, sock, "bogus")
	if code != 1 {
		t.Fatalf("未知命令应退出码 1, got %d", code)
	}
	if stderr == "" {
		t.Error("stderr 应有未知命令提示")
	}
}

// 审计补: --sock=<path> 等号形式
func TestCLISockEqualsForm(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[]`)
	})
	sock, closeFn := startUnixSock(t, handler)
	defer closeFn()
	cmd := exec.Command(binPath, "--sock="+sock, "list")
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("--sock= 等号形式应可用: %v (%s)", err, stderr.String())
	}
}

// A-4(pro 前瞻审计): TCP admin 模式 — mTLS 直连 admin API(Windows 无 unix socket)
// 生成 CA + 服务器证书 + admin 客户端证书, 起 mTLS 假 daemon, CLI 经 --admin 签发成功。
func TestCLITCPAdminMode(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	// ---- 自建 CA + 证书 ----
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now()
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "cli-test-ca"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)

	mkLeaf := func(cn string, isServer bool) tls.Certificate {
		k, _ := rsa.GenerateKey(rand.Reader, 2048)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		if isServer {
			tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		} else {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, caTmpl, &k.PublicKey, caKey)
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
	}
	serverCert := mkLeaf("localhost", true)
	clientCert := mkLeaf("cli-admin", false)

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	os.WriteFile(caPath, caPEM, 0o600)
	certPath := filepath.Join(dir, "admin.pem")
	keyPath := filepath.Join(dir, "admin.key")
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCert.Certificate[0]}), 0o600)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(clientCert.PrivateKey)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)

	// ---- mTLS 假 admin daemon ----
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/certs/issue" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"serial":"TCP-SERIAL","p12_password":"PW","expires":"2027-01-01"}`)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	srv.StartTLS()
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "https://")

	stdout, stderr, code := runCLI(t, "",
		"--admin", addr, "--cert", certPath, "--key", keyPath, "--ca", caPath,
		"issue", "dev-tcp", "--purpose", "dsh")
	if code != 0 {
		t.Fatalf("TCP 模式 issue exit=%d stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, "TCP-SERIAL") {
		t.Errorf("stdout 应含 TCP-SERIAL: %s", stdout)
	}
}

// A-4: TCP 模式参数缺失(有 --admin 无证书) → 启动即报错
func TestCLITCPAdminMissingCerts(t *testing.T) {
	_, stderr, code := runCLI(t, "", "--admin", "127.0.0.1:9444", "issue", "x", "--purpose", "dsh")
	if code != 1 {
		t.Fatalf("缺证书应退出码 1, got %d", code)
	}
	if !strings.Contains(stderr, "TCP admin 模式需要") {
		t.Errorf("stderr 应提示缺证书: %s", stderr)
	}
}
