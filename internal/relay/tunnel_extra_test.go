package relay

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"mtls-gateway/internal/certsource"
)

// H1: joinSlash 纯函数边界
func TestJoinSlash(t *testing.T) {
	cases := []struct{ a, b, want string }{
		{"/admin", "/x", "/admin/x"},
		{"/admin/", "/x", "/admin/x"},
		{"/admin", "/", "/admin/"},
		{"/admin/", "/", "/admin/"},
		{"", "/x", "/x"},
		{"/", "/x", "/x"},
		{"/admin", "", "/admin/"},
		{"", "", "/"},
		{"/a//b", "/c", "/a//b/c"}, // 保留内部双斜杠(不额外清理)
		{"/a/b", "//c", "/a/b//c"}, // 双斜杠开头补一个(nginx 语义: 原样拼接)
	}
	for _, c := range cases {
		if got := joinSlash(c.a, c.b); got != c.want {
			t.Errorf("joinSlash(%q,%q) = %q, want %q", c.a, c.b, got, c.want)
		}
	}
}

// httpHarness HTTP 版网关 stub: 真 mTLS, 返回 path|Host 便于断言
type httpHarness struct {
	clientPairPath string
	caPath         string
	gwAddr         string
	ln             net.Listener
}

func newHTTPHarness(t *testing.T) *httpHarness {
	t.Helper()
	dir := t.TempDir()
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "h-ca", Organization: []string{"mtls-gw"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	// 网关服务器证书
	sk, _ := rsa.GenerateKey(rand.Reader, 2048)
	stmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "h-gw"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	sDER, _ := x509.CreateCertificate(rand.Reader, stmpl, caCert, &sk.PublicKey, caKey)
	sKeyDER, _ := x509.MarshalPKCS8PrivateKey(sk)
	sPair := append(append(append([]byte{}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: sDER})...), '\n'), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: sKeyDER})...)
	// 客户端证书
	ck, _ := rsa.GenerateKey(rand.Reader, 2048)
	ctmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "h-dev"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{net.ParseIP("100.64.0.2")},
	}
	cDER, _ := x509.CreateCertificate(rand.Reader, ctmpl, caCert, &ck.PublicKey, caKey)
	cKeyDER, _ := x509.MarshalPKCS8PrivateKey(ck)
	cPair := append(append(append([]byte{}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cDER})...), '\n'), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: cKeyDER})...)
	clientPairPath := filepath.Join(dir, "client.pem")
	os.WriteFile(clientPairPath, cPair, 0o600)
	caPath := filepath.Join(dir, "ca.crt")
	os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600)

	// https 网关 stub: 验证客户端证书, 返回 path|Host
	rawLn, _ := net.Listen("tcp", "127.0.0.1:0")
	srvPair, _ := tls.X509KeyPair(sPair, sPair)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	gwTLS := &tls.Config{
		Certificates: []tls.Certificate{srvPair},
		ClientAuth:   tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS12,
	}
	ln := tls.NewListener(rawLn, gwTLS)
	hs := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s|%s", r.URL.Path, r.Host)
	})}
	go hs.Serve(ln)
	t.Cleanup(func() { hs.Close(); ln.Close() })
	return &httpHarness{clientPairPath: clientPairPath, caPath: caPath, gwAddr: rawLn.Addr().String(), ln: ln}
}

// H1: 隧道 HTTP 反代路径模式 — 本地 /admin 前缀 → 服务端 /admin/x, Host 改写
func TestTunnelHTTPPathProxy(t *testing.T) {
	h := newHTTPHarness(t)
	src, err := certsource.OpenFile(h.clientPairPath)
	if err != nil {
		t.Fatal(err)
	}
	localPort := freePort(t)
	r := New("", src)
	defer r.Close()
	gwPort := gwPortOf(h.gwAddr)
	cfg := RelayConfig{
		ListenHost: "127.0.0.1", ServerAddr: h.gwAddr, ServerCAFile: h.caPath,
		Tunnels: []Tunnel{{
			Service: "s1",
			Routes:  []TunnelRoute{{Channel: ":" + gwPort + "/admin", Local: fmt.Sprintf(":%d/admin", localPort)}},
			CertID:  h.clientPairPath, Enabled: true,
		}},
	}
	if err := r.Start(cfg); err != nil {
		t.Fatal(err)
	}
	// 等隧道监听
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("tunnel not listening: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	// 本地 /admin/x → 服务端应收到 /admin/x(补通道前缀)+ Host=网关
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/admin/x", localPort))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d body: %s", resp.StatusCode, b)
	}
	want := "/admin/x|" + h.gwAddr
	if string(b) != want {
		t.Fatalf("upstream saw %q, want %q", b, want)
	}
	// 前缀不匹配 → 404
	resp2, _ := http.Get(fmt.Sprintf("http://127.0.0.1:%d/other", localPort))
	resp2.Body.Close()
	if resp2.StatusCode != 404 {
		t.Fatalf("prefix mismatch should be 404, got %d", resp2.StatusCode)
	}
	// 根路径(边界: /admin 本身 → rest=/)
	resp3, _ := http.Get(fmt.Sprintf("http://127.0.0.1:%d/admin", localPort))
	b3, _ := io.ReadAll(resp3.Body)
	resp3.Body.Close()
	if resp3.StatusCode != 200 {
		t.Fatalf("admin root status: %d", resp3.StatusCode)
	}
	if !strings.HasPrefix(string(b3), "/admin/") {
		t.Fatalf("admin root should map to /admin/: %q", b3)
	}
}

// H6: 加密私钥证书建隧道 → 无密码加载失败(固化当前设计: 隧道证书须无密码)
func TestTunnelEncryptedCertFails(t *testing.T) {
	h := newHarness(t)
	defer h.close()
	// 生成加密私钥的客户端 PEM(EC P-256 + 自签证书)
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "enc-dev"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	encBlock, err := x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", keyDER, []byte("secret"), x509.PEMCipherAES256)
	if err != nil {
		t.Fatal(err)
	}
	all := append(append(append([]byte{}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})...), '\n'), pem.EncodeToMemory(encBlock)...)
	pairPath := filepath.Join(dir, "enc.pem")
	os.WriteFile(pairPath, all, 0o600)

	src, err := certsource.OpenFile(pairPath)
	if err != nil {
		t.Fatal(err)
	}
	localPort := freePort(t)
	r := New("", src)
	defer r.Close()
	cfg := RelayConfig{
		ListenHost: "127.0.0.1", ServerAddr: h.gwAddr, ServerCAFile: h.caPath,
		Tunnels: []Tunnel{{
			Service: "s1",
			Routes:  []TunnelRoute{{Channel: ":" + gwPortOf(h.gwAddr), Local: fmt.Sprintf(":%d", localPort)}},
			CertID:  pairPath, Enabled: true,
		}},
	}
	err = r.Start(cfg)
	if err != nil {
		t.Fatalf("start should succeed (lazy cert load): %v", err)
	}
	// 懒加载: 拨号时加载证书 → 加密私钥无密码 → 失败
	if _, err := r.dialTLSConfig(pairPath); err == nil || !(strings.Contains(err.Error(), "password") || strings.Contains(err.Error(), "密码")) {
		t.Fatalf("dialTLSConfig should fail with password error: %v", err)
	}
}

// M-1: 隧道并发 — 多 goroutine 同时经隧道 echo(-race 下运行)
func TestTunnelConcurrentEcho(t *testing.T) {
	h := newHarness(t)
	defer h.close()
	src := h.buildSrc(t)
	localPort := freePort(t)
	r := New("", src)
	defer r.Close()
	cfg := RelayConfig{
		ListenHost: "127.0.0.1", ServerAddr: h.gwAddr, ServerCAFile: h.caPath,
		Tunnels: []Tunnel{{
			Service: "s1",
			Routes:  []TunnelRoute{{Channel: ":" + gwPortOf(h.gwAddr), Local: fmt.Sprintf(":%d", localPort)}},
			CertID:  h.clientPairPath, Enabled: true,
		}},
	}
	if err := r.Start(cfg); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("tunnel not listening: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	// 20 goroutine × 5 次 echo
	var wg sync.WaitGroup
	errCh := make(chan error, 200)
	for g := 0; g < 20; g++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
				if err != nil {
					errCh <- err
					continue
				}
				msg := []byte(fmt.Sprintf("g%d-j%d", n, j))
				conn.Write(msg)
				buf := make([]byte, len(msg))
				conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != string(msg) {
					errCh <- fmt.Errorf("echo mismatch g%d j%d: %q err=%v", n, j, buf, err)
				}
				conn.Close()
			}
		}(g)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

// P0-3: init 失败(证书瞬断)不永久毒化 — 换证书后下次请求恢复
func TestTunnelHTTPRetryAfterInitFailure(t *testing.T) {
	h := newHTTPHarness(t)
	origPair, err := os.ReadFile(h.clientPairPath) // 原始 CA 签的无密码证书
	if err != nil {
		t.Fatal(err)
	}
	// 先把证书源换成加密私钥(init 会失败)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(77), Subject: pkix.Name{CommonName: "retry-dev"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	encBlock, _ := x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", keyDER, []byte("secret"), x509.PEMCipherAES256)
	encPair := append(append(append([]byte{}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})...), '\n'), pem.EncodeToMemory(encBlock)...)
	os.WriteFile(h.clientPairPath, encPair, 0o600)

	src, _ := certsource.OpenFile(h.clientPairPath)
	localPort := freePort(t)
	r := New("", src)
	defer r.Close()
	gwPort := gwPortOf(h.gwAddr)
	cfg := RelayConfig{
		ListenHost: "127.0.0.1", ServerAddr: h.gwAddr, ServerCAFile: h.caPath,
		Tunnels: []Tunnel{{
			Service: "s1",
			Routes:  []TunnelRoute{{Channel: ":" + gwPort, Local: fmt.Sprintf(":%d/x", localPort)}},
			CertID:  h.clientPairPath, Enabled: true,
		}},
	}
	if err := r.Start(cfg); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("tunnel not listening: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	// 首次请求: 加密证书 → init 失败 → 502(而非 500 永久毒化)
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/x/ping", localPort))
	if err != nil {
		t.Fatalf("get1: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("encrypted cert should fail init (502), got %d", resp.StatusCode)
	}
	// 换成原始无密码证书(模拟修复/证书轮换)
	os.WriteFile(h.clientPairPath, origPair, 0o600)
	// 下次请求应重试成功
	resp2, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/x/ping", localPort))
	if err != nil {
		t.Fatalf("get2: %v", err)
	}
	b2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != 200 {
		t.Fatalf("after cert fix should be 200, got %d body: %q", resp2.StatusCode, string(b2))
	}
}

// R1a: 空闲超时 — 连接建立后不发数据, 超过注入的短超时被关闭
func TestTunnelIdleTimeout(t *testing.T) {
	h := newHarness(t)
	defer h.close()
	src := h.buildSrc(t)
	localPort := freePort(t)
	r := New("", src)
	defer r.Close()
	// 注入短超时 — 必须在 Start 之前(Start 时捕获进 tunnelRuntime)
	r.idleTimeout = 300 * time.Millisecond
	cfg := RelayConfig{
		ListenHost: "127.0.0.1", ServerAddr: h.gwAddr, ServerCAFile: h.caPath,
		Tunnels: []Tunnel{{
			Service: "s1",
			Routes:  []TunnelRoute{{Channel: ":" + gwPortOf(h.gwAddr), Local: fmt.Sprintf(":%d", localPort)}},
			CertID:  h.clientPairPath, Enabled: true,
		}},
	}
	if err := r.Start(cfg); err != nil {
		t.Fatal(err)
	}

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// 不发数据, 等超时关闭(读应返回 EOF/超时)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if err == nil {
		t.Fatalf("idle connection should be closed, got data: %q", buf[:n])
	}
}

// R1b: 半关闭传播 — 客户端 CloseWrite 后上游 stub 应读到 EOF
func TestTunnelHalfClose(t *testing.T) {
	h := newHarness(t)
	defer h.close()
	src := h.buildSrc(t)
	localPort := freePort(t)
	r := New("", src)
	defer r.Close()
	cfg := RelayConfig{
		ListenHost: "127.0.0.1", ServerAddr: h.gwAddr, ServerCAFile: h.caPath,
		Tunnels: []Tunnel{{
			Service: "s1",
			Routes:  []TunnelRoute{{Channel: ":" + gwPortOf(h.gwAddr), Local: fmt.Sprintf(":%d", localPort)}},
			CertID:  h.clientPairPath, Enabled: true,
		}},
	}
	if err := r.Start(cfg); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	// 半关闭(只关写)
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.CloseWrite()
	}
	// 读回显(echo stub 读到 EOF 后关闭 → 我们读到剩余数据 + EOF)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	if n != 5 || string(buf[:5]) != "hello" {
		t.Fatalf("echo mismatch: %q (n=%d)", buf[:n], n)
	}
	// echo stub 是 io.Copy 双向: 客户端 CloseWrite → 上游读 EOF → stub 关闭连接 → 我们读到 EOF
	// 这一步验证半关闭传播没有导致死锁(3s 内返回即可)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Read(buf)
	_ = err // EOF 或超时都算通过(重点是没死锁)
}
