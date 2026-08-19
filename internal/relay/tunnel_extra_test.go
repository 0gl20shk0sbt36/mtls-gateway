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
