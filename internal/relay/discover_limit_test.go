package relay

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"crypto/tls"
)

// 中危(测试全面性审计): /info 成功路径限流 — 服务端返回 >1MB JSON 必须报错
// (此前只限了错误路径, 成功路径无界解码是修复过的真实缺口, 需防回归)。
func TestDiscoverOversizedInfoRejected(t *testing.T) {
	// 服务端返回 >1MB 的合法 JSON /info
	svc := `{"name":"s","channels":[{"listen":":1","target":"http://x"}]}`
	body := `{"services":[` + strings.Repeat(svc+",", 40000) + `]}`
	if len(body) < 1<<20 {
		t.Fatalf("test body too small: %d", len(body))
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(body))
	}))
	defer srv.Close()

	r := New(nil) // DiscoverWithCert 不触碰 src, nil 安全
	r.SetServerAddr(strings.TrimPrefix(srv.URL, "https://"))
	caFile := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(caFile, []byte(pemCertOf(srv)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.SetServerCA(caFile); err != nil {
		t.Fatal(err)
	}

	cert := selfSignedClientCert(t)
	if _, err := r.DiscoverWithCert(cert); err == nil {
		t.Fatal(">1MB 的 /info 响应应因限流截断而解析失败, 不得静默成功")
	}
	// 小响应正常成功(限流不误伤)
	srv2 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"services":[{"name":"s","channels":[]}]}`))
	}))
	defer srv2.Close()
	r2 := New(nil)
	r2.SetServerAddr(strings.TrimPrefix(srv2.URL, "https://"))
	caFile2 := filepath.Join(t.TempDir(), "ca2.crt")
	if err := os.WriteFile(caFile2, []byte(pemCertOf(srv2)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r2.SetServerCA(caFile2); err != nil {
		t.Fatal(err)
	}
	if _, err := r2.DiscoverWithCert(cert); err != nil {
		t.Fatalf("小 /info 响应不应被误伤: %v", err)
	}
}

// pemCertOf 提取 httptest TLS server 的自签证书 PEM(用于构建根池)
func pemCertOf(srv *httptest.Server) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
}

// selfSignedClientCert 生成一次性自签客户端证书(测试用; 服务端不校验客户端身份)
func selfSignedClientCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "discover-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}
}
