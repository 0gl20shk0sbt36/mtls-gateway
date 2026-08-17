package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"mtls-gateway/internal/db"
)

// testStore 创建测试用 Store
func testStore(t *testing.T) *db.Store {
	t.Helper()
	s, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// testGateway 创建测试用 Gateway (自签 CA + 服务器证书)
func testGateway(t *testing.T, store *db.Store) (*Gateway, *x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	// 生成测试 CA
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-ca"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create ca: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	// 生成服务器证书
	serverKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	serverTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("100.64.0.1")},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTmpl, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}

	// 写文件
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	serverCertPath := filepath.Join(dir, "server.crt")
	serverKeyPath := filepath.Join(dir, "server.key")
	writePEM(t, caPath, caDER)
	writePEM(t, serverCertPath, serverDER)
	writeKeyPEM(t, serverKeyPath, serverKey)

	gw, err := New(store, caPath, serverCertPath, serverKeyPath)
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	return gw, caCert, caKey
}

func writePEM(t *testing.T, path string, der []byte) {
	t.Helper()
	pemData := pemEncode("CERTIFICATE", der)
	if err := osWriteFile(path, pemData, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func writeKeyPEM(t *testing.T, path string, key *rsa.PrivateKey) {
	t.Helper()
	der := x509.MarshalPKCS1PrivateKey(key)
	pemData := pemEncode("RSA PRIVATE KEY", der)
	if err := osWriteFile(path, pemData, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// issueTestCert 签发测试用客户端证书 (SAN 绑 IP)
func issueTestCert(t *testing.T, ca *x509.Certificate, caKey *rsa.PrivateKey, name, ip string) *x509.Certificate {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if ip != "" {
		tmpl.IPAddresses = []net.IP{net.ParseIP(ip)}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("issue client cert: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert
}

// authRequest 构造带客户端证书的请求
func authRequest(cert *x509.Certificate, remoteAddr string) *http.Request {
	req := &http.Request{
		TLS: &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
		},
		RemoteAddr: remoteAddr,
	}
	return req
}

// TestAuthorizeOK 正常授权: 证书在册 + IP 匹配
func TestAuthorizeOK(t *testing.T) {
	store := testStore(t)
	gw, ca, caKey := testGateway(t, store)

	cert := issueTestCert(t, ca, caKey, "dev-1", "100.64.0.10")
	store.Upsert(db.CertRecord{
		Serial: cert.SerialNumber.String(), Name: "dev-1", Purpose: "dsh",
		TSIP: "100.64.0.10", Status: "enabled", ExpiresAt: time.Now().AddDate(0, 0, 30).Format("2006-01-02"),
	})

	req := authRequest(cert, "100.64.0.10:12345")
	purpose, err := gw.Authorize(req)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if purpose != "dsh" {
		t.Fatalf("expected purpose dsh, got %q", purpose)
	}
}

// TestAuthorizeIPMismatch IP 预检拒绝: 证书 SAN 与来源 IP 不符 (私钥复制场景)
func TestAuthorizeIPMismatch(t *testing.T) {
	store := testStore(t)
	gw, ca, caKey := testGateway(t, store)

	cert := issueTestCert(t, ca, caKey, "dev-1", "100.64.0.10") // 证书绑 100.64.0.10
	store.Upsert(db.CertRecord{
		Serial: cert.SerialNumber.String(), Name: "dev-1", Purpose: "dsh",
		TSIP: "100.64.0.10", Status: "enabled", ExpiresAt: time.Now().AddDate(0, 0, 30).Format("2006-01-02"),
	})

	// 请求来自不同 IP (私钥被复制到别的设备)
	req := authRequest(cert, "100.64.0.99:12345")
	if _, err := gw.Authorize(req); err == nil {
		t.Fatal("expected IP mismatch rejection")
	}
}

// TestAuthorizeNotRegistered 未登记证书拒绝 (CA 签发但不在数据库)
func TestAuthorizeNotRegistered(t *testing.T) {
	store := testStore(t)
	gw, ca, caKey := testGateway(t, store)

	cert := issueTestCert(t, ca, caKey, "ghost", "100.64.0.10") // 签发但未登记
	req := authRequest(cert, "100.64.0.10:12345")
	if _, err := gw.Authorize(req); err == nil {
		t.Fatal("expected rejection for unregistered cert")
	}
}

// TestAuthorizeRevoked 吊销证书拒绝
func TestAuthorizeRevoked(t *testing.T) {
	store := testStore(t)
	gw, ca, caKey := testGateway(t, store)

	cert := issueTestCert(t, ca, caKey, "dev-1", "100.64.0.10")
	store.Upsert(db.CertRecord{
		Serial: cert.SerialNumber.String(), Name: "dev-1", Purpose: "dsh",
		TSIP: "100.64.0.10", Status: "enabled", ExpiresAt: time.Now().AddDate(0, 0, 30).Format("2006-01-02"),
	})
	// 吊销
	store.Revoke(cert.SerialNumber.String())

	req := authRequest(cert, "100.64.0.10:12345")
	if _, err := gw.Authorize(req); err == nil {
		t.Fatal("expected rejection for revoked cert")
	}
}

// TestAuthorizeExpired 过期证书拒绝
func TestAuthorizeExpired(t *testing.T) {
	store := testStore(t)
	gw, ca, caKey := testGateway(t, store)

	cert := issueTestCert(t, ca, caKey, "dev-1", "100.64.0.10")
	// 数据库记录已过期
	store.Upsert(db.CertRecord{
		Serial: cert.SerialNumber.String(), Name: "dev-1", Purpose: "dsh",
		TSIP: "100.64.0.10", Status: "enabled", ExpiresAt: "2020-01-01",
	})

	req := authRequest(cert, "100.64.0.10:12345")
	if _, err := gw.Authorize(req); err == nil {
		t.Fatal("expected rejection for expired cert")
	}
}
