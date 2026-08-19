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
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
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

	gw, err := New(store, caPath, serverCertPath, serverKeyPath, true, "mtls-superadmin", "1.2")
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	return gw, caCert, caKey
}

// testGatewayNoBind 创建关闭 IP 绑定的 Gateway (测试 require_ip_bind=false)
func testGatewayNoBind(t *testing.T, store *db.Store) (*Gateway, *x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	gw, ca, key := testGateway(t, store)
	// 直接改 requireIPBind (测试内可见)
	gw.requireIPBind = false
	return gw, ca, key
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
		Serial: cert.SerialNumber.String(), Name: "dev-1", Purposes: []string{"dsh"},
		TSIP: "100.64.0.10", Status: "enabled", ExpiresAt: time.Now().AddDate(0, 0, 30).Format("2006-01-02"),
	})

	req := authRequest(cert, "100.64.0.10:12345")
	rec, err := gw.Authorize(req)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if !rec.HasPurpose("dsh") {
		t.Fatalf("expected purpose dsh, got %v", rec.Purposes)
	}
}

// TestAuthorizeIPMismatch IP 预检拒绝: 证书 SAN 与来源 IP 不符 (私钥复制场景)
func TestAuthorizeIPMismatch(t *testing.T) {
	store := testStore(t)
	gw, ca, caKey := testGateway(t, store)

	cert := issueTestCert(t, ca, caKey, "dev-1", "100.64.0.10") // 证书绑 100.64.0.10
	store.Upsert(db.CertRecord{
		Serial: cert.SerialNumber.String(), Name: "dev-1", Purposes: []string{"dsh"},
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
		Serial: cert.SerialNumber.String(), Name: "dev-1", Purposes: []string{"dsh"},
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
		Serial: cert.SerialNumber.String(), Name: "dev-1", Purposes: []string{"dsh"},
		TSIP: "100.64.0.10", Status: "enabled", ExpiresAt: "2020-01-01",
	})

	req := authRequest(cert, "100.64.0.10:12345")
	if _, err := gw.Authorize(req); err == nil {
		t.Fatal("expected rejection for expired cert")
	}
}

// TestAuthorizeNoIPBindRejected IP 绑定开启时, 无 IP 的证书被拒
func TestAuthorizeNoIPBindRejected(t *testing.T) {
	store := testStore(t)
	gw, ca, caKey := testGateway(t, store) // requireIPBind=true (默认)

	cert := issueTestCert(t, ca, caKey, "dev-nobind", "") // 不绑 IP
	store.Upsert(db.CertRecord{
		Serial: cert.SerialNumber.String(), Name: "dev-nobind", Purposes: []string{"dsh"},
		TSIP: "", Status: "enabled", ExpiresAt: time.Now().AddDate(0, 0, 30).Format("2006-01-02"),
	})

	req := authRequest(cert, "100.64.0.10:12345")
	if _, err := gw.Authorize(req); err == nil {
		t.Fatal("expected rejection for no-IP cert when require_ip_bind=true")
	}
}

// TestAuthorizeNoIPBindAllowed IP 绑定关闭时, 无 IP 的证书可通过
func TestAuthorizeNoIPBindAllowed(t *testing.T) {
	store := testStore(t)
	gw, ca, caKey := testGatewayNoBind(t, store) // requireIPBind=false

	cert := issueTestCert(t, ca, caKey, "dev-nobind", "") // 不绑 IP
	store.Upsert(db.CertRecord{
		Serial: cert.SerialNumber.String(), Name: "dev-nobind", Purposes: []string{"dsh"},
		TSIP: "", Status: "enabled", ExpiresAt: time.Now().AddDate(0, 0, 30).Format("2006-01-02"),
	})

	// 任意来源 IP 都应通过 (不检查 IP)
	req := authRequest(cert, "10.0.0.99:12345")
	rec, err := gw.Authorize(req)
	if err != nil {
		t.Fatalf("expected allow when require_ip_bind=false: %v", err)
	}
	if !rec.HasPurpose("dsh") {
		t.Fatalf("expected purpose dsh, got %v", rec.Purposes)
	}
}

// TestAuthorizeIPMismatchAllowed IP 绑定关闭时, IP 不匹配也通过
func TestAuthorizeIPMismatchAllowed(t *testing.T) {
	store := testStore(t)
	gw, ca, caKey := testGatewayNoBind(t, store) // requireIPBind=false

	cert := issueTestCert(t, ca, caKey, "dev-1", "100.64.0.10") // 绑了 IP
	store.Upsert(db.CertRecord{
		Serial: cert.SerialNumber.String(), Name: "dev-1", Purposes: []string{"dsh"},
		TSIP: "100.64.0.10", Status: "enabled", ExpiresAt: time.Now().AddDate(0, 0, 30).Format("2006-01-02"),
	})

	// 来源 IP 与证书 SAN 不同, 但关闭了绑定要求 → 应通过
	req := authRequest(cert, "100.64.0.99:12345")
	if _, err := gw.Authorize(req); err != nil {
		t.Fatalf("expected allow when require_ip_bind=false: %v", err)
	}
}

// testGatewayFiles 生成 CA + 服务器证书文件, 返回路径(供 New 直接调用)
func testGatewayFiles(t *testing.T) (caPath, certPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(101), Subject: pkix.Name{CommonName: "tls-test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create ca: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	sk, _ := rsa.GenerateKey(rand.Reader, 2048)
	stmpl := &x509.Certificate{
		SerialNumber: big.NewInt(102), Subject: pkix.Name{CommonName: "tls-test-server"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	sDER, err := x509.CreateCertificate(rand.Reader, stmpl, caCert, &sk.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	caPath = filepath.Join(dir, "ca.crt")
	certPath = filepath.Join(dir, "server.crt")
	keyPath = filepath.Join(dir, "server.key")
	writePEM(t, caPath, caDER)
	writePEM(t, certPath, sDER)
	writeKeyPEM(t, keyPath, sk)
	return
}

// L7: tls_min_version 校验(1.2/1.3/非法)
func TestTLSMinVersionValidation(t *testing.T) {
	store := testStore(t)
	caPath, certPath, keyPath := testGatewayFiles(t)
	for _, v := range []string{"1.2", "1.3"} {
		g, err := New(store, caPath, certPath, keyPath, false, DefaultAdminRole, v)
		if err != nil {
			t.Fatalf("tls_min_version=%s should be ok: %v", v, err)
		}
		if g.ServerTLSConfig().MinVersion == 0 {
			t.Fatalf("tls_min_version=%s not applied", v)
		}
	}
	if _, err := New(store, caPath, certPath, keyPath, false, DefaultAdminRole, "1.0"); err == nil {
		t.Fatal("tls_min_version=1.0 should be rejected")
	}
	if _, err := New(store, caPath, certPath, keyPath, false, DefaultAdminRole, "garbage"); err == nil {
		t.Fatal("garbage tls_min_version should be rejected")
	}
}

// L7: IsAdminPurpose / IsAdmin
func TestIsAdminPurpose(t *testing.T) {
	if !IsAdminPurpose(DefaultAdminRole) {
		t.Fatal("DefaultAdminRole should be admin")
	}
	if IsAdminPurpose("dsh") {
		t.Fatal("dsh should not be admin")
	}
	rec := &db.CertRecord{Name: "x", Purposes: []string{DefaultAdminRole}}
	g := &Gateway{AdminRole: DefaultAdminRole}
	if !g.IsAdmin(rec) {
		t.Fatal("admin purpose record should be admin")
	}
}

// P1-1: 证书过期边界 — 当天到期仍有效/昨天过期被拒/空 ExpiresAt 不判(注入 timeNow)
func TestCertExpiryBoundary(t *testing.T) {
	store := testStore(t)
	gw, ca, caKey := testGateway(t, store)
	oldNow := timeNow
	defer func() { timeNow = oldNow }()
	timeNow = func() string { return "2026-08-19" }

	issue := func(exp string) {
		t.Helper()
		cert := issueTestCert(t, ca, caKey, "edge-"+exp, "100.64.0.10")
		store.Upsert(db.CertRecord{
			Serial: cert.SerialNumber.String(), Name: "edge-" + exp, Purposes: []string{"dsh"},
			TSIP: "100.64.0.10", Status: "enabled", ExpiresAt: exp,
		})
		req := authRequest(cert, "100.64.0.10:12345")
		if _, err := gw.Authorize(req); err != nil {
			t.Fatalf("expires=%q should pass: %v", exp, err)
		}
	}
	expire := func(exp string) {
		t.Helper()
		cert := issueTestCert(t, ca, caKey, "edgex-"+exp, "100.64.0.10")
		store.Upsert(db.CertRecord{
			Serial: cert.SerialNumber.String(), Name: "edgex-" + exp, Purposes: []string{"dsh"},
			TSIP: "100.64.0.10", Status: "enabled", ExpiresAt: exp,
		})
		req := authRequest(cert, "100.64.0.10:12345")
		if _, err := gw.Authorize(req); err == nil {
			t.Fatalf("expires=%q should be rejected", exp)
		}
	}
	// 当天到期 → 有效(字符串 < 语义, 当天 23:59 仍有效)
	issue("2026-08-19")
	// 明天到期 → 有效
	issue("2026-08-20")
	// 空 ExpiresAt → 不判过期(DB 侧无约束)
	issue("")
	// 昨天到期 → 过期
	expire("2026-08-18")
}
