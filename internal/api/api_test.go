package api

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"mtls-gateway/internal/db"
)

// testCA 生成测试 CA 并写文件
func testCA(t *testing.T, dir string) (caPath, caKeyPath string) {
	t.Helper()
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
	caPath = filepath.Join(dir, "ca.crt")
	caKeyPath = filepath.Join(dir, "ca.key")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(caKey)
	if err := os.WriteFile(caKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return
}

// testManager 创建测试用 Manager
func testManager(t *testing.T, tmpl CertTemplate) *Manager {
	t.Helper()
	dir := t.TempDir()
	caPath, caKeyPath := testCA(t, dir)
	store, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	m, err := NewManager(store, caPath, caKeyPath, filepath.Join(dir, "certs"), filepath.Join(dir, "gw.sock"), tmpl)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	return m
}

// TestIssueCert 正常签发: 证书生成 + 数据库登记
func TestIssueCert(t *testing.T) {
	m := testManager(t, CertTemplate{})
	resp, err := m.IssueCert(IssueRequest{
		Name: "dev-1", Purpose: "dsh", TSIP: "100.64.0.10", Days: 90,
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if resp.Serial == "" || resp.P12Password == "" {
		t.Fatalf("missing serial/password: %+v", resp)
	}
	// 数据库已登记
	certs := m.store.List()
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert in db, got %d", len(certs))
	}
	if certs[0].Name != "dev-1" || certs[0].Purpose != "dsh" {
		t.Fatalf("unexpected record: %+v", certs[0])
	}
	if certs[0].TSIP != "100.64.0.10" {
		t.Fatalf("tsip not saved: %q", certs[0].TSIP)
	}
}

// TestIssueCertTemplate 模板配置生效: O/OU 字段 + 默认天数
func TestIssueCertTemplate(t *testing.T) {
	m := testManager(t, CertTemplate{Org: "my-org", OU: "servers", DefaultDays: 100, AdminDays: 7})

	// 普通用途: 用 DefaultDays (100)
	resp, err := m.IssueCert(IssueRequest{Name: "dev-1", Purpose: "app", TSIP: "100.64.0.10"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	cert := parseCertPEM(t, resp.CertPEM)
	if got := cert.Subject.Organization; len(got) != 1 || got[0] != "my-org" {
		t.Fatalf("org not applied: %v", got)
	}
	if got := cert.Subject.OrganizationalUnit; len(got) != 1 || got[0] != "servers" {
		t.Fatalf("ou not applied: %v", got)
	}
	// 有效期 = 100 天
	days := int(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24)
	if days != 100 {
		t.Fatalf("expected 100 days, got %d", days)
	}

	// admin 用途: 用 AdminDays (7)
	resp2, err := m.IssueCert(IssueRequest{Name: "adm", Purpose: "admin", TSIP: "100.64.0.1"})
	if err != nil {
		t.Fatalf("issue admin: %v", err)
	}
	cert2 := parseCertPEM(t, resp2.CertPEM)
	days2 := int(cert2.NotAfter.Sub(cert2.NotBefore).Hours() / 24)
	if days2 != 7 {
		t.Fatalf("expected 7 days for admin, got %d", days2)
	}
}

// TestIssueCertInvalidName 非法设备名拒绝
func TestIssueCertInvalidName(t *testing.T) {
	m := testManager(t, CertTemplate{})
	_, err := m.IssueCert(IssueRequest{Name: "bad name!", Purpose: "app", TSIP: "100.64.0.10"})
	if err == nil {
		t.Fatal("expected error for invalid name")
	}
}

// TestIssueCertMissingFields 缺 name/purpose 拒绝
func TestIssueCertMissingFields(t *testing.T) {
	m := testManager(t, CertTemplate{})
	if _, err := m.IssueCert(IssueRequest{Name: "", Purpose: "app"}); err == nil {
		t.Fatal("expected error for empty name")
	}
	if _, err := m.IssueCert(IssueRequest{Name: "dev", Purpose: ""}); err == nil {
		t.Fatal("expected error for empty purpose")
	}
}

// TestCertTemplateDefaults 模板默认值
func TestCertTemplateDefaults(t *testing.T) {
	tmpl := CertTemplate{}
	tmpl.ApplyDefaults()
	if tmpl.Org != "mtls-gw" || tmpl.OU != "device" {
		t.Fatalf("bad defaults: %+v", tmpl)
	}
	if tmpl.DefaultDays != 365 || tmpl.AdminDays != 30 {
		t.Fatalf("bad day defaults: %+v", tmpl)
	}
}

// parseCertPEM 解析签发的证书 PEM
func parseCertPEM(t *testing.T, pemStr string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatal("bad pem")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}
