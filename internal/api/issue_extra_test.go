package api

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mtls-gateway/internal/certsource"
	"mtls-gateway/internal/db"
	"software.sslmate.com/src/go-pkcs12"
)

// testManagerWith 带密钥参数的管理器(供 key_type/key_bits 测试)
func testManagerWith(t *testing.T, tmpl CertTemplate, keyType string, keyBits int) *Manager {
	t.Helper()
	dir := t.TempDir()
	caPath, caKeyPath := testCA(t, dir)
	store, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	m, err := NewManager(store, caPath, caKeyPath, filepath.Join(dir, "certs"), filepath.Join(dir, "gw.sock"), tmpl, "mtls-superadmin", keyType, keyBits, 16, []string{"dsh", "vaultwarden", "svc-a", "app"})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	return m
}

// H4: 禁止同名签发(含已吊销的)
func TestIssueCert_DuplicateName(t *testing.T) {
	m := testManager(t, CertTemplate{})
	req := IssueRequest{Name: "dev-dup", Purposes: []string{"dsh"}, Days: 90}
	if _, err := m.IssueCert(req); err != nil {
		t.Fatalf("first issue: %v", err)
	}
	if _, err := m.IssueCert(req); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("duplicate should be rejected: %v", err)
	}
	// 吊销后再签同名 → 仍拒绝(FindByName 含 revoked)
	recs := m.store.FindByName("dev-dup")
	if len(recs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(recs))
	}
	if err := m.store.Revoke(recs[0].Serial); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := m.IssueCert(req); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("duplicate after revoke should still be rejected: %v", err)
	}
}

// H5: p12 无密码(no_password=true → 密码空 + 空密码可解码)
func TestIssueCert_NoPassword(t *testing.T) {
	m := testManager(t, CertTemplate{})
	resp, err := m.IssueCert(IssueRequest{Name: "dev-nopwd", Purposes: []string{"dsh"}, NoPassword: true, Days: 90})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if resp.P12Password != "" {
		t.Fatalf("no_password should yield empty password, got %q", resp.P12Password)
	}
	p12Path := filepath.Join(m.certDir, "dev-nopwd", "device.p12")
	data, err := os.ReadFile(p12Path)
	if err != nil {
		t.Fatalf("read p12: %v", err)
	}
	priv, cert, err := pkcs12.Decode(data, "")
	if err != nil {
		t.Fatalf("decode p12 with empty pw: %v", err)
	}
	if priv == nil || cert == nil {
		t.Fatal("p12 decode gave nil key/cert")
	}
}

// H5: p12 自定义密码 → 回显 + 正确密码解码成功/错误密码失败
func TestIssueCert_CustomPassword(t *testing.T) {
	m := testManager(t, CertTemplate{})
	resp, err := m.IssueCert(IssueRequest{Name: "dev-custom", Purposes: []string{"dsh"}, Password: "MySecret123!", Days: 90})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if resp.P12Password != "MySecret123!" {
		t.Fatalf("custom password should be echoed, got %q", resp.P12Password)
	}
	p12Path := filepath.Join(m.certDir, "dev-custom", "device.p12")
	data, _ := os.ReadFile(p12Path)
	if _, _, err := pkcs12.Decode(data, "MySecret123!"); err != nil {
		t.Fatalf("decode with correct pw: %v", err)
	}
	if _, _, err := pkcs12.Decode(data, "wrong"); err == nil {
		t.Fatal("decode with wrong pw should fail")
	}
}

// H5: 自动生成密码 → 非空 + 解码成功
func TestIssueCert_AutoPassword(t *testing.T) {
	m := testManager(t, CertTemplate{})
	resp, err := m.IssueCert(IssueRequest{Name: "dev-auto", Purposes: []string{"dsh"}, Days: 90})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if len(resp.P12Password) != 16 {
		t.Fatalf("auto password should be 16 chars, got %q", resp.P12Password)
	}
	data, _ := os.ReadFile(filepath.Join(m.certDir, "dev-auto", "device.p12"))
	if _, _, err := pkcs12.Decode(data, resp.P12Password); err != nil {
		t.Fatalf("decode with auto pw: %v", err)
	}
}

// H2: ECDSA P-256 签发 → 证书公钥算法正确 + keyPEM 是 EC 私钥 + certsource 可加载
func TestIssueCert_ECDSA_P256(t *testing.T) {
	m := testManagerWith(t, CertTemplate{}, "ecdsa", 256)
	resp, err := m.IssueCert(IssueRequest{Name: "dev-ec", Purposes: []string{"dsh"}, Days: 90})
	if err != nil {
		t.Fatalf("issue ecdsa: %v", err)
	}
	cert := parseCertPEM(t, resp.CertPEM)
	if cert.PublicKeyAlgorithm != x509.ECDSA {
		t.Fatalf("expected ECDSA public key, got %v", cert.PublicKeyAlgorithm)
	}
	block, _ := pem.Decode([]byte(resp.KeyPEM))
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse ec key: %v", err)
	}
	if _, ok := priv.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", priv)
	}
	// ECDSA 证书经 certsource 加载成功(dir 源: 按 id 扫描子目录)
	src, err := certsource.New(certsource.Dir, m.certDir)
	if err != nil {
		t.Fatalf("new dir source: %v", err)
	}
	if _, err := src.Load("dev-ec"); err != nil {
		t.Fatalf("certsource load ec cert: %v", err)
	}
}

// H2: key_bits 非法组合
func TestNewClientKey_BadBits(t *testing.T) {
	m := testManager(t, CertTemplate{})
	m.KeyBits = 1024
	if _, _, err := m.newClientKey(); err == nil || !strings.Contains(err.Error(), "bad key_bits") {
		t.Fatalf("rsa 1024 should be rejected: %v", err)
	}
	m2 := testManagerWith(t, CertTemplate{}, "ecdsa", 999)
	if _, _, err := m2.newClientKey(); err == nil || !strings.Contains(err.Error(), "bad key_bits") {
		t.Fatalf("ecdsa 999 should be rejected: %v", err)
	}
}

// H2: key_type 非法
func TestNewClientKey_BadType(t *testing.T) {
	m := testManager(t, CertTemplate{})
	m.KeyType = "dsa"
	if _, _, err := m.newClientKey(); err == nil || !strings.Contains(err.Error(), "bad key_type") {
		t.Fatalf("dsa should be rejected: %v", err)
	}
}

// H2: RSA 3072/4096 可签发
func TestIssueCert_RSA_4096(t *testing.T) {
	m := testManagerWith(t, CertTemplate{}, "rsa", 4096)
	resp, err := m.IssueCert(IssueRequest{Name: "dev-rsa4096", Purposes: []string{"dsh"}, Days: 90})
	if err != nil {
		t.Fatalf("issue rsa4096: %v", err)
	}
	cert := parseCertPEM(t, resp.CertPEM)
	if cert.PublicKeyAlgorithm != x509.RSA {
		t.Fatalf("expected RSA, got %v", cert.PublicKeyAlgorithm)
	}
	if k, ok := cert.PublicKey.(*rsa.PublicKey); !ok || k.N.BitLen() != 4096 {
		t.Fatalf("expected 4096-bit RSA key, got %T %v", cert.PublicKey, k)
	}
}

// M1: TS IP 实际写入证书 SAN
func TestIssueCert_SANIP(t *testing.T) {
	m := testManager(t, CertTemplate{})
	resp, err := m.IssueCert(IssueRequest{Name: "dev-san", Purposes: []string{"dsh"}, TSIP: "100.64.0.10", Days: 90})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	cert := parseCertPEM(t, resp.CertPEM)
	if len(cert.IPAddresses) != 1 || !cert.IPAddresses[0].Equal(net.ParseIP("100.64.0.10")) {
		t.Fatalf("SAN IP not written: %v", cert.IPAddresses)
	}
}

// M1: 非法 IP 显式报错(不再静默丢弃)
func TestIssueCert_InvalidIP(t *testing.T) {
	m := testManager(t, CertTemplate{})
	_, err := m.IssueCert(IssueRequest{Name: "dev-badip", Purposes: []string{"dsh"}, TSIP: "1.2.3", Days: 90})
	if err == nil || !strings.Contains(err.Error(), "invalid ts_ip") {
		t.Fatalf("invalid ts_ip should be rejected: %v", err)
	}
}
