package certsource

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFileSource_ListAndLoad 单个文件源: List 返回一条, Load 可加载
func TestFileSource_ListAndLoad(t *testing.T) {
	tc := genTestCert(t, "test-ca", "mtls-gw", "device-a")
	dir := t.TempDir()
	pemFile := filepath.Join(dir, "pair.pem")
	combined := append(append(append([]byte{}, tc.CertPEM...), '\n'), tc.KeyPEM...)
	if err := os.WriteFile(pemFile, combined, 0o600); err != nil {
		t.Fatal(err)
	}

	src, err := OpenFile(pemFile)
	if err != nil {
		t.Fatal(err)
	}
	metas, err := src.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(metas) != 1 {
		t.Fatalf("want 1 meta, got %d", len(metas))
	}
	if metas[0].CommonName != "device-a" {
		t.Fatalf("common name mismatch: %q", metas[0].CommonName)
	}

	cert, err := src.Load(metas[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if cert.PrivateKey == nil {
		t.Fatalf("private key is nil")
	}
}

// TestDirSource_ListAndLoad 目录源: 子目录 cert.pem+key.pem, Load 按相对路径
func TestDirSource_ListAndLoad(t *testing.T) {
	root := t.TempDir()
	ta := genTestCert(t, "test-ca", "mtls-gw", "device-a")
	tb := genTestCert(t, "other-ca", "other", "device-b")
	ta.writeDirCert(t, root, "device-a")
	tb.writeDirCert(t, root, "device-b")

	src, err := OpenDir(root)
	if err != nil {
		t.Fatal(err)
	}
	metas, err := src.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(metas) != 2 {
		t.Fatalf("want 2 metas, got %d", len(metas))
	}

	cert, err := src.Load("device-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatalf("no certificate chain")
	}

	// Load 不存在的 ID
	if _, err := src.Load("nope"); err == nil {
		t.Fatalf("expected error loading nonexistent id")
	}
	// 路径穿越拒绝
	if _, err := src.Load("../etc/passwd"); err == nil {
		t.Fatalf("expected path traversal rejection")
	}
}

// TestDirSource_Filter 过滤: 只展示 mtls-gw 签发的证书
func TestDirSource_Filter(t *testing.T) {
	root := t.TempDir()
	ta := genTestCert(t, "mtls-gw-ca", "mtls-gw", "device-a") // 网关签发
	tb := genTestCert(t, "other-ca", "other", "device-b")     // 非网关签发
	ta.writeDirCert(t, root, "device-a")
	tb.writeDirCert(t, root, "device-b")

	d, err := OpenDir(root)
	if err != nil {
		t.Fatal(err)
	}
	ds := d.(*dirSource)
	ds.SetFilter("mtls-gw", false) // 只展示目标 org

	metas, err := d.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(metas) != 1 {
		t.Fatalf("filter: want 1 meta, got %d", len(metas))
	}
	if metas[0].CommonName != "device-a" {
		t.Fatalf("expected device-a, got %s", metas[0].CommonName)
	}

	// showAll 则两个都显示
	ds.SetFilter("mtls-gw", true)
	metas, _ = d.List()
	if len(metas) != 2 {
		t.Fatalf("showAll: want 2 metas, got %d", len(metas))
	}
}

// TestNew_OpenSystem 系统来源工厂 (Linux=统一目录; 不存在时返回错误)
func TestNew_OpenSystem(t *testing.T) {
	// linux 上系统源需要 ~/.mtls-gw/certs 或 /etc/mtls-gw/certs 存在, 测试环境一般没有
	// 这里只验证 New 对非法类型报错
	if _, err := New("bogus", ""); err == nil {
		t.Fatalf("expected error for unknown type")
	}
	// verify enum values exist
	if File != "file" || Dir != "dir" || System != "system" {
		t.Fatalf("const mismatch")
	}
}

// TestAcceptCert 公共过滤规则(winSource/dirSource 共用): issuer 匹配 / org 匹配 / showAll / 空过滤
func TestAcceptCert(t *testing.T) {
	ca := genTestCert(t, "gw-ca", "mtls-gw", "dev")
	cert, err := parseCertFromPEM(ca.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	issuer := cert.Issuer.String()
	if !strings.Contains(issuer, "gw-ca") {
		t.Fatalf("issuer should contain gw-ca: %s", issuer)
	}
	// issuer 精确/包含匹配
	if !acceptCert(issuer, "", false, cert) {
		t.Fatal("issuer 精确匹配应展示")
	}
	if !acceptCert("gw-ca", "", false, cert) {
		t.Fatal("issuer 包含匹配应展示")
	}
	if acceptCert("other-ca", "", false, cert) {
		t.Fatal("issuer 不匹配应拒绝")
	}
	// org 过滤(issuer 优先, 传空)
	if !acceptCert("", "mtls-gw", false, cert) {
		t.Fatal("org 匹配应展示")
	}
	if acceptCert("", "other-org", false, cert) {
		t.Fatal("org 不匹配应拒绝")
	}
	// showAll / 空过滤
	if !acceptCert("", "other-org", true, cert) {
		t.Fatal("showAll 应展示")
	}
	if !acceptCert("", "", false, cert) {
		t.Fatal("空过滤应展示")
	}
}

// compile-time: fileSource implements Source
var _ Source = (*fileSource)(nil)
var _ Source = (*dirSource)(nil)
var _ = tls.Certificate{}

// —— 平台无关签名纯函数(从 Windows CNG 抽出, Linux 可测) ——

// TestCertThumbprint 证书 SHA-1 指纹格式(大写冒号分隔, Windows 标准)
func TestCertThumbprint(t *testing.T) {
	tc := genTestCert(t, "test-ca", "mtls-gw", "dev")
	cert, err := parseCertFromPEM(tc.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	tp := certThumbprint(cert)
	sum := sha1.Sum(cert.Raw)
	want := strings.ToUpper(fmt.Sprintf("%x", sum[:]))
	want = strings.Join(chunks(want, 2), ":")
	if tp != want {
		t.Fatalf("thumbprint = %q, want %q", tp, want)
	}
	if len(tp) != 59 { // 20 字节 hex + 19 冒号
		t.Fatalf("thumbprint 长度 = %d, want 59", len(tp))
	}
}

func chunks(s string, n int) []string {
	var out []string
	for i := 0; i < len(s); i += n {
		if i+n > len(s) {
			out = append(out, s[i:])
		} else {
			out = append(out, s[i:i+n])
		}
	}
	return out
}

// TestECDSARawToDER P1363 raw R||S → DER: P-256(32) 与 P-384(48, digest≠R 场景)
func TestECDSARawToDER(t *testing.T) {
	// P-256: 32+32
	raw256 := bytes.Repeat([]byte{0xab}, 64)
	der256, err := ecdsaRawToDER(raw256, 256)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(der256, []byte{0x30}) {
		t.Fatalf("DER 应以 SEQUENCE 开头: %x", der256[:2])
	}
	// P-384: 48+48(即使 digest=SHA256 32, 也按曲线 48 解析)
	raw384 := bytes.Repeat([]byte{0xcd}, 96)
	der384, err := ecdsaRawToDER(raw384, 384)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(der384, []byte{0x30}) {
		t.Fatalf("DER 应以 SEQUENCE 开头: %x", der384[:2])
	}
	// 长度错误 → 报错
	if _, err := ecdsaRawToDER(raw256, 384); err == nil {
		t.Fatal("长度不匹配应报错")
	}
}

// TestPSSSaltLength PSS salt 计算: EqualsHash → hash 大小; Auto 拒绝
func TestPSSSaltLength(t *testing.T) {
	// EqualsHash: salt = SHA256 大小 = 32
	n, err := pssSaltLength(&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	if err != nil || n != 32 {
		t.Fatalf("EqualsHash(SHA256) = %d, %v; want 32", n, err)
	}
	// 显式值
	n, err = pssSaltLength(&rsa.PSSOptions{SaltLength: 16})
	if err != nil || n != 16 {
		t.Fatalf("显式 salt = %d, %v; want 16", n, err)
	}
	// Auto 拒绝
	if _, err := pssSaltLength(&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}); err == nil {
		t.Fatal("Auto 应拒绝")
	}
}
