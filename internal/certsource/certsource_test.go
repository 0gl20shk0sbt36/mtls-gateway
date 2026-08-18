package certsource

import (
	"crypto/tls"
	"os"
	"path/filepath"
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

// compile-time: fileSource implements Source
var _ Source = (*fileSource)(nil)
var _ Source = (*dirSource)(nil)
var _ = tls.Certificate{}
