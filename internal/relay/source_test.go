package relay

import (
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"mtls-gateway/internal/certsource"
)

// splitPairToDir 把合并的 cert+key PEM 文件拆成 <dir>/<name>/cert.pem + key.pem (目录源格式)
func splitPairToDir(t *testing.T, pairPath, dir, name string) {
	t.Helper()
	data, err := os.ReadFile(pairPath)
	if err != nil {
		t.Fatal(err)
	}
	var certPEM, keyPEM []byte
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "CERTIFICATE":
			certPEM = pem.EncodeToMemory(block)
		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
			keyPEM = pem.EncodeToMemory(block)
		}
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		t.Fatalf("pair %s 缺少证书或私钥 block", pairPath)
	}
	sub := filepath.Join(dir, name)
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "cert.pem"), certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "key.pem"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestSetSource 热换源: 新源 List 生效 + 证书缓存清空(同 ID 从新源重载)
func TestSetSource(t *testing.T) {
	h := newHarness(t)
	defer h.close()
	r := New("", h.buildSrc(t)) // 初始文件源

	// 换到目录源(目录含 clientPair 拆分出的证书)
	dir := t.TempDir()
	splitPairToDir(t, h.clientPairPath, dir, "device-a")
	src, err := certsource.OpenDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	r.SetSource(src)

	metas, err := r.ListCertMeta()
	if err != nil {
		t.Fatal(err)
	}
	if len(metas) != 1 || metas[0].CommonName != "device-a" {
		t.Fatalf("SetSource 后 List 应来自新源: %+v", metas)
	}
	// 缓存清空: 同 ID 从新源加载成功
	cert, err := r.loadCert("device-a")
	if err != nil {
		t.Fatalf("load from new source: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("no certificate chain")
	}
}

// TestUpdateSettingsCertDir 连接设置改 cert_dir: 热换源 + 落盘 + /api/settings 返回 + 无效目录整体失败
func TestUpdateSettingsCertDir(t *testing.T) {
	h := newHarness(t)
	defer h.close()
	src := h.buildSrc(t)
	r := New("", src)
	cfgPath := filepath.Join(t.TempDir(), "relay.json")
	cfg := RelayConfig{ServerAddr: h.gwAddr, Tunnels: []Tunnel{}}
	if err := SaveConfig(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	m, err := NewManager(r, cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	splitPairToDir(t, h.clientPairPath, dir, "device-a")

	// 换源
	if err := m.UpdateSettings(SettingsPatch{CertDir: &dir}); err != nil {
		t.Fatalf("UpdateSettings cert_dir: %v", err)
	}
	metas, err := m.ListCerts()
	if err != nil {
		t.Fatal(err)
	}
	if len(metas) != 1 || metas[0].CommonName != "device-a" {
		t.Fatalf("换源后证书列表应来自新目录: %+v", metas)
	}
	// 落盘验证
	loaded, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.CertDir != dir {
		t.Fatalf("落盘 cert_dir = %q, want %q", loaded.CertDir, dir)
	}
	// /api/settings 返回 cert_dir
	rec := apiReq(m.Handler(), "GET", "/api/settings", "", "")
	if rec.Code != 200 {
		t.Fatalf("settings: %d", rec.Code)
	}
	var s map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	if s["cert_dir"] != dir {
		t.Fatalf("settings cert_dir = %v, want %q", s["cert_dir"], dir)
	}

	// 无效目录 → 整体失败(不改 cfg 不落盘)
	bad := filepath.Join(t.TempDir(), "nope")
	if err := m.UpdateSettings(SettingsPatch{CertDir: &bad}); err == nil {
		t.Fatal("无效 cert_dir 应报错")
	}
	loaded2, _ := LoadConfig(cfgPath)
	if loaded2.CertDir != dir {
		t.Fatalf("失败后落盘 cert_dir 应保持原值: %q", loaded2.CertDir)
	}
}

// TestCertSourceFromConfig 空=系统证书库委托; 非空=目录源; 不存在目录报错
func TestCertSourceFromConfig(t *testing.T) {
	// 非空 → 目录源
	dir := t.TempDir()
	src, err := certSourceFromConfig(dir)
	if err != nil {
		t.Fatalf("certSourceFromConfig(dir): %v", err)
	}
	if _, err := src.List(); err != nil {
		t.Fatalf("dir source list: %v", err)
	}
	// 空 → 系统源 (Windows 必有系统证书库; Linux 无统一证书目录可能报错 — 不强制断言)
	if _, err := certSourceFromConfig(""); err != nil {
		t.Logf("certSourceFromConfig(\"\") = %v (Linux 无统一证书目录属预期)", err)
	}
	// 不存在的目录 → 报错
	if _, err := certSourceFromConfig(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("不存在目录应报错")
	}
}

// TestResolveCertSource 启动时配置 cert_dir 优先于 -source 参数
func TestResolveCertSource(t *testing.T) {
	dir := t.TempDir()
	// 配置优先: flag=system 但配置了 cert_dir → dir 源
	src, err := ResolveCertSource("system", "", dir)
	if err != nil {
		t.Fatalf("resolve(system + cert_dir): %v", err)
	}
	if _, err := src.List(); err != nil {
		t.Fatalf("list: %v", err)
	}
	// flag 生效: 无配置 → system (Linux 可能失败, 不强制断言)
	if _, err := ResolveCertSource("system", "", ""); err != nil {
		t.Logf("resolve(system) = %v (预期于无统一目录环境)", err)
	}
	// flag=dir + arg
	if _, err := ResolveCertSource("dir", dir, ""); err != nil {
		t.Fatalf("resolve(dir): %v", err)
	}
	// 配置优先覆盖 flag=file(即使 file 参数无效)
	if _, err := ResolveCertSource("file", "bogus.pem", dir); err != nil {
		t.Fatalf("cert_dir 应优先于 file flag: %v", err)
	}
}
