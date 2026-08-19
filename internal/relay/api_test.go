package relay

import (
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestLocalizeKnown 兜底翻译覆盖审计出的已知错误
func TestLocalizeKnown(t *testing.T) {
	cases := []struct {
		raw  string
		want string // 期望中文包含词
	}{
		{"decrypt key admin: x509: decryption password incorrect", "密码错误"},
		{"parse pem keypair admin: tls: failed to parse private key", "私钥需要密码"},
		{"private key needs password: admin", "私钥需要密码"},
		{"cert admin not found: open certs/admin/cert.pem: no such file", "未找到"},
		{"relay: /info HTTP 403: forbidden", "无权"},
		{"admin POST /admin/certs/issue: HTTP 400: name and purposes required", "必填"},
		{"config is immutable (read-only): 修改被服务端拒绝", "只读"},
		{"mapping missing listen", "缺少 listen"},
		{"no certificates in source", "没有可用客户端证书"},
		{"admin_addr not set in relay config", "管理地址"},
		{"relay: server address not configured", "服务端地址未配置"},
	}
	for _, c := range cases {
		got := localizeKnown("zh", errors.New(c.raw)).Error()
		if !strings.Contains(got, c.want) {
			t.Errorf("localizeKnown(%q) = %q, 期望包含 %q", c.raw, got, c.want)
		}
		// en 保持英文可读
		en := localizeKnown("en", errors.New(c.raw)).Error()
		if strings.Contains(en, "私钥需要密码") && !strings.Contains(en, "Private key") {
			t.Errorf("en 分支异常: %q", en)
		}
	}
	// 未收录错误原样返回
	raw := errors.New("some unknown error xyz")
	if got := localizeKnown("zh", raw); got.Error() != raw.Error() {
		t.Errorf("未收录错误应原样: %v", got)
	}
}

// R4: writeErr 按语义映射状态码(400/404/403/500) + JSON 体
func TestWriteErrStatusCodes(t *testing.T) {
	cases := []struct {
		msg  string
		want int
	}{
		{"bad request: x", 400},
		{"name and purposes required", 400},
		{"invalid ts_ip: 1.2.3", 400},
		{"证书名 dev 已存在，禁止同名签发", 409},
		{"cert ghost not found", 404},
		{"证书不存在", 404},
		{"forbidden", 403},
		{"角色 x 未在 roles 声明列表中声明", 400},
		{"internal boom", 500},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		writeErr(rec, req, errors.New(c.msg))
		if rec.Code != c.want {
			t.Errorf("writeErr(%q) = %d, want %d", c.msg, rec.Code, c.want)
		}
		if !strings.Contains(rec.Body.String(), `"error"`) {
			t.Errorf("writeErr(%q) body should be JSON: %s", c.msg, rec.Body.String())
		}
	}
}

// 第六批: writeErr 新增分支(保留字→400 / 已存在→409)
func TestWriteErrConflictAndReserved(t *testing.T) {
	cases := []struct {
		msg  string
		want int
	}{
		{"角色 any 是内置保留字, 只可用于服务声明, 不能签发给证书", 400},
		{"certificate name dev already exists (1 record(s)), 禁止同名签发", 409},
		{"证书名 dev 已存在, 禁止同名签发", 409}, // 注意: 不含"禁"单字分支前置于"禁止" — 走 already exists/已存在 → 409
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		writeErr(rec, req, errors.New(c.msg))
		if rec.Code != c.want {
			t.Errorf("writeErr(%q) = %d, want %d", c.msg, rec.Code, c.want)
		}
	}
}

// 第六批: Manager 并发 AddTunnel/DelTunnel(SaveConfig 深拷贝后无竞态)
func TestManagerConcurrentTunnelCRUD(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "relay.json")
	SaveConfig(cfgPath, RelayConfig{})
	m, err := NewManager(nil, cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	// 默认 noPersist=false: 并发 CRUD 走 SaveConfig 分支(CreateTemp 唯一 tmp 防踩踏)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("svc-%d", i)
			m.AddTunnel(Tunnel{Service: id, CertID: "c", Enabled: true, Routes: []TunnelRoute{{Channel: ":1", Local: ":2"}}})
			m.DelTunnel(id)
		}(i)
	}
	wg.Wait()
	if got := len(m.Config().Tunnels); got != 0 {
		t.Fatalf("all tunnels should be deleted, got %d", got)
	}
}

// 第六批: SaveConfig 原子写 round-trip + 权限
func TestSaveConfigAtomicRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "relay.json") // 子目录: 验证自动创建
	cfg := RelayConfig{ListenHost: "127.0.0.1", ServerAddr: "gw:9999",
		Tunnels: []Tunnel{{Service: "s1", CertID: "c", Enabled: true}}}
	if err := SaveConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	// round-trip
	loaded, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ServerAddr != "gw:9999" || len(loaded.Tunnels) != 1 || loaded.Tunnels[0].Service != "s1" {
		t.Fatalf("round-trip mismatch: %+v", loaded)
	}
	// 权限 0600
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("config perm = %v, want 0600", st.Mode().Perm())
	}
	// 无 tmp-* 残留(CreateTemp 前缀)
	entries, _ := os.ReadDir(filepath.Dir(path))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), filepath.Base(path)+".tmp-") {
			t.Fatalf("stale tmp file: %s", e.Name())
		}
	}
}

// 第八批: writeErr Content-Type 断言
func TestWriteErrContentType(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	writeErr(rec, req, errors.New("boom"))
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
}

// 第十一批: Manager.Config Routes 内层深拷贝 — mutate 返回的 Routes 不污染内部
func TestConfigRoutesDeepCopy(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "relay.json")
	SaveConfig(cfgPath, RelayConfig{})
	m, err := NewManager(nil, cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	m.AddTunnel(Tunnel{Service: "s1", CertID: "c", Enabled: true,
		Routes: []TunnelRoute{{Channel: ":1", Local: ":2"}}})
	c := m.Config()
	c.Tunnels[0].Routes[0].Local = ":9999"
	c2 := m.Config()
	if c2.Tunnels[0].Routes[0].Local != ":2" {
		t.Fatalf("Config Routes polluted: %v", c2.Tunnels[0].Routes)
	}
}

// 第二十三批: writeErr 英文路径状态码正确(本地化后 404/403 不落 500)
func TestWriteErrENStatusCodes(t *testing.T) {
	cases := []struct {
		raw  string
		want int
	}{
		{"cert ghost not found", 404},
		{"certificate name x already exists", 409},
		{"name and purposes required", 400},
		{"forbidden", 403},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Lang", "en") // 英文: 译文措辞不影响状态码
		writeErr(rec, req, errors.New(c.raw))
		if rec.Code != c.want {
			t.Errorf("writeErr en(%q) = %d, want %d (body: %s)", c.raw, rec.Code, c.want, rec.Body.String())
		}
	}
}

// 第二十四批: errCertName 提取精确性(回归: 多组正则合并曾致 len(m)==2 恒假)
func TestErrCertNamePrecision(t *testing.T) {
	cases := []struct{ in, want string }{
		{"decrypt key admin: x509: decryption password incorrect", "admin"},
		{"certificate name dev already exists (1 record(s)), 禁止同名签发", "dev"},
		{"name ghost already exists", "ghost"},
		{"cert ghost not found", "ghost"},
		{"private key needs password: admin", "admin"},
	}
	for _, c := range cases {
		if got := errCertName(c.in); got != c.want {
			t.Errorf("errCertName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
