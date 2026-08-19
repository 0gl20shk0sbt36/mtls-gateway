package relay

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"mtls-gateway/internal/certsource"
)

// mgrEnv 构造 Manager + HTTP handler 测试环境
func mgrEnv(t *testing.T, h *harness) (*Manager, http.Handler) {
	t.Helper()
	src := h.buildSrc(t)
	r := New("", src)
	r.SetServerAddr(h.gwAddr)
	_ = r.SetServerCA(h.caPath)
	cfgPath := filepath.Join(t.TempDir(), "relay.json")
	cfg := RelayConfig{ServerAddr: h.gwAddr, ServerCAFile: h.caPath, Tunnels: []Tunnel{}}
	if err := SaveConfig(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	m, err := NewManager(r, cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	m.SetNoPersist(true) // 测试不落盘
	return m, m.Handler()
}

func apiReq(h http.Handler, method, path, body, lang string) *httptest.ResponseRecorder {
	var rd *bytes.Reader
	if body == "" {
		rd = bytes.NewReader(nil)
	} else {
		rd = bytes.NewReader([]byte(body))
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Content-Type", "application/json")
	if lang != "" {
		req.Header.Set("X-Lang", lang)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// H-1: /api/status
func TestManagerHTTP_Status(t *testing.T) {
	h := newHarness(t)
	defer h.close()
	_, handler := mgrEnv(t, h)
	rec := apiReq(handler, "GET", "/api/status", "", "")
	if rec.Code != 200 {
		t.Fatalf("status: %d", rec.Code)
	}
	var st []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatalf("json: %v", err)
	}
	// 未启动时为空数组(合法); 关键是返回 200 合法 JSON
	if st == nil {
		t.Fatal("status should be a json array")
	}
}

// H-1: /api/certs 列出证书源
func TestManagerHTTP_Certs(t *testing.T) {
	h := newHarness(t)
	defer h.close()
	_, handler := mgrEnv(t, h)
	rec := apiReq(handler, "GET", "/api/certs", "", "")
	if rec.Code != 200 {
		t.Fatalf("certs: %d", rec.Code)
	}
	var metas []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &metas); err != nil {
		t.Fatalf("json: %v", err)
	}
	if len(metas) == 0 {
		t.Fatal("certs should not be empty")
	}
}

// H-1: 已收录错误按 X-Lang 本地化(zh/en 不同) — 用 admin 桥的 admin_addr 未配置错误
func TestManagerHTTP_VerifyLang(t *testing.T) {
	h := newHarness(t)
	defer h.close()
	_, handler := mgrEnv(t, h)
	body := `{"cert_id":"whatever"}`
	recZh := apiReq(handler, "POST", "/api/admin/verify", body, "zh")
	if recZh.Code < 400 {
		t.Fatalf("admin verify without admin_addr should fail, got %d", recZh.Code)
	}
	var e struct{ Error string `json:"error"` }
	json.Unmarshal(recZh.Body.Bytes(), &e)
	if e.Error == "" || !strings.Contains(e.Error, "管理") {
		t.Fatalf("zh error expected: %s", e.Error)
	}
	recEn := apiReq(handler, "POST", "/api/admin/verify", body, "en")
	json.Unmarshal(recEn.Body.Bytes(), &e)
	if e.Error == "" || !strings.Contains(e.Error, "admin_addr") {
		t.Fatalf("en error expected: %s", e.Error)
	}
}

// H-1: 错误 JSON body → 不崩溃, 返回错误
func TestManagerHTTP_BadJSON(t *testing.T) {
	h := newHarness(t)
	defer h.close()
	_, handler := mgrEnv(t, h)
	rec := apiReq(handler, "POST", "/api/verify", "{bad json", "")
	if rec.Code == 200 {
		t.Fatal("bad json should not be 200")
	}
	// 服务应仍存活(再请求一次)
	rec2 := apiReq(handler, "GET", "/api/status", "", "")
	if rec2.Code != 200 {
		t.Fatalf("service should survive bad json: %d", rec2.Code)
	}
}

// H-1: 新增隧道缺参数 → 错误; 完整 → 成功(noPersist, 强制断言)
func TestManagerHTTP_AddTunnel(t *testing.T) {
	h := newHarness(t)
	defer h.close()
	_, handler := mgrEnv(t, h)
	// 缺 service/cert_id
	rec := apiReq(handler, "POST", "/api/tunnels", `{"service":"","locals":{}}`, "")
	if rec.Code < 400 {
		t.Fatalf("missing fields should fail: %d", rec.Code)
	}
	// 完整参数 → 需真实 HTTP /info; 换 HTTP stub 环境
	dir := t.TempDir()
	svcs := []map[string]any{{"name": "svc-x", "channels": []any{map[string]any{"listen": ":9601", "target": "http://x"}}}}
	gwAddr, caPath, clientPair := startVerifyGW(t, dir, svcs)
	src, _ := certsource.OpenFile(clientPair)
	r2 := New("", src)
	r2.SetServerAddr(gwAddr)
	_ = r2.SetServerCA(caPath)
	cfgPath := filepath.Join(dir, "relay.json")
	SaveConfig(cfgPath, RelayConfig{ServerAddr: gwAddr, ServerCAFile: caPath, Tunnels: []Tunnel{}})
	m2, _ := NewManager(r2, cfgPath)
	m2.SetNoPersist(true)
	handler2 := m2.Handler()
	rec2 := apiReq(handler2, "POST", "/api/tunnels", fmt.Sprintf(`{"service":"svc-x","cert_id":%q,"locals":{}}`, clientPair), "")
	if rec2.Code != 200 {
		t.Fatalf("add tunnel should be 200, got %d: %s", rec2.Code, rec2.Body.String())
	}
	tuns := m2.Config().Tunnels
	if len(tuns) != 1 || tuns[0].Service != "svc-x" {
		t.Fatalf("tunnel should be in config: %+v", tuns)
	}
}

// H-1: /api/config 读写 + 未知路由 404
func TestManagerHTTP_ConfigAnd404(t *testing.T) {
	h := newHarness(t)
	defer h.close()
	_, handler := mgrEnv(t, h)
	rec := apiReq(handler, "GET", "/api/config", "", "")
	if rec.Code != 200 {
		t.Fatalf("config: %d", rec.Code)
	}
	var cfg RelayConfig
	if err := json.Unmarshal(rec.Body.Bytes(), &cfg); err != nil {
		t.Fatalf("json: %v", err)
	}
	rec404 := apiReq(handler, "GET", "/api/nonexistent", "", "")
	if rec404.Code != 404 {
		t.Fatalf("unknown route should be 404, got %d", rec404.Code)
	}
}

// H-1: admin 桥 — 无 admin 证书时 admin/verify 失败
func TestManagerHTTP_AdminBridge(t *testing.T) {
	h := newHarness(t)
	defer h.close()
	_, handler := mgrEnv(t, h)
	rec := apiReq(handler, "POST", "/api/admin/verify", `{"cert_id":"ghost"}`, "")
	if rec.Code < 400 {
		t.Fatalf("admin verify with ghost cert should fail: %d", rec.Code)
	}
}
