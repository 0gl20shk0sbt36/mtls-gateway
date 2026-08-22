package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mtls-gateway/internal/db"
)

// 高危(测试全面性审计): 审计回调 SetAudit — 签发/吊销成功触发, 失败不触发。
// 双通道(unix socket/TCP)统一留痕是本功能的核心承诺, 必须锁定。
func TestSetAuditCallbacks(t *testing.T) {
	m := testManager(t, CertTemplate{})
	var events []string
	m.SetAudit(func(kind, msg string) { events = append(events, kind+":"+msg) })

	// 签发成功 → 一次 cert_issue, 消息含 name/purposes/serial
	resp, err := m.IssueCert(IssueRequest{Name: "dev-a", Purposes: []string{"dsh"}})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if len(events) != 1 || !strings.HasPrefix(events[0], "cert_issue:") {
		t.Fatalf("签发成功应触发一次 cert_issue: %v", events)
	}
	if !strings.Contains(events[0], "dev-a") || !strings.Contains(events[0], "dsh") || !strings.Contains(events[0], resp.Serial) {
		t.Fatalf("cert_issue 消息应含 name/purposes/serial: %q", events[0])
	}

	// 签发失败(同名含吊销) → 不触发
	events = nil
	if _, err := m.IssueCert(IssueRequest{Name: "dev-a", Purposes: []string{"dsh"}}); err == nil {
		t.Fatal("同名签发应失败")
	}
	if len(events) != 0 {
		t.Fatalf("签发失败不应触发审计: %v", events)
	}

	// 吊销成功(走 HTTP handler, isLocal=true 即 unix socket 通道) → cert_revoke
	events = nil
	body, _ := json.Marshal(map[string]string{"serial": resp.Serial})
	req := httptest.NewRequest(http.MethodPost, "/admin/certs/revoke", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	m.handler(true).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke status: %d %s", rec.Code, rec.Body.String())
	}
	if len(events) != 1 || !strings.HasPrefix(events[0], "cert_revoke:") || !strings.Contains(events[0], resp.Serial) {
		t.Fatalf("吊销成功应触发 cert_revoke: %v", events)
	}

	// 吊销失败(serial 不存在) → 不触发
	events = nil
	body, _ = json.Marshal(map[string]string{"serial": "nonexistent-serial"})
	req = httptest.NewRequest(http.MethodPost, "/admin/certs/revoke", bytes.NewReader(body))
	rec = httptest.NewRecorder()
	m.handler(true).ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("吊销不存在 serial 应 404: %d", rec.Code)
	}
	if len(events) != 0 {
		t.Fatalf("吊销失败不应触发审计: %v", events)
	}
}

// 高危: IssueCert 安全拒绝实测 — "any" 保留字与未声明角色必须被实际调用拒绝
// (此前只有"错误串→状态码"的映射测试, 没有真实调用覆盖)。
func TestIssueCertRejectsReservedAndUndeclared(t *testing.T) {
	m := testManager(t, CertTemplate{})
	// "any" 内置保留字禁签发
	if _, err := m.IssueCert(IssueRequest{Name: "x1", Purposes: []string{"any"}}); err == nil || !strings.Contains(err.Error(), "保留字") {
		t.Fatalf("any 应被拒(保留字): %v", err)
	}
	// 未声明角色禁签发
	if _, err := m.IssueCert(IssueRequest{Name: "x2", Purposes: []string{"undeclared-role"}}); err == nil || !strings.Contains(err.Error(), "声明列表") {
		t.Fatalf("未声明角色应被拒: %v", err)
	}
	// admin_role 免声明可签
	if _, err := m.IssueCert(IssueRequest{Name: "adm", Purposes: []string{"mtls-superadmin"}}); err != nil {
		t.Fatalf("admin_role 免声明应可签: %v", err)
	}
	// 已声明角色正常签
	if _, err := m.IssueCert(IssueRequest{Name: "dev", Purposes: []string{"dsh"}}); err != nil {
		t.Fatalf("已声明角色应可签: %v", err)
	}
}

// 高危: MaxBytesReader 4MB 请求体上限 — 超限请求必须 400, 不得被解析/处理。
func TestIssueBodyLimit(t *testing.T) {
	m := testManager(t, CertTemplate{})
	big := strings.Repeat("x", 5<<20) // 5MB > 4MB 上限
	body := `{"name":"huge","purposes":["dsh"],"password":"` + big + `"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/certs/issue", strings.NewReader(body))
	rec := httptest.NewRecorder()
	m.handler(true).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("超限 body 应 400, got %d", rec.Code)
	}
	// 正常大小不受影响
	req2 := httptest.NewRequest(http.MethodPost, "/admin/certs/issue",
		strings.NewReader(`{"name":"ok","purposes":["dsh"]}`))
	rec2 := httptest.NewRecorder()
	m.handler(true).ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("正常 body 应 200, got %d: %s", rec2.Code, rec2.Body.String())
	}
}

// 中危: NewManager 坏输入 — 坏 CA / 坏 CA 私钥必须报错, 不静默启动。
func TestNewManagerBadInputs(t *testing.T) {
	dir := t.TempDir()
	caPath, caKeyPath := testCA(t, dir)
	store, err := db.Open(filepath.Join(dir, "bad.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	// 坏 CA 文件
	badCA := filepath.Join(dir, "bad-ca.crt")
	if err := os.WriteFile(badCA, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewManager(store, badCA, caKeyPath, filepath.Join(dir, "c"), "sock", CertTemplate{}, "adm", "rsa", 2048, 16, nil); err == nil {
		t.Fatal("坏 CA 文件应报错")
	}
	// 坏 CA 私钥文件
	badKey := filepath.Join(dir, "bad-ca.key")
	if err := os.WriteFile(badKey, []byte("not a private key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewManager(store, caPath, badKey, filepath.Join(dir, "c"), "sock", CertTemplate{}, "adm", "rsa", 2048, 16, nil); err == nil {
		t.Fatal("坏 CA 私钥应报错")
	}
	// 缺失 CA 文件
	if _, err := NewManager(store, filepath.Join(dir, "missing.crt"), caKeyPath, filepath.Join(dir, "c"), "sock", CertTemplate{}, "adm", "rsa", 2048, 16, nil); err == nil {
		t.Fatal("缺失 CA 文件应报错")
	}
}
