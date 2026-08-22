package relay

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

// 中危(测试全面性审计): UpdateSettings 的 SetServerCA 失败必须回滚内存 cfg
// (半提交修复的护栏 — 此前测试用 nil relay 走不到该分支)。
func TestUpdateSettingsServerCARollback(t *testing.T) {
	h := newHarness(t)
	defer h.close()
	m, _ := mgrEnv(t, h)

	bad := filepath.Join(t.TempDir(), "no-such-ca.crt")
	if err := m.UpdateSettings(SettingsPatch{ServerCA: &bad}); err == nil {
		t.Fatal("坏 server_ca 应报错")
	}
	if got := m.Config().ServerCAFile; got != h.caPath {
		t.Fatalf("SetServerCA 失败后 cfg 应回滚为原值 %q, got %q", h.caPath, got)
	}
}

// 高危: relay 管理 API 的 4MB 请求体上限 — 超限 body 必须 400(防内存耗尽)。
func TestManagerHTTP_BodyLimit(t *testing.T) {
	h := newHarness(t)
	defer h.close()
	_, handler := mgrEnv(t, h)

	big := strings.Repeat("x", 5<<20) // 5MB > 4MB
	rec := apiReq(handler, http.MethodPut, "/api/settings", `{"server_addr":"`+big+`"}`, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("超限 body 应 400, got %d", rec.Code)
	}
	// 正常大小不受影响
	rec2 := apiReq(handler, http.MethodPut, "/api/settings", `{"server_addr":"gw.example:9499"}`, "")
	if rec2.Code != http.StatusOK {
		t.Fatalf("正常 body 应 200, got %d: %s", rec2.Code, rec2.Body.String())
	}
}
