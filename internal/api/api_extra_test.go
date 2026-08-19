
package api

import (
	"errors"
	"strings"
	"testing"
)

// 第六批: apiErrStatus 状态码映射(400/409/404/403/500)
func TestAPIErrStatus(t *testing.T) {
	cases := []struct {
		msg  string
		want int
	}{
		{"name required", 400},
		{"角色 any 是内置保留字, 只可用于服务声明, 不能签发给证书", 400},
		{"角色 ghost 未在 roles 声明列表中声明", 400},
		{"certificate name dev already exists (1 record(s)), 禁止同名签发", 409},
		{"证书名 dev 已存在", 409},
		{"cert ghost not found", 404},
		{"admin required", 403},
		{"unknown internal error", 500},
	}
	for _, c := range cases {
		if got := apiErrStatus(errors.New(c.msg)); got != c.want {
			t.Errorf("apiErrStatus(%q) = %d, want %d", c.msg, got, c.want)
		}
	}
}

// 第六批: Days 上限(>3650 拒绝)
func TestIssueCertDaysCap(t *testing.T) {
	m := testManager(t, CertTemplate{})
	_, err := m.IssueCert(IssueRequest{Name: "cap-test", Purposes: []string{"svc-a"}, Days: 100000})
	if err == nil || !strings.Contains(err.Error(), "max 3650") {
		t.Fatalf("oversized days should be rejected: %v", err)
	}
}

// 第七批: Days 边界(3650 通过 / 3651 拒绝)
func TestIssueCertDaysBoundary(t *testing.T) {
	m := testManager(t, CertTemplate{})
	if _, err := m.IssueCert(IssueRequest{Name: "days-ok", Purposes: []string{"svc-a"}, Days: 3650}); err != nil {
		t.Fatalf("3650 should pass: %v", err)
	}
	if _, err := m.IssueCert(IssueRequest{Name: "days-no", Purposes: []string{"svc-a"}, Days: 3651}); err == nil {
		t.Fatal("3651 should be rejected")
	}
}

// 第八批: apiErrStatus 中文 404
func TestAPIErrStatusCN(t *testing.T) {
	if got := apiErrStatus(errors.New("证书 不存在")); got != 404 {
		t.Fatalf("证书 不存在 → %d, want 404", got)
	}
	if got := apiErrStatus(errors.New("未找到")); got != 404 {
		t.Fatalf("未找到 → %d, want 404", got)
	}
}
