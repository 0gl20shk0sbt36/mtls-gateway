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

// 第二十八批: ErrStatus 覆盖配置管理词汇(dup listen/immutable/bad role name)
func TestErrStatusConfigVocab(t *testing.T) {
	cases := []struct {
		msg  string
		want int
	}{
		{"duplicate listen: :9602", 409},
		{"duplicate mapping id m1", 409},
		{"duplicate service name svc-a", 409},
		{"role x 已声明", 409},
		{"role x 仍被服务 svc-a 引用", 409},
		{"Server config is immutable (read-only)", 403},
		{"服务端配置为只读模式（immutable）", 403},
		{"bad role name 'a b'", 400},
		{"missing listen", 400},
		{"missing id", 400},
		{"service svc-a has no channels", 400},
		{"bad target", 400},
	}
	for _, c := range cases {
		if got := ErrStatus(errors.New(c.msg)); got != c.want {
			t.Errorf("ErrStatus(%q) = %d, want %d", c.msg, got, c.want)
		}
	}
}

// 第二十九批: StatusFromKeywords 覆盖真实错误串变体(bad role %q / bad port / too long)
func TestStatusFromKeywordsRealErrors(t *testing.T) {
	cases := []struct {
		msg  string
		want int
	}{
		{"service svc-a bad role ghost! (只允许 [A-Za-z0-9_-])", 400}, // proxy.go:157 变体(缺 "name")
		{"mapping m1: bad port in :99999", 400},
		{"certificate validity too long: 99999 days (max 3650)", 400},
		{"bad role name 'a b'", 400},
		{"role x 仍被服务 svc-a 引用", 409},
		{"缺少隧道 id", 400},
		{"missing tunnel id", 400},
		{"service svc-a has no channels", 400},
	}
	for _, c := range cases {
		if got := StatusFromKeywords(c.msg); got != c.want {
			t.Errorf("StatusFromKeywords(%q) = %d, want %d", c.msg, got, c.want)
		}
	}
}

// 第三十一批: "拒绝"收窄回归护栏(拒绝访问→403, 拒绝降级→500 不误标)
func TestStatusFromKeywordsDenyNarrowing(t *testing.T) {
	if got := StatusFromKeywords("访问被拒绝：证书角色无权访问"); got != 403 {
		t.Fatalf("拒绝访问 should be 403, got %d", got)
	}
	if got := StatusFromKeywords("read server_ca x: (拒绝降级系统根)"); got != 500 {
		t.Fatalf("拒绝降级系统根 should be 500 (not mislabeled 403), got %d", got)
	}
}
