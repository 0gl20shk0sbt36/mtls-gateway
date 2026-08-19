package relay

import (
	"errors"
	"strings"
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
