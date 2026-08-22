package relayweb

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// sameOrigin: 跨源 Origin 拒绝 / 同源放行 / 无 Origin 放行
func TestSameOrigin(t *testing.T) {
	cases := []struct {
		host, origin string
		allowRemote  bool
		want         bool
	}{
		{"127.0.0.1:18081", "", false, true},                       // 无 Origin(CLI/同源)放行
		{"127.0.0.1:18081", "http://127.0.0.1:18081", false, true}, // 同源
		{"127.0.0.1:18081", "http://evil.com", false, false},       // 跨源
		{"127.0.0.1:18081", "http://127.0.0.1:9999", false, false}, // 端口不同=跨源
		{"127.0.0.1:18081", "not-a-url", false, false},             // 非法 Origin
		{"evil.com:18081", "http://evil.com:18081", false, false},  // DNS rebinding: Host 非 loopback 拒绝
		{"192.168.1.5:18081", "", false, false},                    // 非 loopback 无 Origin 也拒绝
		{"[::1]:18081", "", false, true},                           // IPv6 loopback 放行
		{"evil.com:18081", "http://evil.com:18081", true, true},    // --allow-remote 显式放行
	}
	for _, c := range cases {
		req := httptest.NewRequest("POST", "http://127.0.0.1:18081/api/tunnels", nil)
		req.Host = c.host
		if c.origin != "" {
			req.Header.Set("Origin", c.origin)
		}
		if got := sameOrigin(req, c.allowRemote); got != c.want {
			t.Errorf("sameOrigin(host=%q origin=%q allowRemote=%v) = %v, want %v", c.host, c.origin, c.allowRemote, got, c.want)
		}
	}
}

// 集成: 跨源请求到 /api/status → 403(handler 层真实 ServeHTTP; sameOrigin 检查先于 mgr 使用, nil 安全)
func TestHandlerRejectsCrossOrigin(t *testing.T) {
	h := NewHandler(nil, false)
	req := httptest.NewRequest("GET", "/api/status", nil)
	req.Host = "127.0.0.1:18081"
	req.Header.Set("Origin", "http://evil.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("跨源请求应 403, got %d", rec.Code)
	}
}

// R3 集成: NewHandler 对非 loopback Host 返回 403; / 返回 index.html
func TestNewHandlerRejectsRemoteHost(t *testing.T) {
	// 用最小 Manager?NewHandler 需要 *relay.Manager — 用 nil 会 panic(只访问 / 静态页不碰 mgr)
	// 构造真实 Manager 太重; 这里直接测包装层对 Host 的拒绝(用 panic 恢复验证 403 优先于 mgr 使用)
	defer func() {
		r := recover()
		if r != nil {
			t.Fatalf("handler should reject remote host before touching mgr: %v", r)
		}
	}()
	// nil mgr: 只有 sameOrigin 检查通过后才会调用 mgr.Handler()(会 panic)
	h := NewHandler(nil, false)
	req := httptest.NewRequest("GET", "/api/status", nil)
	req.Host = "evil.com:18081"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("remote host should be 403, got %d", rec.Code)
	}
}

// 审计补: 安全响应头(CSP / X-Frame-Options / X-Content-Type-Options)断言
func TestSecurityHeaders(t *testing.T) {
	h := NewHandler(nil, false) // 头在 sameOrigin 检查前设置, nil mgr 不会 panic
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "127.0.0.1:18081"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get("Content-Security-Policy"); got == "" {
		t.Fatal("缺 CSP 头")
	} else if !strings.Contains(got, "default-src 'self'") {
		t.Fatalf("CSP 异常: %s", got)
	}
	if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("X-Frame-Options = %q, want DENY", got)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q, want nosniff", got)
	}
}
