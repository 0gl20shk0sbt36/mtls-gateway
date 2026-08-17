package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRouterRouting 用途路由: 请求按 purpose 分发到对应后端
func TestRouterRouting(t *testing.T) {
	// 两个后端: app-a 和 app-b
	backendA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "A")
		w.WriteHeader(200)
	}))
	defer backendA.Close()
	backendB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "B")
		w.WriteHeader(200)
	}))
	defer backendB.Close()

	router := NewRouter([]Backend{
		{Purpose: "app-a", Target: backendA.URL},
		{Purpose: "app-b", Target: backendB.URL},
	})

	// app-a 用途 → 应到 A
	req := httptest.NewRequest("GET", "http://gw.example/", nil)
	rec := httptest.NewRecorder()
	router.Handler("app-a").ServeHTTP(rec, req)
	if rec.Header().Get("X-Backend") != "A" {
		t.Fatalf("expected backend A, got %q", rec.Header().Get("X-Backend"))
	}

	// app-b 用途 → 应到 B
	req2 := httptest.NewRequest("GET", "http://gw.example/", nil)
	rec2 := httptest.NewRecorder()
	router.Handler("app-b").ServeHTTP(rec2, req2)
	if rec2.Header().Get("X-Backend") != "B" {
		t.Fatalf("expected backend B, got %q", rec2.Header().Get("X-Backend"))
	}
}

// TestRouterUnknownPurpose 未知用途 → 404
func TestRouterUnknownPurpose(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer backend.Close()

	router := NewRouter([]Backend{{Purpose: "app-a", Target: backend.URL}})
	req := httptest.NewRequest("GET", "http://gw.example/", nil)
	rec := httptest.NewRecorder()
	router.Handler("ghost").ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown purpose, got %d", rec.Code)
	}
}

// TestHostRewrite 反代改写 Host 头 (关键: 后端看到 loopback/目标地址)
func TestHostRewrite(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 后端应看到改写后的 Host (目标地址), 而非原始 gw.example
		w.Header().Set("X-Seen-Host", r.Host)
		w.WriteHeader(200)
	}))
	defer backend.Close()

	router := NewRouter([]Backend{{Purpose: "app-a", Target: backend.URL}})
	req := httptest.NewRequest("GET", "http://gw.example:9443/", nil)
	rec := httptest.NewRecorder()
	router.Handler("app-a").ServeHTTP(rec, req)

	seen := rec.Header().Get("X-Seen-Host")
	if seen == "gw.example:9443" {
		t.Fatalf("host was not rewritten: %q", seen)
	}
}

// TestOriginRewrite 反代改写 Origin 头 (关键: 浏览器请求 403 的修复)
func TestOriginRewrite(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-Origin", r.Header.Get("Origin"))
		w.WriteHeader(200)
	}))
	defer backend.Close()

	router := NewRouter([]Backend{{Purpose: "app-a", Target: backend.URL}})
	req := httptest.NewRequest("GET", "http://gw.example:9443/", nil)
	req.Header.Set("Origin", "https://gw.example:9443")
	rec := httptest.NewRecorder()
	router.Handler("app-a").ServeHTTP(rec, req)

	seen := rec.Header().Get("X-Seen-Origin")
	if seen == "https://gw.example:9443" {
		t.Fatalf("origin was not rewritten: %q", seen)
	}
	if seen == "" {
		t.Fatal("origin should be rewritten to target, not empty")
	}
}

// TestPurposes 列出用途
func TestPurposes(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer backend.Close()
	router := NewRouter([]Backend{
		{Purpose: "app-a", Target: backend.URL},
		{Purpose: "admin", Target: backend.URL},
	})
	purposes := router.Purposes()
	if len(purposes) != 2 {
		t.Fatalf("expected 2 purposes, got %d", len(purposes))
	}
	if !router.HasPurpose("app-a") || !router.HasPurpose("admin") {
		t.Fatal("HasPurpose should return true for configured purposes")
	}
	if router.HasPurpose("ghost") {
		t.Fatal("HasPurpose should return false for unknown")
	}
}

// TestWebSocketUpgrade 检测 WebSocket 升级请求
func TestWebSocketUpgrade(t *testing.T) {
	req := httptest.NewRequest("GET", "http://gw.example/", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	if !IsWebSocketUpgrade(req) {
		t.Fatal("should detect websocket upgrade")
	}

	req2 := httptest.NewRequest("GET", "http://gw.example/", nil)
	if IsWebSocketUpgrade(req2) {
		t.Fatal("should not detect websocket upgrade on normal request")
	}
}
