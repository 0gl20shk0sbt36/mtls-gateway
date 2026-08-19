// Package relayweb 提供 mtls-relay 的 WebUI 外壳。
//
// WebUI 是 daemon 管理 API 的对等壳: 本地 HTTP server 在同一 origin 上
// 既提供静态单页(go:embed), 又暴露 /api/* 管理端点。前端纯 HTML+JS,
// 无 Node 构建依赖。默认仅监听 loopback。
package relayweb

import (
	"embed"
	"io/fs"
	"net/http"
	"net/url"
	"strings"

	"mtls-gateway/internal/relay"
)

//go:embed web/*
var webFS embed.FS

// NewHandler 组合管理 handler: /api/* → relay.Manager, 其余 → WebUI 静态页。
func NewHandler(mgr *relay.Manager) http.Handler {
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		panic(err)
	}
	fileHandler := http.FileServer(http.FS(sub))
	apiHandler := mgr.Handler()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// DNS rebinding / CSRF 防护: 浏览器跨源请求(Origin ≠ Host)拒绝
		if !sameOrigin(r) {
			http.Error(w, "cross-origin request rejected", http.StatusForbidden)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			apiHandler.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/" || r.URL.Path == "" {
			// 提供 index.html
			index, err := webFS.ReadFile("web/index.html")
			if err != nil {
				http.Error(w, "internal", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(index)
			return
		}
		fileHandler.ServeHTTP(w, r)
	})
}

// sameOrigin DNS rebinding / CSRF 防护:
// 浏览器跨源请求会带 Origin 头; 若 Origin 的 host 与请求 Host 不一致则拒绝。
// 无 Origin 的请求(CLI/curl/同源浏览器)放行。
func sameOrigin(r *http.Request) bool {
	if o := r.Header.Get("Origin"); o != "" {
		ou, err := url.Parse(o)
		if err != nil || ou.Host != r.Host {
			return false
		}
	}
	return true
}
