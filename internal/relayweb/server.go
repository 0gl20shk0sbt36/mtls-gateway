// Package relayweb 提供 mtls-relay 的 WebUI 外壳。
//
// WebUI 是 daemon 管理 API 的对等壳: 本地 HTTP server 在同一 origin 上
// 既提供静态单页(go:embed), 又暴露 /api/* 管理端点。前端纯 HTML+JS,
// 无 Node 构建依赖。默认仅监听 loopback。
package relayweb

import (
	"embed"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"strings"

	"mtls-gateway/internal/relay"
)

//go:embed web/*
var webFS embed.FS

// NewHandler 组合管理 handler: /api/* → relay.Manager, 其余 → WebUI 静态页。
// allowRemote: --allow-remote 显式放行非 loopback Host(跳过 Host 白名单, 保留 Origin 校验);
// 默认 false = 管理面只服务本机(DNS rebinding 防护)。
func NewHandler(mgr *relay.Manager, allowRemote bool) http.Handler {
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		panic(err)
	}
	fileHandler := http.FileServer(http.FS(sub))
	apiHandler := mgr.Handler()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// DNS rebinding / CSRF 防护: Host 非 loopback(默认)或浏览器跨源请求(Origin ≠ Host)拒绝
		if !sameOrigin(r, allowRemote) {
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
// ① Host 必须为 loopback(localhost/127.0.0.1/::1) — 管理面无鉴权, 只服务本机;
//
//	否则 DNS rebinding 攻击者可让 Origin 与 Host 同值(都为 evil.com)绕过纯 Origin 校验。
//	allowRemote=true(--allow-remote 显式选择)时跳过此检查。
//
// ② 带 Origin 的请求(浏览器跨源)要求 Origin 的 host 与请求 Host 一致; 无 Origin(CLI/curl)放行。
func sameOrigin(r *http.Request, allowRemote bool) bool {
	if !allowRemote {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if host != "localhost" {
			ip := net.ParseIP(host)
			if ip == nil || !ip.IsLoopback() {
				return false // Host 非 loopback → 拒绝(含 rebinding 的 evil.com)
			}
		}
	}
	if o := r.Header.Get("Origin"); o != "" {
		ou, err := url.Parse(o)
		if err != nil || ou.Host != r.Host {
			return false
		}
	}
	return true
}
