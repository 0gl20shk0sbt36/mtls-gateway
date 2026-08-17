// Package proxy 实现按用途(证书授权结果)路由到后端服务的反向代理。
// 关键: 认证通过后把 Host/Origin 改写为后端的 loopback 地址,
//       让后端(如 dsh)的信任围栏看到 loopback 而放行特权方法。
package proxy

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

// Backend 一个后端服务的定义
type Backend struct {
	Purpose string // 证书用途 (dsh, vaultwarden, ...)
	Target  string // 后端地址 http://127.0.0.1:3080
	Prefix  string // 可选路径前缀 (留空=全部)
}

// Router 用途 → 后端映射
type Router struct {
	backends map[string]*Backend
	proxies  map[string]*httputil.ReverseProxy
}

// NewRouter 创建路由
func NewRouter(backends []Backend) *Router {
	r := &Router{
		backends: make(map[string]*Backend),
		proxies:  make(map[string]*httputil.ReverseProxy),
	}
	for _, b := range backends {
		b := b
		target, err := url.Parse(b.Target)
		if err != nil {
			log.Printf("proxy: bad target %q: %v", b.Target, err)
			continue
		}
		r.backends[b.Purpose] = &b
		// 反代: 改写 Host 为后端地址 (让 dsh 围栏看到 loopback)
		rp := httputil.NewSingleHostReverseProxy(target)
		origDirector := rp.Director
		rp.Director = func(req *http.Request) {
			origDirector(req)
			// 关键: 改写 Host/Origin 为 loopback, 后端信任围栏天然放行特权方法
			req.Host = target.Host
			// Origin 必须同步改写, 否则浏览器带的 Origin(网关地址)与 Host(loopback)不匹配 → 403
			req.Header.Set("Origin", "https://"+target.Host)
			// 保留原始协议头给后端 (X-Forwarded-*)
			req.Header.Set("X-Forwarded-Host", req.Header.Get("Host"))
		}
		r.proxies[b.Purpose] = rp
	}
	return r
}

// Handler 返回 HTTP handler: 按请求的授权用途路由
// 用法: 先 auth.Authorize 得到 purpose, 再调用本 handler
func (r *Router) Handler(purpose string) http.Handler {
	rp, ok := r.proxies[purpose]
	if !ok {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			http.Error(w, "no backend for purpose: "+purpose, http.StatusNotFound)
		})
	}
	return rp
}

// HasPurpose 检查用途是否有后端
func (r *Router) HasPurpose(purpose string) bool {
	_, ok := r.proxies[purpose]
	return ok
}

// Purposes 列出所有已配置用途
func (r *Router) Purposes() []string {
	out := make([]string, 0, len(r.backends))
	for k := range r.backends {
		out = append(out, k)
	}
	return out
}

// SanitizeHeader 清理转发头 (避免客户端伪造 X-Forwarded-*)
func SanitizeHeader(req *http.Request) {
	req.Header.Del("X-Forwarded-For")
	req.Header.Del("X-Forwarded-Host")
	req.Header.Del("X-Forwarded-Proto")
}

// IsWebSocketUpgrade 判断是否为 WebSocket 升级请求
func IsWebSocketUpgrade(req *http.Request) bool {
	return strings.EqualFold(req.Header.Get("Upgrade"), "websocket") ||
		strings.EqualFold(req.Header.Get("Connection"), "upgrade")
}
