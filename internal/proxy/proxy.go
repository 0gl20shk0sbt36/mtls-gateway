// Package proxy 实现"映射"路由的反向代理 (v3)。
//
// 模型: mappings 为唯一实体, 每条 = 入口(:port[/path]) → 目标URL, 并声明允许的服务(services)。
//   - listen 合并路径: ":9445/admin" (host 由全局 bind_host 决定, 不在此写)
//   - target 为完整 URL, 其路径段用于"前缀替换"(剥入口 path、补 target path), nginx 同款
//   - services: 允许的用途清单, 证书用途与其有交集才放行; ["any"]=任一已登记证书
// 重复判定: 两个映射 listen 字符串完全相同 → 加载报错; 前缀重叠/同 target 不同 listen 合法。
// 匹配: 同端口按入口路径最长前缀优先; 无路径的 = 整口兜底。
package proxy

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"
)

// Mapping 一条映射的配置形态 (config JSON 直接对应)
type Mapping struct {
	Listen   string   `json:"listen"`
	Target   string   `json:"target"`
	Services []string `json:"services"`
}

// route 编译后的映射
type route struct {
	port     string
	path     string   // 入口路径前缀 ("/a" 或 "")
	services []string
	target   *url.URL
	rp       *httputil.ReverseProxy
}

// Router 按端口分组的路由器
type Router struct {
	byPort map[string]*portRouter
	routes []route // 供 /info
}

type portRouter struct {
	port   string
	prefix []*route // 带路径, 按 path 长度降序
	whole  *route   // 无路径兜底 (整口)
}

// NewRouter 从 mappings 构建路由器; listen 重复返回 error。
func NewRouter(ms []Mapping) (*Router, error) {
	r := &Router{byPort: map[string]*portRouter{}}
	seen := map[string]bool{}
	for _, m := range ms {
		port, path, err := parseListen(m.Listen)
		if err != nil {
			return nil, fmt.Errorf("mapping listen %q: %w", m.Listen, err)
		}
		if seen[m.Listen] {
			return nil, fmt.Errorf("duplicate listen: %s", m.Listen)
		}
		seen[m.Listen] = true
		u, err := url.Parse(m.Target)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("mapping %s bad target %q", m.Listen, m.Target)
		}
		rt := &route{port: port, path: path, services: m.Services, target: u, rp: newReverseProxy(u)}
		pr := r.byPort[port]
		if pr == nil {
			pr = &portRouter{port: port}
			r.byPort[port] = pr
		}
		if path == "" {
			pr.whole = rt
		} else {
			pr.prefix = append(pr.prefix, rt)
		}
		r.routes = append(r.routes, *rt)
	}
	for _, pr := range r.byPort {
		sort.SliceStable(pr.prefix, func(i, j int) bool {
			return len(pr.prefix[i].path) > len(pr.prefix[j].path)
		})
		if pr.whole != nil && len(pr.prefix) > 0 {
			// 带路径的优先按前缀, whole 兜底未命中路径 —— 合法
		}
	}
	return r, nil
}

// parseListen 解析 ":9443" / ":9445/admin" → (port, path)
func parseListen(l string) (string, string, error) {
	orig := l
	l = strings.TrimPrefix(strings.TrimSpace(l), ":")
	var path string
	if i := strings.IndexByte(l, '/'); i >= 0 {
		path = l[i:]
		l = l[:i]
	}
	if l == "" {
		return "", "", fmt.Errorf("missing port in %q", orig)
	}
	for _, c := range l {
		if c < '0' || c > '9' {
			return "", "", fmt.Errorf("bad port in %q", orig)
		}
	}
	return l, path, nil
}

// Listens 返回所有占用的入口端口(去重)
func (r *Router) Listens() []string {
	out := make([]string, 0, len(r.byPort))
	for p := range r.byPort {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Match 在指定端口按路径选映射(最长前缀); 未命中返回 nil。
func (r *Router) Match(port, path string) *route {
	pr := r.byPort[port]
	if pr == nil {
		return nil
	}
	for _, rt := range pr.prefix {
		if matchPath(path, rt.path) {
			return rt
		}
	}
	if pr.whole != nil {
		return pr.whole // 整口兜底
	}
	return nil
}

func matchPath(p, pref string) bool {
	if pref == "" {
		return true
	}
	return p == pref || strings.HasPrefix(p, pref+"/")
}

// Allows 判断用途清单是否允许访问该映射 (services 含 "any" 或存在交集)
func (r *route) Allows(purposes []string) bool {
	for _, s := range r.services {
		if s == "any" {
			return true
		}
		for _, p := range purposes {
			if s == p {
				return true
			}
		}
	}
	return false
}

// Allowed 返回入口端口+路径串(供 /info / 客户端展示)
func (r *route) Listen() string { return ":" + r.port + r.path }
func (r *route) Services() []string { return r.services }
func (r *route) Target() string  { return r.target.String() }

// AllowedRoutes 返回用途清单可访问的所有映射(供 /info 按证书过滤; "any" 或交集)
func (r *Router) AllowedRoutes(purposes []string) []Mapping {
	var out []Mapping
	for i := range r.routes {
		if r.routes[i].Allows(purposes) {
			out = append(out, Mapping{Listen: r.routes[i].Listen(), Target: r.routes[i].Target(), Services: r.routes[i].services})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Listen < out[j].Listen })
	return out
}

// Routes 返回全部映射(供 /info; 服务端再按证书过滤)
func (r *Router) Routes() []Mapping {
	out := make([]Mapping, 0, len(r.routes))
	for _, rt := range r.routes {
		out = append(out, Mapping{Listen: ":" + rt.port + rt.path, Target: rt.target.String(), Services: rt.services})
	}
	return out
}

// Serve 执行前缀替换并转发
func (r *Router) Serve(rt *route, w http.ResponseWriter, req *http.Request) {
	// 前缀替换: 去掉入口 path, 补目标 path (nginx 同款)
	rc := req.Clone(req.Context())
	rc.URL.Path = substitute(rc.URL.Path, rt.path, rt.target.Path)
	rt.rp.ServeHTTP(w, rc)
}

func substitute(p, inPath, outPath string) string {
	if inPath != "" {
		p = strings.TrimPrefix(p, inPath)
	}
	return outPath + p
}

// newReverseProxy Host/Origin 改写为后端 loopback (信任围栏放行); 路径替换由 Serve 负责
func newReverseProxy(target *url.URL) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host
			req.Header.Set("Origin", "https://"+target.Host)
			req.Header.Del("X-Forwarded-Host")
		},
	}
}

// SanitizeHeader 移除可能伪造的转发头(由网关自己生成)
func SanitizeHeader(r *http.Request) {
	r.Header.Del("X-Forwarded-For")
	r.Header.Del("X-Real-Ip")
	r.Header.Del("X-Forwarded-Proto")
	r.Header.Del("X-Forwarded-Host")
}
