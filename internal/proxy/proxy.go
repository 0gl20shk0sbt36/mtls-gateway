// Package proxy 实现"映射 + 服务"路由的反向代理 (v4)。
//
// 模型:
//   - mappings: 唯一实体, 每条 = id(助记符, 唯一) + listen(:port[/path]) + target; 判重靠 listen
//   - services: 服务注册表(所有服务必须注册): name + channels(mapping id 或索引) + roles(允许的证书角色)
//
// 授权: 请求命中映射 → 取引用该映射的所有服务的 roles 并集 → 证书 roles 与并集有交集(或含 "any")→ 放行
// 匹配: 同端口按入口路径最长前缀; 无路径 = 整口兜底。前缀替换(nginx proxy_pass 语义)。
package proxy

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"mtls-gateway/internal/errs"
	"mtls-gateway/internal/pathutil"
	"mtls-gateway/internal/types"
)

// 类型别名: DTO 实体在 internal/types(消除 config→proxy 反向依赖 + 跨包复制)。
type (
	Mapping    = types.Mapping
	HeaderRule = types.HeaderRule
	HeaderVars = types.HeaderVars
	ServiceCfg = types.ServiceCfg
)

// 哨兵常量/校验: 实体在 internal/types(proxy 内部沿用短名)
const (
	RoleAny  = types.RoleAny
	RoleNull = types.RoleNull
)

// ChannelInfo /info 返回的通道信息
type ChannelInfo struct {
	Listen string `json:"listen"`
	Target string `json:"target"`
}

// ServiceInfo /info 返回的服务信息
type ServiceInfo struct {
	Name     string        `json:"name"`
	Channels []ChannelInfo `json:"channels"`
}

// route 编译后的映射
type route struct {
	id      string
	port    string
	path    string   // 入口路径前缀 ("/a" 或 "")
	roles   []string // 引用本映射的所有服务的 roles 并集
	target  *url.URL
	rp      *httputil.ReverseProxy
	headers []HeaderRule // mapping.headers(请求头改写, 认证后应用)
}

// Router 按端口分组的路由器
type Router struct {
	byPort   map[string]*portRouter
	routes   []*route
	mappings []Mapping    // 供 /admin/mappings
	services []ServiceCfg // 供 /info
}

type portRouter struct {
	port   string
	prefix []*route // 带路径, 按 path 长度降序
	whole  *route   // 无路径兜底 (整口)
}

// NewRouter 构建路由器; declaredRoles = 配置里声明的角色列表(服务 roles 必须 ⊆ 它, 除内置 "any")
func NewRouter(ms []Mapping, ss []ServiceCfg, declaredRoles []string) (*Router, error) {
	declared := map[string]bool{}
	for _, r := range declaredRoles {
		if r == RoleAny {
			return nil, errs.New(errs.KindBadRequest, "角色名 %q 是内置保留字(服务声明里直接写 any 即对任意证书开放), 禁止在 roles 声明列表中声明", r)
		}
		if r == RoleNull {
			return nil, errs.New(errs.KindBadRequest, "角色名 %q 是内置保留字(匿名访问, 服务声明里直接写 null 即匿名路由), 禁止在 roles 声明列表中声明", r)
		}
		if !ValidRoleName(r) {
			return nil, errs.New(errs.KindBadRequest, "bad role name %q (只允许字母/数字/下划线/连字符)", r)
		}
		if declared[r] {
			return nil, errs.New(errs.KindConflict, "duplicate role %q", r)
		}
		declared[r] = true
	}
	// 深拷贝: 防 UpdateService/DeleteService 就地写污染(顶层 + 内层切片)
	svcCopy := make([]ServiceCfg, len(ss))
	for i := range ss {
		svcCopy[i] = ss[i]
		svcCopy[i].Roles = append([]string(nil), ss[i].Roles...)
		svcCopy[i].Channels = append([]string(nil), ss[i].Channels...)
	}
	r := &Router{byPort: map[string]*portRouter{}, mappings: append([]Mapping(nil), ms...), services: svcCopy}
	seenNorm, seenID := map[string]bool{}, map[string]bool{}
	for i := range ms {
		m := &ms[i]
		if m.Listen == "" {
			return nil, errs.New(errs.KindBadRequest, "mapping[%d] missing listen", i)
		}
		if m.ID == "" {
			return nil, errs.New(errs.KindBadRequest, "mapping %s missing id (mnemonic, unique)", m.Listen)
		}
		if seenID[m.ID] {
			return nil, errs.New(errs.KindConflict, "duplicate mapping id: %s", m.ID)
		}
		seenID[m.ID] = true
		port, path, err := parseListen(m.Listen)
		if err != nil {
			return nil, fmt.Errorf("mapping %q: %w", m.Listen, err)
		}
		// 判重基于规范化后的 (port, path) 复合键 — 原始串判重会让
		// ":9443" 与 "9443"、":9443/a" 与 ":9443/a/" 等等价写法绕过检查,
		// 导致整口路由被静默覆盖/同路径重复前缀无报错。
		normKey := port + "|" + path
		if seenNorm[normKey] {
			return nil, errs.New(errs.KindConflict, "duplicate listen: %s (规范化后与已有入口相同)", m.Listen)
		}
		seenNorm[normKey] = true
		u, err := url.Parse(m.Target)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, errs.New(errs.KindBadRequest, "mapping %s bad target %q", m.Listen, m.Target)
		}
		// 请求头改写规则校验: op 合法 + name 非空
		for _, h := range m.Headers {
			if h.Op != "set" && h.Op != "del" {
				return nil, errs.New(errs.KindBadRequest, "mapping %s bad header op %q (set|del)", m.Listen, h.Op)
			}
			if strings.TrimSpace(h.Name) == "" {
				return nil, errs.New(errs.KindBadRequest, "mapping %s header rule missing name", m.Listen)
			}
		}
		rt := &route{id: m.ID, port: port, path: path, target: u, rp: newReverseProxy(u),
			headers: append([]HeaderRule(nil), m.Headers...)}
		r.routes = append(r.routes, rt)
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
	}
	// services: 校验 + 汇总 roles 到 route
	seenSvc := map[string]bool{}
	for _, s := range ss {
		if s.Name == "" {
			return nil, errs.New(errs.KindBadRequest, "service missing name")
		}
		if seenSvc[s.Name] {
			return nil, errs.New(errs.KindConflict, "duplicate service name: %s", s.Name)
		}
		seenSvc[s.Name] = true
		if len(s.Channels) == 0 {
			return nil, errs.New(errs.KindBadRequest, "service %s has no channels", s.Name)
		}
		// 服务 roles: "any"(内置)= 任意已登记证书; "null"(内置)= 匿名可访问; 其他必须在声明列表中
		for _, r := range s.Roles {
			if r == RoleAny || r == RoleNull {
				continue
			}
			if !ValidRoleName(r) {
				return nil, errs.New(errs.KindBadRequest, "service %s bad role %q (只允许字母/数字/下划线/连字符)", s.Name, r)
			}
			if !declared[r] {
				return nil, errs.New(errs.KindBadRequest, "service %s role %q 未在 roles 声明列表中", s.Name, r)
			}
		}
		for _, ch := range s.Channels {
			idx := resolveChannelIndex(r.routes, ch)
			if idx < 0 || idx >= len(r.routes) {
				return nil, errs.New(errs.KindNotFound, "service %s channel %q not found", s.Name, ch)
			}
			r.routes[idx].roles = mergeRoles(r.routes[idx].roles, s.Roles)
		}
	}
	for _, pr := range r.byPort {
		sort.SliceStable(pr.prefix, func(i, j int) bool {
			return len(pr.prefix[i].path) > len(pr.prefix[j].path)
		})
	}
	return r, nil
}

func mergeRoles(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range append(a, b...) {
		if r == "" || seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	return out
}

// ValidRoleName 委托 internal/types(实体单点, 防校验规则漂移)
func ValidRoleName(s string) bool { return types.ValidRoleName(s) }

// parseListen 解析 ":9443" / ":9445/admin" → (port, path)
func parseListen(l string) (string, string, error) {
	orig := l
	l = strings.TrimPrefix(strings.TrimSpace(l), ":")
	var path string
	if i := strings.IndexByte(l, '/'); i >= 0 {
		path = l[i:]
		l = l[:i]
	}
	// 规范化尾斜杠: "/a/"→"/a"; 单独 "/" 视为整口(path=""); 否则 matchPath 的前缀匹配会因尾斜杠失效
	path = strings.TrimSuffix(path, "/")
	if l == "" {
		return "", "", errs.New(errs.KindBadRequest, "missing port in %q", orig)
	}
	for _, c := range l {
		if c < '0' || c > '9' {
			return "", "", errs.New(errs.KindBadRequest, "bad port in %q", orig)
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
		return pr.whole
	}
	return nil
}

func matchPath(p, pref string) bool {
	if pref == "" {
		return true
	}
	return p == pref || strings.HasPrefix(p, pref+"/")
}

// Allows 判断证书角色是否允许访问该映射(服务 roles 含内置 "any" = 任意已登记证书; 否则并集 ∩ 证书 roles)
func (r *route) Allows(roles []string) bool {
	return rolesMatch(r.roles, roles)
}

// AllowsNull 该路由是否匿名可访问(服务 roles 含内置 "null" = 不需要证书)
func (r *route) AllowsNull() bool {
	for _, want := range r.roles {
		if want == "null" {
			return true
		}
	}
	return false
}

// Listen 返回入口端口+路径串(供展示)
func (r *route) Listen() string { return ":" + r.port + r.path }
func (r *route) Target() string { return r.target.String() }

// ServicesAllowed 返回证书角色可访问的服务(供 /info 按角色过滤)
func (r *Router) ServicesAllowed(roles []string) []ServiceInfo {
	var out []ServiceInfo
	for _, s := range r.services {
		if !rolesMatch(s.Roles, roles) {
			continue
		}
		si := ServiceInfo{Name: s.Name}
		for _, ch := range s.Channels {
			idx := resolveChannelIndex(r.routes, ch)
			if idx >= 0 && idx < len(r.routes) {
				si.Channels = append(si.Channels, ChannelInfo{Listen: r.routes[idx].Listen(), Target: r.routes[idx].Target()})
			}
		}
		out = append(out, si)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// resolveChannelIndex 解析 channel 引用: 先按 mapping id 精确匹配, 未命中才尝试数字索引(兼容旧配置)。
// 防止全数字 id 被 strconv.Atoi 误解析为索引, 导致服务角色/权限挂到错误的路由上(权限错配)。
func resolveChannelIndex(routes []*route, ch string) int {
	for i, rt := range routes {
		if rt.id == ch {
			return i
		}
	}
	if n, err := strconv.Atoi(ch); err == nil && n >= 0 && n < len(routes) {
		// 数字索引回退: 映射重排会静默把服务角色挂到另一条路由(权限错配) — 显式警告
		log.Printf("警告: services.channels 使用数字索引 %q(mapping id 优先); 映射顺序变化会导致角色错配, 请改用 mapping id", ch)
		return n
	}
	return -1
}

func rolesMatch(want, have []string) bool {
	for _, w := range want {
		if w == RoleAny {
			return true
		}
		for _, h := range have {
			if h == w {
				return true
			}
		}
	}
	return false
}

// Close 释放资源(热重载丢弃旧 router 时调用): 关闭全部 route 的 idle 连接, 防 Transport/goroutine 累积
func (r *Router) Close() {
	for _, rt := range r.routes {
		if rt.rp == nil {
			continue
		}
		if tr, ok := rt.rp.Transport.(*http.Transport); ok {
			tr.CloseIdleConnections()
		}
	}
}

// Serve 执行前缀替换并转发
func (r *Router) Serve(rt *route, w http.ResponseWriter, req *http.Request) {
	rc := req.Clone(req.Context())
	rc.URL.Path = substitute(rc.URL.Path, rt.path, rt.target.Path)
	rc.URL.RawPath = "" // 强制按新 Path 重编码(与 relay 侧对齐)
	rt.rp.ServeHTTP(w, rc)
}

// substitute 前缀替换: 剥掉命中入口前缀, 换成目标前缀 (nginx proxy_pass 语义, 斜杠去重)
func substitute(p, inPath, outPath string) string {
	rest := p
	if inPath != "" {
		rest = strings.TrimPrefix(p, inPath)
	}
	if outPath == "" {
		outPath = "/"
	}
	return joinURLPath(outPath, rest)
}

// joinURLPath 拼接两个路径段, 去除多余斜杠; 并清除 dot-segment(防 .. 穿透前缀)
func joinURLPath(base, tail string) string {
	base = strings.TrimSuffix(base, "/")
	tail = strings.TrimPrefix(tail, "/")
	r := base + "/" + tail
	if r == "" || r == "/" {
		return "/"
	}
	return pathutil.CleanDotSegments(r)
}

// newReverseProxy Host/Origin 改写为后端 loopback (信任围栏放行); 路径替换由 Serve 负责
// 带超时 + 502 ErrorHandler(后端宕机/慢时不静默)
func newReverseProxy(target *url.URL) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host
			req.Header.Set("Origin", target.Scheme+"://"+target.Host)
			req.Header.Del("X-Forwarded-Host")
		},
		Transport: &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			// 脱敏: 后端错误细节(内部 IP/端口/DNS)只写日志, 对外统一 502
			// 路径先清洗 C0 控制字符: 已认证客户端可把 %0d%0a 编进 URL 伪造文本日志行
			// (CWE-117; JSON 事件日志由 json.Marshal 转义不受影响)
			log.Printf("proxy %s -> %s: %v", sanitizeLogPath(r.URL.Path), target.Host, err)
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
	}
}

// SanitizeHeader 移除可能伪造的转发头(由网关自己生成)。
// 补全 RFC 7239 Forwarded 及常见代理/URL 重写头, 防已认证客户端伪造直达后端的路径级访问控制。
func SanitizeHeader(r *http.Request) {
	r.Header.Del("X-Forwarded-For")
	r.Header.Del("X-Real-Ip")
	r.Header.Del("X-Forwarded-Proto")
	r.Header.Del("X-Forwarded-Host")
	r.Header.Del("X-Forwarded-Server")
	r.Header.Del("Forwarded")
	r.Header.Del("X-Original-URL")
	r.Header.Del("X-Rewrite-URL")
	r.Header.Del("Via")
}

// sanitizeLogPath 清洗日志输出的路径: 删除 CR/LF 及其余 C0 控制字符(含 ANSI ESC)。
// 已认证客户端可把 %0d%0a 编进 URL 伪造文本日志行(CWE-117); ANSI 转义只能污染外观、
// 不能伪造日志行, 一并滤除; JSON 事件日志由 json.Marshal 转义不受影响。
func sanitizeLogPath(p string) string {
	return pathutil.SanitizeForLog(p)
}

// ApplyHeaders 转发前应用请求头改写: 先执行默认防伪造基线(SanitizeHeader),
// 再按 mapping.headers 配置执行 set/del(变量认证后求值)。
// 防伪造: set 一律先删后设(客户端自带同名头被覆盖, 后端拿到的身份头只能来自网关)。
func (rt *route) ApplyHeaders(req *http.Request, v HeaderVars) {
	SanitizeHeader(req) // 默认基线: 删 9 个转发头
	for _, h := range rt.headers {
		switch h.Op {
		case "del":
			req.Header.Del(h.Name)
		case "set":
			val := types.ExpandVars(h.Value, v)
			if val == "" {
				req.Header.Del(h.Name) // 变量为空(匿名路由): 不注入空头
				continue
			}
			req.Header.Set(h.Name, val)
		}
	}
}
