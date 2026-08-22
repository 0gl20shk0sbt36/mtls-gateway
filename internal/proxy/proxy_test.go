package proxy

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newEcho() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 回显 Host + Origin + 转发头是否存在: 断言网关 Director 的信任围栏改写
		w.Write([]byte("ECHO " + r.Method + " " + r.URL.Path + " HOST=" + r.Host +
			" ORIGIN=" + r.Header.Get("Origin") +
			" XFH=" + r.Header.Get("X-Forwarded-Host") +
			" XFF=" + r.Header.Get("X-Forwarded-For")))
	}))
}

// TestDirectorRewrites 转发时: Host/Origin 改写为后端 loopback(信任围栏放行), 伪造转发头被删
func TestDirectorRewrites(t *testing.T) {
	back := newEcho()
	defer back.Close()
	r, err := NewRouter([]Mapping{
		{ID: "m", Listen: ":9005", Target: back.URL},
	}, []ServiceCfg{{Name: "s", Channels: []string{"m"}, Roles: []string{"x"}}}, []string{"x"})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:9005")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		rt := r.Match("9005", req.URL.Path)
		if rt == nil {
			http.Error(w, "no route", 404)
			return
		}
		rt.ApplyHeaders(req, HeaderVars{CertName: "dev", RemoteIP: "100.64.0.2"})
		r.Serve(rt, w, req)
	}))
	req, _ := http.NewRequest("GET", "http://127.0.0.1:9005/x", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4") // 客户端伪造
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	got := string(body)
	wantOrigin := back.URL // Director: Origin = target scheme://host
	if !strings.Contains(got, "ORIGIN="+wantOrigin) {
		t.Errorf("Origin 应改写为后端 %q: %s", wantOrigin, got)
	}
	if !strings.Contains(got, "XFH=") {
		t.Errorf("X-Forwarded-Host 应被删除: %s", got)
	}
	if !strings.Contains(got, "XFF=") {
		t.Errorf("X-Forwarded-For 应被删除(防伪造): %s", got)
	}
	if !strings.Contains(got, "HOST=") {
		t.Errorf("缺少 HOST 回显: %s", got)
	}
}

func TestLongestPrefixMatch(t *testing.T) {
	r, err := NewRouter([]Mapping{
		{ID: "a", Listen: ":9001", Target: "http://127.0.0.1:1"},
		{ID: "ab", Listen: ":9001/a/b", Target: "http://127.0.0.1:1"},
		{ID: "aa", Listen: ":9001/a", Target: "http://127.0.0.1:1"},
	}, []ServiceCfg{
		{Name: "s", Channels: []string{"a", "ab", "aa"}, Roles: []string{"x"}},
	}, []string{"x"})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"/a/b/c": ":9001/a/b",
		"/a/c":   ":9001/a",
		"/ab":    ":9001", // /ab 不匹配前缀 /a(需 /a/... 或相等)→ 整口兜底
		"/x":     ":9001", // 整口兜底
	}
	for p, want := range cases {
		rt := r.Match("9001", p)
		if rt == nil || rt.Listen() != want {
			t.Errorf("path %s: got %v want %s", p, rt.Listen(), want)
		}
	}
}

func TestWholePortFallback(t *testing.T) {
	r, _ := NewRouter([]Mapping{
		{ID: "w", Listen: ":9002", Target: "http://127.0.0.1:1"},
	}, []ServiceCfg{{Name: "s", Channels: []string{"w"}, Roles: []string{"x"}}}, []string{"x"})
	for _, p := range []string{"/", "/x", "/a/b"} {
		if rt := r.Match("9002", p); rt == nil {
			t.Errorf("whole-port should match %q", p)
		}
	}
}

func TestSubstitution(t *testing.T) {
	back := newEcho()
	defer back.Close()
	r, err := NewRouter([]Mapping{
		{ID: "strip", Listen: ":9003/a", Target: back.URL},
		{ID: "prep", Listen: ":9004", Target: back.URL + "/x"},
	}, []ServiceCfg{
		{Name: "s", Channels: []string{"strip", "prep"}, Roles: []string{"x"}},
	}, []string{"x"})
	if err != nil {
		t.Fatal(err)
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		rt := r.Match(portOf(req.Host), req.URL.Path)
		if rt == nil {
			http.Error(w, "no route", 404)
			return
		}
		r.Serve(rt, w, req)
	})
	srv9003 := httptest.NewUnstartedServer(h)
	ln9003, err := net.Listen("tcp", "127.0.0.1:9003")
	if err != nil {
		t.Fatalf("listen 9003: %v", err)
	}
	srv9003.Listener = ln9003
	srv9003.Start()
	defer srv9003.Close()
	srv9004 := httptest.NewUnstartedServer(h)
	ln9004, err := net.Listen("tcp", "127.0.0.1:9004")
	if err != nil {
		t.Fatalf("listen 9004: %v", err)
	}
	srv9004.Listener = ln9004
	srv9004.Start()
	defer srv9004.Close()

	if got := get("http://127.0.0.1:9003/a/hello"); !strings.Contains(got, "ECHO GET /hello HOST="+back.Listener.Addr().String()) {
		t.Errorf("strip: %q", got)
	}
	if got := get("http://127.0.0.1:9003/a/x"); !strings.Contains(got, "ECHO GET /x HOST="+back.Listener.Addr().String()) {
		t.Errorf("strip /a/x: %q", got)
	}
	if got := get("http://127.0.0.1:9004/p"); !strings.Contains(got, "ECHO GET /x/p HOST="+back.Listener.Addr().String()) {
		t.Errorf("prepend: %q", got)
	}
}

func TestDupAndIDChecks(t *testing.T) {
	if _, err := NewRouter([]Mapping{
		{ID: "a", Listen: ":9101", Target: "http://127.0.0.1:1"},
		{ID: "b", Listen: ":9101", Target: "http://127.0.0.1:2"},
	}, nil, nil); err == nil {
		t.Fatal("duplicate listen should error")
	}
	if _, err := NewRouter([]Mapping{
		{ID: "a", Listen: ":9102", Target: "http://127.0.0.1:1"},
		{ID: "a", Listen: ":9103", Target: "http://127.0.0.1:1"},
	}, nil, nil); err == nil {
		t.Fatal("duplicate id should error")
	}
	if _, err := NewRouter([]Mapping{
		{Listen: ":9104", Target: "http://127.0.0.1:1"},
	}, nil, nil); err == nil {
		t.Fatal("missing id should error")
	}
	if _, err := NewRouter([]Mapping{
		{ID: "a", Listen: ":9105", Target: "http://127.0.0.1:1"},
	}, []ServiceCfg{{Name: "s", Channels: []string{"nope"}, Roles: []string{"x"}}}, []string{"x"}); err == nil {
		t.Fatal("bad channel ref should error")
	}
	if _, err := NewRouter([]Mapping{
		{ID: "a", Listen: ":9106", Target: "http://127.0.0.1:1"},
	}, []ServiceCfg{{Name: "s", Channels: []string{"a"}, Roles: []string{"x"}}, {Name: "s", Channels: []string{"a"}, Roles: []string{"x"}}}, []string{"x"}); err == nil {
		t.Fatal("duplicate service should error")
	}
	// 未声明的角色 → 报错
	if _, err := NewRouter([]Mapping{
		{ID: "a", Listen: ":9107", Target: "http://127.0.0.1:1"},
	}, []ServiceCfg{{Name: "s", Channels: []string{"a"}, Roles: []string{"ghost"}}}, []string{"x"}); err == nil {
		t.Fatal("undeclared role should error")
	}
	// "any" 禁止声明
	if _, err := NewRouter(nil, nil, []string{"any"}); err == nil {
		t.Fatal("declaring reserved any should error")
	}
}

func TestRolesAuth(t *testing.T) {
	r, err := NewRouter([]Mapping{
		{ID: "m1", Listen: ":9201", Target: "http://127.0.0.1:1"},
		{ID: "m2", Listen: ":9202", Target: "http://127.0.0.1:1"},
		{ID: "m3", Listen: ":9203", Target: "http://127.0.0.1:1"},
	}, []ServiceCfg{
		{Name: "svc-a", Channels: []string{"m1"}, Roles: []string{"ra", "rb"}},
		{Name: "svc-b", Channels: []string{"m2", "m1"}, Roles: []string{"rb", "rc"}}, // m1 被两个服务引用
		{Name: "svc-open", Channels: []string{"m3"}, Roles: []string{"any"}},         // 内置 any = 任意证书
	}, []string{"ra", "rb", "rc"})
	if err != nil {
		t.Fatal(err)
	}
	// 证书角色 rb → m1(经 svc-a 或 svc-b)、m2、m3 都可访问
	for _, port := range []string{"9201", "9202", "9203"} {
		if rt := r.Match(port, "/x"); rt == nil || !rt.Allows([]string{"rb"}) {
			t.Errorf("role rb should access %s", port)
		}
	}
	// m1 被 svc-a(ra,rb) 和 svc-b(rb,rc) 引用 → roles 并集 ra,rb,rc → rc 能进 m1
	if rt := r.Match("9201", "/x"); !rt.Allows([]string{"rc"}) {
		t.Error("m1 roles union = ra,rb,rc → rc allowed")
	}
	if rt := r.Match("9201", "/x"); rt.Allows([]string{"zz"}) {
		t.Error("zz should not access m1")
	}
	// any 服务: 任意证书可访问
	if rt := r.Match("9203", "/x"); !rt.Allows([]string{"zz"}) {
		t.Error("any service should allow zz")
	}
	// ServicesAllowed 按角色过滤
	svcs := r.ServicesAllowed([]string{"rb"})
	if len(svcs) != 3 {
		t.Errorf("rb should see 3 services, got %d", len(svcs))
	}
	svcs = r.ServicesAllowed([]string{"zz"})
	if len(svcs) != 1 || svcs[0].Name != "svc-open" {
		t.Errorf("zz should only see svc-open (any), got %+v", svcs)
	}
	// 通道索引引用
	r2, err := NewRouter([]Mapping{
		{ID: "a", Listen: ":9301", Target: "http://127.0.0.1:1"},
	}, []ServiceCfg{{Name: "s", Channels: []string{"0"}, Roles: []string{"x"}}}, []string{"x"})
	if err != nil || len(r2.ServicesAllowed([]string{"x"})) != 1 {
		t.Errorf("index channel ref failed: %v", err)
	}
}

func portOf(hostport string) string {
	for i := len(hostport) - 1; i >= 0; i-- {
		if hostport[i] == ':' {
			return hostport[i+1:]
		}
	}
	return ""
}

func get(u string) string {
	resp, err := http.Get(u)
	if err != nil {
		return "ERR " + err.Error()
	}
	defer resp.Body.Close()
	b := make([]byte, 512)
	n, _ := resp.Body.Read(b)
	return string(b[:n])
}

// L6: substitute/joinURLPath 边界(尾斜杠/双斜杠/空)
func TestSubstituteEdges(t *testing.T) {
	cases := []struct{ p, in, out, want string }{
		{"/admin/x", "/admin", "", "/x"},             // 剥入口前缀, 无出口 → /
		{"/admin/x", "/admin", "/", "/x"},            // 出口 / → /x
		{"/admin/", "/admin", "/admin2", "/admin2/"}, // 尾斜杠
		{"/x", "", "/base", "/base/x"},               // 无入口前缀
		{"/x", "", "", "/x"},                         // 无入口无出口
		{"/a//b", "", "/base", "/base/a//b"},         // 内部双斜杠保留
		{"/admin", "/admin", "/o", "/o/"},            // 完全匹配 → 出口(nginx 语义带尾斜杠)
		{"/admin/", "/admin/", "/o", "/o/"},          // 带尾斜杠入口
	}
	for _, c := range cases {
		if got := substitute(c.p, c.in, c.out); got != c.want {
			t.Errorf("substitute(%q,%q,%q) = %q, want %q", c.p, c.in, c.out, got, c.want)
		}
	}
}

// 第七批: NewRouter 深拷贝 — mutate 输入切片不影响 router 内部
func TestNewRouterDeepCopy(t *testing.T) {
	ms := []Mapping{{ID: "m1", Listen: ":9100", Target: "http://a"}}
	ss := []ServiceCfg{{Name: "s1", Channels: []string{"m1"}, Roles: []string{"any"}}}
	r, err := NewRouter(ms, ss, []string{"svc-a"})
	if err != nil {
		t.Fatal(err)
	}
	// 就地改写输入切片(模拟 configmgr Delete/Update 行为)
	ms[0].Listen = ":9999"
	ss[0].Roles[0] = "hacked"
	ss[0].Channels[0] = "hacked-ch"
	// router 内部不受影响(用 Listen + 匹配验证, Routes 已移除)
	if got := r.Listens(); len(got) != 1 || got[0] != "9100" {
		t.Fatalf("routes polluted: %+v", got)
	}
	if rt := r.Match("9100", "/"); rt == nil {
		t.Fatal("route m1 应仍可匹配")
	}
	if got := r.ServicesAllowed([]string{"any"}); len(got) != 1 || got[0].Name != "s1" {
		t.Fatalf("services polluted: %+v", got)
	}
}

// 第十三批: substitute/joinURLPath 清除 dot-segment(服务端防穿透)
func TestSubstituteCleanDotSegments(t *testing.T) {
	cases := []struct{ p, in, out, want string }{
		{"/admin/../admin/secret/x", "/admin", "", "/admin/secret/x"},
		{"/admin/../../x", "/admin", "/app", "/x"}, // .. 弹掉 app 前缀再钳制根
		{"/admin/a/../b", "/admin", "", "/b"},      // rest 内 .. 回退
		{"/admin/", "/admin", "", "/"},             // 剥空后根
	}
	for _, c := range cases {
		if got := substitute(c.p, c.in, c.out); got != c.want {
			t.Errorf("substitute(%q,%q,%q) = %q, want %q", c.p, c.in, c.out, got, c.want)
		}
	}
}

// —— 请求头改写(headers 配置 + 证书变量注入) ——

// headerRouter 构造带 headers 规则的路由器
func headerRouter(t *testing.T, rules []HeaderRule) *Router {
	t.Helper()
	r, err := NewRouter(
		[]Mapping{{ID: "m1", Listen: ":9601", Target: "http://127.0.0.1:1", Headers: rules}},
		[]ServiceCfg{{Name: "s1", Channels: []string{"m1"}, Roles: []string{"x"}}},
		[]string{"x"})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestHeaderRulesValidation 非法规则拒绝(新配置校验)
func TestHeaderRulesValidation(t *testing.T) {
	bad := [][]HeaderRule{
		{{Op: "bogus", Name: "X-A"}}, // op 非法
		{{Op: "set", Name: "  "}},    // name 空
	}
	for _, rules := range bad {
		if _, err := NewRouter(
			[]Mapping{{ID: "m1", Listen: ":9601", Target: "http://127.0.0.1:1", Headers: rules}},
			[]ServiceCfg{{Name: "s1", Channels: []string{"m1"}, Roles: []string{"x"}}},
			[]string{"x"}); err == nil {
			t.Fatalf("非法规则应报错: %+v", rules)
		}
	}
	// 合法规则通过
	headerRouter(t, []HeaderRule{{Op: "set", Name: "X-Client-Cert", Value: "{cert_name}"}})
}

// TestApplyHeaders 规则执行: set(变量注入) / del / 默认基线 / 先删后设防伪造 / 匿名空值不注入
func TestApplyHeaders(t *testing.T) {
	rt := headerRouter(t, []HeaderRule{
		{Op: "set", Name: "X-Client-Cert", Value: "{cert_name}"},
		{Op: "set", Name: "X-Client-Serial", Value: "serial:{cert_serial}"},
		{Op: "set", Name: "X-Client-Roles", Value: "{cert_roles}"},
		{Op: "del", Name: "X-Strip-Me"},
	}).Match("9601", "/")
	if rt == nil {
		t.Fatal("route not found")
	}

	req := httptest.NewRequest("GET", "/", nil)
	// 客户端伪造身份头 + 伪造转发头 + 要删的头
	req.Header.Set("X-Client-Cert", "FORGED")
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("X-Strip-Me", "x")
	rt.ApplyHeaders(req, HeaderVars{CertName: "dev-1", CertSerial: "ABC123", CertRoles: "dsh,staff", RemoteIP: "100.64.0.2"})

	// 先删后设: 伪造头被真实值覆盖
	if got := req.Header.Get("X-Client-Cert"); got != "dev-1" {
		t.Errorf("X-Client-Cert = %q, want dev-1(防伪造先删后设)", got)
	}
	if got := req.Header.Get("X-Client-Serial"); got != "serial:ABC123" {
		t.Errorf("X-Client-Serial = %q", got)
	}
	if got := req.Header.Get("X-Client-Roles"); got != "dsh,staff" {
		t.Errorf("X-Client-Roles = %q", got)
	}
	// 默认基线: 伪造转发头被删
	if req.Header.Get("X-Forwarded-For") != "" {
		t.Error("X-Forwarded-For 应被默认基线删除")
	}
	// del 规则
	if req.Header.Get("X-Strip-Me") != "" {
		t.Error("X-Strip-Me 应被 del 规则删除")
	}
}

// TestApplyHeadersAnonymous 匿名(null 路由): 证书变量为空 → 不注入空头, del 仍执行
func TestApplyHeadersAnonymous(t *testing.T) {
	rt := headerRouter(t, []HeaderRule{
		{Op: "set", Name: "X-Client-Cert", Value: "{cert_name}"},
		{Op: "del", Name: "X-Anon-Strip"},
	}).Match("9601", "/")
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Anon-Strip", "x")
	rt.ApplyHeaders(req, HeaderVars{RemoteIP: "100.64.0.9"}) // 无证书变量
	if req.Header.Get("X-Client-Cert") != "" {
		t.Error("匿名时证书头不应注入(空值)")
	}
	if req.Header.Get("X-Anon-Strip") != "" {
		t.Error("匿名时 del 规则仍应执行")
	}
}

// TestExpandVars 变量模板替换 + 未识别占位原样保留
func TestExpandVars(t *testing.T) {
	got := expandVars("cert={cert_name} serial={cert_serial} roles={cert_roles} ip={remote_ip} x={unknown}",
		HeaderVars{CertName: "a", CertSerial: "b", CertRoles: "c", RemoteIP: "d"})
	want := "cert=a serial=b roles=c ip=d x={unknown}"
	if got != want {
		t.Fatalf("expandVars = %q, want %q", got, want)
	}
}
