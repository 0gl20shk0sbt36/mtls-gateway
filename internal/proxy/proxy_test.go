package proxy

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newEcho() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ECHO " + r.Method + " " + r.URL.Path + " HOST=" + r.Host))
	}))
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

	if got := get("http://127.0.0.1:9003/a/hello"); got != "ECHO GET /hello HOST="+back.Listener.Addr().String() {
		t.Errorf("strip: %q", got)
	}
	if got := get("http://127.0.0.1:9003/a/x"); got != "ECHO GET /x HOST="+back.Listener.Addr().String() {
		t.Errorf("strip /a/x: %q", got)
	}
	if got := get("http://127.0.0.1:9004/p"); got != "ECHO GET /x/p HOST="+back.Listener.Addr().String() {
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
		{Name: "svc-open", Channels: []string{"m3"}, Roles: []string{"any"}},        // 内置 any = 任意证书
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
		{"/admin/x", "/admin", "", "/x"},        // 剥入口前缀, 无出口 → /
		{"/admin/x", "/admin", "/", "/x"},       // 出口 / → /x
		{"/admin/", "/admin", "/admin2", "/admin2/"}, // 尾斜杠
		{"/x", "", "/base", "/base/x"},          // 无入口前缀
		{"/x", "", "", "/x"},                    // 无入口无出口
		{"/a//b", "", "/base", "/base/a//b"},    // 内部双斜杠保留
		{"/admin", "/admin", "/o", "/o/"},      // 完全匹配 → 出口(nginx 语义带尾斜杠)
		{"/admin/", "/admin/", "/o", "/o/"},    // 带尾斜杠入口
	}
	for _, c := range cases {
		if got := substitute(c.p, c.in, c.out); got != c.want {
			t.Errorf("substitute(%q,%q,%q) = %q, want %q", c.p, c.in, c.out, got, c.want)
		}
	}
}
