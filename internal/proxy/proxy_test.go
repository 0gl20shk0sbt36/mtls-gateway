package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newEcho() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Path", r.URL.Path)
		w.Header().Set("X-Host", r.Host)
		w.WriteHeader(200)
		w.Write([]byte(r.URL.Path))
	}))
}

func TestLongestPrefixMatch(t *testing.T) {
	a := newEcho(); defer a.Close()
	b := newEcho(); defer b.Close()
	r, err := NewRouter([]Mapping{
		{Listen: ":9990/a", Target: a.URL, Services: []string{"svc-a"}},
		{Listen: ":9990/a/b", Target: b.URL, Services: []string{"svc-b"}},
	})
	if err != nil { t.Fatal(err) }
	cases := []struct{ path, want string }{
		{"/a/b/c", ":9990/a/b"},
		{"/a/x", ":9990/a"},
		{"/a/b", ":9990/a/b"},
		{"/a", ":9990/a"},
	}
	for _, c := range cases {
		m := r.Match("9990", c.path)
		if m == nil || m.Listen() != c.want {
			t.Errorf("Match(:9990 %q) = %v, want %s", c.path, m, c.want)
		}
	}
}

func TestBoundaryNoFalseMatch(t *testing.T) {
	a := newEcho(); defer a.Close()
	r, _ := NewRouter([]Mapping{{Listen: ":9990/a", Target: a.URL, Services: nil}})
	for _, p := range []string{"/ab", "/ax", "/a-b"} {
		if m := r.Match("9990", p); m != nil {
			t.Errorf("Match(%q) should be nil, got %v", p, m)
		}
	}
}

func TestWholePortFallbackAndServe(t *testing.T) {
	back := newEcho(); defer back.Close()
	r, _ := NewRouter([]Mapping{
		{Listen: ":9991/a", Target: back.URL, Services: nil}, // 带前缀
	})
	// 整口兜底: 无路径映射
	r2, _ := NewRouter([]Mapping{
		{Listen: ":9992", Target: back.URL, Services: nil},
	})
	if m := r.Match("9991", "/b"); m != nil {
		t.Errorf("no-path on :9991 should be nil (no whole), got %v", m)
	}
	_ = r2
	if m := r2.Match("9992", "/anything"); m == nil || m.Listen() != ":9992" {
		t.Errorf("whole-port fallback failed, got %v", m)
	}
}

func TestPrefixSubstitution(t *testing.T) {
	back := newEcho(); defer back.Close()
	r, _ := NewRouter([]Mapping{
		{Listen: ":9993/a", Target: back.URL, Services: nil},        // 剥 /a
		{Listen: ":9994", Target: back.URL + "/x", Services: nil},  // 补 /x
	})
	// 剥
	rec := httptest.NewRecorder()
	r.Serve(r.Match("9993", "/a/hello"), rec, httptest.NewRequest("GET", "http://t/a/hello", nil))
	if got := rec.Header().Get("X-Path"); got != "/hello" {
		t.Errorf("strip: backend path = %q, want /hello", got)
	}
	// 补
	rec2 := httptest.NewRecorder()
	r.Serve(r.Match("9994", "/p"), rec2, httptest.NewRequest("GET", "http://t/p", nil))
	if got := rec2.Header().Get("X-Path"); got != "/x/p" {
		t.Errorf("prepend: backend path = %q, want /x/p", got)
	}
}

func TestDuplicateListenError(t *testing.T) {
	a := newEcho(); defer a.Close()
	if _, err := NewRouter([]Mapping{
		{Listen: ":9995/a", Target: a.URL},
		{Listen: ":9995/a", Target: "http://127.0.0.1:9"},
	}); err == nil {
		t.Error("duplicate listen should error")
	} else if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("want duplicate error, got: %v", err)
	}
	// 同 target 不同 listen: 合法
	if _, err := NewRouter([]Mapping{
		{Listen: ":9995/a", Target: a.URL},
		{Listen: ":9996/b", Target: a.URL},
	}); err != nil {
		t.Errorf("same target different listen should be ok, got %v", err)
	}
}

func TestAllows(t *testing.T) {
	a := newEcho(); defer a.Close()
	r, _ := NewRouter([]Mapping{
		{Listen: ":9997", Target: a.URL, Services: []string{"svc-a", "svc-b"}},
		{Listen: ":9998", Target: a.URL, Services: []string{"any"}},
	})
	sa := r.Match("9997", "/")
	if !sa.Allows([]string{"svc-b"}) { t.Error("svc-b should be allowed") }
	if sa.Allows([]string{"svc-c"}) { t.Error("svc-c should be denied") }
	an := r.Match("9998", "/")
	if !an.Allows([]string{}) { t.Error("any should allow any (even empty)") }
}

func TestListens(t *testing.T) {
	a := newEcho(); defer a.Close()
	r, _ := NewRouter([]Mapping{
		{Listen: ":9443", Target: a.URL},
		{Listen: ":9445/admin", Target: a.URL},
	})
	got := r.Listens()
	if len(got) != 2 || got[0] != "9443" || got[1] != "9445" {
		t.Errorf("Listens = %v", got)
	}
}
