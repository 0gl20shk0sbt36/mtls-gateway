package pathutil

import "testing"

func TestCleanDotSegments(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/admin/../../x", "/x"},
		{"/../x", "/x"},
		{"/..", "/"},
		{"/a/./b", "/a/b"},
		{"/a//b", "/a//b"},
		{"/admin/", "/admin/"},
		{"/a/b/../../c", "/c"},
		{"/a/../../../b", "/b"},
		{"/a/..", "/"},
	}
	for _, c := range cases {
		if got := CleanDotSegments(c.in); got != c.want {
			t.Errorf("CleanDotSegments(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// 第十七批: 反斜杠 dot-segment + 短路
func TestCleanDotSegmentsBackslash(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/admin\\..\\secret", "/secret"},
		{"/admin\\x", "/admin/x"}, // 反斜杠归一化
		{"/admin/.\\..\\x", "/x"},
		{"/plain/path", "/plain/path"}, // 短路: 原样
		{"/admin/", "/admin/"},
	}
	for _, c := range cases {
		if got := CleanDotSegments(c.in); got != c.want {
			t.Errorf("CleanDotSegments(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
