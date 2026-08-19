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
