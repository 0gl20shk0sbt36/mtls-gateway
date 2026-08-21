package logging

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestDefaultPath 分平台默认路径: 组件隔离 + .log 后缀 + 绝对路径
func TestDefaultPath(t *testing.T) {
	for _, comp := range []string{"mtls-gw", "mtls-relay"} {
		p := DefaultPath(comp, "events.log")
		if p == "" || !filepath.IsAbs(p) {
			t.Fatalf("%s 默认日志路径应为绝对路径: %q", comp, p)
		}
		if !strings.Contains(p, comp) {
			t.Errorf("%s 默认路径应含组件名: %q", comp, p)
		}
		if filepath.Ext(p) != ".log" {
			t.Errorf("%s 应为 .log: %q", comp, p)
		}
	}
	// 组件间隔离(不同子目录)
	gw, rl := DefaultPath("mtls-gw", "x.log"), DefaultPath("mtls-relay", "x.log")
	if gw == rl {
		t.Fatalf("组件日志目录应隔离: %q", gw)
	}
}
