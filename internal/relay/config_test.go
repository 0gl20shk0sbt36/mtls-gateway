package relay

import (
	"path/filepath"
	"testing"
)

// 首次启动自动生成默认配置: 不存在→生成模板; 已存在→不覆盖
func TestEnsureDefaultConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "config.json") // 目录不存在, 也应自动创建

	created, err := EnsureDefaultConfig(path)
	if err != nil {
		t.Fatalf("EnsureDefaultConfig: %v", err)
	}
	if !created {
		t.Fatal("首次调用应返回 created=true")
	}
	// 生成的文件可被 LoadConfig 读回(默认 listen_host + 空 tunnels)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.ListenHost != "127.0.0.1" {
		t.Errorf("默认 ListenHost = %q, want 127.0.0.1", cfg.ListenHost)
	}
	if cfg.Tunnels == nil {
		t.Error("默认 Tunnels 应为空数组而非 null")
	}

	// 已存在 → 不覆盖, 返回 false
	created, err = EnsureDefaultConfig(path)
	if err != nil || created {
		t.Fatalf("已存在时: created=%v err=%v, want false,nil", created, err)
	}
}
