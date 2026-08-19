package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mtls-gateway/internal/proxy"
)

func testConfigManager(t *testing.T, mode string) (*ConfigManager, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	cfg := DefaultConfig()
	cfg.ConfigMode = mode
	cfg.Roles = []string{"x"}
	cfg.Mappings = []proxy.Mapping{{ID: "m1", Listen: ":9601", Target: "http://127.0.0.1:1"}}
	cfg.Services = []proxy.ServiceCfg{{Name: "s1", Channels: []string{"m1"}, Roles: []string{"x"}}}
	router, err := proxy.NewRouter(cfg.Mappings, cfg.Services, cfg.Roles)
	if err != nil {
		t.Fatal(err)
	}
	cm := NewConfigManager(path, cfg, router)
	// 写一份初始配置文件 (mutable 落盘测试用)
	_ = os.WriteFile(path, []byte("bind_host = \"127.0.0.1\"\n"), 0o600)
	return cm, path
}

func TestConfigManagerMutablePersists(t *testing.T) {
	cm, path := testConfigManager(t, "mutable")
	if err := cm.AddMapping(proxy.Mapping{ID: "m2", Listen: ":9602", Target: "http://127.0.0.1:2"}); err != nil {
		t.Fatal(err)
	}
	// 热重载生效
	if len(cm.Mappings()) != 2 {
		t.Fatalf("want 2 mappings, got %d", len(cm.Mappings()))
	}
	// 落盘: 文件应包含新映射
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), ":9602") {
		t.Fatal("mutable: new mapping not persisted")
	}
	// 备份存在
	entries, _ := os.ReadDir(filepath.Dir(path))
	found := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "config.toml.bak-") {
			found = true
		}
	}
	if !found {
		t.Fatal("mutable: no backup file created")
	}
}

func TestConfigManagerEphemeralNotPersisted(t *testing.T) {
	cm, path := testConfigManager(t, "ephemeral")
	if err := cm.AddMapping(proxy.Mapping{ID: "m2", Listen: ":9603", Target: "http://127.0.0.1:2"}); err != nil {
		t.Fatal(err)
	}
	if len(cm.Mappings()) != 2 {
		t.Fatalf("ephemeral: runtime should have 2, got %d", len(cm.Mappings()))
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), ":9603") {
		t.Fatal("ephemeral: must NOT persist to file")
	}
}

func TestConfigManagerImmutableRejects(t *testing.T) {
	cm, _ := testConfigManager(t, "immutable")
	if err := cm.AddMapping(proxy.Mapping{ID: "m2", Listen: ":9604", Target: "http://127.0.0.1:2"}); err == nil {
		t.Fatal("immutable: add must be rejected")
	}
	if err := cm.DeleteService("s1"); err == nil {
		t.Fatal("immutable: delete must be rejected")
	}
	if len(cm.Mappings()) != 1 {
		t.Fatal("immutable: config must not change")
	}
}

func TestConfigManagerValidationRollback(t *testing.T) {
	cm, _ := testConfigManager(t, "mutable")
	// 重复 listen → 应拒绝且回滚
	if err := cm.AddMapping(proxy.Mapping{ID: "m2", Listen: ":9601", Target: "http://127.0.0.1:2"}); err == nil {
		t.Fatal("duplicate listen should be rejected")
	}
	if len(cm.Mappings()) != 1 {
		t.Fatalf("rollback failed: got %d mappings", len(cm.Mappings()))
	}
}
