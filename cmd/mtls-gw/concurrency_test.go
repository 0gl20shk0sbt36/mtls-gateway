package main

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"mtls-gateway/internal/config"
	"mtls-gateway/internal/configmgr"
	"mtls-gateway/internal/proxy"
)

// MH-2/M-3: configmgr 并发 CRUD 不崩 + 最终一致(-race 下运行)
func TestConfigManagerConcurrent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	cfg := config.DefaultConfig()
	cfg.ConfigMode = "ephemeral"
	cfg.Roles = []string{"x"}
	cfg.Mappings = []proxy.Mapping{{ID: "m1", Listen: ":9601", Target: "http://127.0.0.1:1"}}
	cfg.Services = []proxy.ServiceCfg{{Name: "s1", Channels: []string{"m1"}, Roles: []string{"x"}}}
	router, _ := proxy.NewRouter(cfg.Mappings, cfg.Services, cfg.Roles)
	cm := configmgr.New(path, cfg, router)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			id := fmt.Sprintf("cm%d", n) // 避开初始 m1(且不用 listen 9601 段)
			for j := 0; j < 20; j++ {
				_ = cm.AddMapping(proxy.Mapping{ID: id, Listen: fmt.Sprintf(":%d", 20000+n*100+j), Target: "http://127.0.0.1:1"})
				_ = cm.DeleteMapping(id)
			}
		}(i)
	}
	wg.Wait()
	// 并发下不崩 + 路由器仍可用
	if cm.Router() == nil {
		t.Fatal("router nil after concurrent ops")
	}
	// 配置内容仍合法(不要求精确, 但必须能重建)
	if _, err := proxy.NewRouter(cm.Mappings(), cm.Services(), cm.Roles()); err != nil {
		t.Fatalf("config corrupted by concurrent ops: %v", err)
	}
}
