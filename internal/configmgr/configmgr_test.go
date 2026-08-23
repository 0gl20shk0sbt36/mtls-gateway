package configmgr

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mtls-gateway/internal/config"
	"mtls-gateway/internal/proxy"
)

func testConfigManager(t *testing.T, mode string) (*ConfigManager, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	cfg := config.DefaultConfig()
	cfg.ConfigMode = mode
	cfg.Roles = []string{"x"}
	cfg.Mappings = []proxy.Mapping{{ID: "m1", Listen: ":9601", Target: "http://127.0.0.1:1"}}
	cfg.Services = []proxy.ServiceCfg{{Name: "s1", Channels: []string{"m1"}, Roles: []string{"x"}}}
	router, err := proxy.NewRouter(cfg.Mappings, cfg.Services, cfg.Roles)
	if err != nil {
		t.Fatal(err)
	}
	cm := New(path, cfg, router)
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

// TestConfigManagerPersistFailureRollback 复现 2026-08-21 22:18 生产事件:
// 落盘失败(目录不可写 → backup denied → 主写入失败)时, 内存 cfg 与 router 必须整体回滚,
// 不留下"内存已变、磁盘没写"的半态(此前该半态导致内存 services 变空、重启才恢复)。
// 用"config 路径指向目录"强制 rename 阶段失败 — 不依赖文件权限(root 跑测试同样复现)。
func TestConfigManagerPersistFailureRollback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.MkdirAll(path, 0o700); err != nil { // config.toml 位置是个目录 → rename 必然失败
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.ConfigMode = "mutable"
	cfg.Roles = []string{"x"}
	cfg.Mappings = []proxy.Mapping{{ID: "m1", Listen: ":9601", Target: "http://127.0.0.1:1"}}
	cfg.Services = []proxy.ServiceCfg{{Name: "s1", Channels: []string{"m1"}, Roles: []string{"x"}}}
	router, err := proxy.NewRouter(cfg.Mappings, cfg.Services, cfg.Roles)
	if err != nil {
		t.Fatal(err)
	}
	cm := New(path, cfg, router)

	// 22:18 场景: 批量保存提交空 services(ReplaceAll) → 落盘失败 → 必须整体回滚
	err = cm.ReplaceAll(
		[]proxy.Mapping{{ID: "m1", Listen: ":9700", Target: "http://127.0.0.1:9"}},
		nil, []string{"x"})
	if err == nil {
		t.Fatal("落盘失败时 ReplaceAll 应报错")
	}
	if !strings.Contains(err.Error(), "persist config") {
		t.Fatalf("错误应标明 persist 失败: %v", err)
	}
	// 内存 cfg 回滚: services 不得变空
	if n := len(cm.Services()); n != 1 || cm.Services()[0].Name != "s1" {
		t.Fatalf("persist 失败后内存 services 应回滚为原状, got %d: %+v", n, cm.Services())
	}
	if n := len(cm.Mappings()); n != 1 || cm.Mappings()[0].Listen != ":9601" {
		t.Fatalf("persist 失败后内存 mappings 应回滚为原状, got %d: %+v", n, cm.Mappings())
	}
	// router 回滚: 新 listen 不再匹配, 旧 listen 恢复匹配
	if rt := cm.Router().Match("9700", "/"); rt != nil {
		t.Fatal("persist 失败后 router 应回滚, :9700 不应匹配")
	}
	if rt := cm.Router().Match("9601", "/"); rt == nil {
		t.Fatal("persist 失败后 router 应回滚, :9601 应匹配")
	}

	// 单条 CRUD 同样回滚(AddService / AddMapping / DeleteService 方向相反的场景)
	if err := cm.AddService(proxy.ServiceCfg{Name: "s2", Channels: []string{"m1"}, Roles: []string{"x"}}); err == nil {
		t.Fatal("落盘失败时 AddService 应报错")
	}
	if n := len(cm.Services()); n != 1 {
		t.Fatalf("AddService persist 失败应回滚, got %d services", n)
	}
	if err := cm.AddMapping(proxy.Mapping{ID: "m2", Listen: ":9602", Target: "http://127.0.0.1:2"}); err == nil {
		t.Fatal("落盘失败时 AddMapping 应报错")
	}
	if n := len(cm.Mappings()); n != 1 {
		t.Fatalf("AddMapping persist 失败应回滚, got %d mappings", n)
	}
}

// TestConfigManagerReloadFromDisk 热重载: 配置文件变更后 ReloadFromDisk 生效; 坏配置失败保持旧状态
func TestConfigManagerReloadFromDisk(t *testing.T) {
	cm, path := testConfigManager(t, "mutable") // 初始: m1 :9601 + s1
	// 写一份可解析的初始配置文件(ReloadFromDisk 读它)
	initial := "roles = [\"x\"]\n\n[[mappings]]\nid = \"m1\"\nlisten = \":9601\"\ntarget = \"http://127.0.0.1:1\"\n\n[[services]]\nname = \"s1\"\nchannels = [\"m1\"]\nroles = [\"x\"]\n"
	if err := os.WriteFile(path, []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}
	// 配置变更: 新增 m2 :9602(模拟管理进程改配置)
	updated := "roles = [\"x\"]\n\n[[mappings]]\nid = \"m1\"\nlisten = \":9601\"\ntarget = \"http://127.0.0.1:1\"\n\n[[mappings]]\nid = \"m2\"\nlisten = \":9602\"\ntarget = \"http://127.0.0.1:2\"\n\n[[services]]\nname = \"s1\"\nchannels = [\"m1\"]\nroles = [\"x\"]\n"
	if err := os.WriteFile(path, []byte(updated), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cm.ReloadFromDisk(); err != nil {
		t.Fatalf("ReloadFromDisk: %v", err)
	}
	if n := len(cm.Mappings()); n != 2 {
		t.Fatalf("reload 后 mappings 应为 2, got %d", n)
	}
	if rt := cm.Router().Match("9602", "/"); rt == nil {
		t.Fatal("reload 后 :9602 应可匹配")
	}

	// 坏配置(重复 listen) → 报错 + 状态保持
	bad := "roles = [\"x\"]\n\n[[mappings]]\nid = \"m1\"\nlisten = \":9601\"\ntarget = \"http://127.0.0.1:1\"\n\n[[mappings]]\nid = \"m3\"\nlisten = \":9601\"\ntarget = \"http://127.0.0.1:3\"\n"
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cm.ReloadFromDisk(); err == nil {
		t.Fatal("坏配置 reload 应报错")
	}
	if n := len(cm.Mappings()); n != 2 {
		t.Fatalf("reload 失败后应保持旧状态(2 mappings), got %d", n)
	}
	if rt := cm.Router().Match("9602", "/"); rt == nil {
		t.Fatal("reload 失败后旧路由 :9602 应保持")
	}

	// 配置文件缺失 → 报错(不得静默用默认值清空路由)
	missing := filepath.Join(t.TempDir(), "nope.toml")
	cm2 := New(missing, config.DefaultConfig(), nil)
	if err := cm2.ReloadFromDisk(); err == nil {
		t.Fatal("配置文件缺失 reload 应报错")
	}
}

// S-2 防回归(pro 前瞻审计): ReloadFromDisk 拒绝安全字段(admin_role/require_ip_bind/
// tls_min_version)变更 — 网关 auth 启动固化, 接受新值会造成"校验新值/闸门旧值"分叉,
// admin_role 轮换时旧 admin 证书 stale-open 直到重启。
func TestReloadRejectsSecurityFieldChange(t *testing.T) {
	cm, path := testConfigManager(t, "mutable")
	initial := "roles = [\"x\"]\n\n[[mappings]]\nid = \"m1\"\nlisten = \":9601\"\ntarget = \"http://127.0.0.1:1\"\n\n[[services]]\nname = \"s1\"\nchannels = [\"m1\"]\nroles = [\"x\"]\n"
	if err := os.WriteFile(path, []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}
	// 三种安全字段任一变更 → 拒绝 + 状态保持
	variants := map[string]string{
		"admin_role":      "admin_role = \"opsadmin\"\n",
		"require_ip_bind": "require_ip_bind = false\n",
		"tls_min_version": "tls_min_version = \"1.3\"\n",
	}
	for name, extra := range variants {
		changed := extra + initial
		if err := os.WriteFile(path, []byte(changed), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := cm.ReloadFromDisk(); err == nil {
			t.Fatalf("%s 变更应被拒绝(S-2)", name)
		}
		// 状态保持: 旧 admin_role 等仍生效, mappings 不变
		if n := len(cm.Mappings()); n != 1 {
			t.Fatalf("%s 拒绝后 mappings 应保持 1, got %d", name, n)
		}
		if cm.AdminRole() != config.DefaultConfig().AdminRole {
			t.Fatalf("%s 拒绝后 admin_role 应保持默认, got %q", name, cm.AdminRole())
		}
	}
	// 恢复原配置后 reload 成功
	if err := os.WriteFile(path, []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cm.ReloadFromDisk(); err != nil {
		t.Fatalf("恢复后 reload 应成功: %v", err)
	}
}
