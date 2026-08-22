package configmgr

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"mtls-gateway/internal/config"
	"mtls-gateway/internal/proxy"
)

// 重新加载配置(模拟重启) — 测试用
func reloadConfigManager(t *testing.T, path string) (*ConfigManager, error) {
	t.Helper()
	cfg, err := config.Parse(path)
	if err != nil {
		return nil, err
	}
	router, err := proxy.NewRouter(cfg.Mappings, cfg.Services, cfg.Roles)
	if err != nil {
		return nil, err
	}
	return New(path, cfg, router), nil
}

// M3: UpdateMapping 成功 + 不存在报错
func TestConfigManagerUpdateMapping(t *testing.T) {
	cm, _ := testConfigManager(t, "mutable")
	// 先加 m2, 构造冲突场景
	if err := cm.AddMapping(proxy.Mapping{ID: "m2", Listen: ":9602", Target: "http://127.0.0.1:2"}); err != nil {
		t.Fatalf("add m2: %v", err)
	}
	upd := proxy.Mapping{ID: "m1", Listen: ":9701", Target: "http://127.0.0.1:9"}
	if err := cm.UpdateMapping("m1", upd); err != nil {
		t.Fatalf("update: %v", err)
	}
	m := cm.Mappings()[0]
	if m.Listen != ":9701" || m.Target != "http://127.0.0.1:9" {
		t.Fatalf("update not applied: %+v", m)
	}
	// 更新为重复 listen → 拒绝
	if err := cm.UpdateMapping("m1", proxy.Mapping{ID: "m1", Listen: ":9602", Target: "http://x"}); err == nil {
		t.Fatal("update to duplicate listen should be rejected")
	}
	if err := cm.UpdateMapping("ghost", proxy.Mapping{ID: "ghost", Listen: ":9702", Target: "http://x"}); err == nil {
		t.Fatal("update missing id should be rejected")
	}
}

// M3: DeleteMapping 成功 + 不存在报错
func TestConfigManagerDeleteMapping(t *testing.T) {
	cm, _ := testConfigManager(t, "mutable")
	if err := cm.AddMapping(proxy.Mapping{ID: "m2", Listen: ":9602", Target: "http://127.0.0.1:2"}); err != nil {
		t.Fatalf("add m2: %v", err)
	}
	if err := cm.DeleteMapping("m2"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if len(cm.Mappings()) != 1 || cm.Mappings()[0].ID != "m1" {
		t.Fatalf("delete not applied: %+v", cm.Mappings())
	}
	if err := cm.DeleteMapping("ghost"); err == nil {
		t.Fatal("delete missing id should be rejected")
	}
}

// M3: AddService / UpdateService / DeleteService
func TestConfigManagerServiceCRUD(t *testing.T) {
	cm, _ := testConfigManager(t, "mutable")
	// AddService(角色 x 已声明)
	if err := cm.AddService(proxy.ServiceCfg{Name: "web", Channels: []string{"m1"}, Roles: []string{"x"}}); err != nil {
		t.Fatalf("add service: %v", err)
	}
	if len(cm.Services()) != 2 {
		t.Fatalf("expected 2 services, got %d", len(cm.Services()))
	}
	// 重复 name
	if err := cm.AddService(proxy.ServiceCfg{Name: "web", Channels: []string{"m1"}, Roles: []string{"x"}}); err == nil {
		t.Fatal("duplicate service name should be rejected")
	}
	// 未声明角色
	if err := cm.AddService(proxy.ServiceCfg{Name: "web2", Channels: []string{"m1"}, Roles: []string{"ghost"}}); err == nil {
		t.Fatal("undeclared role should be rejected")
	}
	// 引用不存在通道
	if err := cm.AddService(proxy.ServiceCfg{Name: "web2", Channels: []string{"ghost"}, Roles: []string{"x"}}); err == nil {
		t.Fatal("bad channel ref should be rejected")
	}
	// UpdateService
	if err := cm.UpdateService("web", proxy.ServiceCfg{Name: "web", Channels: []string{"m1"}, Roles: []string{"x"}}); err != nil {
		t.Fatalf("update service: %v", err)
	}
	// 更新后角色引用 ghost → 拒绝
	if err := cm.UpdateService("web", proxy.ServiceCfg{Name: "web", Channels: []string{"m1"}, Roles: []string{"ghost"}}); err == nil {
		t.Fatal("update with undeclared role should be rejected")
	}
	if err := cm.UpdateService("ghost", proxy.ServiceCfg{Name: "ghost", Channels: []string{"m1"}, Roles: []string{"x"}}); err == nil {
		t.Fatal("update missing name should be rejected")
	}
	// DeleteService
	if err := cm.DeleteService("web"); err != nil {
		t.Fatalf("delete service: %v", err)
	}
	if len(cm.Services()) != 1 {
		t.Fatalf("expected 1 service, got %d", len(cm.Services()))
	}
	if err := cm.DeleteService("ghost"); err == nil {
		t.Fatal("delete missing name should be rejected")
	}
}

// M3: AddRole / DeleteRole(被引用禁止删 / 保留字 / 重复)
func TestConfigManagerRoleCRUD(t *testing.T) {
	cm, _ := testConfigManager(t, "mutable")
	// AddRole
	if err := cm.AddRole("ops"); err != nil {
		t.Fatalf("add role: %v", err)
	}
	if len(cm.Roles()) != 2 {
		t.Fatalf("expected 2 roles, got %d", len(cm.Roles()))
	}
	// 重复
	if err := cm.AddRole("ops"); err == nil {
		t.Fatal("duplicate role should be rejected")
	}
	// any 禁声明
	if err := cm.AddRole("any"); err == nil {
		t.Fatal("any cannot be declared")
	}
	// 非法名
	if err := cm.AddRole("a b"); err == nil {
		t.Fatal("bad role name should be rejected")
	}
	// 被服务引用禁止删除(x 被 s1 引用)
	if err := cm.DeleteRole("x"); err == nil {
		t.Fatal("role referenced by service cannot be deleted")
	}
	// 正常删除
	if err := cm.DeleteRole("ops"); err != nil {
		t.Fatalf("delete role: %v", err)
	}
	// 不存在
	if err := cm.DeleteRole("ghost"); err == nil {
		t.Fatal("delete missing role should be rejected")
	}
}

// M3: ReplaceAll 整体替换成功 + 校验失败回滚
func TestConfigManagerReplaceAll(t *testing.T) {
	cm, _ := testConfigManager(t, "mutable")
	ms := []proxy.Mapping{{ID: "n1", Listen: ":9801", Target: "http://127.0.0.1:1"}, {ID: "n2", Listen: ":9802", Target: "http://127.0.0.1:2"}}
	ss := []proxy.ServiceCfg{{Name: "svc-n", Channels: []string{"n1", "n2"}, Roles: []string{"svc-a"}}}
	if err := cm.ReplaceAll(ms, ss, []string{"svc-a"}); err != nil {
		t.Fatalf("replace: %v", err)
	}
	if len(cm.Mappings()) != 2 || len(cm.Services()) != 1 || len(cm.Roles()) != 1 {
		t.Fatalf("replace not applied: %d/%d/%d", len(cm.Mappings()), len(cm.Services()), len(cm.Roles()))
	}
	// 失败回滚: 重复 listen
	bad := []proxy.Mapping{{ID: "x1", Listen: ":9801", Target: "http://x"}, {ID: "x2", Listen: ":9801", Target: "http://x"}}
	if err := cm.ReplaceAll(bad, ss, []string{"svc-a"}); err == nil {
		t.Fatal("replace with dup listen should be rejected")
	}
	if len(cm.Mappings()) != 2 || cm.Mappings()[0].ID != "n1" {
		t.Fatalf("rollback failed: %+v", cm.Mappings())
	}
}

// M3: mutable 落盘 round-trip(TOML 读回全等)
func TestConfigManagerPersistRoundTrip(t *testing.T) {
	cm, path := testConfigManager(t, "mutable")
	if err := cm.AddRole("ops"); err != nil {
		t.Fatalf("add role: %v", err)
	}
	// 重新加载(模拟重启)
	cm2, err := reloadConfigManager(t, path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(cm2.Mappings()) != len(cm.Mappings()) || len(cm2.Services()) != len(cm.Services()) || len(cm2.Roles()) != len(cm.Roles()) {
		t.Fatalf("round-trip mismatch: %d/%d vs %d/%d", len(cm2.Mappings()), len(cm2.Services()), len(cm.Mappings()), len(cm.Services()))
	}
	if cm2.Mappings()[0].Listen != cm.Mappings()[0].Listen || cm2.Mappings()[0].Target != cm.Mappings()[0].Target {
		t.Fatalf("mapping content mismatch: %+v vs %+v", cm2.Mappings()[0], cm.Mappings()[0])
	}
}

// M3: ephemeral 不落盘 + 不建备份
func TestConfigManagerEphemeralNoBackup(t *testing.T) {
	cm, path := testConfigManager(t, "ephemeral")
	if err := cm.AddMapping(proxy.Mapping{ID: "tmp", Listen: ":9901", Target: "http://127.0.0.1:1"}); err != nil {
		t.Fatalf("add: %v", err)
	}
	// 文件未变 + 无备份
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.Contains(string(data), "9901") {
		t.Fatal("ephemeral should not persist")
	}
	backs, _ := filepath.Glob(path + ".bak-*")
	if len(backs) != 0 {
		t.Fatalf("ephemeral should not create backups: %v", backs)
	}
	// 重载后无 tmp
	cm2, err := reloadConfigManager(t, path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	for _, m := range cm2.Mappings() {
		if m.Listen == ":9901" {
			t.Fatal("ephemeral mapping persisted across reload")
		}
	}
}

// 第九批: persist 原子写(临时文件唯一/无残留/权限/内容 round-trip)
func TestConfigManagerPersistAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gw.toml")
	cm := New(path, config.Config{ConfigMode: "mutable"}, nil)
	if err := cm.AddRole("svc-x"); err != nil {
		t.Fatal(err)
	}
	// 无 tmp-* 残留 + 权限 0600
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("stale tmp: %s", e.Name())
		}
	}
	// 权限 0600(Unix 语义; Windows 上 os.Stat 的 Perm() 恒 0666, 无意义)
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(path)
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("perm %v, want 0600", st.Mode().Perm())
		}
	}
	// round-trip
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "svc-x") {
		t.Fatalf("config content missing role: %s", data)
	}
	// 备份限量: 多次 persist 后 .bak-* ≤ 6(限量5+可能本次)
	for i := 0; i < 8; i++ {
		cm.AddRole(fmt.Sprintf("r%d", i))
	}
	baks := 0
	for _, e := range entries2(dir) {
		if strings.Contains(e, ".bak-") {
			baks++
		}
	}
	if baks > 6 {
		t.Fatalf("backups = %d, want ≤6", baks)
	}
}

func entries2(dir string) []string {
	var out []string
	es, _ := os.ReadDir(dir)
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

// 中危(测试全面性审计): 保留字分支 — null/admin_role 禁声明, "any" 禁删
func TestConfigManagerReservedRoleBranches(t *testing.T) {
	cm, _ := testConfigManager(t, "mutable")
	if err := cm.AddRole("null"); err == nil {
		t.Fatal("null 禁声明")
	}
	if err := cm.AddRole(cm.AdminRole()); err == nil {
		t.Fatal("admin_role 禁声明为普通角色")
	}
	if err := cm.DeleteRole("any"); err == nil {
		t.Fatal("any 禁删除(内置保留字)")
	}
}

// pro 深度审计补: ReplaceAll 必须拒绝 admin_role 进 roles 声明(与 config.Parse/AddRole 对称;
// 此前 ReplaceAll 直接赋 m.cfg.Roles 绕过校验, 可持久化网关拒载配置)
func TestReplaceAllRejectsAdminRoleInRoles(t *testing.T) {
	cm, _ := testConfigManager(t, "mutable")
	if err := cm.ReplaceAll(nil, nil, []string{cm.AdminRole(), "x"}); err == nil || !strings.Contains(err.Error(), "禁止出现在 roles 声明列表") {
		t.Fatalf("ReplaceAll 含 admin_role 的 roles 应拒绝: %v", err)
	}
	if err := cm.ReplaceAll(nil, nil, []string{"x", "y"}); err != nil {
		t.Fatalf("正常 ReplaceAll 应通过: %v", err)
	}
}
