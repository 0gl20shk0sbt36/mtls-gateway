package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 写入临时配置并 Parse; 返回 cfg/err
func parseFixture(t *testing.T, content string) (Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return Parse(path)
}

// Parse 各校验分支(安全关键: admin_role/保留字/角色声明一致性)
func TestParseValidation(t *testing.T) {
	cases := []struct {
		name    string
		content string
		wantErr string // 期望错误包含子串; 空=期望成功
	}{
		{"admin_role=any 拒绝", "admin_role = \"any\"\n", "admin_role"},
		{"admin_role=null 拒绝", "admin_role = \"null\"\n", "admin_role"},
		{"admin_role 非法名拒绝", "admin_role = \"bad role!\"\n", "admin_role"},
		{"admin_role 在 roles 声明列表拒绝(提权)", "admin_role = \"staff\"\nroles = [\"staff\"]\n", "禁止出现在 roles 声明列表"},
		{"bad config_mode 拒绝", "config_mode = \"bogus\"\n", "config_mode"},
		{"服务 roles 含 admin_role 拒绝", "roles = [\"x\"]\nadmin_role = \"y\"\n[[mappings]]\nid=\"m\"\nlisten=\":1\"\ntarget=\"http://x\"\n[[services]]\nname=\"s\"\nchannels=[\"m\"]\nroles=[\"y\"]\n", "不允许出现内置管理角色"},
		{"bad key_bits 拒绝", "key_type = \"rsa\"\nkey_bits = 1024\n", "key_bits"},
		{"重复角色拒绝", "roles = [\"x\", \"x\"]\n", "duplicate role"},
		{"角色非法名拒绝", "roles = [\"x y\"]\n", "bad role name"},
		{"角色 any 声明拒绝(保留字)", "roles = [\"any\"]\n", "any"},
		{"角色 null 声明拒绝(保留字)", "roles = [\"null\"]\n", "null"},
		{"合法配置通过", "admin_role = \"mtls-superadmin\"\nroles = [\"x\"]\n", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, perr := parseFixture(t, c.content)
			if c.wantErr == "" {
				if perr != nil {
					t.Fatalf("应解析成功: %v", perr)
				}
				if cfg.AdminRole != "mtls-superadmin" {
					t.Fatalf("默认 admin_role 应为 mtls-superadmin: %q", cfg.AdminRole)
				}
				return
			}
			if perr == nil {
				t.Fatalf("应报错(含 %q), 却成功: %+v", c.wantErr, cfg)
			}
			if !strings.Contains(perr.Error(), c.wantErr) {
				t.Fatalf("错误应含 %q: %v", c.wantErr, perr)
			}
		})
	}
}

// 配置文件缺失 → 报错(不静默用默认值 — reload/启动一致性)
func TestParseMissingFile(t *testing.T) {
	if _, err := Parse(filepath.Join(t.TempDir(), "nope.toml")); err == nil {
		t.Fatal("配置文件缺失应报错")
	}
}

func TestRequireIPBindResolved(t *testing.T) {
	// nil → 默认 true
	cfg := DefaultConfig()
	if !cfg.RequireIPBindResolved() {
		t.Fatal("nil RequireIPBind 应默认 true")
	}
	// 显式 false
	f := false
	cfg.RequireIPBind = &f
	if cfg.RequireIPBindResolved() {
		t.Fatal("显式 false 应返回 false")
	}
	// 显式 true
	t2 := true
	cfg.RequireIPBind = &t2
	if !cfg.RequireIPBindResolved() {
		t.Fatal("显式 true 应返回 true")
	}
}

func TestResolveListen(t *testing.T) {
	if got := ResolveListen("0.0.0.0", ":9444"); got != "0.0.0.0:9444" {
		t.Fatalf("端口拼接: %q", got)
	}
	if got := ResolveListen("100.64.0.1", ":9444"); got != "100.64.0.1:9444" {
		t.Fatalf("bindHost 拼接: %q", got)
	}
	if got := ResolveListen("0.0.0.0", "127.0.0.1:1"); got != "127.0.0.1:1" {
		t.Fatalf("绝对地址原样: %q", got)
	}
	if got := ResolveListen("0.0.0.0", ""); got != "" {
		t.Fatalf("空串: %q", got)
	}
	// IPv6 回归用例: 修复动机场景 — 字符串拼接产出非法 ":::9444", JoinHostPort 产出 "[::]:9444"
	if got := ResolveListen("::", ":9444"); got != "[::]:9444" {
		t.Fatalf("IPv6 bind_host=%q: got %q, want \"[::]:9444\"", "::", got)
	}
}
