//go:build linux

package permissioncheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mtls-gateway/internal/config"
)

// 构造一份全字段可用的网关配置(所有路径存在且可读写)
func permsOKConfig(t *testing.T) config.Config {
	t.Helper()
	dir := t.TempDir()
	file := func(name string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cfg := config.DefaultConfig()
	cfg.CA = file("ca.pem", 0o600)
	cfg.CAKey = file("ca.key", 0o600)
	cfg.ServerCert = file("server.pem", 0o600)
	cfg.ServerKey = file("server.key", 0o600)
	cfg.DB = filepath.Join(dir, "mtls.db") // 不存在: 检查父目录写
	cfg.CertDir = filepath.Join(dir, "certs")
	if err := os.MkdirAll(cfg.CertDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg.SockPath = filepath.Join(dir, "mtls.sock")
	cfg.LogFile = filepath.Join(dir, "events.log")
	cfg.AccessLogFile = filepath.Join(dir, "access.log")
	cfg.StdoutLogFile = filepath.Join(dir, "stdout.log")
	cfg.ReloadCert = file("reload.pem", 0o600)
	cfg.ReloadKey = file("reload.key", 0o600)
	return cfg
}

func TestGatewayNeedsOK(t *testing.T) {
	cfg := permsOKConfig(t)
	if fails := Check(GatewayNeeds(cfg)); len(fails) != 0 {
		t.Fatalf("全可用网关配置不应报权限失败: %v", fails)
	}
}

func TestAdminNeedsOK(t *testing.T) {
	cfg := permsOKConfig(t)
	if fails := Check(AdminNeeds(cfg, filepath.Join(t.TempDir(), "c.toml"))); len(fails) != 0 {
		t.Fatalf("全可用管理配置不应报权限失败: %v", fails)
	}
}

// 网关: 服务器私钥 world 可读 → mode 检查拒绝(不依赖 root, stat 检查)
func TestGatewayKeyModeRestrict(t *testing.T) {
	cfg := permsOKConfig(t)
	if err := os.Chmod(cfg.ServerKey, 0o644); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(cfg.ServerKey, 0o600)
	fails := Check(GatewayNeeds(cfg))
	found := false
	for _, f := range fails {
		if strings.Contains(f, "服务器私钥") && strings.Contains(f, "权限过宽") {
			found = true
		}
	}
	if !found {
		t.Fatalf("world 可读的服务器私钥应报 mode 失败: %v", fails)
	}
}

// 管理: CA 私钥 world 可读 → mode 检查拒绝
func TestAdminCAKeyModeRestrict(t *testing.T) {
	cfg := permsOKConfig(t)
	if err := os.Chmod(cfg.CAKey, 0o644); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(cfg.CAKey, 0o600)
	fails := Check(AdminNeeds(cfg, filepath.Join(t.TempDir(), "c.toml")))
	found := false
	for _, f := range fails {
		if strings.Contains(f, "CA 私钥") && strings.Contains(f, "权限过宽") {
			found = true
		}
	}
	if !found {
		t.Fatalf("world 可读的 CA 私钥应报 mode 失败: %v", fails)
	}
}

// 只读目录场景: 签发目录/日志/socket 父目录不可写 → 报失败
func TestAdminNeedsUnwritableDir(t *testing.T) {
	cfg := permsOKConfig(t)
	ro := filepath.Join(t.TempDir(), "ro")
	if err := os.MkdirAll(ro, 0o700); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(ro, 0o700)
	if err := os.Chmod(ro, 0o500); err != nil {
		t.Fatal(err)
	}
	cfg.CertDir = ro
	cfg.SockPath = filepath.Join(ro, "mtls.sock")
	cfg.LogFile = filepath.Join(ro, "events.log")
	fails := Check(AdminNeeds(cfg, filepath.Join(t.TempDir(), "c.toml")))
	if len(fails) < 3 {
		t.Fatalf("只读目录应至少报 3 项(cert_dir/日志/socket), got %d: %v", len(fails), fails)
	}
}

// 配置目录缺失(管理进程落盘) → 报失败
func TestAdminNeedsMissingConfigDir(t *testing.T) {
	cfg := permsOKConfig(t)
	missing := filepath.Join(t.TempDir(), "no-such-dir", "config.toml")
	fails := Check(AdminNeeds(cfg, missing))
	found := false
	for _, f := range fails {
		if strings.Contains(f, "配置文件目录") {
			found = true
		}
	}
	if !found {
		t.Fatalf("配置目录缺失应报失败: %v", fails)
	}
}

// Report: stderr 必有内容; 日志文件可写时追加成功
func TestReport(t *testing.T) {
	dir := t.TempDir()
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	defer func() { os.Stderr = oldStderr }()

	logFile := filepath.Join(dir, "events.log")
	fails := []string{"/etc/x (CA 私钥(读, 禁 world)): permission denied"}
	if !Report(fails, logFile) {
		t.Fatal("有失败应返回 true(需退出)")
	}
	w.Close()
	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	out := string(buf[:n])
	if !strings.Contains(out, "启动失败") || !strings.Contains(out, "permission denied") {
		t.Fatalf("stderr 应包含失败详情: %q", out)
	}
	data, err := os.ReadFile(logFile)
	if err != nil || !strings.Contains(string(data), "启动失败") {
		t.Fatalf("事件日志应被写入: %v %q", err, data)
	}
	// 无失败 → 不退出
	if Report(nil, "") {
		t.Fatal("无失败应返回 false")
	}
}
