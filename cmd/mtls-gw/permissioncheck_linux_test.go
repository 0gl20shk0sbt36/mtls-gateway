//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 构造一份全字段可用的配置(所有路径存在且可读写)
func permsOKConfig(t *testing.T) (Config, string) {
	t.Helper()
	dir := t.TempDir()
	file := func(name string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cfg := DefaultConfig()
	cfg.ConfigMode = "mutable"
	cfg.CA = file("ca.pem")
	cfg.CAKey = file("ca.key")
	cfg.ServerCert = file("server.pem")
	cfg.ServerKey = file("server.key")
	cfg.DB = filepath.Join(dir, "mtls.db") // 不存在: 检查父目录写
	cfg.CertDir = filepath.Join(dir, "certs")
	if err := os.MkdirAll(cfg.CertDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg.SockPath = filepath.Join(dir, "mtls.sock")
	cfg.LogFile = filepath.Join(dir, "events.log")
	cfg.AccessLogFile = filepath.Join(dir, "access.log")
	cfg.StdoutLogFile = filepath.Join(dir, "stdout.log")
	cfgPath = &dir // 配置目录(可写)
	return cfg, dir
}

func TestCheckStartupPathsOK(t *testing.T) {
	cfg, _ := permsOKConfig(t)
	defer func() { cfgPath = nil }()
	if fails := checkStartupPaths(cfg); len(fails) != 0 {
		t.Fatalf("全可用配置不应报权限失败: %v", fails)
	}
}

func TestCheckStartupPathsUnwritableDir(t *testing.T) {
	cfg, dir := permsOKConfig(t)
	defer func() { cfgPath = nil }()
	// 证书目录改只读(模拟 /etc/mtls-gw nobody:nogroup 755 + 服务其他用户)
	ro := filepath.Join(dir, "ro")
	if err := os.MkdirAll(ro, 0o700); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(ro, 0o700)
	if err := os.Chmod(ro, 0o500); err != nil {
		t.Fatal(err)
	}
	cfg.CertDir = ro
	cfg.LogFile = filepath.Join(ro, "events.log")       // 父目录不可写 → 报
	cfg.SockPath = filepath.Join(ro, "mtls.sock")       // 父目录不可写 → 报
	cfg.AccessLogFile = filepath.Join(ro, "access.log") // 父目录不可写 → 报

	fails := checkStartupPaths(cfg)
	if len(fails) < 3 {
		t.Fatalf("只读目录场景应至少报 3 项(cert_dir/日志/sock), got %d: %v", len(fails), fails)
	}
	joined := strings.Join(fails, "\n")
	for _, want := range []string{ro, "证书目录", "事件日志", "访问日志", "socket"} {
		if !strings.Contains(joined, want) {
			t.Errorf("失败输出应含 %q:\n%s", want, joined)
		}
	}
}

func TestCheckStartupPathsReadOnlyFile(t *testing.T) {
	cfg, dir := permsOKConfig(t)
	defer func() { cfgPath = nil }()
	// CA 私钥不可读(0000 → 属主也不可读; root 下 Access 不受 mode 限制, 跳过该断言)
	key := filepath.Join(dir, "ca.key")
	if err := os.Chmod(key, 0o000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(key, 0o600)
	if os.Geteuid() != 0 { // root 的 Access 不受 mode 限制, 无法构造失败场景
		fails := checkStartupPaths(cfg)
		found := false
		for _, f := range fails {
			if strings.Contains(f, "ca.key") && strings.Contains(f, "CA 私钥") {
				found = true
			}
		}
		if !found {
			t.Fatalf("CA 私钥不可读应报失败: %v", fails)
		}
	}
}

func TestCheckStartupPathsMissingParent(t *testing.T) {
	// 配置文件所在目录不存在 → 落盘检查报失败(配置错误显式暴露)
	dir := t.TempDir()
	missing := filepath.Join(dir, "no-such-dir", "config.toml")
	cfg := DefaultConfig()
	cfg.ConfigMode = "mutable"
	cfgPath = &missing
	defer func() { cfgPath = nil }()
	fails := checkStartupPaths(cfg)
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

// TestReportStartupFailures 失败输出: stderr 必有内容; 日志文件可写时追加成功, 不可写时静默跳过。
func TestReportStartupFailures(t *testing.T) {
	dir := t.TempDir()
	// stderr 捕获
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	defer func() { os.Stderr = oldStderr }()

	logFile := filepath.Join(dir, "events.log")
	cfg := DefaultConfig()
	cfg.LogFile = logFile
	fails := []string{"/etc/x (配置目录(落盘写)): permission denied"}
	reportStartupFailures(cfg, fails)

	w.Close()
	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	out := string(buf[:n])
	if !strings.Contains(out, "启动失败") || !strings.Contains(out, "permission denied") {
		t.Fatalf("stderr 应包含失败详情: %q", out)
	}
	// 日志文件被追加
	data, err := os.ReadFile(logFile)
	if err != nil || !strings.Contains(string(data), "启动失败") {
		t.Fatalf("事件日志应被写入(尽力而为): %v %q", err, data)
	}
}
