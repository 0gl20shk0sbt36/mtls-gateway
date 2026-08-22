//go:build !linux

package permissioncheck

import (
	"os"
	"path/filepath"
	"testing"
)

// 非 Linux 平台: mode 检查必须不触发。
// 背景: Windows 上 os.Stat 的 Perm() 恒为 0666, 若在平台无关层做 mode&ModeRestrict
// 检查会把全部密钥文件误判"权限过宽" → mtls-gw/mtls-admin 一旦有密钥文件就拒绝启动。
// 本测试随 CI windows-test job 在 Windows 上执行, 防止该平台回归再次漏网。
func TestModeCheckSkippedNonLinux(t *testing.T) {
	p := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if modePerm(p)&os.FileMode(ModeRestrict) != 0 {
		t.Fatal("非 Linux 平台 modePerm 应恒 0(即使文件 world 可读)")
	}
	if fails := Check([]Need{{Path: p, Perm: Read, Mode: ModeRestrict, Desc: "test key"}}); len(fails) != 0 {
		t.Fatalf("非 Linux 平台不应报 mode 权限失败: %v", fails)
	}
}
