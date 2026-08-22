//go:build !linux

// access_other.go: 非 Linux 权限检查桩(Windows 无 POSIX 权限语义, 恒放行)。

package permissioncheck

import "os"

// access 非 Linux 平台不检查权限(用户要求仅 Linux), 恒返回成功。
func access(string, int) error { return nil }

// modePerm 非 Linux 恒 0(不检查 mode): Windows 上 os.Stat 的 Perm() 恒 0666,
// 若在平台无关层做 mode&ModeRestrict 检查会把全部密钥文件误判"权限过宽"拒绝启动。
func modePerm(string) os.FileMode { return 0 }
