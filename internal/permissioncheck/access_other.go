//go:build !linux

package permissioncheck

// access 非 Linux 平台不检查权限(用户要求仅 Linux), 恒返回成功。
func access(string, int) error { return nil }
