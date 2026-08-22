//go:build linux

// access_linux.go: Linux 权限检查实现(unix.Access; 禁 world 读密钥)。

package permissioncheck

import (
	"os"

	"golang.org/x/sys/unix"
)

// access 按当前进程 uid/gid 判定路径权限(含 root 特判), 不实际打开文件。
func access(path string, perm int) error {
	var m uint32
	if perm&Read != 0 {
		m |= unix.R_OK
	}
	if perm&Write != 0 {
		m |= unix.W_OK
	}
	return unix.Access(path, m)
}

// modePerm 返回路径权限位; stat 失败返回 0(不拦截, 由 access 报错)。
// mode 检查仅限 Linux: Windows 上 os.Stat 的 Perm() 恒 0666(不反映真实 ACL),
// 若在平台无关层检查会把全部密钥文件误判"权限过宽"拒绝启动(双进程回归)。
func modePerm(path string) os.FileMode {
	st, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return st.Mode().Perm()
}
