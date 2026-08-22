//go:build linux

package permissioncheck

import (
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
