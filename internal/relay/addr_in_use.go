//go:build !windows

// addr_in_use.go: 端口占用错误识别(非 Windows; EADDRINUSE/WSAEADDRINUSE 归一)。

package relay

import (
	"errors"
	"syscall"
)

// isAddrInUse 判断监听错误是否为"地址已占用"。
// Unix 平台: EADDRINUSE(仅 Linux/BSD; Windows 见 addr_in_use_windows.go)。
func isAddrInUse(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE)
}
