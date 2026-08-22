//go:build windows

package relay

import (
	"errors"
	"syscall"
)

// isAddrInUse 判断监听错误是否为"地址已占用"。
// Windows: 真实套接字错误是 WSAEADDRINUSE(10048), 而 syscall.EADDRINUSE 是
// 为跨平台编译定义的"发明值"(536870914), 两者永不相等 —
// 原实现(仅比较 EADDRINUSE)导致同端口多路由复用功能在 Windows 上静默失效。
func isAddrInUse(err error) bool {
	return errors.Is(err, syscall.Errno(10048)) // WSAEADDRINUSE
}
