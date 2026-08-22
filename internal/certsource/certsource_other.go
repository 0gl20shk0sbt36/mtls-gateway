//go:build !windows && !linux && !android

// 未支持平台(macOS/FreeBSD 等): system 源不可用。
// 返回清晰错误而非含糊的编译失败(undefined: openSystemImpl)。
// 平台分派与 permissioncheck 同理: linux/android 走真实实现, 其余平台显式报错/跳过。
package certsource

import "fmt"

func openSystemImpl() (Source, error) {
	return nil, fmt.Errorf("system cert source not supported on this platform (use --source dir or --source file)")
}
