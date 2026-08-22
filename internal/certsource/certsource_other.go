//go:build !windows && !linux && !android

// 未支持平台(macOS/FreeBSD 等): system 源不可用。
// 返回清晰错误而非含糊的编译失败(undefined: openSystemImpl), 与 permissioncheck 的
// 非 Linux 跳过策略一致。
package certsource

import "fmt"

func openSystemImpl() (Source, error) {
	return nil, fmt.Errorf("system cert source not supported on this platform (use --source dir or --source file)")
}
