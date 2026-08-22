// Package logging 日志路径的平台分派(跨平台默认位置)。
//
// 平台默认:
//   - Windows: 可执行文件同目录下的组件子目录(便携式, 与 relay 配置一致, 不写用户文件夹;
//     子目录保证同目录多进程 mtls-gw/mtls-admin 日志互不污染)
//   - Linux/其他: 用户缓存目录 $XDG_CACHE_HOME/<component> 或 ~/.cache/<component>
//     (用户级无需特权; 生产部署可显式配置 /var/log/<component>/...)
//
// 组件命名空间: "mtls-gw"(服务端) / "mtls-relay"(客户端中继), 各组件日志互不污染。
package logging

import (
	"os"
	"path/filepath"
	"runtime"
)

// DefaultDir 返回组件的平台默认日志目录(不存在时由调用方创建)。
func DefaultDir(component string) string {
	if runtime.GOOS == "windows" {
		// 可执行文件同目录 + 组件子目录(便携式, 不写用户文件夹):
		// 组件子目录保证同目录多进程(mtls-gw + mtls-admin)日志互不污染 —
		// 否则两者默认路径相同, mtls-admin 的"强制组件路径"替换在 Windows 上失效。
		if exe, err := os.Executable(); err == nil {
			return filepath.Join(filepath.Dir(exe), component)
		}
		return filepath.Join(".", component)
	}
	if dir, err := os.UserCacheDir(); err == nil && dir != "" {
		return filepath.Join(dir, component)
	}
	return filepath.Join(os.TempDir(), component)
}

// DefaultPath 返回组件下某日志文件的平台默认路径(如 "events.log")。
func DefaultPath(component, name string) string {
	return filepath.Join(DefaultDir(component), name)
}
