//go:build linux

// 启动前文件/目录权限预检: mtls-gw 用到的所有路径(配置/DB/CA/证书/日志/sock/落盘目录)
// 权限不足 → 拒绝启动(报错输出到 stderr, 并尝试写事件日志; 日志无权限则跳过)。
// 背景: 2026-08-21 22:18 生产事件 —— /etc/mtls-gw 属主 nobody 而服务以 yyx 运行,
// 配置落盘/备份静默失败导致内存与磁盘分叉; 若启动时即检查权限, 可第一时间暴露而非带病运行。
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// pathNeed 一条路径的权限要求
type pathNeed struct {
	path string // 空 = 跳过(可空配置字段)
	perm int    // unix.R_OK / unix.W_OK / 组合
	desc string // 用途描述(错误输出用)
}

// checkStartupPaths 启动前检查全部文件/目录权限, 返回失败描述列表(空 = 全部通过)。
// 用 unix.Access(2) 按当前进程 uid/gid 判定(含 root 特判), 不实际打开文件。
// 文件已存在 → 检查其自身权限; 不存在 → 检查父目录写权限(创建路径)。
func checkStartupPaths(cfg Config) []string {
	var fails []string
	for _, n := range startupPathNeeds(cfg) {
		if n.path == "" {
			continue
		}
		if err := unix.Access(n.path, uint32(n.perm)); err != nil {
			fails = append(fails, fmt.Sprintf("%s (%s): %v", n.path, n.desc, err))
		}
	}
	return fails
}

// startupPathNeeds 汇总配置引用的全部文件/目录及其权限要求。
// 可空字段(path=="")自动跳过; 文件不存在时改查父目录写权限(自动创建)。
func startupPathNeeds(cfg Config) []pathNeed {
	needs := []pathNeed{
		{cfg.CA, unix.R_OK, "CA 证书(读)"},
		{cfg.CAKey, unix.R_OK, "CA 私钥(读)"},
		{cfg.ServerCert, unix.R_OK, "服务器证书(读)"},
		{cfg.ServerKey, unix.R_OK, "服务器私钥(读)"},
	}
	// DB: 已存在=读写; 不存在=父目录可写(首次启动创建)
	needs = append(needs, filePermNeed(cfg.DB, "SQLite 数据库", unix.R_OK|unix.W_OK)...)
	// 签发产物目录: 需可写
	if cfg.CertDir != "" {
		needs = append(needs, dirPermNeed(cfg.CertDir, "签发证书目录")...)
	}
	// Unix socket: 父目录可写
	if cfg.SockPath != "" {
		needs = append(needs, pathNeed{filepath.Dir(cfg.SockPath), unix.W_OK, "unix socket 目录(写)"})
	}
	// 事件/访问/标准日志: 文件存在=可写; 不存在=父目录可写
	needs = append(needs, filePermNeed(cfg.LogFile, "事件日志", unix.W_OK)...)
	needs = append(needs, filePermNeed(cfg.AccessLogFile, "访问日志", unix.W_OK)...)
	needs = append(needs, filePermNeed(cfg.StdoutLogFile, "标准日志(终端+文件双写)", unix.W_OK)...)
	// 配置落盘(mutable): 配置文件父目录需可写(22:18 事件根因)
	if cfg.ConfigMode != "ephemeral" && cfgPath != nil && *cfgPath != "" {
		needs = append(needs, pathNeed{filepath.Dir(*cfgPath), unix.W_OK, "配置文件目录(落盘写)"})
	}
	return needs
}

// filePermNeed 文件路径权限要求: 已存在 → 检查 perm; 不存在 → 检查父目录写(创建文件)。
// path 空 → 返回空(跳过)。
func filePermNeed(path, desc string, perm int) []pathNeed {
	if path == "" {
		return nil
	}
	if _, err := os.Stat(path); err == nil {
		return []pathNeed{{path, perm, desc}}
	}
	return []pathNeed{{filepath.Dir(path), unix.W_OK, desc + " 父目录(创建文件)"}}
}

// dirPermNeed 目录路径权限要求: 已存在 → 检查写; 不存在 → 检查父目录写(创建目录)。
func dirPermNeed(dir, desc string) []pathNeed {
	if dir == "" {
		return nil
	}
	if st, err := os.Stat(dir); err == nil && st.IsDir() {
		return []pathNeed{{dir, unix.W_OK, desc + "(写)"}}
	}
	return []pathNeed{{filepath.Dir(dir), unix.W_OK, desc + " 父目录(创建目录)"}}
}

// reportStartupFailures 输出启动失败原因并退出(1):
//   - stderr 一定有权限(进程启动时 stderr 已打开) — 用户要求"输出一定有权限";
//   - 尝试追加到事件日志文件(日志文件本身可能不可写 → 忽略错误, "没权限就算了")。
func reportStartupFailures(cfg Config, fails []string) {
	msg := "mtls-gw 启动失败: 文件/目录权限不足(拒绝带病运行):\n"
	for _, f := range fails {
		msg += "  - " + f + "\n"
	}
	fmt.Fprint(os.Stderr, msg)
	if cfg.LogFile != "" {
		if f, err := os.OpenFile(cfg.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
			fmt.Fprint(f, msg)
			f.Close()
		}
	}
}
