// Package permissioncheck 启动前文件/目录权限预检(网关与 mtls-admin 共用)。
//
// 背景: 2026-08-21 22:18 生产事件 — 配置目录不可写致落盘/备份静默失败、内存与磁盘分叉。
// 预检在启动时暴露"目录不可写/密钥权限过宽带病运行", 不足拒绝启动。
//
// 平台分派: Linux 用 unix.Access(按当前 uid/gid, 含 root 特判); 其余平台跳过
// (用户要求仅 Linux 检查)。
package permissioncheck

import (
	"fmt"
	"os"
	"path/filepath"
)

// 权限位(平台无关; 映射到 unix.R_OK/W_OK 在 access_linux.go)
const (
	Read  = 1 << iota // 可读
	Write             // 可写
)

// ModeRestrict 组合进 Need.Mode: 要求文件 mode & 0o077 == 0(拒绝 world 可读/可写)。
// 用于密钥/配置类敏感文件 — 世界可读的 CA 私钥/配置是提权面。
const ModeRestrict = 0o077

// Need 一条路径的权限要求
type Need struct {
	Path string // 空 = 跳过(可空配置字段)
	Perm int    // permissioncheck.Read / Write / 组合
	Mode int    // 0=不检查; 0o077=要求 mode&0o077==0
	Desc string // 用途描述(错误输出用)
}

// Check 检查全部路径, 返回失败描述列表(空 = 全部通过)。
// 文件已存在 → 检查其自身权限(+可选 mode); 不存在 → 检查父目录写权限(创建路径)。
func Check(needs []Need) []string {
	var fails []string
	for _, n := range needs {
		if n.Path == "" {
			continue
		}
		if err := access(n.Path, n.Perm); err != nil {
			fails = append(fails, fmt.Sprintf("%s (%s): %v", n.Path, n.Desc, err))
			continue
		}
		if n.Mode != 0 {
			if st, err := os.Stat(n.Path); err == nil && st.Mode().Perm()&os.FileMode(n.Mode) != 0 {
				fails = append(fails, fmt.Sprintf("%s (%s): 权限过宽 mode=%v(要求 mode&0o077==0)", n.Path, n.Desc, st.Mode().Perm()))
			}
		}
	}
	return fails
}

// Report 输出启动失败原因并退出(1):
//   - stderr 一定有权限(进程启动时 stderr 已打开) — "输出一定有权限";
//   - 尝试追加到事件日志文件(日志文件本身可能不可写 → 忽略错误, "没权限就算了")。
//
// 返回是否应退出(有失败)。
func Report(fails []string, logFile string) bool {
	if len(fails) == 0 {
		return false
	}
	msg := "启动失败: 文件/目录权限不足(拒绝带病运行):\n"
	for _, f := range fails {
		msg += "  - " + f + "\n"
	}
	fmt.Fprint(os.Stderr, msg)
	if logFile != "" {
		if f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
			fmt.Fprint(f, msg)
			f.Close()
		}
	}
	return true
}

// fileNeeds 文件路径权限要求: 已存在 → 检查 perm(+mode); 不存在 → 检查父目录写(创建文件)。
func fileNeeds(path, desc string, perm, mode int) []Need {
	if path == "" {
		return nil
	}
	if _, err := os.Stat(path); err == nil {
		return []Need{{Path: path, Perm: perm, Mode: mode, Desc: desc}}
	}
	return []Need{{Path: filepath.Dir(path), Perm: Write, Desc: desc + " 父目录(创建文件)"}}
}

// dirNeeds 目录路径权限要求: 已存在 → 检查写; 不存在 → 检查父目录写(创建目录)。
func dirNeeds(dir, desc string) []Need {
	if dir == "" {
		return nil
	}
	if st, err := os.Stat(dir); err == nil && st.IsDir() {
		return []Need{{Path: dir, Perm: Write, Desc: desc + "(写)"}}
	}
	return []Need{{Path: filepath.Dir(dir), Perm: Write, Desc: desc + " 父目录(创建目录)"}}
}
