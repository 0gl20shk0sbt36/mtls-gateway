// Package atomicfile 原子写文件: 目标目录内 CreateTemp 唯一临时文件 + rename。
//
// 崩溃/写失败不残留半截文件(目标要么旧内容要么新内容); 并发写同一路径不踩踏
// (各自唯一临时名); rename 为同文件系统原子操作, 不跟随符号链接。
// 收敛 configmgr.persist 与 relay.SaveConfig 的重复实现(P2 债)。
package atomicfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteFile 把 data 原子写入 path(权限 0600, 由 CreateTemp 保证)。
func WriteFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	defer os.Remove(tmp.Name())                // rename 失败/异常时清理残留
	if _, err := tmp.Write(data); err != nil { // 用句柄写(避免二次打开 + fd 泄漏)
		tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("replace: %w", err)
	}
	return nil
}
