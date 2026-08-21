//go:build android

// Android 的 system 源: 应用沙箱内无统一系统证书库(系统信任锚只读且无私钥),
// 退化为"约定证书目录"的 dir 语义 — 与 Linux 一致, 目录可经 MTLS_CERT_DIR 覆盖。
// 未来扩展点: Android Keystore(KeyChain/Keystore API, 硬件背书密钥, 通常需 gomobile 桥接)。
package certsource

import (
	"fmt"
	"os"
	"path/filepath"
)

func openSystemImpl() (Source, error) {
	dir := os.Getenv("MTLS_CERT_DIR")
	if dir == "" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			dir = filepath.Join(home, ".mtls-gw", "certs")
		}
	}
	if dir == "" {
		return nil, fmt.Errorf("android: no cert dir (set MTLS_CERT_DIR)")
	}
	return openDirImpl(dir)
}
