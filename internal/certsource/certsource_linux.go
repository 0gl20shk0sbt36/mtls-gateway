//go:build linux && !android

package certsource

import (
	"fmt"
	"os"
	"path/filepath"
)

// Linux 无统一身份证书库 (/etc/ssl/certs 只含 CA 信任锚, 基本无私钥,
// 不能用于 mTLS 客户端认证). 因此"系统证书源" = 约定统一证书目录:
//
//	用户级 ~/.mtls-gw/certs/  (对齐 mtls-gw-cli 导出目录的客户端侧约定)
//	系统级 /etc/mtls-gw/certs/ (只读, 可选)
//
// 目录中每个子目录一个证书 (<name>/cert.pem + <name>/key.pem), 或 *.p12.
func openSystemImpl() (Source, error) {
	var candidates []string
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		candidates = append(candidates, filepath.Join(home, ".mtls-gw", "certs"))
	}
	candidates = append(candidates, "/etc/mtls-gw/certs")

	for _, dir := range candidates {
		st, err := os.Stat(dir)
		if err == nil && st.IsDir() {
			return openDirImpl(dir)
		}
	}
	return nil, fmt.Errorf("no unified cert dir found (tried %v); use --source dir or --source file", candidates)
}
