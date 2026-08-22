// needs.go: 启动权限检查项定义(GatewayNeeds 数据面 / AdminNeeds 管理面)。

package permissioncheck

import (
	"path/filepath"

	"mtls-gateway/internal/config"
)

// GatewayNeeds 网关(纯数据面只读消费者)的启动路径检查:
// 认证读 CA/服务器证书/私钥 + DB + 日志写。不查配置目录写(网关从不写配置, 写者是 mtls-admin)。
func GatewayNeeds(cfg config.Config) []Need {
	needs := []Need{
		{Path: cfg.CA, Perm: Read, Desc: "CA 证书(读)"},
		{Path: cfg.ServerCert, Perm: Read, Desc: "服务器证书(读)"},
		{Path: cfg.ServerKey, Perm: Read, Mode: ModeRestrict, Desc: "服务器私钥(读, 禁 world)"},
	}
	needs = append(needs, fileNeeds(cfg.DB, "SQLite 数据库", Read|Write, 0)...)
	needs = append(needs, fileNeeds(cfg.LogFile, "事件日志", Write, 0)...)
	needs = append(needs, fileNeeds(cfg.AccessLogFile, "访问日志", Write, 0)...)
	needs = append(needs, fileNeeds(cfg.StdoutLogFile, "标准日志(终端+文件双写)", Write, 0)...)
	return needs
}

// AdminNeeds 管理进程(唯一写者: DB/CA 签发/配置落盘)的启动路径检查:
// CA 私钥(mode 检查) + reload 客户端证书(mode 检查) + DB 读写 + 签发目录/socket/配置目录写。
func AdminNeeds(cfg config.Config, configPath string) []Need {
	needs := []Need{
		{Path: cfg.CA, Perm: Read, Desc: "CA 证书(读)"},
		{Path: cfg.CAKey, Perm: Read, Mode: ModeRestrict, Desc: "CA 私钥(读, 禁 world)"},
		{Path: cfg.ServerCert, Perm: Read, Desc: "服务器证书(读)"},
		{Path: cfg.ReloadCert, Perm: Read, Mode: ModeRestrict, Desc: "reload 客户端证书(读, 禁 world)"},
		{Path: cfg.ReloadKey, Perm: Read, Mode: ModeRestrict, Desc: "reload 客户端私钥(读, 禁 world)"},
	}
	needs = append(needs, fileNeeds(cfg.DB, "SQLite 数据库", Read|Write, 0)...)
	// 签发产物目录 + Unix socket 父目录 + 配置落盘目录(管理进程写 TOML)
	needs = append(needs, dirNeeds(cfg.CertDir, "签发证书目录")...)
	if cfg.SockPath != "" {
		needs = append(needs, Need{Path: filepath.Dir(cfg.SockPath), Perm: Write, Desc: "unix socket 目录(写)"})
	}
	if configPath != "" {
		needs = append(needs, Need{Path: filepath.Dir(configPath), Perm: Write, Desc: "配置文件目录(落盘写)"})
	}
	needs = append(needs, fileNeeds(cfg.LogFile, "事件日志", Write, 0)...)
	needs = append(needs, fileNeeds(cfg.AccessLogFile, "访问日志", Write, 0)...)
	needs = append(needs, fileNeeds(cfg.StdoutLogFile, "标准日志(终端+文件双写)", Write, 0)...)
	return needs
}
