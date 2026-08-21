// Package certsource 提供 mTLS 客户端证书的来源抽象。
//
// 核心层(relay)不感知平台差异:Windows 有系统证书库("My" 存储),
// Linux 无统一身份库, 用约定证书目录作为"库";两者都带文件(pem/p12)兜底。
// 具体实现按 build tag 隔离 (certsource_windows.go / certsource_linux.go),
// certsource_file.go 为跨平台兜底。
package certsource

import (
	"crypto/tls"
	"fmt"
)

// SourceType 证书来源类型
type SourceType string

const (
	// System 系统证书源: Windows = 系统证书库(My); Linux = 统一证书目录
	System SourceType = "system"
	// Dir 指定目录扫描 (通用, 跨平台)
	Dir SourceType = "dir"
	// File 单个文件 pem/p12 (通用, 跨平台)
	File SourceType = "file"
)

// IdentityMeta 一个可选的证书身份 (展示用元数据)
type IdentityMeta struct {
	ID         string `json:"id"` // 稳定标识 (Windows thumbprint | 目录相对路径 | 文件路径)
	CommonName string `json:"common_name"`
	Issuer     string `json:"issuer"`
	ValidFrom  string `json:"valid_from"`
	ValidUntil string `json:"valid_until"`
	FoundIn    string `json:"found_in"` // 如 "system:My" | "dir:~/.mtls-gw/certs" | "file:path"
}

// Source 证书来源: 列出候选身份, 按 ID 加载可用的 mTLS 客户端证书
type Source interface {
	// List 列出所有可选身份
	List() ([]IdentityMeta, error)
	// Load 按 ID 加载 tls.Certificate, 用于 mTLS 客户端认证
	Load(id string) (tls.Certificate, error)
}

// LoaderWithPassword 支持带密码加载的源 (加密私钥 / 需密码的 p12)
type LoaderWithPassword interface {
	LoadWithPassword(id, password string) (tls.Certificate, error)
}

// OpenSystem 打开"系统证书源" (跨平台分派):
//   - Windows: 系统证书库 "My" 存储
//   - Linux:   统一证书目录 (~/.mtls-gw/certs, /etc/mtls-gw/certs)
//
// 由平台实现文件提供 (certsource_windows.go / certsource_linux.go)。
func OpenSystem() (Source, error) { return openSystemImpl() }

// OpenDir 打开指定目录扫描源 (每子目录一个证书, 或顶层 *.p12)
func OpenDir(dir string) (Source, error) {
	return openDirImpl(dir)
}

// OpenFile 打开单个 pem/p12 文件源
func OpenFile(path string) (Source, error) {
	return &fileSource{path: path}, nil
}

// New 按类型 + 参数创建一个来源。
//   - System: 系统来源 (arg 忽略)
//   - Dir:    arg = 目录路径
//   - File:   arg = 文件路径
func New(typ SourceType, arg string) (Source, error) {
	switch typ {
	case System:
		return OpenSystem()
	case Dir:
		if arg == "" {
			return nil, fmt.Errorf("dir source requires a directory path")
		}
		return OpenDir(arg)
	case File:
		if arg == "" {
			return nil, fmt.Errorf("file source requires a file path")
		}
		return OpenFile(arg)
	default:
		return nil, fmt.Errorf("unknown source type %q", typ)
	}
}

// ApplyGwFilter 设置来源只展示由 org 签发的证书。
// winSource / dirSource 支持过滤; fileSource 单个文件无需过滤(忽略)。
// org 为空时不过滤。
func ApplyGwFilter(src Source, org string, showAll bool) {
	if org == "" {
		return
	}
	if f, ok := src.(interface{ SetFilter(string, bool) }); ok {
		f.SetFilter(org, showAll)
	}
}

// ApplyIssuerFilter 按 CA 主题过滤证书源: 只展示由该 CA(issuer 匹配主题)签发的证书。
// 空主题 = 不过滤。用于 system 证书源(只显示自家 CA 签发的身份, 过滤 Adobe 等无关证书)。
func ApplyIssuerFilter(src Source, caSubject string) {
	if caSubject == "" {
		return
	}
	if f, ok := src.(interface{ SetIssuerFilter(string) }); ok {
		f.SetIssuerFilter(caSubject)
	}
}
