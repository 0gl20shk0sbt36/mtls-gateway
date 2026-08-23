// Package relay
//
// admin.go: 客户端"管理客户端" — 用一枚 admin 证书通过 mTLS 调用服务端 TCP admin API。
// 用于 WebUI 的证书签发/吊销(管理台), 使服务端无需单独的管理 WebUI。
// 实现已移至 internal/httpshared.AdminClient(A-4: relay 与 mtls-gw-cli TCP 模式共用),
// 本文件保留类型别名与兼容包装, relay 内部调用点零改动。
package relay

import (
	"crypto/tls"
	"crypto/x509"

	"mtls-gateway/internal/httpshared"
	"mtls-gateway/internal/types"
)

// 与 internal/types 对齐的类型别名 (管理 API DTO)
type (
	IssueRequest  = types.IssueRequest
	IssueResponse = types.IssueResponse
	MappingInfo   = types.MappingInfo
	ServiceInfo   = types.ServiceInfo
	ChannelInfo   = types.ChannelInfo
	AdminClient   = httpshared.AdminClient
)

// NewAdminClient addr=服务端 admin_listen (host:port), cert=admin 客户端证书, roots=网关 CA
// (实现移至 httpshared; 此处保留兼容包装, relay 调用点不改名)
func NewAdminClient(addr string, cert tls.Certificate, roots *x509.CertPool) *AdminClient {
	return httpshared.NewAdminClient(addr, cert, roots)
}
