// Package auth 实现 mTLS 认证与授权。
// 流程: TLS 握手验证 CA → IP 预检(SAN vs 来源) → 内存表查权限(serial)
// 权限判断完全依赖内部数据库, 不读证书里的名字/用途字段。
package auth

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"mtls-gateway/internal/db"
)

// Gateway 认证器
type Gateway struct {
	store         *db.Store
	caPool        *x509.CertPool
	serverTLS     *tls.Config
	requireIPBind bool   // 是否强制 IP 绑定 (默认 true; false = 允许不绑 IP 的证书)
	AdminRole     string // 内置管理角色名 (config admin_role, 默认 mtls-superadmin)
}

// DefaultAdminRole 内置管理角色的默认名(可通过 config admin_role 覆盖; 勿用常用名)
const DefaultAdminRole = "mtls-superadmin"

// New 创建认证器, 加载 CA 和服务器证书
// caPath: 受信 CA 证书路径
// serverCertPath/serverKeyPath: 网关自己的 TLS 证书
// requireIPBind: true=强制证书 SAN IP 必须等于来源 IP (默认); false=跳过 IP 预检
// adminRole: 内置管理角色名 (config admin_role)
// tlsMinVersion: "1.2" 或 "1.3"
func New(store *db.Store, caPath, serverCertPath, serverKeyPath string, requireIPBind bool, adminRole, tlsMinVersion string) (*Gateway, error) {
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("parse ca pem")
	}
	cert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load server cert: %w", err)
	}
	if adminRole == "" {
		adminRole = DefaultAdminRole
	}
	var minV uint16 = tls.VersionTLS12
	switch tlsMinVersion {
	case "", "1.2":
		minV = tls.VersionTLS12
	case "1.3":
		minV = tls.VersionTLS13
	default:
		return nil, fmt.Errorf("bad tls_min_version %q (want 1.2/1.3)", tlsMinVersion)
	}
	g := &Gateway{
		store:         store,
		caPool:        pool,
		requireIPBind: requireIPBind,
		AdminRole:     adminRole,
		serverTLS: &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    pool,
			MinVersion:   minV,
		},
	}
	return g, nil
}

// ServerTLSConfig 返回给监听器用的 TLS 配置
func (g *Gateway) ServerTLSConfig() *tls.Config { return g.serverTLS }

// certFromRequest 从请求的 TLS 连接提取客户端证书
func certFromRequest(r *http.Request) (*x509.Certificate, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no client cert")
	}
	return r.TLS.PeerCertificates[0], nil
}

// RemoteIP 获取真实来源 IP (tailscale0 解封后的 100.x)
func RemoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Authorize 核心授权流程:
//  1. 取客户端证书 (serial, SAN IP)
//  2. IP 预检: SAN IP == 来源 IP (不等立刻拒, 不碰数据库)
//  3. 内存查表: 证书在册? 启用? → 返回用途
//
// 返回: 证书身份记录 (含权限列表), 或错误
func (g *Gateway) Authorize(r *http.Request) (*db.CertRecord, error) {
	cert, err := certFromRequest(r)
	if err != nil {
		return nil, err
	}

	// 1. 取证书 SAN IP (绑定检查用)
	var sanIP string
	for _, ip := range cert.IPAddresses {
		sanIP = ip.String()
		break // 证书只绑一个 TS IP
	}

	// 2. IP 预检: 证书绑定的 IP 必须等于来源 IP (防私钥复制到别的设备)
	//    仅当 requireIPBind=true (默认); false = 允许不绑 IP 的证书 (配置显式关闭)
	remote := RemoteIP(r)
	if g.requireIPBind {
		if sanIP != "" && sanIP != remote {
			return nil, fmt.Errorf("ip bind mismatch: cert=%s remote=%s", sanIP, remote)
		}
		// 证书没绑 IP 时, 视为未绑定 → 拒绝 (除非关闭 IP 绑定要求)
		if sanIP == "" {
			return nil, fmt.Errorf("cert has no IP bind but require_ip_bind=true")
		}
	}
	// requireIPBind=false: 跳过 IP 预检, 仅凭证书身份授权

	// 3. 内存查表: 序列号 → 记录
	serial := cert.SerialNumber.String()
	rec, ok := g.store.Get(serial)
	if !ok {
		return nil, fmt.Errorf("cert %s not registered", serial)
	}
	if rec.Status != "enabled" {
		return nil, fmt.Errorf("cert %s status=%s", serial, rec.Status)
	}
	// 过期检查
	if rec.ExpiresAt != "" && rec.ExpiresAt < timeNow() {
		return nil, fmt.Errorf("cert %s expired", serial)
	}

	// 4. 返回证书身份记录 (权限列表由数据库决定, 不读证书字段)
	return &rec, nil
}

// AuthorizePurposes 返回该证书可访问的用途列表 (等价于返回 rec.Purposes)
func (g *Gateway) AuthorizePurposes(r *http.Request) ([]string, error) {
	rec, err := g.Authorize(r)
	if err != nil {
		return nil, err
	}
	return rec.Purposes, nil
}

// IsAdminPurpose 判断用途是否 admin
func IsAdminPurpose(purpose string) bool { return purpose == DefaultAdminRole }

// IsAdmin 判断记录是否持有内置管理角色(实例化后的 admin_role)
func (g *Gateway) IsAdmin(rec *db.CertRecord) bool { return rec.HasPurpose(g.AdminRole) }

// SerialHex 格式化序列号为可读 hex
func SerialHex(serial []byte) string { return hex.EncodeToString(serial) }

// 便于测试注入
var timeNow = func() string {
	// 简化为 yyyy-mm-dd 比较
	return nowDate()
}

// nowDate 返回当前 UTC 日期 yyyy-mm-dd
func nowDate() string {
	return time.Now().UTC().Format("2006-01-02")
}

// AuthLog 记录认证事件
func AuthLog(purpose, remote, serial string, ok bool) {
	status := "ALLOW"
	if !ok {
		status = "DENY"
	}
	log.Printf("auth[%s] purpose=%s remote=%s serial=%s", status, purpose, remote, serial)
}
