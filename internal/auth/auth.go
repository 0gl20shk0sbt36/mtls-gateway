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
	store    *db.Store
	caPool   *x509.CertPool
	serverTLS *tls.Config
}

// 用途常量
const (
	PurposeAdmin = "admin"
)

// New 创建认证器, 加载 CA 和服务器证书
// caPath: 受信 CA 证书路径
// serverCertPath/serverKeyPath: 网关自己的 TLS 证书
func New(store *db.Store, caPath, serverCertPath, serverKeyPath string) (*Gateway, error) {
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
	g := &Gateway{
		store:  store,
		caPool: pool,
		serverTLS: &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    pool,
			MinVersion:   tls.VersionTLS12,
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
// 返回: purpose 授权结果, 或错误
func (g *Gateway) Authorize(r *http.Request) (string, error) {
	cert, err := certFromRequest(r)
	if err != nil {
		return "", err
	}

	// 1. 取证书 SAN IP (绑定检查用)
	var sanIP string
	for _, ip := range cert.IPAddresses {
		sanIP = ip.String()
		break // 证书只绑一个 TS IP
	}

	// 2. IP 预检: 证书绑定的 IP 必须等于来源 IP (防私钥复制到别的设备)
	remote := RemoteIP(r)
	if sanIP != "" && sanIP != remote {
		return "", fmt.Errorf("ip bind mismatch: cert=%s remote=%s", sanIP, remote)
	}

	// 3. 内存查表: 序列号 → 记录
	serial := cert.SerialNumber.String()
	rec, ok := g.store.Get(serial)
	if !ok {
		return "", fmt.Errorf("cert %s not registered", serial)
	}
	if rec.Status != "enabled" {
		return "", fmt.Errorf("cert %s status=%s", serial, rec.Status)
	}
	// 过期检查
	if rec.ExpiresAt != "" && rec.ExpiresAt < timeNow() {
		return "", fmt.Errorf("cert %s expired", serial)
	}

	// 4. 返回用途 (权限由数据库决定, 不读证书字段)
	return rec.Purpose, nil
}

// IsAdminPurpose 判断用途是否 admin
func IsAdminPurpose(purpose string) bool { return purpose == PurposeAdmin }

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
