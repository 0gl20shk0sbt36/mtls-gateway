package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"
)

// Dialer 建立到网关后端的 mTLS 上行连接
type Dialer struct {
	ServerAddr string           // 网关后端地址 host:port
	ServerName string           // TLS SNI (可选)
	ClientCert *tls.Certificate // 取自证书缓存 (按 CertID)
	RootCAs    *x509.CertPool   // 验证网关服务器证书的根池 (nil=系统根)
	Timeout    time.Duration    // 连接超时
}

// Dial 建立一条到网关的 mTLS 连接 (TCP + TLS, 客户端证书)
func (d *Dialer) Dial(ctx context.Context) (net.Conn, error) {
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	dialer := &net.Dialer{Timeout: timeout}
	tlsCfg := &tls.Config{
		InsecureSkipVerify: false, // 默认验证网关服务器证书
		ServerName:         d.ServerName,
		RootCAs:            d.RootCAs,
		MinVersion:         tls.VersionTLS12,
	}
	if d.ClientCert != nil {
		tlsCfg.Certificates = []tls.Certificate{*d.ClientCert}
	}
	raw, err := dialer.DialContext(ctx, "tcp", d.ServerAddr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", d.ServerAddr, err)
	}
	client := tls.Client(raw, tlsCfg)
	if err := client.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("tls handshake to %s: %w", d.ServerAddr, err)
	}
	return client, nil
}
