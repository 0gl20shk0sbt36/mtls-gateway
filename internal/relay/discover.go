// discover.go: 客户端通过服务端 /info 发现可用服务(规则)。
//
// 思路: 客户端只需配一个发现端点(RelayConfig.ServerAddr, 即服务端 /info 的 mTLS 入口),
// 调用 /info 拿回规则列表; 每条规则自带入口 listen 端口, 隧道据此 dial 对应入口即可,
// 中继保持透明(URL 前缀由应用侧路径携带, 匹配在服务端完成)。
package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// ServiceInfo 服务端 /info 返回的一条映射(服务)
type ServiceInfo struct {
	Listen   string   `json:"listen"`   // ":9443" 或 ":9445/admin"
	Services []string `json:"services"` // 允许的用途; ["any"]=任一已登记
	Target   string   `json:"target"`   // 后端 URL
}

// DiscoverResult /info 响应包装
type DiscoverResult struct {
	Mappings []ServiceInfo `json:"mappings"`
}

// discoverHTTPClient 为该次发现构造带客户端证书的 HTTPS 客户端(验服务端证书用 rootCAs)。
func discoverHTTPClient(addr string, cert *tls.Certificate, rootCAs *x509.CertPool) *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{*cert},
			RootCAs:      rootCAs,
			ServerName:   stripPort(addr),
		},
	}
	return &http.Client{Transport: tr, Timeout: 8 * time.Second}
}

// Discover 向服务端 /info 拉取可用服务。
// 需要 Relay 已配置 ServerAddr(发现端点), 并至少能从来源取到一枚证书(用做 mTLS 客户端证书)。
func (r *Relay) Discover() ([]ServiceInfo, error) {
	r.mu.Lock()
	addr := r.serverAddr
	serverCA := r.serverCA
	rootCAs := r.rootCAs
	r.mu.Unlock()
	if addr == "" {
		return nil, fmt.Errorf("relay: server address not configured")
	}
	cert, err := r.loadFirstCert()
	if err != nil {
		return nil, fmt.Errorf("relay: no client cert for discovery: %w", err)
	}
	// 未 Start 时 rootCAs 可能未构建; 有 serverCA 则现建根池
	if rootCAs == nil && serverCA != "" {
		pool, err := loadCAPool(serverCA)
		if err != nil {
			return nil, err
		}
		rootCAs = pool
	}
	ep := "https://" + addr + "/info"
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	cli := discoverHTTPClient(addr, &cert, rootCAs)
	resp, err := cli.Do(req)
	if err != nil {
		return nil, fmt.Errorf("relay: discover %s: %w", ep, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("relay: /info HTTP %d: %s", resp.StatusCode, firstLine(string(b)))
	}
	var out DiscoverResult
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("relay: parse /info: %w", err)
	}
	return out.Mappings, nil
}

// loadFirstCert 取来源里第一枚可用证书(用于发现/默认)
func (r *Relay) loadFirstCert() (tls.Certificate, error) {
	r.mu.Lock()
	metas, err := r.src.List()
	r.mu.Unlock()
	if err != nil {
		return tls.Certificate{}, err
	}
	if len(metas) == 0 {
		return tls.Certificate{}, fmt.Errorf("no certificates in source")
	}
	return r.loadCert(metas[0].ID)
}

// loadCAPool 从 CA 文件构建根池(用于验证网关服务器证书)
func loadCAPool(caFile string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read server_ca %s: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("parse server_ca %s failed", caFile)
	}
	return pool, nil
}

// stripPort 从 host:port 取 host(用于 TLS ServerName)。
func stripPort(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

// portOfListen 从 ":9443[/path]" 取端口; 失败返回空串。
func portOfListen(l string) string {
	p := strings.TrimPrefix(l, ":")
	if i := strings.IndexByte(p, '/'); i >= 0 {
		p = p[:i]
	}
	return p
}

func firstLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' || s[i] == '\r' {
			return s[:i]
		}
	}
	return s
}
