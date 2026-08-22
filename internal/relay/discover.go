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
	"mtls-gateway/internal/errs"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// ServiceInfo 服务端 /info 返回的一个服务(含其全部通道)
type ServiceInfo struct {
	Name     string        `json:"name"`     // 服务名
	Channels []ChannelInfo `json:"channels"` // 该服务的通道列表
}

// ChannelInfo 服务的一个通道
type ChannelInfo struct {
	Listen string `json:"listen"` // ":9443" 或 ":9445/admin"
	Target string `json:"target"` // 后端 URL
}

// DiscoverResult /info 响应包装
type DiscoverResult struct {
	Services []ServiceInfo `json:"services"`
}

// discoverHTTPClient 为该次发现构造带客户端证书的 HTTPS 客户端(验服务端证书用 rootCAs)。
func discoverHTTPClient(addr string, cert *tls.Certificate, rootCAs *x509.CertPool) *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{*cert},
			RootCAs:      rootCAs,
			ServerName:   stripPort(addr),
			MinVersion:   tls.VersionTLS12, // 纵深防御: 与服务端/其它客户端一致
		},
		IdleConnTimeout: 30 * time.Second, // 空闲连接主动到期回收, 不依赖对端 FIN
	}
	return &http.Client{Transport: tr, Timeout: 8 * time.Second}
}

// Discover 向服务端 /info 拉取可用服务(默认用来源第一枚证书)。
func (r *Relay) Discover() ([]ServiceInfo, error) {
	cert, err := r.loadFirstCert()
	if err != nil {
		return nil, fmt.Errorf("%s: %v", r.lang().S("errNoCert"), err)
	}
	return r.DiscoverWithCert(cert)
}

// DiscoverWithCert 用指定证书做 /info 发现(WebUI 验证时用所选证书)。
func (r *Relay) DiscoverWithCert(cert tls.Certificate) ([]ServiceInfo, error) {
	r.mu.Lock()
	addr := r.serverAddr
	serverCA := r.serverCA
	rootCAs := r.rootCAs
	r.mu.Unlock()
	if addr == "" {
		return nil, errs.New(errs.KindBadRequest, "relay: server address not configured")
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
	defer cli.CloseIdleConnections() // 一次性 client 用后释放空闲连接(防 mTLS 连接累积)
	resp, err := cli.Do(req)
	if err != nil {
		return nil, fmt.Errorf("relay: discover %s: %w", ep, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxInfoBody)) // 限 1MB: 防误配/MITM 内存耗尽
		return nil, fmt.Errorf("relay: /info HTTP %d: %s", resp.StatusCode, firstLine(string(b)))
	}
	var out DiscoverResult
	// 成功路径同样限流: 200 大响应此前无界解码, MITM/误配服务端可耗尽 relay 内存
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxInfoBody)).Decode(&out); err != nil {
		return nil, fmt.Errorf("relay: parse /info: %w", err)
	}
	return out.Services, nil
}

// DiscoverWithCertOf 用指定证书(从来源加载)做发现 — 建隧道时按用户所选证书
// lang: 请求语言(zh/en; 空=进程默认)
func (r *Relay) DiscoverWithCertOf(certID, lang string) ([]ServiceInfo, error) {
	cert, err := r.loadCertLang(certID, lang)
	if err != nil {
		return nil, err
	}
	return r.DiscoverWithCert(cert)
}

// maxInfoBody /info 响应体读取上限(防误配/MITM 超大 JSON 耗尽内存; 错误路径与成功路径一致)
const maxInfoBody = 1 << 20

// loadFirstCert 取来源里第一枚可用证书(用于发现/默认)
func (r *Relay) loadFirstCert() (tls.Certificate, error) {
	// src 可被 SetSource 热替换(WebUI 改 cert_dir), 锁内拷贝指针再锁外执行磁盘/证书库 IO
	r.mu.Lock()
	src := r.src
	r.mu.Unlock()
	metas, err := src.List()
	if err != nil {
		return tls.Certificate{}, err
	}
	if len(metas) == 0 {
		return tls.Certificate{}, errs.New(errs.KindNoCert, "no certificates in source")
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

// splitListen 从 ":9443[/path]" 拆出 (port, path); 无路径 path=""; 不校验(与 proxy.parseListen 的校验式互补)
func splitListen(l string) (port, path string) {
	p := strings.TrimPrefix(strings.TrimSpace(l), ":")
	if i := strings.IndexByte(p, '/'); i >= 0 {
		return p[:i], p[i:]
	}
	return p, ""
}

// portOfListen 从 ":9443[/path]" 取端口; 失败返回空串。
func portOfListen(l string) string {
	p, _ := splitListen(l)
	return p
}

// pathOfListen 从 ":9443[/path]" 取路径前缀; 无路径返回 ""。
func pathOfListen(l string) string {
	_, p := splitListen(l)
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
