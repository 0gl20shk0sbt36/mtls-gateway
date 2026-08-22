package httpshared

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

// ReloadClient 调网关 POST /admin/reload(admin 证书 mTLS)触发全量热重载。
// 管理进程是配置写者, 网关是只读消费者: 每次配置变更落盘后 Trigger 一次,
// 网关内存副本才与 DB 同步(吊销/新证书/新映射才生效)。
type ReloadClient struct {
	addr string // host:port
	cli  *http.Client
}

// NewReloadClient 构建 reload 客户端; addr=网关 reload 端点 host:port,
// reloadCert/reloadKey=admin 客户端证书(文件路径), caPath=网关 CA(校验服务端)。
func NewReloadClient(addr, reloadCert, reloadKey, caPath string) (*ReloadClient, error) {
	if reloadCert == "" || reloadKey == "" {
		return nil, fmt.Errorf("gateway_reload_addr 已配置但缺 reload_cert/reload_key(admin 客户端证书)")
	}
	cert, err := tls.LoadX509KeyPair(reloadCert, reloadKey)
	if err != nil {
		return nil, fmt.Errorf("load reload cert: %w", err)
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("parse ca pem")
	}
	return &ReloadClient{
		addr: addr,
		cli: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{cert}},
			},
		},
	}, nil
}

// Trigger 调网关 /admin/reload; 返回是否成功(失败由调用方写事件留痕, 管理侧已落盘可重试)。
func (c *ReloadClient) Trigger() bool {
	if c == nil {
		return false
	}
	resp, err := c.cli.Post("https://"+c.addr+"/admin/reload", "application/json", nil)
	if err != nil {
		log.Printf("gateway reload: %v (管理侧已落盘, 可稍后重试)", err)
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("gateway reload: HTTP %d (管理侧已落盘)", resp.StatusCode)
		return false
	}
	log.Printf("gateway reload: ok")
	return true
}
