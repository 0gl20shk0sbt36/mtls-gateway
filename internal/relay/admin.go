// Package relay
//
// admin.go: 客户端"管理客户端" — 用一枚 admin 证书通过 mTLS 调用服务端 TCP admin API。
// 用于 WebUI 的证书签发/吊销(管理台), 使服务端无需单独的管理 WebUI。
package relay

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"mtls-gateway/internal/types"
)

// 与 internal/types 对齐的类型别名 (管理 API DTO)
type (
	IssueRequest  = types.IssueRequest
	IssueResponse = types.IssueResponse
	MappingInfo   = types.MappingInfo
)

// 管理操作请求/响应 (与服务端 internal/api 的 IssueRequest/IssueResponse 对齐)
// AdminClient 服务端管理 API 客户端 (mTLS, 需 admin 证书)
type AdminClient struct {
	addr   string // 服务端 admin 端点 host:port
	server string // TLS ServerName
	h      *http.Client
}

// NewAdminClient addr=服务端 admin_listen (host:port), cert=admin 客户端证书, roots=网关 CA
func NewAdminClient(addr string, cert tls.Certificate, roots *x509.CertPool) *AdminClient {
	return &AdminClient{
		addr:   addr,
		server: stripPort(addr),
		h: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					Certificates: []tls.Certificate{cert},
					RootCAs:      roots,
					ServerName:   stripPort(addr),
					MinVersion:   tls.VersionTLS12,
				},
				IdleConnTimeout: 30 * time.Second, // 空闲连接主动到期回收
			},
		},
	}
}

// Close 释放底层空闲连接(一次性 AdminClient 用后调用, 防 mTLS 连接累积)
func (a *AdminClient) Close() {
	if a != nil && a.h != nil {
		if tr, ok := a.h.Transport.(*http.Transport); ok {
			tr.CloseIdleConnections()
		}
	}
}

func (a *AdminClient) do(method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "https://"+a.addr+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.h.Do(req)
	if err != nil {
		return fmt.Errorf("admin %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("admin %s %s: HTTP %d: %s", method, path, resp.StatusCode, string(b))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	io.Copy(io.Discard, resp.Body)
	return nil
}

// Verify 探活 (检测 admin 证书是否被服务端接受; 403=非 admin)
func (a *AdminClient) Verify() error { return a.do("GET", "/admin/health", nil, nil) }

// List 拉取全部证书(吊销下拉用)
func (a *AdminClient) List() (json.RawMessage, error) {
	var raw json.RawMessage
	err := a.do("GET", "/admin/certs", nil, &raw)
	return raw, err
}

// ListMappings 拉取全部映射(admin 用; 供签发时选用途)
// 服务端 GET /admin/mappings 返回 {"mappings":[{id,listen,target}]}
func (a *AdminClient) ListMappings() ([]MappingInfo, error) {
	var out struct {
		Mappings []MappingInfo `json:"mappings"`
	}
	if err := a.do("GET", "/admin/mappings", nil, &out); err != nil {
		return nil, err
	}
	return out.Mappings, nil
}

// MappingInfo 服务端映射条目(与 internal/proxy.Mapping JSON 键对齐)
// Cfg 拉取服务端配置总览 (mode + mappings + services)
func (a *AdminClient) Cfg() (json.RawMessage, error) {
	var raw json.RawMessage
	err := a.do("GET", "/admin/config", nil, &raw)
	return raw, err
}

// SetConfig 整体替换服务端配置 (mappings+services+roles)
func (a *AdminClient) SetConfig(body json.RawMessage) (json.RawMessage, error) {
	var raw json.RawMessage
	err := a.do("POST", "/admin/config", body, &raw)
	return raw, err
}

// Mapping 通道 CRUD (method: POST/PUT/DELETE)
func (a *AdminClient) Mapping(method, id string, body json.RawMessage) (json.RawMessage, error) {
	path := "/admin/mappings"
	if id != "" {
		path += "?id=" + url.QueryEscape(id)
	}
	var raw json.RawMessage
	err := a.do(method, path, body, &raw)
	return raw, err
}

// Service 服务 CRUD (method: POST/PUT/DELETE)
func (a *AdminClient) Service(method, name string, body json.RawMessage) (json.RawMessage, error) {
	path := "/admin/services"
	if name != "" {
		path += "?name=" + url.QueryEscape(name)
	}
	var raw json.RawMessage
	err := a.do(method, path, body, &raw)
	return raw, err
}

// Issue 向服务端申请签发一张新证书 (由 admin 授权)
func (a *AdminClient) Issue(req IssueRequest) (*IssueResponse, error) {
	var r IssueResponse
	if err := a.do("POST", "/admin/certs/issue", req, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Revoke 吊销一张证书
func (a *AdminClient) Revoke(serial string) error {
	return a.do("POST", "/admin/certs/revoke", struct {
		Serial string `json:"serial"`
	}{serial}, nil)
}
