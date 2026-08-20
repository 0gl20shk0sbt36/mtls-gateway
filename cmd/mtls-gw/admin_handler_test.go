package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mtls-gateway/internal/api"
	"mtls-gateway/internal/auth"
	"mtls-gateway/internal/db"
	"mtls-gateway/internal/eventlog"
	"mtls-gateway/internal/proxy"
)

// adminEnv adminHandler 完整测试环境
type adminEnv struct {
	store    *db.Store
	gw       *auth.Gateway
	cm       *ConfigManager
	mgr      *api.Manager
	ev       *eventlog.Logger
	evPath   string
	caCert   *x509.Certificate
	caKey    *rsa.PrivateKey
	srv      *httptest.Server
	adminTLS tls.Certificate // admin 客户端证书
	userTLS  tls.Certificate // 普通证书(非 admin)
}

func newAdminEnv(t *testing.T) *adminEnv {
	t.Helper()
	dir := t.TempDir()
	caCert, caKey, caPath, caKeyPath := genCA(t, dir)
	certPath, keyPath := genServerCert(t, dir, caCert, caKey)
	store, _ := db.Open(filepath.Join(dir, "gw.db"))
	t.Cleanup(func() { store.Close() })

	gw, err := auth.New(store, caPath, certPath, keyPath, false, "mtls-superadmin", "1.2")
	if err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.Roles = []string{"svc-a"}
	cfg.Mappings = []proxy.Mapping{{ID: "m1", Listen: ":9601", Target: "http://127.0.0.1:1"}}
	cfg.Services = []proxy.ServiceCfg{{Name: "svc-a", Channels: []string{"m1"}, Roles: []string{"svc-a"}}}
	router, _ := proxy.NewRouter(cfg.Mappings, cfg.Services, cfg.Roles)
	cm := NewConfigManager(filepath.Join(dir, "c.toml"), cfg, router)

	mgr, err := api.NewManager(store, caPath, caKeyPath, filepath.Join(dir, "issued"), filepath.Join(dir, "gw.sock"), api.CertTemplate{Org: "e2e", OU: "e2e", AdminDays: 7, DefaultDays: 100}, "mtls-superadmin", "rsa", 2048, 16, []string{"svc-a"})
	if err != nil {
		t.Fatal(err)
	}
	evPath := filepath.Join(dir, "ev.log")
	ev, _ := eventlog.New(evPath, 5, 2)
	t.Cleanup(func() { ev.Close() })

	h := adminHandler(gw, mgr, cm, ev)
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = gw.ServerTLSConfig()
	srv.StartTLS()
	t.Cleanup(srv.Close)

	// admin + 普通客户端证书
	adm := genClientCert(t, dir, "adm", caCert, caKey)
	admLeaf, _ := x509.ParseCertificate(adm.Certificate[0])
	store.Upsert(db.CertRecord{Serial: admLeaf.SerialNumber.String(), Name: "adm", Purposes: []string{"mtls-superadmin"}, Status: "enabled", IssuedAt: time.Now().Format(time.RFC3339), ExpiresAt: "2099-01-01"})
	usr := genClientCert(t, dir, "usr", caCert, caKey)
	usrLeaf, _ := x509.ParseCertificate(usr.Certificate[0])
	store.Upsert(db.CertRecord{Serial: usrLeaf.SerialNumber.String(), Name: "usr", Purposes: []string{"svc-a"}, Status: "enabled", IssuedAt: time.Now().Format(time.RFC3339), ExpiresAt: "2099-01-01"})

	return &adminEnv{store: store, gw: gw, cm: cm, mgr: mgr, ev: ev, evPath: evPath, caCert: caCert, caKey: caKey, srv: srv, adminTLS: adm, userTLS: usr}
}

func (e *adminEnv) client(cert tls.Certificate) *http.Client {
	pool := x509.NewCertPool()
	pool.AddCert(e.caCert)
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{cert}}}}
}

func (e *adminEnv) do(cert tls.Certificate, method, path, body string) (*http.Response, string) {
	var rd io.Reader
	if body != "" {
		rd = bytes.NewReader([]byte(body))
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client(cert).Do(req)
	if err != nil {
		return nil, err.Error()
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

// H-2: 非 admin 证书 → 403 admin cert required
func TestAdminHandler_NonAdminDenied(t *testing.T) {
	e := newAdminEnv(t)
	resp, body := e.do(e.userTLS, "GET", "/admin/certs", "")
	if resp.StatusCode != 403 {
		t.Fatalf("non-admin should be 403, got %d: %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "admin cert required") {
		t.Fatalf("body: %s", body)
	}
	// POST 操作同样拒绝
	resp2, _ := e.do(e.userTLS, "POST", "/admin/mappings", `{"id":"x","listen":":9609","target":"http://x"}`)
	if resp2.StatusCode != 403 {
		t.Fatalf("non-admin POST should be 403, got %d", resp2.StatusCode)
	}
	// 配置未被修改
	if len(e.cm.Mappings()) != 1 {
		t.Fatal("mappings should be unchanged")
	}
}

// H-2: 未登记证书 → 403 forbidden(认证层)
func TestAdminHandler_UnregisteredDenied(t *testing.T) {
	e := newAdminEnv(t)
	ghost := genClientCert(t, t.TempDir(), "ghost", e.caCert, e.caKey)
	resp, _ := e.do(ghost, "GET", "/admin/certs", "")
	if resp.StatusCode != 403 {
		t.Fatalf("unregistered should be 403, got %d", resp.StatusCode)
	}
}

// H-2: admin 证书 CRUD — mappings/services/roles + 热重载
func TestAdminHandler_CRUDAndHotReload(t *testing.T) {
	e := newAdminEnv(t)
	// 新增映射
	resp, body := e.do(e.adminTLS, "POST", "/admin/mappings", `{"id":"m2","listen":":9602","target":"http://127.0.0.1:2"}`)
	if resp.StatusCode != 200 {
		t.Fatalf("add mapping: %d %s", resp.StatusCode, body)
	}
	if len(e.cm.Mappings()) != 2 {
		t.Fatalf("mappings: %d", len(e.cm.Mappings()))
	}
	// 热重载生效: 新路由可匹配
	if rt := e.cm.Router().Match("9602", "/x"); rt == nil {
		t.Fatal("hot reload: new mapping should be routable")
	}
	// 新增服务
	resp, body = e.do(e.adminTLS, "POST", "/admin/services", `{"name":"svc-b","channels":["m2"],"roles":["svc-a"]}`)
	if resp.StatusCode != 200 {
		t.Fatalf("add service: %d %s", resp.StatusCode, body)
	}
	if len(e.cm.Services()) != 2 {
		t.Fatalf("services: %d", len(e.cm.Services()))
	}
	// 新增角色
	resp, body = e.do(e.adminTLS, "POST", "/admin/roles", `{"name":"ops"}`)
	if resp.StatusCode != 200 {
		t.Fatalf("add role: %d %s", resp.StatusCode, body)
	}
	if len(e.cm.Roles()) != 2 {
		t.Fatalf("roles: %d", len(e.cm.Roles()))
	}
	// 非法操作被拒(重复 listen → 409 精确断言)
	resp, body = e.do(e.adminTLS, "POST", "/admin/mappings", `{"id":"m3","listen":":9602","target":"http://x"}`)
	if resp.StatusCode != 409 {
		t.Fatalf("dup listen should be 409: %d %s", resp.StatusCode, body)
	}
	// 非法角色名 → 400
	resp, body = e.do(e.adminTLS, "POST", "/admin/roles", `{"name":"bad role!"}`)
	if resp.StatusCode != 400 {
		t.Fatalf("bad role name should be 400: %d %s", resp.StatusCode, body)
	}
	// 删除服务
	resp, _ = e.do(e.adminTLS, "DELETE", "/admin/services?name=svc-b", "")
	if resp.StatusCode != 200 {
		t.Fatalf("del service: %d", resp.StatusCode)
	}
	// 配置变更事件已记录
	e.ev.Close()
	data, _ := os.ReadFile(e.evPath)
	if !strings.Contains(string(data), "新增通道") || !strings.Contains(string(data), "新增服务") || !strings.Contains(string(data), "新增角色") {
		t.Fatalf("config events missing: %s", string(data)[:min(len(data), 400)])
	}
}

// H-2: 签发 + 吊销闭环(HTTP 层)
func TestAdminHandler_IssueAndRevoke(t *testing.T) {
	e := newAdminEnv(t)
	// 签发
	resp, body := e.do(e.adminTLS, "POST", "/admin/certs/issue", `{"name":"dev-http","purposes":["svc-a"],"days":30}`)
	if resp.StatusCode != 200 {
		t.Fatalf("issue: %d %s", resp.StatusCode, body)
	}
	var ir api.IssueResponse
	json.Unmarshal([]byte(body), &ir)
	if ir.Serial == "" {
		t.Fatalf("issue response: %s", body)
	}
	// 远程通道(HTTPHandler→handler(false))不回明文私钥(KeyPEM 置空 + omitempty 省略)
	if ir.KeyPEM != "" {
		t.Fatalf("remote channel must not return KeyPEM: %s", body)
	}
	if strings.Contains(body, "key_pem") {
		t.Fatalf("remote channel JSON should omit key_pem: %s", body)
	}
	// 库中已登记
	if len(e.store.FindByName("dev-http")) != 1 {
		t.Fatal("dev-http should be in db")
	}
	// 吊销
	resp, body = e.do(e.adminTLS, "POST", "/admin/certs/revoke", `{"serial":"`+ir.Serial+`"}`)
	if resp.StatusCode != 200 {
		t.Fatalf("revoke: %d %s", resp.StatusCode, body)
	}
	recs := e.store.FindByName("dev-http")
	if recs[0].Status != "revoked" {
		t.Fatalf("status: %s", recs[0].Status)
	}
	// 事件
	e.ev.Close()
	data, _ := os.ReadFile(e.evPath)
	if !strings.Contains(string(data), "签发") || !strings.Contains(string(data), "吊销") {
		t.Fatalf("issue/revoke events missing: %s", string(data)[:min(len(data), 300)])
	}
}

// H-2: 批量保存配置(ReplaceAll)
func TestAdminHandler_ReplaceAll(t *testing.T) {
	e := newAdminEnv(t)
	body := `{"mappings":[{"id":"n1","listen":":9701","target":"http://127.0.0.1:1"}],"services":[{"name":"svc-n","channels":["n1"],"roles":["svc-a"]}],"roles":["svc-a"]}`
	resp, b := e.do(e.adminTLS, "POST", "/admin/config", body)
	if resp.StatusCode != 200 {
		t.Fatalf("replace: %d %s", resp.StatusCode, b)
	}
	if len(e.cm.Mappings()) != 1 || e.cm.Mappings()[0].ID != "n1" {
		t.Fatalf("replace not applied: %+v", e.cm.Mappings())
	}
}
