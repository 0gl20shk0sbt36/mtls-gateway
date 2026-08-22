package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mtls-gateway/internal/auth"
	"mtls-gateway/internal/config"
	"mtls-gateway/internal/configmgr"
	"mtls-gateway/internal/db"
	"mtls-gateway/internal/eventlog"
	"mtls-gateway/internal/proxy"
)

// adminEnv adminHandler 测试环境(网关瘦身后仅 reload 端点; 管理功能已拆 mtls-admin)
type adminEnv struct {
	store    *db.Store
	gw       *auth.Gateway
	cm       *configmgr.ConfigManager
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
	caCert, caKey, caPath, _ := genCA(t, dir)
	certPath, keyPath := genServerCert(t, dir, caCert, caKey)
	store, _ := db.Open(filepath.Join(dir, "gw.db"))
	t.Cleanup(func() { store.Close() })

	gw, err := auth.New(store, caPath, certPath, keyPath, false, "mtls-superadmin", "1.2")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.Roles = []string{"svc-a"}
	cfg.Mappings = []proxy.Mapping{{ID: "m1", Listen: ":9601", Target: "http://127.0.0.1:1"}}
	cfg.Services = []proxy.ServiceCfg{{Name: "svc-a", Channels: []string{"m1"}, Roles: []string{"svc-a"}}}
	router, _ := proxy.NewRouter(cfg.Mappings, cfg.Services, cfg.Roles)
	cm := configmgr.New(filepath.Join(dir, "c.toml"), cfg, router)

	evPath := filepath.Join(dir, "ev.log")
	ev, _ := eventlog.New(evPath, 5, 2)
	t.Cleanup(func() { ev.Close() })

	h := adminHandler(gw, cm, ev)
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

	return &adminEnv{store: store, gw: gw, cm: cm, ev: ev, evPath: evPath, caCert: caCert, caKey: caKey, srv: srv, adminTLS: adm, userTLS: usr}
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

// 网关瘦身: 非 admin 证书访问 /admin/reload → 403
func TestAdminHandler_NonAdminDenied(t *testing.T) {
	e := newAdminEnv(t)
	resp, body := e.do(e.userTLS, "POST", "/admin/reload", "")
	if resp.StatusCode != 403 {
		t.Fatalf("non-admin should be 403, got %d: %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "admin cert required") {
		t.Fatalf("body: %s", body)
	}
}

// 未登记证书 → 403 forbidden(认证层)
func TestAdminHandler_UnregisteredDenied(t *testing.T) {
	e := newAdminEnv(t)
	ghost := genClientCert(t, t.TempDir(), "ghost", e.caCert, e.caKey)
	resp, _ := e.do(ghost, "POST", "/admin/reload", "")
	if resp.StatusCode != 403 {
		t.Fatalf("unregistered should be 403, got %d", resp.StatusCode)
	}
}

// POST /admin/reload — 全量热重载(DB + 配置), admin 证书
func TestAdminHandler_Reload(t *testing.T) {
	e := newAdminEnv(t)
	// 准备: cm.path 写初始配置文件(ReloadFromDisk 读它)
	initial := "roles = [\"svc-a\"]\n\n[[mappings]]\nid = \"m1\"\nlisten = \":9601\"\ntarget = \"http://127.0.0.1:1\"\n\n[[services]]\nname = \"svc-a\"\nchannels = [\"m1\"]\nroles = [\"svc-a\"]\n"
	if err := os.WriteFile(e.cm.ConfigPath(), []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}
	// DB 变更(模拟管理进程写库) + 配置变更(:9602)
	ghost := genClientCert(t, t.TempDir(), "newdev", e.caCert, e.caKey)
	leaf, _ := x509.ParseCertificate(ghost.Certificate[0])
	if err := e.store.Upsert(db.CertRecord{Serial: leaf.SerialNumber.String(), Name: "newdev", Purposes: []string{"svc-a"}, Status: "enabled", IssuedAt: time.Now().Format(time.RFC3339), ExpiresAt: "2099-01-01"}); err != nil {
		t.Fatal(err)
	}
	updated := "roles = [\"svc-a\"]\n\n[[mappings]]\nid = \"m1\"\nlisten = \":9601\"\ntarget = \"http://127.0.0.1:1\"\n\n[[mappings]]\nid = \"m2\"\nlisten = \":9602\"\ntarget = \"http://127.0.0.1:2\"\n\n[[services]]\nname = \"svc-a\"\nchannels = [\"m1\", \"m2\"]\nroles = [\"svc-a\"]\n"
	if err := os.WriteFile(e.cm.ConfigPath(), []byte(updated), 0o600); err != nil {
		t.Fatal(err)
	}
	resp, body := e.do(e.adminTLS, "POST", "/admin/reload", "")
	if resp.StatusCode != 200 {
		t.Fatalf("reload should be 200, got %d: %s", resp.StatusCode, body)
	}
	// 配置热重载生效: :9602 可路由
	if n := len(e.cm.Mappings()); n != 2 {
		t.Fatalf("reload 后 mappings 应为 2, got %d", n)
	}
	if rt := e.cm.Router().Match("9602", "/"); rt == nil {
		t.Fatal("reload 后 :9602 应可匹配")
	}
	// DB 热重载生效: 新证书可认证
	req := httptest.NewRequest("GET", "https://gw/", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	if rec, err := e.gw.Authorize(req); err != nil || rec.Name != "newdev" {
		t.Fatalf("reload 后新证书应可认证: rec=%+v err=%v", rec, err)
	}
	// 事件日志记录 reload
	data, _ := os.ReadFile(e.evPath)
	if !strings.Contains(string(data), "热重载") {
		t.Fatalf("事件日志应记录 reload: %s", data)
	}
}

// reload 配置失败(重复 listen) → 报错; DB 侧已生效(先 DB 后配置), 配置保持旧状态
func TestAdminHandler_ReloadBadConfig(t *testing.T) {
	e := newAdminEnv(t)
	initial := "roles = [\"svc-a\"]\n\n[[mappings]]\nid = \"m1\"\nlisten = \":9601\"\ntarget = \"http://127.0.0.1:1\"\n\n[[services]]\nname = \"svc-a\"\nchannels = [\"m1\"]\nroles = [\"svc-a\"]\n"
	if err := os.WriteFile(e.cm.ConfigPath(), []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}
	ghost := genClientCert(t, t.TempDir(), "ghost2", e.caCert, e.caKey)
	leaf, _ := x509.ParseCertificate(ghost.Certificate[0])
	if err := e.store.Upsert(db.CertRecord{Serial: leaf.SerialNumber.String(), Name: "ghost2", Purposes: []string{"svc-a"}, Status: "enabled", IssuedAt: time.Now().Format(time.RFC3339), ExpiresAt: "2099-01-01"}); err != nil {
		t.Fatal(err)
	}
	bad := "roles = [\"svc-a\"]\n\n[[mappings]]\nid = \"m1\"\nlisten = \":9601\"\ntarget = \"http://127.0.0.1:1\"\n\n[[mappings]]\nid = \"m3\"\nlisten = \":9601\"\ntarget = \"http://127.0.0.1:3\"\n"
	if err := os.WriteFile(e.cm.ConfigPath(), []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	resp, _ := e.do(e.adminTLS, "POST", "/admin/reload", "")
	if resp.StatusCode == 200 {
		t.Fatal("坏配置 reload 应报错")
	}
	if n := len(e.cm.Mappings()); n != 1 {
		t.Fatalf("reload 失败后配置应保持 1 个 mapping, got %d", n)
	}
	if rt := e.cm.Router().Match("9601", "/"); rt == nil {
		t.Fatal("旧路由 :9601 应保持")
	}
	// DB 侧已生效(先 DB 后配置)
	req := httptest.NewRequest("GET", "https://gw/", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	if rec, err := e.gw.Authorize(req); err != nil || rec.Name != "ghost2" {
		t.Fatalf("DB 侧 reload 应已生效: rec=%+v err=%v", rec, err)
	}
}
