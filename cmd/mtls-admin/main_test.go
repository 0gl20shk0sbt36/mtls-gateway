package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mtls-gateway/internal/api"
	"mtls-gateway/internal/auth"
	"mtls-gateway/internal/config"
	"mtls-gateway/internal/configmgr"
	"mtls-gateway/internal/db"
	"mtls-gateway/internal/httpshared"
	"mtls-gateway/internal/proxy"
)

// adminEnv mtls-admin 管理 handler 测试环境(admin 证书 + 普通证书)
type adminEnv struct {
	store    *db.Store
	gw       *auth.Gateway
	cm       *configmgr.ConfigManager
	mgr      *api.Manager
	caCert   *x509.Certificate
	caKey    *rsa.PrivateKey
	srv      *httptest.Server
	adminTLS tls.Certificate
	userTLS  tls.Certificate
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
	cfg := config.DefaultConfig()
	cfg.Roles = []string{"svc-a"}
	cfg.Mappings = []proxy.Mapping{{ID: "m1", Listen: ":9601", Target: "http://127.0.0.1:1"}}
	cfg.Services = []proxy.ServiceCfg{{Name: "svc-a", Channels: []string{"m1"}, Roles: []string{"svc-a"}}}
	cfg.ConfigMode = "ephemeral" // 测试不落盘
	cm := configmgr.New(filepath.Join(dir, "c.toml"), cfg, nil)
	mgr, err := api.NewManager(store, caPath, caKeyPath, filepath.Join(dir, "issued"), filepath.Join(dir, "gw.sock"),
		api.CertTemplate{Org: "t", OU: "t", AdminDays: 7, DefaultDays: 100}, "mtls-superadmin", "rsa", 2048, 16, []string{"svc-a"})
	if err != nil {
		t.Fatal(err)
	}
	h := adminHandler(gw, mgr, cm, nil, nil)
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = gw.ServerTLSConfig()
	srv.StartTLS()
	t.Cleanup(srv.Close)

	adm := genClientCert(t, dir, "adm", caCert, caKey)
	admLeaf, _ := x509.ParseCertificate(adm.Certificate[0])
	store.Upsert(db.CertRecord{Serial: admLeaf.SerialNumber.String(), Name: "adm", Purposes: []string{"mtls-superadmin"}, Status: "enabled", ExpiresAt: "2099-01-01"})
	usr := genClientCert(t, dir, "usr", caCert, caKey)
	usrLeaf, _ := x509.ParseCertificate(usr.Certificate[0])
	store.Upsert(db.CertRecord{Serial: usrLeaf.SerialNumber.String(), Name: "usr", Purposes: []string{"svc-a"}, Status: "enabled", ExpiresAt: "2099-01-01"})
	return &adminEnv{store: store, gw: gw, cm: cm, mgr: mgr, caCert: caCert, caKey: caKey, srv: srv, adminTLS: adm, userTLS: usr}
}

func (e *adminEnv) do(cert tls.Certificate, method, path, body string) (*http.Response, string) {
	var rd io.Reader
	if body != "" {
		rd = bytes.NewReader([]byte(body))
	}
	pool := x509.NewCertPool()
	pool.AddCert(e.caCert)
	cli := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{cert}}}}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err.Error()
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

// 管理进程: 非 admin 证书 → 403; admin 证书 → 配置 CRUD 生效(内存, ephemeral 不落盘)
func TestAdminHandlerBasic(t *testing.T) {
	e := newAdminEnv(t)
	// 非 admin → 403
	resp, _ := e.do(e.userTLS, "GET", "/admin/config", "")
	if resp.StatusCode != 403 {
		t.Fatalf("non-admin should be 403, got %d", resp.StatusCode)
	}
	// admin: 配置总览
	resp2, body := e.do(e.adminTLS, "GET", "/admin/config", "")
	if resp2.StatusCode != 200 {
		t.Fatalf("config: %d %s", resp2.StatusCode, body)
	}
	// admin: 新增 mapping → configmgr 更新
	resp3, _ := e.do(e.adminTLS, "POST", "/admin/mappings", `{"id":"m2","listen":":9602","target":"http://127.0.0.1:2"}`)
	if resp3.StatusCode != 200 {
		t.Fatalf("add mapping: %d", resp3.StatusCode)
	}
	if n := len(e.cm.Mappings()); n != 2 {
		t.Fatalf("mappings should be 2, got %d", n)
	}
	// 证书管理: GET /admin/certs(admin 证书)
	resp4, _ := e.do(e.adminTLS, "GET", "/admin/certs", "")
	if resp4.StatusCode != 200 {
		t.Fatalf("certs: %d", resp4.StatusCode)
	}
	// 健康检查
	resp5, _ := e.do(e.adminTLS, "GET", "/admin/health", "")
	if resp5.StatusCode != 200 {
		t.Fatalf("health: %d", resp5.StatusCode)
	}
}

// 配置 CRUD 校验失败回滚(与管理语义一致)
func TestAdminHandlerValidationRollback(t *testing.T) {
	e := newAdminEnv(t)
	// 重复 listen → 拒绝且回滚
	resp, body := e.do(e.adminTLS, "POST", "/admin/mappings", `{"id":"m2","listen":":9601","target":"http://127.0.0.1:2"}`)
	if resp.StatusCode == 200 {
		t.Fatalf("duplicate listen should fail: %s", body)
	}
	if n := len(e.cm.Mappings()); n != 1 {
		t.Fatalf("rollback failed: %d mappings", n)
	}
}

// reload client 构造: 配置缺证书报错; 完整配置可用
func TestNewReloadClient(t *testing.T) {
	dir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.GatewayReloadAddr = "127.0.0.1:1"
	cfg.CA = filepath.Join(dir, "ca.crt")
	if _, err := httpshared.NewReloadClient(cfg.GatewayReloadAddr, cfg.ReloadCert, cfg.ReloadKey, cfg.CA); err == nil {
		t.Fatal("缺 reload_cert/reload_key 应报错")
	}
	cfg.ReloadCert = filepath.Join(dir, "c.pem")
	cfg.ReloadKey = filepath.Join(dir, "k.pem")
	if _, err := httpshared.NewReloadClient(cfg.GatewayReloadAddr, cfg.ReloadCert, cfg.ReloadKey, cfg.CA); err == nil {
		t.Fatal("证书文件不存在应报错")
	}
}

// —— 证书生成 helper(与 cmd/mtls-gw 测试同款) ——

func genCA(t *testing.T, dir string) (caCert *x509.Certificate, caKey *rsa.PrivateKey, caPath, caKeyPath string) {
	t.Helper()
	caKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "m-test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	caCert, _ = x509.ParseCertificate(der)
	caPath = filepath.Join(dir, "ca.crt")
	caKeyPath = filepath.Join(dir, "ca.key")
	os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	kd, _ := x509.MarshalPKCS8PrivateKey(caKey)
	os.WriteFile(caKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), 0o600)
	return
}

func genServerCert(t *testing.T, dir string, caCert *x509.Certificate, caKey *rsa.PrivateKey) (certPath, keyPath string) {
	t.Helper()
	sk, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "m-test-server"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, caCert, &sk.PublicKey, caKey)
	certPath = filepath.Join(dir, "server.crt")
	keyPath = filepath.Join(dir, "server.key")
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	kd, _ := x509.MarshalPKCS8PrivateKey(sk)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), 0o600)
	return
}

func genClientCert(t *testing.T, dir, name string, caCert *x509.Certificate, caKey *rsa.PrivateKey) tls.Certificate {
	t.Helper()
	ck, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, caCert, &ck.PublicKey, caKey)
	cp := filepath.Join(dir, name+".crt")
	kp := filepath.Join(dir, name+".key")
	os.WriteFile(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	kd, _ := x509.MarshalPKCS8PrivateKey(ck)
	os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), 0o600)
	cert, err := tls.LoadX509KeyPair(cp, kp)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// pro 深度审计补: reloadClient.Trigger() 真实 mTLS 握手 — 200→true / 403→false / 网络失败→false
// (此前只有构造测试, 握手/URL/状态码判定零覆盖 — pro 测试有效性审计点名的最高价值空白)
func TestReloadClientTriggerHandshake(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, caPath, _ := genCA(t, dir)
	// reload 客户端证书(CA 签发, 写文件供 NewReloadClient 加载)
	rcCert := genClientCert(t, dir, "reload-client", caCert, caKey)
	certPath := filepath.Join(dir, "reload.crt")
	keyPath := filepath.Join(dir, "reload.key")
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rcCert.Certificate[0]}), 0o600)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(rcCert.PrivateKey)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)
	// 服务器证书 + 客户端证书校验
	serverCertPath, serverKeyPath := genServerCert(t, dir, caCert, caKey)
	serverCert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	mkSrv := func(status int) *httptest.Server {
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
		}))
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
		srv.StartTLS()
		return srv
	}

	// 200 → true
	srvOK := mkSrv(http.StatusOK)
	defer srvOK.Close()
	cfgOK := config.DefaultConfig()
	cfgOK.GatewayReloadAddr = strings.TrimPrefix(srvOK.URL, "https://")
	cfgOK.CA = caPath
	cfgOK.ReloadCert = certPath
	cfgOK.ReloadKey = keyPath
	rcOK, err := httpshared.NewReloadClient(cfgOK.GatewayReloadAddr, cfgOK.ReloadCert, cfgOK.ReloadKey, cfgOK.CA)
	if err != nil {
		t.Fatalf("NewReloadClient: %v", err)
	}
	if !rcOK.Trigger() {
		t.Fatal("200 握手应返回 true")
	}
	// 403 → false
	srvDeny := mkSrv(http.StatusForbidden)
	defer srvDeny.Close()
	cfgDeny := cfgOK
	cfgDeny.GatewayReloadAddr = strings.TrimPrefix(srvDeny.URL, "https://")
	rcDeny, err := httpshared.NewReloadClient(cfgDeny.GatewayReloadAddr, cfgDeny.ReloadCert, cfgDeny.ReloadKey, cfgDeny.CA)
	if err != nil {
		t.Fatal(err)
	}
	if rcDeny.Trigger() {
		t.Fatal("403 应返回 false")
	}
	// 网络失败(未监听) → false
	cfgBad := cfgOK
	cfgBad.GatewayReloadAddr = "127.0.0.1:1"
	rcBad, err := httpshared.NewReloadClient(cfgBad.GatewayReloadAddr, cfgBad.ReloadCert, cfgBad.ReloadKey, cfgBad.CA)
	if err != nil {
		t.Fatal(err)
	}
	if rcBad.Trigger() {
		t.Fatal("网络失败应返回 false")
	}
}
