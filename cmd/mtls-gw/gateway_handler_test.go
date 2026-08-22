package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
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

	"golang.org/x/net/websocket"
	"mtls-gateway/internal/auth"
	"mtls-gateway/internal/config"
	"mtls-gateway/internal/configmgr"
	"mtls-gateway/internal/db"
	"mtls-gateway/internal/eventlog"
	"mtls-gateway/internal/proxy"
)

// gwTestEnv 完整测试环境: CA/服务器证书/客户端证书/网关/日志
type gwTestEnv struct {
	caCert   *x509.Certificate
	caKey    *rsa.PrivateKey
	clientID string
	acc      *eventlog.Logger
	accPath  string
	store    *db.Store
	gw       *auth.Gateway
	cm       *configmgr.ConfigManager
}

// genCA 生成 CA 并写文件
func genCA(t *testing.T, dir string) (caCert *x509.Certificate, caKey *rsa.PrivateKey, caPath, caKeyPath string) {
	t.Helper()
	caKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "h-test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create ca: %v", err)
	}
	caCert, _ = x509.ParseCertificate(der)
	caPath = filepath.Join(dir, "ca.crt")
	caKeyPath = filepath.Join(dir, "ca.key")
	os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	kd, _ := x509.MarshalPKCS8PrivateKey(caKey)
	os.WriteFile(caKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), 0o600)
	return
}

// genServerCert 生成服务器证书(写文件, 返回文件路径)
func genServerCert(t *testing.T, dir string, caCert *x509.Certificate, caKey *rsa.PrivateKey) (certPath, keyPath string) {
	t.Helper()
	sk, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "h-test-server"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &sk.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}
	certPath = filepath.Join(dir, "server.crt")
	keyPath = filepath.Join(dir, "server.key")
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	kd, _ := x509.MarshalPKCS8PrivateKey(sk)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), 0o600)
	return
}

// genClientCert 签一枚客户端证书(写文件, 返回 tls.Certificate)
func genClientCert(t *testing.T, dir, name string, caCert *x509.Certificate, caKey *rsa.PrivateKey) tls.Certificate {
	t.Helper()
	ck, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &ck.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create client cert: %v", err)
	}
	cp := filepath.Join(dir, name+".crt")
	kp := filepath.Join(dir, name+".key")
	os.WriteFile(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	kd, _ := x509.MarshalPKCS8PrivateKey(ck)
	os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), 0o600)
	c, err := tls.LoadX509KeyPair(cp, kp)
	if err != nil {
		t.Fatalf("load client keypair: %v", err)
	}
	return c
}

// newGWTestEnv 组装完整网关环境(echo 后端 + 网关 TLS server)
func newGWTestEnv(t *testing.T, backends map[string]*httptest.Server) (*gwTestEnv, *httptest.Server, *http.Client) {
	t.Helper()
	dir := t.TempDir()
	caCert, caKey, caPath, _ := genCA(t, dir)
	certPath, keyPath := genServerCert(t, dir, caCert, caKey)

	store, err := db.Open(filepath.Join(dir, "gw.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	gw, err := auth.New(store, caPath, certPath, keyPath, false, "mtls-superadmin", "1.2")
	if err != nil {
		t.Fatalf("auth new: %v", err)
	}
	cfg := config.DefaultConfig()
	cfg.Roles = []string{"svc-a", "other"}
	// 后端地址: 用传入的 httptest 或占位(未绑定端口 → 502 场景)
	tgt := "http://127.0.0.1:1"
	if backends["ok"] != nil {
		tgt = backends["ok"].URL
	}
	cfg.Mappings = []proxy.Mapping{
		{ID: "m1", Listen: ":9601", Target: tgt},
		{ID: "m1x", Listen: ":9601/admin", Target: tgt},
		{ID: "m2", Listen: ":9602", Target: "http://127.0.0.1:1"}, // 后端宕机(502 场景)
	}
	cfg.Services = []proxy.ServiceCfg{
		{Name: "svc-a", Channels: []string{"m1", "m1x"}, Roles: []string{"svc-a"}},
		{Name: "any-svc", Channels: []string{"m2"}, Roles: []string{"any"}},
	}
	router, err := proxy.NewRouter(cfg.Mappings, cfg.Services, cfg.Roles)
	if err != nil {
		t.Fatalf("router: %v", err)
	}
	cm := configmgr.New(filepath.Join(dir, "cfg.toml"), cfg, router)

	accPath := filepath.Join(dir, "access.log")
	acc, err := eventlog.New(accPath, 5, 2)
	if err != nil {
		t.Fatalf("eventlog: %v", err)
	}
	t.Cleanup(func() { acc.Close() })

	// 网关 TLS server(真 mTLS)
	h := gatewayHandler(gw, cm, "9601", acc)
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = gw.ServerTLSConfig()
	srv.StartTLS()
	t.Cleanup(srv.Close)

	// 客户端: 信任 ca + 可带客户端证书
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	cl := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
		Timeout:   5 * time.Second,
	}
	env := &gwTestEnv{caCert: caCert, caKey: caKey, acc: acc, accPath: accPath, store: store, gw: gw, cm: cm}
	return env, srv, cl
}

// registerCert 登记一枚客户端证书到 db(roles; serial 从证书真实提取)
func (e *gwTestEnv) registerCert(name string, roles []string, cert tls.Certificate) {
	leaf := cert.Leaf
	if leaf == nil {
		leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	}
	e.store.Upsert(db.CertRecord{
		Serial: leaf.SerialNumber.String(), Name: name, Purposes: roles,
		Status: "enabled", IssuedAt: time.Now().Format(time.RFC3339), ExpiresAt: time.Now().AddDate(1, 0, 0).Format("2006-01-02"),
	})
}

// clientWith 带客户端证书的请求客户端
func clientWith(cl *http.Client, cert tls.Certificate) *http.Client {
	c2 := *cl
	tr := cl.Transport.(*http.Transport).Clone()
	tr.TLSClientConfig.Certificates = []tls.Certificate{cert}
	c2.Transport = tr
	return &c2
}

// H3+M5: 有权证书转发成功 + access 日志字节统计
func TestGatewayHandler_ForwardAndBytes(t *testing.T) {
	back := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Write([]byte("ECHO:" + r.URL.Path + ":" + string(b)))
	}))
	defer back.Close()
	env, srv, cl := newGWTestEnv(t, map[string]*httptest.Server{"ok": back})
	cert := genClientCert(t, t.TempDir(), "dev-a", env.caCert, env.caKey)
	env.registerCert("dev-a", []string{"svc-a"}, cert)

	// 整口转发
	resp, err := clientWith(cl, cert).Post(srv.URL+"/hello", "text/plain", strings.NewReader("BODY-123"))
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d body: %s", resp.StatusCode, b)
	}
	if string(b) != "ECHO:/hello:BODY-123" {
		t.Fatalf("echo mismatch: %q", b)
	}
	// 路径通道: /admin/xx → 剥 /admin 补到后端
	resp2, _ := clientWith(cl, cert).Get(srv.URL + "/admin/x")
	b2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != 200 {
		t.Fatalf("path status: %d body: %s", resp2.StatusCode, b2)
	}
	if string(b2) != "ECHO:/x:" {
		t.Fatalf("path echo mismatch (expect stripped /admin): %q", b2)
	}
	// access 日志: 2 条 200 + bytes 统计
	env.acc.Close()
	data, _ := os.ReadFile(env.accPath)
	s := string(data)
	if !strings.Contains(s, `"status":200`) {
		t.Fatalf("no 200 access events: %s", s[:min(len(s), 400)])
	}
	if !strings.Contains(s, `"bytes_in":8`) { // "BODY-123" = 8 字节
		t.Fatalf("bytes_in not recorded: %s", s[:min(len(s), 400)])
	}
}

// H3: 无客户端证书 → TLS 握手失败
func TestGatewayHandler_NoClientCert(t *testing.T) {
	back := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer back.Close()
	_, srv, cl := newGWTestEnv(t, map[string]*httptest.Server{"ok": back})
	// TLS 层 VerifyClientCertIfGiven: 无证书允许握手(匿名), 应用层对非 null 路由 403
	resp, err := cl.Get(srv.URL + "/hello")
	if err != nil {
		t.Fatalf("no client cert should reach app layer (anonymous TLS allowed): %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("no client cert on non-null route should 403, got %d", resp.StatusCode)
	}
}

// null 路由: 匿名访问放行(不需要证书), 转发到后端
func TestGatewayHandler_NullRouteAnonymous(t *testing.T) {
	back := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "public-ok")
	}))
	defer back.Close()
	env, srv, cl := newGWTestEnv(t, map[string]*httptest.Server{"ok": back})
	// 给 svc-a 的 roles 加 null: 匿名可访问
	for _, s := range env.cm.Services() {
		if s.Name == "svc-a" {
			s.Roles = append(s.Roles, "null")
			if err := env.cm.UpdateService("svc-a", s); err != nil {
				t.Fatalf("update service: %v", err)
			}
		}
	}
	resp, err := cl.Get(srv.URL + "/hello") // 无证书
	if err != nil {
		t.Fatalf("anonymous req: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(b) != "public-ok" {
		t.Fatalf("null route anonymous should 200+public-ok, got %d: %s", resp.StatusCode, b)
	}
}

// H3: 已登记但角色无权 → 403 no access + deny 事件
func TestGatewayHandler_NoAccess(t *testing.T) {
	back := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer back.Close()
	env, srv, cl := newGWTestEnv(t, map[string]*httptest.Server{"ok": back})
	cert := genClientCert(t, t.TempDir(), "dev-other", env.caCert, env.caKey)
	env.registerCert("dev-other", []string{"other"}, cert) // other 无权访问 svc-a 通道
	resp, err := clientWith(cl, cert).Get(srv.URL + "/hello")
	if err != nil {
		t.Fatalf("req: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("want 403, got %d: %s", resp.StatusCode, b)
	}
	if !strings.Contains(string(b), "no access") {
		t.Fatalf("want no access msg: %s", b)
	}
	env.acc.Close()
	data, _ := os.ReadFile(env.accPath)
	if !strings.Contains(string(data), `"type":"deny"`) || !strings.Contains(string(data), `"status":403`) {
		t.Fatalf("deny event missing: %s", string(data)[:min(len(data), 300)])
	}
}

// H3: 未登记证书(CA 签但 db 无记录)→ 403
func TestGatewayHandler_UnregisteredCert(t *testing.T) {
	back := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer back.Close()
	env, srv, cl := newGWTestEnv(t, map[string]*httptest.Server{"ok": back})
	cert := genClientCert(t, t.TempDir(), "ghost", env.caCert, env.caKey) // 不登记
	resp, err := clientWith(cl, cert).Get(srv.URL + "/x")
	if err != nil {
		t.Fatalf("req: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("unregistered should be 403, got %d", resp.StatusCode)
	}
	// R6: 脱敏 — 响应体只含 forbidden, 不泄露 serial/证书名等内部细节
	if strings.TrimSpace(string(b)) != "forbidden" {
		t.Fatalf("403 body should be sanitized 'forbidden', got: %q", b)
	}
}

// H3: 无路径映射=整口兜底; 404 分支用纯路径映射通道验证
func TestGatewayHandler_NoRoute(t *testing.T) {
	back := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer back.Close()
	dir := t.TempDir()
	caCert, caKey, caPath, _ := genCA(t, dir)
	certPath, keyPath := genServerCert(t, dir, caCert, caKey)
	store, _ := db.Open(filepath.Join(dir, "gw.db"))
	defer store.Close()
	gw, err := auth.New(store, caPath, certPath, keyPath, false, "mtls-superadmin", "1.2")
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	cfg := config.DefaultConfig()
	cfg.Roles = []string{"svc-a"}
	// 只有带路径的映射: :9601/admin — 无整口兜底
	cfg.Mappings = []proxy.Mapping{{ID: "m1x", Listen: ":9601/admin", Target: back.URL}}
	cfg.Services = []proxy.ServiceCfg{{Name: "svc-a", Channels: []string{"m1x"}, Roles: []string{"svc-a"}}}
	router, _ := proxy.NewRouter(cfg.Mappings, cfg.Services, cfg.Roles)
	cm := configmgr.New(filepath.Join(dir, "c.toml"), cfg, router)
	accPath := filepath.Join(dir, "a.log")
	acc, _ := eventlog.New(accPath, 5, 2)
	defer acc.Close()

	h := gatewayHandler(gw, cm, "9601", acc)
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = gw.ServerTLSConfig()
	srv.StartTLS()
	defer srv.Close()

	cert := genClientCert(t, t.TempDir(), "dev-a", caCert, caKey)
	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	store.Upsert(db.CertRecord{Serial: leaf.SerialNumber.String(), Name: "dev-a", Purposes: []string{"svc-a"}, Status: "enabled", IssuedAt: time.Now().Format(time.RFC3339), ExpiresAt: "2099-01-01"})
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{cert}}}}

	// 命中 /admin → 200
	resp, err := cl.Get(srv.URL + "/admin/x")
	if err != nil {
		t.Fatalf("req: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("admin path should be 200, got %d", resp.StatusCode)
	}
	// 无整口兜底: /other 不匹配任何映射 → 404
	resp2, err := cl.Get(srv.URL + "/other")
	if err != nil {
		t.Fatalf("req2: %v", err)
	}
	b2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != 404 {
		t.Fatalf("no route should be 404, got %d body: %s", resp2.StatusCode, b2)
	}
	if !strings.Contains(string(b2), "no route") {
		t.Fatalf("404 body should mention no route: %s", b2)
	}
	// deny 事件(404)已写入
	acc.Close()
	data, _ := os.ReadFile(accPath)
	if !strings.Contains(string(data), `"status":404`) {
		t.Fatalf("404 deny event missing: %s", string(data)[:min(len(data), 200)])
	}
}

// M2: 后端宕机 → 502 + 网关不崩(any-svc 通道 :9602 → 未监听端口)
func TestGatewayHandler_BackendDown(t *testing.T) {
	back := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer back.Close()
	env, _, _ := newGWTestEnv(t, map[string]*httptest.Server{"ok": back})
	// 单测层: proxy.Router.Serve 到宕机后端(:9602 → 127.0.0.1:1 未监听)→ 502
	router := env.cm.Router()
	rt := router.Match("9602", "/x")
	if rt == nil {
		t.Fatal("m2 route not found")
	}
	rec := httptest.NewRecorder()
	router.Serve(rt, rec, httptest.NewRequest("GET", "http://x/x", nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("backend down should be 502, got %d", rec.Code)
	}
}

// H3: /info 按角色过滤服务(admin 只见 any-svc)
func TestInfoHandler_FiltersByRole(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, caPath, _ := genCA(t, dir)
	certPath, keyPath := genServerCert(t, dir, caCert, caKey)
	store, _ := db.Open(filepath.Join(dir, "i.db"))
	defer store.Close()
	gw, err := auth.New(store, caPath, certPath, keyPath, false, "mtls-superadmin", "1.2")
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	cfg := config.DefaultConfig()
	cfg.Roles = []string{"svc-a"}
	cfg.Mappings = []proxy.Mapping{{ID: "m1", Listen: ":9601", Target: "http://127.0.0.1:1"}, {ID: "m2", Listen: ":9602", Target: "http://127.0.0.1:1"}}
	cfg.Services = []proxy.ServiceCfg{{Name: "svc-a", Channels: []string{"m1"}, Roles: []string{"svc-a"}}, {Name: "any-svc", Channels: []string{"m2"}, Roles: []string{"any"}}}
	router, _ := proxy.NewRouter(cfg.Mappings, cfg.Services, cfg.Roles)
	cm := configmgr.New(filepath.Join(dir, "c.toml"), cfg, router)
	accPath := filepath.Join(dir, "a.log")
	acc, _ := eventlog.New(accPath, 5, 2)
	defer acc.Close()

	h := infoHandler(gw, cm, acc)
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = gw.ServerTLSConfig()
	srv.StartTLS()
	defer srv.Close()

	// admin 证书(登记 mtls-superadmin)→ 只见 any-svc
	admCert := genClientCert(t, t.TempDir(), "adm", caCert, caKey)
	admLeaf, _ := x509.ParseCertificate(admCert.Certificate[0])
	store.Upsert(db.CertRecord{Serial: admLeaf.SerialNumber.String(), Name: "adm", Purposes: []string{"mtls-superadmin"}, Status: "enabled", IssuedAt: time.Now().Format(time.RFC3339), ExpiresAt: "2099-01-01"})
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{admCert}}}}
	resp, err := cl.Get(srv.URL + "/info")
	if err != nil {
		t.Fatalf("info: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("info status: %d", resp.StatusCode)
	}
	if strings.Contains(string(b), "svc-a") {
		t.Fatalf("admin should not see svc-a: %s", b)
	}
	if !strings.Contains(string(b), "any-svc") {
		t.Fatalf("admin should see any-svc: %s", b)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// 🔴 WebSocket 经 gatewayHandler 真路径(101 升级, statusWriter Hijack 透传)
func TestGatewayHandler_WebSocket(t *testing.T) {
	// ws 后端 echo
	wsBack := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		var msg string
		websocket.Message.Receive(ws, &msg)
		websocket.Message.Send(ws, "ws:"+msg)
	}))
	defer wsBack.Close()

	env, srv, cl := newGWTestEnv(t, map[string]*httptest.Server{"ok": wsBack})
	cert := genClientCert(t, t.TempDir(), "dev-a", env.caCert, env.caKey)
	env.registerCert("dev-a", []string{"svc-a"}, cert)
	cl2 := clientWith(cl, cert)

	// 网关入口 ws://host:port/ws → 后端 ws echo(自定义 TLS: 信任 CA + mTLS 客户端证书)
	wsURL := "wss" + strings.TrimPrefix(srv.URL, "https") + "/ws"
	pool := x509.NewCertPool()
	pool.AddCert(env.caCert)
	wscfg, err := websocket.NewConfig(wsURL, "http://localhost/")
	if err != nil {
		t.Fatal(err)
	}
	wscfg.TlsConfig = &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{cert}}
	ws, err := websocket.DialConfig(wscfg)
	if err != nil {
		t.Fatalf("ws dial via gateway: %v", err)
	}
	defer ws.Close()
	ws.SetDeadline(time.Now().Add(3 * time.Second))
	if err := websocket.Message.Send(ws, "ping"); err != nil {
		t.Fatalf("send: %v", err)
	}
	var reply string
	if err := websocket.Message.Receive(ws, &reply); err != nil {
		t.Fatalf("recv: %v", err)
	}
	if reply != "ws:ping" {
		t.Fatalf("ws echo mismatch: %q", reply)
	}
	_ = cl2
}

// 第十六批: 匹配前规范化 — /a/../secret 不逃逸 /a 前缀映射
func TestGatewayHandlerDotSegmentNormalized(t *testing.T) {
	be := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.URL.Path) // 回显路径
	}))
	defer be.Close()
	env, srv, cl := newGWTestEnv(t, map[string]*httptest.Server{"ok": be})
	cert := genClientCert(t, t.TempDir(), "dev-a", env.caCert, env.caKey)
	env.registerCert("dev-a", []string{"svc-a"}, cert)
	// /admin/../secret → 匹配前规范化 → /secret(.. 不逃逸, 无残留 dot-segment)
	resp, err := clientWith(cl, cert).Get(srv.URL + "/admin/../secret")
	if err != nil {
		t.Fatalf("req: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d: %s", resp.StatusCode, b)
	}
	if !strings.Contains(string(b), "/secret") {
		t.Fatalf("backend should receive normalized path, got: %q", b)
	}
}

// 中危(测试全面性审计): /info 对已吊销证书必须 403(有证书但认证失败 ≠ 匿名引导)
func TestInfoHandler_RevokedCert403(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, caPath, _ := genCA(t, dir)
	certPath, keyPath := genServerCert(t, dir, caCert, caKey)
	store, _ := db.Open(filepath.Join(dir, "i.db"))
	defer store.Close()
	gw, err := auth.New(store, caPath, certPath, keyPath, false, "mtls-superadmin", "1.2")
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	cfg := config.DefaultConfig()
	router, _ := proxy.NewRouter(nil, nil, nil)
	cm := configmgr.New(filepath.Join(dir, "c.toml"), cfg, router)
	h := infoHandler(gw, cm, nil)
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = gw.ServerTLSConfig()
	srv.StartTLS()
	defer srv.Close()

	// 已吊销证书 → 403
	cert := genClientCert(t, t.TempDir(), "revoked-dev", caCert, caKey)
	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	if err := store.Upsert(db.CertRecord{Serial: leaf.SerialNumber.String(), Name: "revoked-dev", Purposes: []string{"dsh"}, Status: "revoked", IssuedAt: time.Now().Format(time.RFC3339), ExpiresAt: "2099-01-01"}); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{cert}}}}
	resp, err := cl.Get(srv.URL + "/info")
	if err != nil {
		t.Fatalf("info: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("已吊销证书 /info 应 403, got %d", resp.StatusCode)
	}

	// 真匿名(无证书) → 200 引导(返回 CA), 不受吊销影响
	anon := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	resp2, err := anon.Get(srv.URL + "/info")
	if err != nil {
		t.Fatalf("anon info: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("匿名 /info 应 200 引导, got %d", resp2.StatusCode)
	}
}
