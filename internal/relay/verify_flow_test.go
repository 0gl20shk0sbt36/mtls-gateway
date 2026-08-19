package relay

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mtls-gateway/internal/certsource"
	"time"
)

// startVerifyGW HTTP 网关 stub: /info 返回 services + /admin/verify 200 (真 mTLS)
func startVerifyGW(t *testing.T, dir string, services []map[string]any) (gwAddr, caPath, clientPair string) {
	t.Helper()
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "verify-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	sk, _ := rsa.GenerateKey(rand.Reader, 2048)
	stmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "verify-gw"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	sDER, err := x509.CreateCertificate(rand.Reader, stmpl, caCert, &sk.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	sKeyDER, _ := x509.MarshalPKCS8PrivateKey(sk)
	sPair := joinPEM(sDER, sKeyDER)
	ck, _ := rsa.GenerateKey(rand.Reader, 2048)
	ctmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "verify-dev"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{net.ParseIP("100.64.0.2")},
	}
	cDER, err := x509.CreateCertificate(rand.Reader, ctmpl, caCert, &ck.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cKeyDER, _ := x509.MarshalPKCS8PrivateKey(ck)
	clientPair = filepath.Join(dir, "client.pem")
	os.WriteFile(clientPair, joinPEM(cDER, cKeyDER), 0o600)
	caPath = filepath.Join(dir, "ca.crt")
	os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600)

	rawLn, _ := net.Listen("tcp", "127.0.0.1:0")
	srvPair, _ := tls.X509KeyPair(sPair, sPair)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	gwTLS := &tls.Config{
		Certificates: []tls.Certificate{srvPair},
		ClientAuth:   tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS12,
	}
	ln := tls.NewListener(rawLn, gwTLS)
	mux := http.NewServeMux()
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"services": services})
	})
	mux.HandleFunc("/admin/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/admin/certs/issue", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name string `json:"name"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		json.NewEncoder(w).Encode(map[string]any{"name": req.Name, "serial": "test-serial-1", "p12_password": "pw"})
	})
	mux.HandleFunc("/admin/certs/revoke", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/admin/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" { // 真实服务端 SetConfig 走 POST
			w.Write([]byte(`{"ok":true}`))
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"listen_host": "127.0.0.1", "tunnels": []any{}})
	})
	mux.HandleFunc("/admin/mappings", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"mappings": []any{map[string]any{"id": "m1", "listen": ":9601", "target": "http://x"}}})
	})
	mux.HandleFunc("/admin/certs", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]any{map[string]any{"serial": "1", "name": "dev", "status": "enabled"}})
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close(); ln.Close() })
	return rawLn.Addr().String(), caPath, clientPair
}

func joinPEM(certDER, keyDER []byte) []byte {
	c := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	k := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	out := make([]byte, 0, len(c)+len(k)+1)
	out = append(out, c...)
	out = append(out, '\n')
	out = append(out, k...)
	return out
}

// MH-1: Manager.Verify 完整流程 — /info 成功 + admin 探活成功 → Services+Admin
func TestManagerVerify_FullFlow(t *testing.T) {
	dir := t.TempDir()
	svcs := []map[string]any{{"name": "svc-a", "channels": []any{map[string]any{"listen": ":9601", "target": "http://x"}}}}
	gwAddr, caPath, clientPair := startVerifyGW(t, dir, svcs)
	src, err := certsource.OpenFile(clientPair)
	if err != nil {
		t.Fatal(err)
	}
	r := New("", src)
	r.SetServerAddr(gwAddr)
	_ = r.SetServerCA(caPath)
	cfgPath := filepath.Join(dir, "relay.json")
	SaveConfig(cfgPath, RelayConfig{ServerAddr: gwAddr, ServerCAFile: caPath, AdminAddr: gwAddr, Tunnels: []Tunnel{}})
	m, err := NewManager(r, cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	res, err := m.Verify(clientPair, "")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(res.Services) == 0 {
		t.Fatal("services should be discovered")
	}
	if !res.Admin {
		t.Fatal("admin probe should succeed (gw stub /admin/verify 200)")
	}
}

// MH-4: admin 探活静默失败语义 — gw stub 无 /admin/verify → Admin=false 不报错
func TestManagerVerify_AdminProbeSilent(t *testing.T) {
	dir := t.TempDir()
	svcs := []map[string]any{{"name": "svc-a", "channels": []any{map[string]any{"listen": ":9601", "target": "http://x"}}}}
	gwAddr, caPath, clientPair := startVerifyGW(t, dir, svcs)
	src, _ := certsource.OpenFile(clientPair)
	r := New("", src)
	r.SetServerAddr(gwAddr)
	_ = r.SetServerCA(caPath)
	cfgPath := filepath.Join(dir, "relay.json")
	// AdminAddr 指向一个不响应 /admin/verify 的地址 → 探活失败
	SaveConfig(cfgPath, RelayConfig{ServerAddr: gwAddr, ServerCAFile: caPath, AdminAddr: "127.0.0.1:1", Tunnels: []Tunnel{}})
	m, _ := NewManager(r, cfgPath)
	res, err := m.Verify(clientPair, "")
	if err != nil {
		t.Fatalf("verify should not fail on admin probe: %v", err)
	}
	if res.Admin {
		t.Fatal("admin probe should silently fail (Admin=false)")
	}
	if len(res.Services) == 0 {
		t.Fatal("services should still be discovered")
	}
}

// R7: admin 桥成功路径 — 经 Manager.Handler() 调服务端签发(HTTP 层)
func TestManagerAdminBridgeIssueHTTP(t *testing.T) {
	dir := t.TempDir()
	svcs := []map[string]any{{"name": "svc-a", "channels": []any{map[string]any{"listen": ":9601", "target": "http://x"}}}}
	gwAddr, caPath, clientPair := startVerifyGW(t, dir, svcs)
	src, _ := certsource.OpenFile(clientPair)
	r := New("", src)
	r.SetServerAddr(gwAddr)
	r.SetServerCA(caPath)
	cfgPath := filepath.Join(dir, "relay.json")
	SaveConfig(cfgPath, RelayConfig{ServerAddr: gwAddr, ServerCAFile: caPath, AdminAddr: gwAddr, Tunnels: []Tunnel{}})
	m, _ := NewManager(r, cfgPath)
	m.SetNoPersist(true)
	h := m.Handler()

	// 签发(经管理桥 → stub /admin/certs/issue)
	body := `{"cert_id":"` + clientPair + `","name":"bridge-dev","purposes":["svc-a"],"no_password":true}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/admin/issue", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("admin issue via bridge should be 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["serial"] != "test-serial-1" {
		t.Fatalf("issue response: %v", resp)
	}
	// 吊销(经管理桥)
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("POST", "/api/admin/revoke", strings.NewReader(`{"cert_id":"`+clientPair+`","serial":"test-serial-1"}`))
	req2.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec2, req2)
	if rec2.Code != 200 {
		t.Fatalf("admin revoke via bridge should be 200, got %d: %s", rec2.Code, rec2.Body.String())
	}
}

// 第二十一批: Discover 默认路径(loadFirstCert → /info)+ AdminClient 配置 CRUD
func TestDiscoverDefaultPath(t *testing.T) {
	dir := t.TempDir()
	svcs := []map[string]any{{"name": "svc-a", "channels": []any{map[string]any{"listen": ":9601", "target": "http://x"}}}}
	gwAddr, caPath, clientPair := startVerifyGW(t, dir, svcs)
	src, _ := certsource.OpenFile(clientPair)
	r := New("", src)
	r.SetServerAddr(gwAddr)
	r.SetServerCA(caPath)
	svc, err := r.Discover() // 默认路径: 无证书参数 → loadFirstCert
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(svc) != 1 || svc[0].Name != "svc-a" {
		t.Fatalf("discover result: %+v", svc)
	}
}

// 第二十一批: AdminClient 配置 CRUD(List/Cfg/SetConfig/Mapping/Service)
func TestAdminClientConfigCRUD(t *testing.T) {
	dir := t.TempDir()
	svcs := []map[string]any{{"name": "svc-a", "channels": []any{map[string]any{"listen": ":9601", "target": "http://x"}}}}
	gwAddr, caPath, clientPair := startVerifyGW(t, dir, svcs)
	src, _ := certsource.OpenFile(clientPair)
	r := New("", src)
	r.SetServerAddr(gwAddr)
	r.SetServerCA(caPath)
	cfgPath := filepath.Join(dir, "relay.json")
	SaveConfig(cfgPath, RelayConfig{ServerAddr: gwAddr, ServerCAFile: caPath, AdminAddr: gwAddr})
	m, err := NewManager(r, cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	m.SetNoPersist(true)
	// Verify(解锁 admin)
	if _, err := m.Verify(clientPair, ""); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// List(证书列表, 经 AdminVerify 解锁)
	if err := m.AdminVerify(clientPair, ""); err != nil {
		t.Fatalf("AdminVerify: %v", err)
	}
	// Cfg(服务端配置, RawMessage)
	raw, err := m.AdminConfig(clientPair, "")
	if err != nil || !strings.Contains(string(raw), "127.0.0.1") {
		t.Fatalf("AdminConfig: %s err=%v", raw, err)
	}
	// SetConfig(写配置)
	if _, err := m.AdminSetConfig(clientPair, "", raw); err != nil {
		t.Fatalf("AdminSetConfig: %v", err)
	}
	// Mappings(映射列表)
	rawM, err := m.AdminMapping(clientPair, "", "GET", "", nil)
	if err != nil || !strings.Contains(string(rawM), "m1") {
		t.Fatalf("AdminMapping GET: %s err=%v", rawM, err)
	}
}

// 第二十二批: AdminClient List(证书列表)+ ListMappings(映射, 真类型)+ Service
func TestAdminClientListAndService(t *testing.T) {
	dir := t.TempDir()
	svcs := []map[string]any{{"name": "svc-a", "channels": []any{map[string]any{"listen": ":9601", "target": "http://x"}}}}
	gwAddr, caPath, clientPair := startVerifyGW(t, dir, svcs)
	src, _ := certsource.OpenFile(clientPair)
	r := New("", src)
	r.SetServerAddr(gwAddr)
	r.SetServerCA(caPath)
	cfgPath := filepath.Join(dir, "relay.json")
	SaveConfig(cfgPath, RelayConfig{ServerAddr: gwAddr, ServerCAFile: caPath, AdminAddr: gwAddr})
	m, err := NewManager(r, cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	m.SetNoPersist(true)
	// List(证书列表原始 JSON)
	raw, err := m.AdminListCerts(clientPair, "")
	if err != nil || !strings.Contains(string(raw), `"dev"`) {
		t.Fatalf("AdminListCerts: %s err=%v", raw, err)
	}
	// ListMappings(映射, 修正后类型: id/listen/target)
	ms, err := m.AdminMappings(clientPair, "")
	if err != nil || len(ms) != 1 || ms[0].ID != "m1" || ms[0].Listen != ":9601" {
		t.Fatalf("AdminMappings: %+v err=%v", ms, err)
	}
}
