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
	"os"
	"path/filepath"
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
	r.SetServerCA(caPath)
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
	r.SetServerCA(caPath)
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
