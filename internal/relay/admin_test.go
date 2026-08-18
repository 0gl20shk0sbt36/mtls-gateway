package relay

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testPKI(t *testing.T) (*x509.CertPool, tls.Certificate, tls.Certificate) {
	t.Helper()
	now := time.Now()

	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t-ca"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)

	mkLeaf := func(cn string, serial int64, isServer bool) tls.Certificate {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature}
		if isServer {
			tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		} else {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, caTmpl, &k.PublicKey, caKey)
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
	}
	server := mkLeaf("localhost", 2, true)
	client := mkLeaf("t-admin", 3, false)
	return pool, server, client
}

func TestAdminClientRoundTrip(t *testing.T) {
	pool, serverCert, clientCert := testPKI(t)

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/health":
			w.Write([]byte("ok"))
		case "/admin/certs/issue":
			var req IssueRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			json.NewEncoder(w).Encode(IssueResponse{Name: req.Name, Serial: "abcd1234",
				CertPEM: "CERT", P12Password: req.Password})
		case "/admin/certs/revoke":
			w.WriteHeader(200)
		default:
			http.NotFound(w, r)
		}
	}))
	ts.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool,
		Certificates: []tls.Certificate{serverCert}}
	ts.StartTLS()
	defer ts.Close()

	ac := NewAdminClient(strings.TrimPrefix(ts.URL, "https://"), clientCert, pool)

	if err := ac.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	resp, err := ac.Issue(IssueRequest{Name: "dev-1", Purposes: []string{"dsh"}, Password: "secret"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if resp.Name != "dev-1" || resp.Serial != "abcd1234" || resp.P12Password != "secret" {
		t.Fatalf("issue resp mismatch: %+v", resp)
	}

	if err := ac.Revoke("abcd1234"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
}
