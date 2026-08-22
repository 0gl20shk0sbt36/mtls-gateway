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

	"mtls-gateway/internal/errs"
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

// 批次 B-4: AdminClient 解析服务端 JSON 错误信封 {error, kind} —
// kind 还原结构化分类, localizeKnown 直接按 kind 翻译(不再依赖消息子串)
func TestAdminClientEnvelopeKind(t *testing.T) {
	pool, serverCert, clientCert := testPKI(t)
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(409)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "certificate name dev already exists (3 record(s)), 禁止同名签发",
			"kind":  "conflict",
		})
	}))
	ts.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool,
		Certificates: []tls.Certificate{serverCert}}
	ts.StartTLS()
	defer ts.Close()

	ac := NewAdminClient(strings.TrimPrefix(ts.URL, "https://"), clientCert, pool)
	_, err := ac.Issue(IssueRequest{Name: "dev", Purposes: []string{"dsh"}})
	if err == nil {
		t.Fatal("应报错")
	}
	if k := errs.KindOf(err); k != errs.KindConflict {
		t.Fatalf("kind = %q, want conflict", k)
	}
	// errStatus: 信封还原后的错误仍能提取 HTTP 状态(权威 409)
	if got := errStatus(err); got != 409 {
		t.Fatalf("errStatus = %d, want 409", got)
	}
	// localizeKnown 按 kind 翻译(含证书名与记录数参数)
	zh := localizeKnown("zh", err).Error()
	if !strings.Contains(zh, "dev") || !strings.Contains(zh, "3") {
		t.Fatalf("localizeKnown = %q, 期望含证书名与记录数", zh)
	}
}

// 批次 B-4: localizeKnown 结构化 kind 快路径(本地 typed 错误, 无需子串匹配)
func TestLocalizeKnownTypedKind(t *testing.T) {
	cases := []struct {
		err  error
		want string // 期望中文包含词
	}{
		{errs.New(errs.KindPwdNeeded, "private key needs password: admin"), "私钥需要密码"},
		{errs.New(errs.KindBadPwd, "decrypt key admin: password incorrect"), "密码错误"},
		{errs.New(errs.KindExpired, "cert abc expired"), "过期"},
		{errs.New(errs.KindNoCert, "no certificates in source"), "没有可用客户端证书"},
		{errs.New(errs.KindAdminDenied, "admin cert required"), "管理权限被拒绝"},
		{errs.New(errs.KindForbidden, "forbidden"), "拒绝"},
		{errs.New(errs.KindNotFound, "cert ghost not found"), "未找到"},
		{errs.New(errs.KindNotRegistered, "cert abc not registered"), "未找到"},
		{errs.New(errs.KindRevoked, "cert abc status=revoked"), "已被吊销"},
		{errs.New(errs.KindImmutable, "config is immutable"), "只读"},
		{errs.New(errs.KindConflict, "certificate name dev already exists (3 record(s))"), "已存在"},
	}
	for _, c := range cases {
		got := localizeKnown("zh", c.err).Error()
		if !strings.Contains(got, c.want) {
			t.Errorf("localizeKnown(%q) = %q, 期望含 %q", c.err.Error(), got, c.want)
		}
		// 未收录 kind(BadRequest 泛化)回退子串: 有专属翻译仍命中
		br := errs.New(errs.KindBadRequest, "name and purposes required")
		if got := localizeKnown("zh", br).Error(); !strings.Contains(got, "必填") {
			t.Errorf("BadRequest 回退子串翻译: %q", got)
		}
		// 完全未知错误原样
		raw := errs.New(errs.KindBadRequest, "some unknown error xyz")
		if localizeKnown("zh", raw).Error() != raw.Error() {
			t.Errorf("未收录应原样")
		}
	}
}
