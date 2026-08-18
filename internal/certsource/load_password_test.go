package certsource

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestTLSFromPEMWithPassword(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	// 一个自签叶子证书 (tls.X509KeyPair 需要证书块)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pwd-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// 加密私钥 (遗留 DEK-Info)
	encBlock, err := x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", keyDER, []byte("secret"), x509.PEMCipherAES256)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(encBlock)
	all := append(append(append([]byte{}, certPEM...), '\n'), keyPEM...)

	// 无密码 → needs password
	if _, err := tlsFromPEMWithPassword("t", all, ""); err == nil {
		t.Fatal("expected: needs password")
	}
	// 正确密码 → 加载成功
	c, err := tlsFromPEMWithPassword("t", all, "secret")
	if err != nil {
		t.Fatalf("load with pwd: %v", err)
	}
	if c.PrivateKey == nil {
		t.Fatal("no private key loaded")
	}
	// 错误密码 → 解密失败
	if _, err := tlsFromPEMWithPassword("t", all, "wrong"); err == nil {
		t.Fatal("expected: wrong password error")
	}
}
