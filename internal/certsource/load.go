package certsource

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// tlsFromPEM 从 PEM 字节构造 tls.Certificate.
// pemBytes 应含 CERTIFICATE 块 (可含链), 以及 PRIVATE KEY 或 RSA PRIVATE KEY 块.
func tlsFromPEM(name string, pemBytes []byte) (tls.Certificate, error) {
	cert, err := tls.X509KeyPair(pemBytes, pemBytes)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse pem keypair %s: %w", name, err)
	}
	return cert, nil
}

// tlsFromP12 从 p12 字节 + 密码构造 tls.Certificate
func tlsFromP12(name string, p12Bytes []byte, password string) (tls.Certificate, error) {
	key, cert, err := pkcs12.Decode(p12Bytes, password)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("decode p12 %s: %w", name, err)
	}
	k, ok := key.(crypto.PrivateKey)
	if !ok {
		return tls.Certificate{}, fmt.Errorf("p12 %s: private key type %T unsupported", name, key)
	}
	return tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  k,
		Leaf:        cert,
	}, nil
}

// readCertMeta 从 DER 证书提取展示元数据 (不加载私钥)
func metaFromCert(cert *x509.Certificate, id, foundIn string) IdentityMeta {
	m := IdentityMeta{
		ID:      id,
		Issuer:  cert.Issuer.CommonName,
		FoundIn: foundIn,
	}
	if cert.Subject.CommonName != "" {
		m.CommonName = cert.Subject.CommonName
	} else if len(cert.Subject.Organization) > 0 {
		m.CommonName = cert.Subject.Organization[0]
	}
	m.ValidFrom = cert.NotBefore.Format("2006-01-02")
	m.ValidUntil = cert.NotAfter.Format("2006-01-02")
	return m
}

// isGwIssued 判断证书是否由 mtls-gw 类 CA 签发 (Issuer 或 O 含 mtls-gw / org)
func isGwIssued(cert *x509.Certificate, org string) bool {
	if cert.Issuer.CommonName == "" {
		return false
	}
	if containsCI(cert.Issuer.CommonName, "mtls-gw") || containsCI(cert.Issuer.CommonName, "mtls") {
		return true
	}
	if org != "" {
		for _, o := range cert.Issuer.Organization {
			if containsCI(o, org) {
				return true
			}
		}
	}
	return false
}

func containsCI(s, sub string) bool {
	if len(sub) > len(s) {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if equalFold(s[i:i+len(sub)], sub) {
			return true
		}
	}
	return false
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// parseCertFromPEM 从 PEM 字节解析第一个证书
func parseCertFromPEM(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no CERTIFICATE block in pem")
	}
	return parseCertFromDER(block.Bytes)
}

// parseCertFromDER 从 DER 字节解析证书
func parseCertFromDER(der []byte) (*x509.Certificate, error) {
	return x509.ParseCertificate(der)
}

// p12DecodeCerts 尝试从 p12 数据解析证书链 (仅空密码, V1 目录内 p12 密码要求.)
func p12DecodeCerts(data []byte) ([]*x509.Certificate, error) {
	_, cert, caCerts, err := pkcs12.DecodeChain(data, "")
	if err != nil {
		return nil, err
	}
	return append([]*x509.Certificate{cert}, caCerts...), nil
}

// loadFilePEMOrP12 按扩展名加载文件 (pem/crt=keypair; p12/pfx=需要密码)
func loadFilePEMOrP12(path string) (tls.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("read %s: %w", path, err)
	}
	ext := lowerExt(path)
	switch ext {
	case ".p12", ".pfx":
		// p12 需要密码: 常见为无密码 (空串) 或尝试常见缺省; 成功与否取决于文件.
		// 这里先试空密码, 失败则报错提示 (V1 不做交互取密码).
		if c, err := tlsFromP12(path, data, ""); err == nil {
			return c, nil
		}
		return tls.Certificate{}, fmt.Errorf("p12 needs password (unsupported in V1); use pem instead: %s", path)
	default:
		return tlsFromPEM(path, data)
	}
}

func lowerExt(path string) string {
	s := ""
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '.' {
			s = path[i:]
			break
		}
		if path[i] == '/' || path[i] == '\\' {
			break
		}
	}
	b := []byte(s)
	for i := range b {
		if 'A' <= b[i] && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}
