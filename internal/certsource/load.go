// load.go: pem/p12 加载与加密私钥密码处理(密码加载/错误归一)。

package certsource

import (
	"crypto"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"mtls-gateway/internal/errs"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// certThumbprint 返回证书 SHA-1 指纹 (大写, 冒号分隔) — Windows 标准 thumbprint(平台无关)
func certThumbprint(cert *x509.Certificate) string {
	sum := sha1.Sum(cert.Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = strings.ToUpper(hex.EncodeToString([]byte{b}))
	}
	return strings.Join(parts, ":")
}

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

// containsCI 大小写不敏感子串匹配(复用标准库, 正确处理 Unicode)
func containsCI(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
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

// tlsFromPEMWithPassword 从 PEM 构造证书; 若私钥被加密则用 password 解密重建。
// 支持遗留 DEK-Info 加密 (RSA/EC PRIVATE KEY); PKCS#8 "ENCRYPTED PRIVATE KEY" 无标准库 → 提示用 .p12。
func tlsFromPEMWithPassword(name string, pemBytes []byte, password string) (tls.Certificate, error) {
	if c, err := tls.X509KeyPair(pemBytes, pemBytes); err == nil {
		return c, nil // 未加密
	}
	if password == "" {
		return tls.Certificate{}, errs.New(errs.KindPwdNeeded, "private key needs password: %s", name)
	}
	rest := pemBytes
	var all []byte
	for {
		b, r := pem.Decode(rest)
		if b == nil {
			break
		}
		rest = r
		// 兼容 openssl 传统加密私钥(DEK-Info 头): 仅 x509.DecryptPEMBlock 能解。
		// 该 API 自 Go 1.16 起 deprecated, 但 Go 标准库暂无替代(go-pkcs12 只处理 p12);
		// 保留直至官方移除或引入替代。PKCS#8 加密私钥(ENCRYPTED PRIVATE KEY)走 p12。
		if x509.IsEncryptedPEMBlock(b) {
			der, err := x509.DecryptPEMBlock(b, []byte(password))
			if err != nil {
				return tls.Certificate{}, errs.WithKind(fmt.Errorf("decrypt key %s: %v", name, err), errs.KindBadPwd)
			}
			b = &pem.Block{Type: b.Type, Bytes: der}
		} else if b.Type == "ENCRYPTED PRIVATE KEY" {
			return tls.Certificate{}, fmt.Errorf("pkcs#8 encrypted key unsupported, use .p12: %s", name)
		}
		all = append(all, pem.EncodeToMemory(b)...)
	}
	kc, err := tls.X509KeyPair(all, all)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse keypair %s: %w", name, err)
	}
	return kc, nil
}

// loadFilePEMOrP12Pwd 按扩展名加载 (pem/crt keypair 或 p12/pfx); 带密码支持
func loadFilePEMOrP12Pwd(path, password string) (tls.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("read %s: %w", path, err)
	}
	switch lowerExt(path) {
	case ".p12", ".pfx":
		return tlsFromP12(path, data, password)
	default:
		return tlsFromPEMWithPassword(path, data, password)
	}
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
		return tls.Certificate{}, errs.New(errs.KindPwdNeeded, "p12 needs password (加密 p12 需密码, 请用密码加载或改用 pem): %s", path)
	default:
		return tlsFromPEM(path, data)
	}
}

func lowerExt(path string) string {
	return strings.ToLower(filepath.Ext(path))
}
