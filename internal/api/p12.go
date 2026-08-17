package api

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// writeP12 生成 PKCS#12 (p12) 文件供浏览器/手机导入
func writeP12(path string, certPEM, keyPEM []byte, password string) error {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return fmt.Errorf("decode cert pem")
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("decode key pem")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse cert: %w", err)
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse key: %w", err)
	}
	p12Data, err := pkcs12.Modern.Encode(key, cert, nil, password)
	if err != nil {
		return fmt.Errorf("pkcs12 encode: %w", err)
	}
	return os.WriteFile(path, p12Data, 0o600)
}
