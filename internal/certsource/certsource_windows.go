//go:build windows

package certsource

import (
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/tg123/certstore"
)

// Windows 系统证书库: 打开「个人 / My」存储, 列出所有带私钥的身份,
// 用户选择其一用于 mTLS 客户端认证. 默认只展示 mtls-gw 签发的身份.
type winSource struct {
	filterOrg string
	showAll   bool
}

func openSystemImpl() (Source, error) {
	return &winSource{}, nil
}

// SetFilter 设置是否只展示给定 org 签发的证书
func (s *winSource) SetFilter(org string, showAll bool) { s.filterOrg, s.showAll = org, showAll }

// accept 是否展示该证书 (无过滤要求 / 显示全部 / 由目标 org 签发)
func (s *winSource) accept(cert *x509.Certificate) bool {
	if s.filterOrg == "" || s.showAll {
		return true
	}
	return isGwIssued(cert, s.filterOrg)
}

// List 列出「个人/My」存储里带私钥的身份
func (s *winSource) List() ([]IdentityMeta, error) {
	store, err := certstore.Open()
	if err != nil {
		return nil, fmt.Errorf("open cert store: %w", err)
	}
	defer store.Close()

	idents, err := store.Identities()
	if err != nil {
		return nil, fmt.Errorf("list identities: %w", err)
	}

	var metas []IdentityMeta
	for _, id := range idents {
		cert, err := id.Certificate()
		if err != nil {
			id.Close()
			continue
		}
		thumb := certThumbprint(cert)
		if s.accept(cert) {
			m := metaFromCert(cert, thumb, "system:My")
			metas = append(metas, m)
		}
		id.Close()
	}
	sort.Slice(metas, func(i, j int) bool { return metas[i].CommonName < metas[j].CommonName })
	return metas, nil
}

// Load 按 thumbprint 加载身份并组装可用的 mTLS 客户端证书
func (s *winSource) Load(thumb string) (tls.Certificate, error) {
	store, err := certstore.Open()
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("open cert store: %w", err)
	}
	defer store.Close()

	idents, err := store.Identities()
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("list identities: %w", err)
	}
	for _, id := range idents {
		cert, err := id.Certificate()
		if err != nil {
			id.Close()
			continue
		}
		if certThumbprint(cert) == thumb {
			signer, err := id.Signer()
			if err != nil {
				id.Close()
				return tls.Certificate{}, fmt.Errorf("signer for %s: %w", thumb, err)
			}
			chain := [][]byte{cert.Raw}
			if chainCerts, err := id.CertificateChain(); err == nil && len(chainCerts) > 0 {
				chain = chainCertsToDER(chainCerts)
			}
			tc := tls.Certificate{
				Certificate: chain,
				PrivateKey:  signer,
				Leaf:        cert,
			}
			id.Close()
			return tc, nil
		}
		id.Close()
	}
	return tls.Certificate{}, fmt.Errorf("certificate with thumbprint %s not found in system:My", thumb)
}

func chainCertsToDER(certs []*x509.Certificate) [][]byte {
	out := make([][]byte, 0, len(certs))
	for _, c := range certs {
		out = append(out, c.Raw)
	}
	return out
}

// certThumbprint 返回证书 SHA-1 指纹 (大写, 冒号分隔) — Windows 标准 thumbprint
func certThumbprint(cert *x509.Certificate) string {
	sum := sha1.Sum(cert.Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = strings.ToUpper(hex.EncodeToString([]byte{b}))
	}
	return strings.Join(parts, ":")
}
