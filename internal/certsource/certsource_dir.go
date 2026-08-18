package certsource

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// dirSource 目录扫描源: 每子目录一个证书 (<name>/cert.pem + <name>/key.pem),
// 或顶层 *.p12。ID = 相对路径 (如 "device-a" 或 "device-a.p12")。
type dirSource struct {
	root      string
	filterOrg string // 非空则只展示由该 org 签发的证书
	showAll   bool   // 显示全部 (跳过 filterOrg 过滤)
}

// openDirImpl 创建目录源 (certsource.go 分派的平台无关实现)
func openDirImpl(root string) (Source, error) {
	st, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("stat cert dir: %w", err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("not a directory: %s", root)
	}
	return &dirSource{root: root}, nil
}

// SetFilter 设置是否只展示给定 org 签发的证书
func (d *dirSource) SetFilter(org string, showAll bool) { d.filterOrg, d.showAll = org, showAll }

// accept 是否展示该证书 (无过滤要求 / 显示全部 / 由目标 org 签发)
func (d *dirSource) accept(cert *x509.Certificate) bool {
	if d.filterOrg == "" || d.showAll {
		return true
	}
	return isGwIssued(cert, d.filterOrg)
}

// List 扫描目录, 返回每条身份元数据
func (d *dirSource) List() ([]IdentityMeta, error) {
	entries, err := os.ReadDir(d.root)
	if err != nil {
		return nil, fmt.Errorf("read dir %s: %w", d.root, err)
	}
	var metas []IdentityMeta
	for _, e := range entries {
		name := e.Name()
		full := filepath.Join(d.root, name)
		if e.IsDir() {
			// 子目录: cert.pem + key.pem
			if _, err := os.Stat(filepath.Join(full, "cert.pem")); err != nil {
				continue
			}
			if _, err := os.Stat(filepath.Join(full, "key.pem")); err != nil {
				continue
			}
			data, err := os.ReadFile(filepath.Join(full, "cert.pem"))
			if err != nil {
				continue
			}
			cert, err := parseCertFromPEM(data)
			if err != nil {
				continue
			}
			if !d.accept(cert) {
				continue
			}
			metas = append(metas, metaFromCert(cert, name, "dir:"+d.root))
		} else if strings.EqualFold(filepath.Ext(name), ".p12") {
			data, err := os.ReadFile(full)
			if err != nil {
				continue
			}
			certs, err := p12DecodeCerts(data)
			if err != nil || len(certs) == 0 {
				continue // 需密码的 p12 跳过 (V1)
			}
			if !d.accept(certs[0]) {
				continue
			}
			metas = append(metas, metaFromCert(certs[0], name, "dir:"+d.root))
		}
	}
	sort.Slice(metas, func(i, j int) bool { return metas[i].ID < metas[j].ID })
	return metas, nil
}

// Load 按 ID (相对路径) 加载证书
func (d *dirSource) Load(id string) (tls.Certificate, error) {
	// 拒绝路径穿越
	if strings.Contains(id, "..") || filepath.IsAbs(id) {
		return tls.Certificate{}, fmt.Errorf("invalid cert id: %s", id)
	}
	full := filepath.Join(d.root, id)
	st, err := os.Stat(full)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("cert %s not found: %w", id, err)
	}
	if st.IsDir() {
		cert, err := os.ReadFile(filepath.Join(full, "cert.pem"))
		if err != nil {
			return tls.Certificate{}, err
		}
		key, err := os.ReadFile(filepath.Join(full, "key.pem"))
		if err != nil {
			return tls.Certificate{}, err
		}
		combined := append(append(append([]byte{}, cert...), '\n'), key...)
		return tlsFromPEM(id, combined)
	}
	return loadFilePEMOrP12(full)
}
