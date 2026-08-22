// certsource_file.go: file 证书源 — 单文件 pem/p12 证书(显式路径)。

package certsource

import "crypto/tls"

// fileSource 单个文件来源 (pem/p12), 跨平台兜底.
type fileSource struct {
	path string
}

// List 单文件源只有一条身份 (ID = 路径)
func (s *fileSource) List() ([]IdentityMeta, error) {
	cert, err := loadFilePEMOrP12(s.path)
	if err != nil {
		return nil, err
	}
	if cert.Leaf != nil {
		return []IdentityMeta{metaFromCert(cert.Leaf, s.path, "file:"+s.path)}, nil
	}
	// tls.X509KeyPair 不填 Leaf; 从证书 DER 解析
	if len(cert.Certificate) > 0 {
		if leaf, err := parseCertFromDER(cert.Certificate[0]); err == nil {
			return []IdentityMeta{metaFromCert(leaf, s.path, "file:"+s.path)}, nil
		}
	}
	return []IdentityMeta{{ID: s.path, CommonName: s.path, FoundIn: "file:" + s.path}}, nil
}

// Load 读取文件构造证书 (p12 需要密码的场景 V1 以 pem 为主)
func (s *fileSource) Load(id string) (tls.Certificate, error) {
	return loadFilePEMOrP12(s.path)
}

// LoadWithPassword 带密码加载 (加密私钥/p12)
func (s *fileSource) LoadWithPassword(id, password string) (tls.Certificate, error) {
	return loadFilePEMOrP12Pwd(s.path, password)
}
