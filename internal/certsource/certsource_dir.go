package certsource

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"mtls-gateway/internal/errs"
	"mtls-gateway/internal/pathutil"
)

// dirSource 目录扫描源: 每子目录一个证书 (<name>/cert.pem + <name>/key.pem),
// 或顶层 *.p12。ID = 相对路径 (如 "device-a" 或 "device-a.p12")。
type dirSource struct {
	mu        sync.RWMutex // 保护过滤字段(SetFilter 与 List 并发; relay 异步 fetchCAAndFilter 写)
	root      string
	filterOrg string    // 非空则只展示由该 org 签发的证书
	showAll   bool      // 显示全部 (跳过 filterOrg 过滤)
	warnOnce  sync.Once // 逃逸符号链接一次性告警(目录被污染时留痕, 不刷屏)
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
func (d *dirSource) SetFilter(org string, showAll bool) {
	d.mu.Lock()
	d.filterOrg, d.showAll = org, showAll
	d.mu.Unlock()
}

// accept 是否展示该证书(与 winSource 共用 acceptCert 公共规则)
func (d *dirSource) accept(cert *x509.Certificate) bool {
	d.mu.RLock()
	org, showAll := d.filterOrg, d.showAll
	d.mu.RUnlock()
	return acceptCert("", org, showAll, cert)
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
			certPath, keyPath := filepath.Join(full, "cert.pem"), filepath.Join(full, "key.pem")
			if _, err := os.Stat(certPath); err != nil {
				continue
			}
			if _, err := os.Stat(keyPath); err != nil {
				continue
			}
			// 符号链接防护: 与 Load/LoadWithPassword 一致 — 逃逸 root 的身份不展示(否则列出却加载失败)
			if err := d.checkWithinRoot(certPath); err != nil {
				d.warnSymlinkEscape(err)
				continue
			}
			if err := d.checkWithinRoot(keyPath); err != nil {
				d.warnSymlinkEscape(err)
				continue
			}
			data, err := os.ReadFile(certPath)
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
			if err := d.checkWithinRoot(full); err != nil {
				d.warnSymlinkEscape(err) // 顶层 p12 符号链接逃逸 root: 不展示
				continue
			}
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
		return tls.Certificate{}, errs.New(errs.KindBadRequest, "invalid cert id: %s", id)
	}
	full := filepath.Join(d.root, id)
	st, err := os.Stat(full)
	if err != nil {
		return tls.Certificate{}, errs.WithKind(fmt.Errorf("cert %s not found: %w", id, err), errs.KindNotFound)
	}
	// 符号链接防护: 身份路径本身 + 目录内 cert.pem/key.pem 都不得解析到 root 外
	// (目录内 symlink 可把 os.ReadFile 指向目录外任意文件)
	if err := d.checkWithinRoot(full); err != nil {
		return tls.Certificate{}, err
	}
	if st.IsDir() {
		certPath, keyPath := filepath.Join(full, "cert.pem"), filepath.Join(full, "key.pem")
		if err := d.checkWithinRoot(certPath); err != nil {
			return tls.Certificate{}, err
		}
		if err := d.checkWithinRoot(keyPath); err != nil {
			return tls.Certificate{}, err
		}
		cert, err := os.ReadFile(certPath)
		if err != nil {
			return tls.Certificate{}, err
		}
		key, err := os.ReadFile(keyPath)
		if err != nil {
			return tls.Certificate{}, err
		}
		combined := append(append(append([]byte{}, cert...), '\n'), key...)
		return tlsFromPEM(id, combined)
	}
	return loadFilePEMOrP12(full)
}

// warnSymlinkEscape 逃逸符号链接一次性告警: 目录被污染(攻击者写入逃逸链接)时留痕,
// 只告警一次避免 List 高频轮询刷屏。路径先清洗控制字符 — Linux 文件名可含 \n/ESC,
// 攻击者命名带控制字符的逃逸链接可在文本日志注入伪行(CWE-117, 与 proxy 同款防护)。
func (d *dirSource) warnSymlinkEscape(err error) {
	d.warnOnce.Do(func() {
		log.Printf("cert source %s: 检测到逃逸符号链接, 已跳过该身份: %v (请检查证书目录是否被污染)",
			pathutil.SanitizeForLog(d.root), pathutil.SanitizeForLog(err.Error()))
	})
}

// checkWithinRoot 符号链接防护: 解析后路径必须仍在 root 目录内。
// EvalSymlinks 失败(路径缺失等)不在此拦截, 由调用方后续 stat/read 报错。
// 注意: root 也须先 EvalSymlinks — Windows 会把 8.3 短名(RUNNER~1)展开为长名,
// 只解析 p 时 Rel(root, real) 会算到 root 外 → 合法文件被误判逃逸(CI windows 抓出)。
func (d *dirSource) checkWithinRoot(p string) error {
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return nil
	}
	rootReal, rerr := filepath.EvalSymlinks(d.root)
	if rerr != nil {
		rootReal = d.root
	}
	if !withinRoot(rootReal, real) {
		return fmt.Errorf("%s resolves outside cert dir (symlink rejected)", p)
	}
	return nil
}

// withinRoot 判断 resolved 路径是否仍在 root 目录内(符号链接防护)
func withinRoot(root, resolved string) bool {
	rel, err := filepath.Rel(root, resolved)
	if err != nil {
		return false
	}
	return rel == "." || !strings.HasPrefix(rel, "..")
}

// LoadWithPassword 带密码加载 (加密私钥/p12)
func (d *dirSource) LoadWithPassword(id, password string) (tls.Certificate, error) {
	if strings.Contains(id, "..") || filepath.IsAbs(id) {
		return tls.Certificate{}, errs.New(errs.KindBadRequest, "invalid cert id: %s", id)
	}
	full := filepath.Join(d.root, id)
	st, err := os.Stat(full)
	if err != nil {
		return tls.Certificate{}, errs.WithKind(fmt.Errorf("cert %s not found: %w", id, err), errs.KindNotFound)
	}
	// 符号链接防护: 与 Load 同一攻击面(WebUI 密码加载路径), 目录/文件 + 目录内 pem 都须在 root 内
	if err := d.checkWithinRoot(full); err != nil {
		return tls.Certificate{}, err
	}
	if st.IsDir() {
		certPath, keyPath := filepath.Join(full, "cert.pem"), filepath.Join(full, "key.pem")
		if err := d.checkWithinRoot(certPath); err != nil {
			return tls.Certificate{}, err
		}
		if err := d.checkWithinRoot(keyPath); err != nil {
			return tls.Certificate{}, err
		}
		cert, err := os.ReadFile(certPath)
		if err != nil {
			return tls.Certificate{}, err
		}
		key, err := os.ReadFile(keyPath)
		if err != nil {
			return tls.Certificate{}, err
		}
		combined := append(append(append([]byte{}, cert...), '\n'), key...)
		return tlsFromPEMWithPassword(id, combined, password)
	}
	return loadFilePEMOrP12Pwd(full, password)
}
