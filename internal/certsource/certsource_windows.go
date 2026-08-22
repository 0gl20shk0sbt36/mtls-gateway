//go:build windows

// Windows 系统证书库源(CNG 重写): 枚举「个人/My」存储的证书, 私钥经 CNG
// (NCryptSignHash) 签名 — 支持 RSACng(软件 KSP)与 TPM/智能卡(硬件 KSP)私钥。
//
// 替代 tg123/certstore(v0.1.3, 2021 停更): certstore 只支持老式 CAPI 私钥,
// 对现代 Windows 的 RSACng 私钥签名报 "bad private key", 导致 -source system 无法做 mTLS。
//
// 零新依赖: 枚举用 x/sys/windows 的 crypt32 绑定(CertOpenStore/CertEnumCertificatesInStore),
// 私钥用 CryptAcquireCertificatePrivateKey(CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG 强制 CNG),
// NCryptSignHash/NCryptFreeObject 自声明(ncrypt.dll lazy proc)。
// 签名包装参考 google/certtostore(Apache-2.0): RSA PKCS1/PSS padding + ECDSA raw→DER。
package certsource

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"sort"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// CERT_SYSTEM_STORE_CURRENT_USER: 当前用户证书存储(My)。
// x/sys/windows 未导出该常量, 按 wincrypt.h 定义:
// CERT_SYSTEM_STORE_CURRENT_USER_ID(1) << CERT_SYSTEM_STORE_SHIFT(16)
const certSystemStoreCurrentUser = 0x00010000

// winSource 系统证书库源: 枚举 CurrentUser\My, 只展示带私钥的身份
type winSource struct {
	mu           sync.RWMutex // 保护过滤字段(SetFilter/SetIssuerFilter 与 List 并发)
	filterOrg    string
	issuerFilter string // CA 主题; 非空时按 issuer 匹配(只展示该 CA 签发的)
	showAll      bool
}

func openSystemImpl() (Source, error) {
	return &winSource{}, nil
}

func (s *winSource) SetFilter(org string, showAll bool) {
	s.mu.Lock()
	s.filterOrg, s.showAll = org, showAll
	s.mu.Unlock()
}
func (s *winSource) SetIssuerFilter(caSubject string) {
	s.mu.Lock()
	s.issuerFilter = caSubject
	s.mu.Unlock()
}

// accept 是否展示该证书(issuer 精确/包含匹配, 或 org 过滤; 与 dir 源同规则, 共用 acceptCert)
func (s *winSource) accept(cert *x509.Certificate) bool {
	s.mu.RLock()
	issuer, org, showAll := s.issuerFilter, s.filterOrg, s.showAll
	s.mu.RUnlock()
	return acceptCert(issuer, org, showAll, cert)
}

// List 枚举 CurrentUser\My 全部带私钥的证书(过滤后)
func (s *winSource) List() ([]IdentityMeta, error) {
	certs, err := enumMyCerts()
	if err != nil {
		return nil, err
	}
	var metas []IdentityMeta
	for _, c := range certs {
		if !s.accept(c.cert) {
			c.close()
			continue
		}
		metas = append(metas, metaFromCert(c.cert, certThumbprint(c.cert), "system:My"))
		c.close()
	}
	sort.Slice(metas, func(i, j int) bool { return metas[i].CommonName < metas[j].CommonName })
	return metas, nil
}

// Load 按 thumbprint 加载, 构建 mTLS 客户端证书(私钥为 CNG signer)
func (s *winSource) Load(thumb string) (tls.Certificate, error) {
	certs, err := enumMyCerts()
	if err != nil {
		return tls.Certificate{}, err
	}
	for _, c := range certs {
		if certThumbprint(c.cert) != thumb {
			c.close()
			continue
		}
		signer, err := newNcryptSigner(c.cert, c.ctx)
		if err != nil {
			c.close()
			return tls.Certificate{}, fmt.Errorf("private key for %s: %w", thumb, err)
		}
		tc := tls.Certificate{
			Certificate: [][]byte{c.cert.Raw},
			PrivateKey:  signer,
			Leaf:        c.cert,
		}
		c.close() // 释放 CertContext 不影响已获取的 NCRYPT_KEY_HANDLE
		return tc, nil
	}
	return tls.Certificate{}, fmt.Errorf("certificate with thumbprint %s not found in system:My", thumb)
}

// myCert 一枚枚举到的证书 + 其 CertContext(用后 close)
type myCert struct {
	cert *x509.Certificate
	ctx  *windows.CertContext
}

func (c *myCert) close() {
	if c.ctx != nil {
		windows.CertFreeCertificateContext(c.ctx)
	}
}

// enumMyCerts 枚举 CurrentUser\My 存储的全部证书。
// MSDN 契约: CertEnumCertificatesInStore 每次调用会释放传入的 pPrevCertContext,
// 因此枚举返回的 ctx 只在本次迭代有效 — 传给下一次调用即被释放。
//   - 解析失败: 跳过即可, 下一次枚举调用会释放该 ctx(不得手动释放后把悬垂指针
//     当 prev 传入下一轮 — double-free/UAF, flash 横向审计抓出);
//   - 成功保留: 必须先 CertDuplicateCertificateContext 再存 out(否则 out 里全是
//     悬垂指针: close() double-free / Load() 的 CryptAcquire 用已释放内存 — pro 复审抓出)。
func enumMyCerts() ([]myCert, error) {
	storeName, _ := windows.UTF16PtrFromString("MY")
	store, err := windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM_W, 0, 0,
		certSystemStoreCurrentUser, uintptr(unsafe.Pointer(storeName)))
	if err != nil {
		return nil, fmt.Errorf("open MY store: %w", err)
	}
	defer windows.CertCloseStore(store, 0)

	var out []myCert
	var prev *windows.CertContext
	for {
		ctx, err := windows.CertEnumCertificatesInStore(store, prev)
		if err != nil {
			break // 枚举完毕(prev 已被本次调用释放)
		}
		prev = ctx
		// 先拷贝 DER 到 Go 拥有内存再解析: x509.ParseCertificate 保留对输入 DER 的引用
		// (cert.Raw = input, parser.go:896), 而输入别名枚举上下文内存 — 枚举 ctx 下一轮
		// 即被释放, 不拷贝则 cert.Raw 悬垂(pro 深度审计 F1; 即使从 dup 解析也不够,
		// dup 在 myCert.close 时同样释放, cert.Raw 照样悬垂)
		raw := make([]byte, int(ctx.Length))
		copy(raw, unsafe.Slice(ctx.EncodedCert, int(ctx.Length)))
		cert, perr := x509.ParseCertificate(raw)
		if perr != nil {
			continue // 损坏条目跳过; 下一次枚举调用会释放该 ctx(不得手动释放)
		}
		dup := windows.CertDuplicateCertificateContext(ctx) // 枚举 ctx 下轮即被释放, 保留须 dup
		if dup == nil {
			continue // dup 失败罕见: 跳过该证书(原 ctx 仍由下一次枚举调用释放)
		}
		out = append(out, myCert{cert: cert, ctx: dup})
	}
	return out, nil
}

// —— CNG 私钥签名 (ncrypt.dll; x/sys/windows 未绑定 ncrypt, 自声明) ——

var (
	ncryptMod            = windows.NewLazySystemDLL("ncrypt.dll")
	procNCryptSignHash   = ncryptMod.NewProc("NCryptSignHash")
	procNCryptFreeObject = ncryptMod.NewProc("NCryptFreeObject")
)

// ncryptSigner 包装 NCRYPT_KEY_HANDLE 实现 crypto.Signer(mTLS 客户端签名用)
type ncryptSigner struct {
	kh  windows.Handle
	pub crypto.PublicKey
}

// Public 实现 crypto.Signer
func (s *ncryptSigner) Public() crypto.PublicKey { return s.pub }

// Close 释放 NCRYPT 密钥句柄(relay 证书缓存替换时调用, 防句柄泄漏)
func (s *ncryptSigner) Close() error {
	r, _, _ := procNCryptFreeObject.Call(uintptr(s.kh))
	if r != 0 {
		return fmt.Errorf("NCryptFreeObject: %X", r)
	}
	return nil
}

// Sign 实现 crypto.Signer: RSA 走 PKCS1/PSS padding, ECDSA 走 raw→DER
func (s *ncryptSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	switch pub := s.pub.(type) {
	case *rsa.PublicKey:
		return ncryptSignRSA(s.kh, digest, opts)
	case *ecdsa.PublicKey:
		return ncryptSignECDSA(s.kh, pub, digest)
	default:
		return nil, fmt.Errorf("unsupported key type %T", s.pub)
	}
}

// newNcryptSigner 从证书上下文获取 CNG 私钥并包装为 signer。
// CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG: 强制 CNG 密钥(RSACng/TPM), 拒绝老式 CAPI 私钥。
func newNcryptSigner(cert *x509.Certificate, ctx *windows.CertContext) (crypto.Signer, error) {
	var hKey windows.Handle
	var keySpec uint32
	var free bool
	if err := windows.CryptAcquireCertificatePrivateKey(ctx,
		windows.CRYPT_ACQUIRE_SILENT_FLAG|windows.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
		nil, &hKey, &keySpec, &free); err != nil {
		return nil, fmt.Errorf("acquire private key: %w", err)
	}
	if !free {
		// 非常规: CNG 密钥通常需释放; 若标志未置位则不持有(避免误释放)
		return nil, fmt.Errorf("unexpected: caller not required to free key")
	}
	return &ncryptSigner{kh: hKey, pub: cert.PublicKey}, nil
}

// ncryptSignECDSA NCryptSignHash 对 ECDSA 返回 raw R||S(P1363 固定长度), 转 Go 的 DER 编码
func ncryptSignECDSA(kh windows.Handle, pub *ecdsa.PublicKey, digest []byte) ([]byte, error) {
	size, err := ncryptSignSize(kh, digest, nil, 0)
	if err != nil {
		return nil, err
	}
	sig := make([]byte, size)
	if err := ncryptSign(kh, digest, sig, nil, 0); err != nil {
		return nil, err
	}
	// raw R||S → DER(平台无关纯函数, 有单测)
	return ecdsaRawToDER(sig, pub.Curve.Params().BitSize)
}

// ncryptSignRSA RSA 签名: 默认 PKCS1 v1.5; opts 为 *rsa.PSSOptions 时走 PSS
func ncryptSignRSA(kh windows.Handle, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	paddingInfo, flags, err := rsaPaddingInfo(opts)
	if err != nil {
		return nil, err
	}
	size, err := ncryptSignSize(kh, digest, paddingInfo, flags)
	if err != nil {
		return nil, err
	}
	sig := make([]byte, size)
	if err := ncryptSign(kh, digest, sig, paddingInfo, flags); err != nil {
		return nil, err
	}
	return sig, nil
}

// ncryptSignSize 第一次调用拿签名长度; ncryptSign 第二次实际签名
func ncryptSignSize(kh windows.Handle, digest []byte, padInfo unsafe.Pointer, flags uintptr) (uint32, error) {
	var size uint32
	r, _, _ := procNCryptSignHash.Call(uintptr(kh), uintptr(padInfo),
		uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
		0, 0, uintptr(unsafe.Pointer(&size)), flags)
	if r != 0 {
		return 0, fmt.Errorf("NCryptSignHash size: %X", r)
	}
	return size, nil
}

func ncryptSign(kh windows.Handle, digest, sig []byte, padInfo unsafe.Pointer, flags uintptr) error {
	var written uint32
	r, _, _ := procNCryptSignHash.Call(uintptr(kh), uintptr(padInfo),
		uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
		uintptr(unsafe.Pointer(&sig[0])), uintptr(len(sig)),
		uintptr(unsafe.Pointer(&written)), flags)
	if r != 0 {
		return fmt.Errorf("NCryptSignHash: %X", r)
	}
	return nil
}

// BCRYPT_PKCS1_PADDING_INFO / BCRYPT_PSS_PADDING_INFO(bcrypt.h)
type bcryptPKCS1PaddingInfo struct{ pszAlgID *uint16 }
type bcryptPSSPaddingInfo struct {
	pszAlgID *uint16
	cbSalt   uint32 // 真实 BCRYPT_PSS_PADDING_INFO 仅两字段(对照 bcrypt.h); 曾误加 cbTrailer, 已删(F3)
}

const (
	bcryptPadPKCS1 uintptr = 0x2
	bcryptPadPSS   uintptr = 0x8
)

// algIDs hash → CNG 算法名 LPCWSTR(懒初始化, 字符串由 Go GC 托管)
var (
	algIDsOnce sync.Once
	algIDs     map[crypto.Hash]*uint16
)

func initAlgIDs() {
	algIDs = map[crypto.Hash]*uint16{
		crypto.MD5:    utf16Ptr("MD5"),
		crypto.SHA1:   utf16Ptr("SHA1"),
		crypto.SHA256: utf16Ptr("SHA256"),
		crypto.SHA384: utf16Ptr("SHA384"),
		crypto.SHA512: utf16Ptr("SHA512"),
	}
}

func utf16Ptr(s string) *uint16 {
	p, _ := windows.UTF16PtrFromString(s)
	return p
}

// rsaPaddingInfo 构造 padding 结构与 NCryptSignHash 的 dwFlags
func rsaPaddingInfo(opts crypto.SignerOpts) (unsafe.Pointer, uintptr, error) {
	algIDsOnce.Do(initAlgIDs)
	h := crypto.SHA256
	if opts != nil {
		h = opts.HashFunc()
	}
	algID, ok := algIDs[h]
	if !ok {
		return nil, 0, fmt.Errorf("unsupported RSA hash algorithm %v", h)
	}
	if o, ok := opts.(*rsa.PSSOptions); ok {
		salt, err := pssSaltLength(o)
		if err != nil {
			return nil, 0, err
		}
		return unsafe.Pointer(&bcryptPSSPaddingInfo{pszAlgID: algID, cbSalt: uint32(salt)}), bcryptPadPSS, nil
	}
	return unsafe.Pointer(&bcryptPKCS1PaddingInfo{pszAlgID: algID}), bcryptPadPKCS1, nil
}
