// Package api 提供管理 API。
// 双通道: Unix socket(本机 CLI, 文件权限控制 = 直接 admin)
//   - TCP mTLS(远程 Web, 需 admin 用途证书)。
//
// 管理操作全部走这里: 签发/吊销/列表/路由配置。
package api

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"mtls-gateway/internal/db"
)

// CertTemplate 证书模板配置 (来自配置文件, 部署级)
type CertTemplate struct {
	Org         string // 证书 O 字段 (默认 "mtls-gw")
	OU          string // 证书 OU 字段 (默认 "device")
	DefaultDays int    // 普通用途默认有效期天数 (默认 365)
	AdminDays   int    // admin 用途默认天数 (默认 30)
}

// ApplyDefaults 填充默认值
func (t *CertTemplate) ApplyDefaults() {
	if t.Org == "" {
		t.Org = "mtls-gw"
	}
	if t.OU == "" {
		t.OU = "device"
	}
	if t.DefaultDays <= 0 {
		t.DefaultDays = 365
	}
	if t.AdminDays <= 0 {
		t.AdminDays = 30
	}
}

// Manager 管理 API 服务
type Manager struct {
	store     *db.Store
	caCert    *x509.Certificate
	caKey     *rsa.PrivateKey
	certDir   string       // 已签发证书输出目录
	sockPath  string       // Unix socket 路径
	adminOnly bool         // TCP 通道是否要求 admin 用途
	tmpl      CertTemplate // 证书模板 (可配置)
	AdminRole string       // 内置管理角色名 (config admin_role)
	KeyType   string       // 签发密钥类型: rsa | ecdsa
	KeyBits   int          // rsa: 2048/3072/4096; ecdsa: 256/384/521
	PwdLength int          // 自动生成 p12 密码长度
	roles     map[string]bool // 声明角色集合 (签发 purposes 校验用)
}

// orgName 返回证书 O 字段
func (m *Manager) orgName() []string { return []string{m.tmpl.Org} }

// ouName 返回证书 OU 字段
func (m *Manager) ouName() string { return m.tmpl.OU }

// NewManager 创建管理器, 加载 CA 私钥用于签发
// tmpl: 证书模板配置 (可传零值, 自动用默认)
// adminRole: 内置管理角色名; keyType/keyBits: 签发密钥; pwdLength: 自动密码长度; declaredRoles: 声明角色列表
func NewManager(store *db.Store, caCertPath, caKeyPath, certDir, sockPath string, tmpl CertTemplate, adminRole, keyType string, keyBits, pwdLength int, declaredRoles []string) (*Manager, error) {
	caPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("read ca cert: %w", err)
	}
	block, _ := pem.Decode(caPEM)
	if block == nil {
		return nil, fmt.Errorf("decode ca cert")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca cert: %w", err)
	}
	keyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read ca key: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("decode ca key")
	}
	caKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		// 尝试 PKCS1
		caKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse ca key: %w", err)
		}
	}
	rsaKey, ok := caKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ca key is not RSA")
	}
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir certdir: %w", err)
	}
	tmpl.ApplyDefaults()
	roles := map[string]bool{}
	for _, r := range declaredRoles {
		roles[r] = true
	}
	return &Manager{
		store:     store,
		caCert:    caCert,
		caKey:     rsaKey,
		certDir:   certDir,
		sockPath:  sockPath,
		adminOnly: true,
		AdminRole: adminRole,
		KeyType:   keyType,
		KeyBits:   keyBits,
		PwdLength: pwdLength,
		roles:     roles,
		tmpl:      tmpl,
	}, nil
}

// SetDeclaredRoles 更新声明角色集合 (服务端配置管理热更新时调用)
func (m *Manager) SetDeclaredRoles(declaredRoles []string) {
	m.roles = map[string]bool{}
	for _, r := range declaredRoles {
		m.roles[r] = true
	}
}

// IssueRequest 签发请求
type IssueRequest struct {
	Name     string   `json:"name"`     // 设备名
	Purposes []string `json:"purposes"` // 可访问的用途列表: admin | dsh | vaultwarden | ...
	TSIP     string   `json:"ts_ip"`    // 绑定 TS IP (写入 SAN)
	Days     int      `json:"days"`     // 有效期天数 (默认 365)
	Password   string `json:"password"`     // p12 密码; 留空且未设 NoPassword 时自动生成
	NoPassword bool   `json:"no_password"`  // true = 无密码(留空=真的没密码)
}

// normalizePurposes 规范化用途列表, 返回警告列表 (不终止)
// admin 规则:
//   - admin 在首位 + 有其他 → 警告, 仅保留 admin (剔除其他)
//   - admin 在非首位 → 警告, 剔除 admin (保留其他)
//   - 仅 admin → 无警告
// normalizePurposes 规范化用途列表; adminRole 为内置管理角色名(可配置)
func (r *IssueRequest) normalizePurposes(adminRole string) (warnings []string) {
	if len(r.Purposes) == 0 {
		return nil
	}
	// 兼容旧请求: purposes 可能是逗号分隔字符串
	if len(r.Purposes) == 1 && strings.Contains(r.Purposes[0], ",") {
		parts := []string{}
		for _, p := range strings.Split(r.Purposes[0], ",") {
			if p = strings.TrimSpace(p); p != "" {
				parts = append(parts, p)
			}
		}
		r.Purposes = parts
	}
	// admin 规则 (admin_role 可配置)
	for i, p := range r.Purposes {
		if p == adminRole {
			if i == 0 {
				// admin_role 在首位: 若还有其他, 剔除其他
				if len(r.Purposes) > 1 {
					warnings = append(warnings, adminRole+" 与其他用途混用, 已忽略其他用途, 仅保留 "+adminRole)
					r.Purposes = []string{adminRole}
				}
			} else {
				// admin_role 不在首位: 剔除, 保留其他
				warnings = append(warnings, adminRole+" 不在首位, 已剔除 "+adminRole+", 保留其他用途")
				others := []string{}
				for _, x := range r.Purposes {
					if x != adminRole {
						others = append(others, x)
					}
				}
				r.Purposes = others
			}
			return warnings
		}
	}
	return warnings
}

// IssueResponse 签发结果
type IssueResponse struct {
	Name        string   `json:"name"` // 证书名(回显)
	Serial      string   `json:"serial"`
	CertPEM     string   `json:"cert_pem"`
	KeyPEM      string   `json:"key_pem"` // 仅本机返回; 生产建议只给 p12
	P12Password string   `json:"p12_password,omitempty"`
	Expires     string   `json:"expires"`
	Fingerprint string   `json:"fingerprint"`
	Warnings    []string `json:"warnings,omitempty"` // 规范化警告 (如 admin 混用)
}

// IssueCert 签发客户端证书并登记数据库
// SAN: 绑定 TS IP (设备绑定); 不写用途字段 (权限在数据库)
func (m *Manager) IssueCert(req IssueRequest) (*IssueResponse, error) {
	warnings := req.normalizePurposes(m.AdminRole)
	if req.Name == "" || len(req.Purposes) == 0 {
		return nil, fmt.Errorf("name and purposes required")
	}
	// 签发校验: purposes 必须 ∈ 声明角色 ∪ {admin_role}; "any" 禁止签发给证书
	for _, p := range req.Purposes {
		if p == "any" {
			return nil, fmt.Errorf("角色 %q 是内置保留字, 只可用于服务声明, 不能签发给证书", p)
		}
		if p != m.AdminRole && !m.roles[p] {
			return nil, fmt.Errorf("角色 %q 未在 roles 声明列表中声明", p)
		}
	}
	if req.Days <= 0 {
		// 默认天数: admin 用途用 AdminDays, 其他用 DefaultDays
		if req.Purposes[0] == m.AdminRole {
			req.Days = m.tmpl.AdminDays
		} else {
			req.Days = m.tmpl.DefaultDays
		}
	}
	// 禁止同名证书(含已吊销的): 避免同名多条记录混淆
	if recs := m.store.FindByName(req.Name); len(recs) > 0 {
		return nil, fmt.Errorf("certificate name %s already exists (%d record(s)), 禁止同名签发", req.Name, len(recs))
	}
	if req.NoPassword {
		req.Password = "" // 无密码 p12
	} else if req.Password == "" {
		n := m.PwdLength
		if n <= 0 {
			n = 16
		}
		req.Password = randPassword(n)
	}
	// 设备名合法性
	if !validName(req.Name) {
		return nil, fmt.Errorf("invalid name: %s", req.Name)
	}

	// 1. 生成密钥 (key_type/key_bits 可配置)
	key, pub, err := m.newClientKey()
	if err != nil {
		return nil, err
	}
	// 2. 序列号 (唯一, 数据库主键)
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, fmt.Errorf("gen serial: %w", err)
	}
	// 3. 证书模板: CN=设备名, 不写用途, SAN 绑 TS IP
	notBefore := time.Now().UTC().Add(-time.Minute)
	notAfter := time.Now().UTC().AddDate(0, 0, req.Days)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         req.Name,
			Organization:       m.orgName(),          // O 字段 (配置 org)
			OrganizationalUnit: []string{m.ouName()}, // OU 字段 (配置 ou)
		},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	// SAN: 绑定 TS IP (可多 IP 但这里单绑)
	if req.TSIP != "" {
		if ip := net.ParseIP(req.TSIP); ip != nil {
			tmpl.IPAddresses = []net.IP{ip}
		}
	}
	// 4. 签发
	der, err := x509.CreateCertificate(rand.Reader, tmpl, m.caCert, pub, m.caKey)
	if err != nil {
		return nil, fmt.Errorf("create cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse issued: %w", err)
	}
	// 5. 输出文件
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	outDir := filepath.Join(m.certDir, req.Name)
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(outDir, "cert.pem"), certPEM, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(outDir, "key.pem"), keyPEM, 0o600); err != nil {
		return nil, err
	}
	// 6. p12 (浏览器/手机导入)
	p12Path := filepath.Join(outDir, "device.p12")
	if err := writeP12(p12Path, certPEM, keyPEM, req.Password); err != nil {
		return nil, fmt.Errorf("p12: %w", err)
	}
	// 7. 登记数据库 (权限在这里, 证书里没有)
	rec := db.CertRecord{
		Serial:      serial.String(),
		Name:        req.Name,
		Purposes:    req.Purposes,
		TSIP:        req.TSIP,
		Status:      "enabled",
		IssuedAt:    notBefore.Format(time.RFC3339),
		ExpiresAt:   notAfter.Format("2006-01-02"),
		Fingerprint: fmt.Sprintf("%X", cert.RawSubjectPublicKeyInfo),
	}
	if err := m.store.Upsert(rec); err != nil {
		return nil, err
	}
	return &IssueResponse{
		Name:        req.Name,
		Serial:      serial.String(),
		CertPEM:     string(certPEM),
		KeyPEM:      string(keyPEM),
		P12Password: req.Password,
		Expires:     rec.ExpiresAt,
		Fingerprint: rec.Fingerprint,
		Warnings:    warnings,
	}, nil
}

// ServeUnixSocket 启动 Unix socket 管理通道 (本机 = 直接 admin)
func (m *Manager) ServeUnixSocket() error {
	_ = os.Remove(m.sockPath)
	ln, err := net.Listen("unix", m.sockPath)
	if err != nil {
		return fmt.Errorf("unix listen: %w", err)
	}
	if err := os.Chmod(m.sockPath, 0o600); err != nil {
		return fmt.Errorf("chmod sock: %w", err)
	}
	log.Printf("admin unix socket: %s (本机直接 admin)", m.sockPath)
	return http.Serve(ln, m.handler(true))
}

// handler 管理 API 路由; isLocal=true 时 Unix socket 通道(直接 admin)
func (m *Manager) handler(isLocal bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /admin/certs/issue", func(w http.ResponseWriter, r *http.Request) {
		if !isLocal {
			// 远程通道: 管理 API 只给 admin 用途 (由外层 middleware 检查, 这里再兜底)
			if r.Header.Get("X-Auth-Purpose") != m.AdminRole {
				http.Error(w, "admin required", http.StatusForbidden)
				return
			}
		}
		var req IssueRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		resp, err := m.IssueCert(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("POST /admin/certs/revoke", func(w http.ResponseWriter, r *http.Request) {
		if !isLocal && r.Header.Get("X-Auth-Purpose") != m.AdminRole {
			http.Error(w, "admin required", http.StatusForbidden)
			return
		}
		var req struct {
			Serial string `json:"serial"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if err := m.store.Revoke(req.Serial); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /admin/certs", func(w http.ResponseWriter, r *http.Request) {
		if !isLocal && r.Header.Get("X-Auth-Purpose") != m.AdminRole {
			http.Error(w, "admin required", http.StatusForbidden)
			return
		}
		json.NewEncoder(w).Encode(m.store.List())
	})
	mux.HandleFunc("GET /admin/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	return mux
}

// HTTPHandler 返回可挂到 TCP mTLS 服务器的管理 handler
// 外层认证通过后设置 X-Auth-Purpose 头, 这里按用途放行
func (m *Manager) HTTPHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 管理路径只允许 admin 用途
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if r.Header.Get("X-Auth-Purpose") != m.AdminRole {
				http.Error(w, "admin required", http.StatusForbidden)
				return
			}
		}
		m.handler(false).ServeHTTP(w, r)
	})
}

// 工具函数
func validName(s string) bool {
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return len(s) > 0
}

// newClientKey 按 key_type/key_bits 生成客户端密钥 (rsa 2048/3072/4096; ecdsa 256/384/521)
func (m *Manager) newClientKey() (crypto.PrivateKey, any, error) {
	bits := m.KeyBits
	switch m.KeyType {
	case "", "rsa":
		if bits == 0 {
			bits = 2048
		}
		if bits != 2048 && bits != 3072 && bits != 4096 {
			return nil, nil, fmt.Errorf("bad key_bits %d for rsa (2048/3072/4096)", bits)
		}
		k, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, nil, fmt.Errorf("gen rsa key: %w", err)
		}
		return k, &k.PublicKey, nil
	case "ecdsa":
		var curve elliptic.Curve
		switch bits {
		case 0, 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			return nil, nil, fmt.Errorf("bad key_bits %d for ecdsa (256/384/521)", bits)
		}
		k, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("gen ecdsa key: %w", err)
		}
		return k, &k.PublicKey, nil
	default:
		return nil, nil, fmt.Errorf("bad key_type %q (rsa|ecdsa)", m.KeyType)
	}
}

func randPassword(n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	rand.Read(b)
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return string(b)
}
