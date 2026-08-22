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
	"crypto/sha256"
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
	"sync"
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
	certDir   string          // 已签发证书输出目录
	sockPath  string          // Unix socket 路径
	tmpl      CertTemplate    // 证书模板 (可配置)
	AdminRole string          // 内置管理角色名 (config admin_role)
	KeyType   string          // 签发密钥类型: rsa | ecdsa
	KeyBits   int             // rsa: 2048/3072/4096; ecdsa: 256/384/521
	PwdLength int             // 自动生成 p12 密码长度
	rolesMu   sync.RWMutex    // 保护 roles(热更新与签发并发)
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
	// 清理上次崩溃残留的签发临时目录(.tmp-<serial>, 内含密钥材料)
	if entries, err := os.ReadDir(certDir); err == nil {
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".tmp-") {
				os.RemoveAll(filepath.Join(certDir, e.Name()))
			}
		}
	}
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
		AdminRole: adminRole,
		KeyType:   keyType,
		KeyBits:   keyBits,
		PwdLength: pwdLength,
		roles:     roles,
		tmpl:      tmpl,
	}, nil
}

// SetDeclaredRoles 更新声明角色集合 (服务端配置管理热更新时调用; 与签发并发安全)
func (m *Manager) SetDeclaredRoles(declaredRoles []string) {
	m.rolesMu.Lock()
	defer m.rolesMu.Unlock()
	m.roles = map[string]bool{}
	for _, r := range declaredRoles {
		m.roles[r] = true
	}
}

// hasRole 检查角色是否声明(读锁)
func (m *Manager) hasRole(p string) bool {
	m.rolesMu.RLock()
	defer m.rolesMu.RUnlock()
	return m.roles[p]
}

// IssueRequest 签发请求
type IssueRequest struct {
	Name       string   `json:"name"`        // 设备名
	Purposes   []string `json:"purposes"`    // 可访问的用途列表: admin | dsh | vaultwarden | ...
	TSIP       string   `json:"ts_ip"`       // 绑定 TS IP (写入 SAN)
	Days       int      `json:"days"`        // 有效期天数 (默认 365)
	Password   string   `json:"password"`    // p12 密码; 留空且未设 NoPassword 时自动生成
	NoPassword bool     `json:"no_password"` // true = 无密码(留空=真的没密码)
}

// normalizePurposes 规范化用途列表, 返回警告列表 (不终止)
// admin 规则:
//   - admin 在首位 + 有其他 → 警告, 仅保留 admin (剔除其他)
//   - admin 在非首位 → 警告, 剔除 admin (保留其他)
//   - 仅 admin → 无警告
//
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
					warnings = append(warnings, "admin 与其他用途混用, 已忽略其他用途, 仅保留 admin")
					r.Purposes = []string{adminRole}
				}
			} else {
				// admin_role 不在首位: 剔除, 保留其他
				warnings = append(warnings, "admin 不在首位, 已剔除 admin, 保留其他用途")
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
	KeyPEM      string   `json:"key_pem,omitempty"` // 仅本机返回(远程通道置空); 生产建议只给 p12
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
		if p != m.AdminRole && !m.hasRole(p) {
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
	if req.Days > 3650 { // 上限 10 年: 保证"过期"吊销兜底有效
		return nil, fmt.Errorf("certificate validity too long: %d days (max 3650)", req.Days)
	}
	// 禁止同名证书(含已吊销的): 原子检查+登记(防并发同名 TOCTOU)
	// 先快速预检(友好错误), 最终以 InsertUniqueName 原子判定为准
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
		pw, err := randPassword(n)
		if err != nil {
			return nil, err
		}
		req.Password = pw
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
	// SAN: 绑定 TS IP (可多 IP 但这里单绑); 非法 IP 显式报错(避免静默丢 SAN 掩盖事故)
	if req.TSIP != "" {
		ip := net.ParseIP(req.TSIP)
		if ip == nil {
			return nil, fmt.Errorf("invalid ts_ip: %s (应为合法 IPv4/IPv6)", req.TSIP)
		}
		tmpl.IPAddresses = []net.IP{ip}
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
	// 输出目录用唯一临时名(防并发同名: 败者回滚只删自己的目录, 不误删胜者文件)
	tmpDir := filepath.Join(m.certDir, ".tmp-"+serial.String())
	if err := os.MkdirAll(tmpDir, 0o700); err != nil {
		return nil, err
	}
	// 失败回滚: 清理本请求的临时目录(唯一名, 绝不影响他人)
	committed := false
	defer func() {
		if !committed {
			os.RemoveAll(tmpDir)
		}
	}()
	if err := os.WriteFile(filepath.Join(tmpDir, "cert.pem"), certPEM, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "key.pem"), keyPEM, 0o600); err != nil {
		return nil, err
	}
	// 6. p12 (浏览器/手机导入)
	p12Path := filepath.Join(tmpDir, "device.p12")
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
		Fingerprint: fmt.Sprintf("%X", sha256.Sum256(cert.Raw)), // SHA-256 指纹
	}
	if err := m.store.InsertUniqueName(rec); err != nil { // 原子: 并发同名签发时只有一个成功
		return nil, err
	}
	// 登记成功 → 临时目录改名为正式名(唯一路径迁移, 不影响并发请求)
	finalDir := filepath.Join(m.certDir, req.Name)
	if err := os.Rename(tmpDir, finalDir); err != nil {
		// 回滚 DB 记录: 避免"DB 在册但文件丢失"的幽灵记录/名字占坑
		if derr := m.store.Delete(rec.Serial); derr != nil {
			log.Printf("issue finalize failed + db rollback failed: %v (serial=%s)", derr, rec.Serial)
		}
		return nil, fmt.Errorf("finalize cert dir: %w", err)
	}
	committed = true
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

// StatusFromKeywords 按错误消息关键字映射 HTTP 状态码(单一权威表, 消除两处映射漂移)。
// 供 internal/api.ErrStatus 与 internal/relay.writeErr 共用。
// 关键字表须同时覆盖: 证书签发/吊销 + 配置管理(configmgr/proxy) + 客户端输入(密码/通道)三类错误词汇。
func StatusFromKeywords(msg string) int {
	switch {
	case strings.Contains(msg, "admin required"), strings.Contains(msg, "admin cert required"): // 403 语义优先于 400 的 "required"
		return http.StatusForbidden
	case strings.Contains(msg, "immutable"), strings.Contains(msg, "只读模式"):
		return http.StatusForbidden // 配置只读拒绝写入
	case strings.Contains(msg, "already exists"), strings.Contains(msg, "已存在"), strings.Contains(msg, "已声明"),
		strings.Contains(msg, "duplicate"), strings.Contains(msg, "重复"), strings.Contains(msg, "仍被"):
		return http.StatusConflict
	case strings.Contains(msg, "bad request"),
		strings.Contains(msg, "required"), strings.Contains(msg, "必填"), strings.Contains(msg, "不能为空"),
		strings.Contains(msg, "invalid"), strings.Contains(msg, "非法"), strings.Contains(msg, "格式"),
		strings.Contains(msg, "保留字"), strings.Contains(msg, "未声明"), strings.Contains(msg, "未在 roles 声明列表"),
		strings.Contains(msg, "not declared"),
		strings.Contains(msg, "missing"), strings.Contains(msg, "缺少"), strings.Contains(msg, "bad role"),
		strings.Contains(msg, "bad target"), strings.Contains(msg, "bad port"), strings.Contains(msg, "has no channels"),
		strings.Contains(msg, "too long"),
		strings.Contains(msg, "needs password"), strings.Contains(msg, "password incorrect"),
		strings.Contains(msg, "私钥需要密码"), strings.Contains(msg, "密码错误"):
		return http.StatusBadRequest
	case strings.Contains(msg, "not found"), strings.Contains(msg, "未找到"), strings.Contains(msg, "不存在"):
		return http.StatusNotFound
	case strings.Contains(msg, "forbidden"), strings.Contains(msg, "无权"), strings.Contains(msg, "拒绝访问"):
		return http.StatusForbidden
	}
	return http.StatusInternalServerError
}

// ErrStatus 按错误语义映射 HTTP 状态码(客户端错误 4xx, 其余 500)
// 导出供 cmd/mtls-gw 的 gwErr 复用; 委托 StatusFromKeywords。
func ErrStatus(err error) int {
	return StatusFromKeywords(err.Error())
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
		r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		resp, err := m.IssueCert(req)
		if err != nil {
			http.Error(w, err.Error(), ErrStatus(err))
			return
		}
		if !isLocal {
			resp.KeyPEM = "" // 远程通道不回明文私钥(仅 p12+密码)
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
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
		r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if err := m.store.Revoke(req.Serial); err != nil {
			http.Error(w, err.Error(), ErrStatus(err))
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /admin/certs", func(w http.ResponseWriter, r *http.Request) {
		if !isLocal && r.Header.Get("X-Auth-Purpose") != m.AdminRole {
			http.Error(w, "admin required", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(m.store.List())
	})
	mux.HandleFunc("GET /admin/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	return mux
}

// HTTPHandler 返回可挂到 TCP mTLS 服务器的管理 handler
// 外层认证通过后设置 X-Auth-Purpose 头, 这里按用途放行
func (m *Manager) HTTPHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 管理路径只允许 admin 用途(端点均为 /admin/*)
		if r.Header.Get("X-Auth-Purpose") != m.AdminRole {
			http.Error(w, "admin required", http.StatusForbidden)
			return
		}
		m.handler(false).ServeHTTP(w, r)
	})
}

// 工具函数
func validName(s string) bool {
	if len(s) == 0 || len(s) > 64 { // 长度上限: 防 ENAMETOOLONG(输出目录/CN)
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
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

func randPassword(n int) (string, error) {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	// 无模偏差: crypto/rand.Int 均匀采样
	max := big.NewInt(int64(len(chars)))
	b := make([]byte, n)
	for i := range b {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("randPassword: entropy unavailable: %w", err) // 返回错误由调用方 500, 不杀进程
		}
		b[i] = chars[idx.Int64()]
	}
	return string(b), nil
}
