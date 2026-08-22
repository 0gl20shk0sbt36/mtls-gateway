// Package types 共享类型与校验: 跨包 DTO(映射/服务/签发请求)+ 角色保留字与校验。
//
// 目的(可维护性审计批次 B): 消除 config→proxy 反向依赖(类型实体下沉, 两端都依赖本包)、
// api/relay 的类型复制(admin 桥与服务端共用本包, 字段漂移即编译错误)、角色校验四处对称。
package types

import "strings"

// 内置角色保留字(哨兵常量, 防拼写漂移 — 可读性审计)
const (
	RoleAny  = "any"  // 服务声明: 任一已登记证书可访问
	RoleNull = "null" // 服务声明: 匿名可访问(无需证书)
)

// ValidRoleName 角色名合法性: 字母/数字/下划线/连字符 (无特殊符号, 无通配符)
func ValidRoleName(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// Mapping 一条映射(通道)配置 (TOML [[mappings]] 直接对应)
type Mapping struct {
	ID      string       `toml:"id" json:"id"`           // 助记符(唯一; 判重仍靠 listen)
	Listen  string       `toml:"listen" json:"listen"`   // 入口 :port[/path]
	Target  string       `toml:"target" json:"target"`   // 后端 URL(带路径=前缀替换)
	Headers []HeaderRule `toml:"headers" json:"headers"` // 请求头改写规则(认证后求值); 空=仅默认防伪造基线
}

// HeaderRule 一条请求头改写规则。
//   - Op: "set" | "del"
//   - Value 支持动态变量(认证后求值): {cert_name} {cert_serial} {cert_roles}(逗号分隔) {remote_ip}
//   - set 时变量为空(匿名/null 路由) → 删除该头, 不注入空值
//   - 防伪造: 所有 set 先删后设(客户端自带同名头被覆盖), 且默认基线先删 9 个转发头
type HeaderRule struct {
	Op    string `toml:"op" json:"op"`
	Name  string `toml:"name" json:"name"`
	Value string `toml:"value" json:"value"`
}

// HeaderVars 头规则动态变量(认证后由网关填充)
type HeaderVars struct {
	CertName   string // {cert_name}   证书登记名(匿名=空)
	CertSerial string // {cert_serial} 证书序列号(匿名=空)
	CertRoles  string // {cert_roles}  角色列表, 逗号分隔(匿名=空)
	RemoteIP   string // {remote_ip}   来源 IP
}

// ExpandVars 模板替换 {cert_*}/{remote_ip}(导出: 网关与测试共用)
func ExpandVars(s string, v HeaderVars) string {
	return strings.NewReplacer(
		"{cert_name}", v.CertName,
		"{cert_serial}", v.CertSerial,
		"{cert_roles}", v.CertRoles,
		"{remote_ip}", v.RemoteIP,
	).Replace(s)
}

// ServiceCfg 服务注册条目 (TOML [[services]] 直接对应)
type ServiceCfg struct {
	Name     string   `toml:"name" json:"name"`         // 服务名(唯一)
	Channels []string `toml:"channels" json:"channels"` // 通道: mapping id 或索引(不建议)
	Roles    []string `toml:"roles" json:"roles"`       // 允许访问本服务的证书角色; "any"=任一已登记
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

// NormalizePurposes 规范化用途列表, 返回警告列表(不终止); adminRole 为内置管理角色名(可配置)。
// 移自 internal/api(admin 桥与服务端共用本类型, 校验逻辑单点)。
func (r *IssueRequest) NormalizePurposes(adminRole string) (warnings []string) {
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

// MappingInfo 管理桥映射条目(服务端 mapping 的 JSON 对齐视图, 供签发选用途/列表)
type MappingInfo struct {
	ID     string `json:"id"`
	Listen string `json:"listen"`
	Target string `json:"target"`
}
