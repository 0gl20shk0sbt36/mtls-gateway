// Package i18n 极简多语言支持 (中/英)
// 用法: lang := i18n.Detect()  →  i18n.T(lang, "key", args...)
// 语言检测: 环境变量 LC_ALL > LC_MESSAGES > LANG > 默认 zh
package i18n

import (
	"fmt"
	"os"
	"strings"
)

// Lang 语言代码
type Lang string

const (
	Zh Lang = "zh"
	En Lang = "en"
)

// 消息表: key → {zh, en}
// 占位符用 %s %d 等 fmt 风格
var messages = map[string][2]string{
	// 通用
	"unknown_command": {"未知命令: %s", "unknown command: %s"},
	"usage":           {"用法: %s", "usage: %s"},
	"ok":              {"OK", "OK"},

	// issue
	"issue_success": {"=== 签发成功 ===", "=== issued successfully ==="},
	"serial":        {"序列号: %s", "serial: %s"},
	"p12_password":  {"p12 密码: %s", "p12 password: %s"},
	"expires":       {"到期: %s", "expires: %s"},
	"cert_dir":      {"证书目录: %s", "cert directory: %s"},
	"issue_failed":  {"签发失败: %v (核心进程在跑吗? sock=%s)", "issue failed: %v (is the daemon running? sock=%s)"},
	"issue_error":   {"签发错误: %v", "issue error: %v"},
	"issue_usage":   {"用法: mtls-gw-cli issue <name> --purpose <p> [--ts-ip <ip>] [--days N]", "usage: mtls-gw-cli issue <name> --purpose <p> [--ts-ip <ip>] [--days N]"},

	// revoke
	"revoked":       {"已吊销: %s", "revoked: %s"},
	"revoke_failed": {"吊销失败: %v", "revoke failed: %v"},
	"revoke_error":  {"吊销错误: HTTP %d", "revoke error: HTTP %d"},
	"revoke_usage":  {"用法: mtls-gw-cli revoke <serial>", "usage: mtls-gw-cli revoke <serial>"},

	// list
	"no_certs":    {"(无证书)", "(no certs)"},
	"list_failed": {"列表失败: %v", "list failed: %v"},
	"list_header": {"%-12s %-20s %-16s %-16s %-10s %s", "%-12s %-20s %-16s %-16s %-10s %s"},

	// health
	"core_ok":       {"核心进程: OK", "core process: OK"},
	"health_failed": {"健康检查失败: %v", "health check failed: %v"},

	// admin 警告 (核心进程返回)
	"warn_admin_mixed":    {"admin 与其他用途混用, 已忽略其他用途, 仅保留 admin", "admin mixed with other purposes; ignoring others, keeping admin only"},
	"warn_admin_notfirst": {"admin 不在首位, 已剔除 admin, 保留其他用途", "admin is not first; removed admin, keeping other purposes"},

	// ---- 服务端/客户端错误消息 (relay/gw 按配置 lang 返回) ----
	"errPwdNeeded":      {"私钥需要密码：%s，请在\"证书密码\"框输入密码后重试", "Private key needs password: %s — enter the cert password and retry"},
	"errBadPwd":         {"证书密码错误：%s，请重新输入正确的密码", "Wrong certificate password: %s — please retry with the correct password"},
	"errNoCert":         {"没有可用客户端证书：证书源为空或证书加载失败", "No usable client certificate: cert source empty or load failed"},
	"errSvcNotFound":    {"服务端不存在该服务：%s", "Service not found on server: %s"},
	"errNoChannels":     {"服务 %s 没有可用通道", "Service %s has no channels"},
	"errNeedSvcCert":    {"service 与 cert_id 均为必填", "service and cert_id are required"},
	"errNeedTunnelID":   {"缺少隧道 id", "missing tunnel id"},
	"errCertNotFound":   {"证书不存在：%s", "Certificate not found: %s"},
	"errImmutable":      {"服务端配置为只读模式（immutable），无法修改", "Server config is immutable (read-only), cannot modify"},
	"errRevoked":        {"证书已被吊销", "Certificate has been revoked"},
	"errDenied":         {"访问被拒绝（403）：证书角色无权访问", "Access denied (403): cert role has no access"},
	"errAdminDenied":    {"管理权限被拒绝：当前证书不是管理证书", "Admin access denied: this cert is not an admin cert"},
	"errExpired":        {"证书已过期，请联系管理员重新签发", "Certificate has expired — contact the admin for a reissue"},
	"errBadRole":        {"角色 %s 无效：只允许字母/数字/下划线/连字符", "Role %s invalid: letters/digits/underscore/hyphen only"},
	"errRoleUndeclared": {"角色 %s 未在 roles 声明列表中声明", "Role %s is not declared in the roles list"},
	"errSvcExists":      {"服务 %s 已存在", "Service %s already exists"},
	"errMapExists":      {"通道 %s 已存在", "Mapping %s already exists"},
	"errListenDup":      {"监听地址 %s 重复", "Listen address %s duplicated"},
	"errChannelRef":     {"通道引用不存在：%s", "Channel reference not found: %s"},
	"errNameRequired":   {"name 与 purposes 为必填", "name and purposes are required"},
}

// Detect 检测系统语言
func Detect() Lang {
	for _, env := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		v := os.Getenv(env)
		if v == "" {
			continue
		}
		v = strings.ToLower(v)
		if strings.HasPrefix(v, "zh") {
			return Zh
		}
		if strings.HasPrefix(v, "en") {
			return En
		}
	}
	return Zh // 默认中文
}

// T 翻译: T(lang, key, args...)
func T(lang Lang, key string, args ...any) string {
	pair, ok := messages[key]
	if !ok {
		return fmt.Sprintf("[missing:%s]", key)
	}
	var s string
	if lang == En {
		s = pair[1]
	} else {
		s = pair[0]
	}
	if len(args) > 0 {
		return fmt.Sprintf(s, args...)
	}
	return s
}

// TranslateWarnings 翻译核心进程返回的警告 (按语言选择对应文案)
func TranslateWarnings(lang Lang, warnings []string) []string {
	out := make([]string, 0, len(warnings))
	for _, w := range warnings {
		switch w {
		case "admin 与其他用途混用, 已忽略其他用途, 仅保留 admin":
			out = append(out, T(lang, "warn_admin_mixed"))
		case "admin 不在首位, 已剔除 admin, 保留其他用途":
			out = append(out, T(lang, "warn_admin_notfirst"))
		default:
			out = append(out, w)
		}
	}
	return out
}

// ---- 进程内错误字典 (relay/gw 持有, 按配置 lang 生成错误) ----

// L 带语言的错误字典。Lang: "zh" | "en"(默认 zh)
type L struct {
	Lang Lang
}

// New 创建错误字典。lang 非法时默认 zh。
func New(lang string) *L {
	l := Lang(strings.ToLower(strings.TrimSpace(lang)))
	if l != En {
		l = Zh
	}
	return &L{Lang: l}
}

// S 按语言取模板并格式化(未收录键返回原 key)。
func (l *L) S(id string, args ...any) string {
	if l == nil {
		return id
	}
	return T(l.Lang, id, args...)
}

// E 返回本地化 error。
func (l *L) E(id string, args ...any) error {
	if l == nil {
		return fmt.Errorf("%s", id)
	}
	return fmt.Errorf("%s", T(l.Lang, id, args...))
}
