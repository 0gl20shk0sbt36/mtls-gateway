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
	"unknown_command":     {"未知命令: %s", "unknown command: %s"},
	"usage":               {"用法: %s", "usage: %s"},
	"ok":                  {"OK", "OK"},

	// issue
	"issue_success":       {"=== 签发成功 ===", "=== issued successfully ==="},
	"serial":              {"序列号: %s", "serial: %s"},
	"p12_password":        {"p12 密码: %s", "p12 password: %s"},
	"expires":             {"到期: %s", "expires: %s"},
	"cert_dir":            {"证书目录: %s", "cert directory: %s"},
	"issue_failed":        {"签发失败: %v (核心进程在跑吗? sock=%s)", "issue failed: %v (is the daemon running? sock=%s)"},
	"issue_error":         {"签发错误: %v", "issue error: %v"},
	"issue_usage":         {"用法: mtls-gw-cli issue <name> --purpose <p> [--ts-ip <ip>] [--days N]", "usage: mtls-gw-cli issue <name> --purpose <p> [--ts-ip <ip>] [--days N]"},

	// revoke
	"revoked":             {"已吊销: %s", "revoked: %s"},
	"revoke_failed":       {"吊销失败: %v", "revoke failed: %v"},
	"revoke_error":        {"吊销错误: HTTP %d", "revoke error: HTTP %d"},
	"revoke_usage":        {"用法: mtls-gw-cli revoke <serial>", "usage: mtls-gw-cli revoke <serial>"},

	// list
	"no_certs":            {"(无证书)", "(no certs)"},
	"list_failed":         {"列表失败: %v", "list failed: %v"},
	"list_header":         {"%-12s %-20s %-16s %-16s %-10s %s", "%-12s %-20s %-16s %-16s %-10s %s"},

	// health
	"core_ok":             {"核心进程: OK", "core process: OK"},
	"health_failed":       {"健康检查失败: %v", "health check failed: %v"},

	// admin 警告 (核心进程返回)
	"warn_admin_mixed":    {"admin 与其他用途混用, 已忽略其他用途, 仅保留 admin", "admin mixed with other purposes; ignoring others, keeping admin only"},
	"warn_admin_notfirst": {"admin 不在首位, 已剔除 admin, 保留其他用途", "admin is not first; removed admin, keeping other purposes"},
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
