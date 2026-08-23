// Package httpshared 跨进程共享的 HTTP 基建。
//
// mtls-gw(数据面) / mtls-admin(管理面) / relay(管理客户端) 三处曾各自重复定义
// 超时常量(gwWriteTimeout/gwIdleTimeout/maxBodyBytes)、writeJSON、X-Lang 解析、
// 错误出口与 reload 客户端。集中到本包后改一处全局生效, 消除常量/信封漂移。
//
// 本包为叶子包: 只依赖标准库 + i18n, 不 import 任何内部业务包
// (状态码映射/错误本地化由调用方注入, 避免 httpshared↔api 循环依赖)。
package httpshared

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"mtls-gateway/internal/errs"
	"mtls-gateway/internal/i18n"
)

// —— 超时常量(全部 http.Server 共用; cmd/mtls-gw timeout_test 防回归断言) ——
const (
	// WriteTimeout 不限制响应写时限(长流式/SSE 刚需)。
	// 绝对时限会在响应中途强关连接, 即使流式响应持续输出也会到点被切。
	// LLM/SSE 长流式响应(如 DSH 对话)总时长可远超 60s, 原 60s 表现为
	// "每次发送消息的第一次发送超时"。frp 对照: 隧道只设 ReadHeaderTimeout,
	// 连接生命周期交对端。
	WriteTimeout = 0 * time.Second

	// IdleTimeout keep-alive 空闲上限(对齐浏览器连接池习惯); 过短(60s)会让
	// 浏览器复用已被关闭的死连接。
	IdleTimeout = 300 * time.Second

	// MaxBodyBytes 管理 API 请求体上限(防内存耗尽)。
	MaxBodyBytes = 4 << 20
)

// WriteJSON 输出 JSON 成功响应(统一 Content-Type; 与错误信封同款)。
func WriteJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}

// LangFromRequest 按请求头 X-Lang 取语言("en"/"zh", 默认 zh; r 可为 nil)。
// 前端 api() 注入 X-Lang, 后端错误出口按此兜底翻译(未收录错误原样返回)。
func LangFromRequest(r *http.Request) string {
	if r != nil {
		if lang := r.Header.Get("X-Lang"); lang == "en" || lang == "zh" {
			return lang
		}
	}
	return "zh"
}

// L 按请求语言返回 i18n 字典(默认 zh)。
func L(r *http.Request) *i18n.L { return i18n.New(LangFromRequest(r)) }

// —— 管理 API 授权上下文 ——
//
// 授权结论(mTLS + admin_role 校验通过)经 context 传递, 不用客户端可控的请求头
// (X-Auth-Purpose 已废弃): 内层 handler 只读 context, 任何绕过外层中间件的挂载
// 路径都会 fail-closed。S-1 安全加固(pro 前瞻审计 2026-08-23): GUI 阶段"换方式
// 挂载 admin API"不会再意外产生提权旁路。
type adminCtxKey struct{}

// WithAdminAuth 标记请求已通过外层管理授权(Authorize + IsAdmin)。
// 由 mtls-admin 外层中间件在认证通过后调用, 返回带标记的新请求。
func WithAdminAuth(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), adminCtxKey{}, true))
}

// IsAdminAuth 检查请求是否已通过外层管理授权(无标记 = 未授权, 内层必须拒绝)。
func IsAdminAuth(r *http.Request) bool {
	ok, _ := r.Context().Value(adminCtxKey{}).(bool)
	return ok
}

// KindOfErr 返回错误的 errs.Kind 字符串(空串=未分类)。ErrWriter.Kind 的常用注入。
func KindOfErr(err error) string { return string(errs.KindOf(err)) }

// LocalizeErrImmutable 仅 errImmutable 按请求语言重翻; 其余错误原样返回。
// 网关与管理进程的管理端点共用(现状: configmgr/proxy 的 CRUD 错误硬编码中文,
// 完整 i18n 接入属后续工作; 结构化 errs.Kind 已覆盖状态码与高频翻译)。
func LocalizeErrImmutable(lang string, err error) error {
	if errs.IsKind(err, errs.KindImmutable) {
		return i18n.New(lang).E("errImmutable")
	}
	return err
}

// ErrWriter 统一管理 API 错误出口: JSON 信封 {"error": msg} + 状态码 + 请求语言。
//
// 三处历史实现(relay.writeErr / mtls-admin gwErr / api handler 的 http.Error)
// 收敛到本类型; 状态码映射与本地化策略由调用方注入(Status/Localize), 本包不感知
// 具体错误语义。错误体统一 JSON 信封: WebUI app.js 读 data.error, CLI 按 JSON 解码。
//
// 注: internal/api 的 http.Error 纯文本出口暂不迁移 — 其错误被 AdminClient/CLI
// 原样消费, 信封化留给结构化错误改造(typedError)一并决策。
type ErrWriter struct {
	// Status 错误→HTTP 状态码; nil 时恒 500。
	Status func(err error) int
	// Localize 按请求语言翻译错误; nil 时原样输出。返回 err 本身即"不翻译"。
	Localize func(lang string, err error) error
	// Kind 错误结构化分类(机器可读, 如 errs.Kind); 非 nil 时随 JSON 信封上传,
	// 客户端可还原分类而不再依赖消息子串。nil 时信封不含 kind 字段。
	Kind func(err error) string
}

// Write 输出错误响应(先设头再 WriteHeader)。信封: {"error": msg[, "kind": kind]}。
func (ew ErrWriter) Write(w http.ResponseWriter, r *http.Request, err error) {
	msg := err.Error()
	if ew.Localize != nil {
		msg = ew.Localize(LangFromRequest(r), err).Error()
	}
	code := http.StatusInternalServerError
	if ew.Status != nil {
		code = ew.Status(err)
	}
	body := map[string]string{"error": msg}
	if ew.Kind != nil {
		if k := ew.Kind(err); k != "" {
			body["kind"] = k
		}
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(body)
}
