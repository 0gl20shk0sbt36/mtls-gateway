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
	"encoding/json"
	"net/http"
	"time"

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
}

// Write 输出错误响应(先设头再 WriteHeader)。
func (ew ErrWriter) Write(w http.ResponseWriter, r *http.Request, err error) {
	msg := err.Error()
	if ew.Localize != nil {
		msg = ew.Localize(LangFromRequest(r), err).Error()
	}
	code := http.StatusInternalServerError
	if ew.Status != nil {
		code = ew.Status(err)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
