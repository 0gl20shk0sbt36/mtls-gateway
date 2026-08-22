// Package errs 轻量结构化错误: 机器可读的 Kind 语义分类。
//
// 背景: 错误状态码映射(api.StatusFromKeywords)与客户端本地化(relay.localizeKnown)
// 长期依赖【消息文本子串匹配】, 两表各自维护且措辞变化会错标/漏译。本包给错误
// 挂一个 Kind, 让分类与文本解耦:
//
//   - 服务端创建错误用 errs.New/WithKind 标注 Kind(消息文本保持不变, 测试兼容);
//   - api.ErrStatus 先查 KindOf(err), 未标注才回退子串表;
//   - httpshared.ErrWriter 把 kind 放进 JSON 信封随线上传;
//   - relay AdminClient 解析信封还原 Kind, localizeKnown 先查 KindOf 再回退子串。
//
// 本包为叶子包(仅标准库), 任何包可 import, 无循环依赖风险。
package errs

import "fmt"

// Kind 错误语义分类(机器可读; 状态码映射/本地化/日志结构化共用)。
// 空值 = 未分类(KindUnknown)。
type Kind string

// 分类集: 对齐 api.StatusFromKeywords 语义 + relay.localizeKnown 高频翻译项。
const (
	KindUnknown       Kind = ""               // 未分类(回退子串匹配)
	KindAdminDenied   Kind = "admin_denied"   // 403 非 admin 证书
	KindImmutable     Kind = "immutable"      // 403 配置只读拒绝写入
	KindForbidden     Kind = "forbidden"      // 403 无权/拒绝访问
	KindNotFound      Kind = "not_found"      // 404 未找到/不存在
	KindConflict      Kind = "conflict"       // 409 已存在/重复/仍被引用
	KindBadRequest    Kind = "bad_request"    // 400 参数/格式/校验失败
	KindPwdNeeded     Kind = "pwd_needed"     // 400 私钥需要密码
	KindBadPwd        Kind = "bad_pwd"        // 400 密码错误
	KindExpired       Kind = "expired"        // 400/403 证书过期
	KindRevoked       Kind = "revoked"        // 403 已吊销
	KindNoCert        Kind = "no_cert"        // 400 无可用客户端证书
	KindNotRegistered Kind = "not_registered" // 403 证书未登记
)

// Error 带 Kind 的错误。Msg 为人类可读消息(与转换前文本一致, 兼容子串匹配回退)。
type Error struct {
	K   Kind
	Msg string
	// Err 可选原始错误: WithKind 使用, 保留 errors.Is/Unwrap 链
	// (如 os.ErrNotExist / x509 解析错误), 同时让 KindOf 能继续向链深处提取。
	Err error
}

// Error 实现 error 接口。
func (e *Error) Error() string { return e.Msg }

// Unwrap 保留原始错误链(WithKind 构造时)。
func (e *Error) Unwrap() error { return e.Err }

// KindOf 实现 Kind 提取接口(供 errs.KindOf 与外部直接调用)。
func (e *Error) KindOf() Kind { return e.K }

// New 创建带 Kind 的错误(消息格式化, 与 fmt.Errorf 同款; 无原始错误链)。
func New(k Kind, format string, args ...any) *Error {
	return &Error{K: k, Msg: fmt.Sprintf(format, args...)}
}

// WithKind 给已有错误挂 Kind(保留原消息与原始错误链, errors.Is/Unwrap 不受影响)。
// err 为 nil 时返回 nil。
func WithKind(err error, k Kind) error {
	if err == nil {
		return nil
	}
	return &Error{K: k, Msg: err.Error(), Err: err}
}

// KindOf 提取错误链上第一个 Kind(含 %w 包装; 支持 errs.Error 与实现
// KindOf() Kind 接口的任意类型)。未标注返回 KindUnknown。
func KindOf(err error) Kind {
	for err != nil {
		if ke, ok := err.(*Error); ok {
			if ke.K != KindUnknown {
				return ke.K
			}
			err = ke.Unwrap()
			continue
		}
		if k, ok := err.(interface{ KindOf() Kind }); ok {
			if k.KindOf() != KindUnknown {
				return k.KindOf()
			}
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			break
		}
		err = u.Unwrap()
	}
	return KindUnknown
}

// IsKind 判断错误链上是否带指定 Kind。
func IsKind(err error, k Kind) bool { return KindOf(err) == k }
