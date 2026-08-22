// httperr.go: 中继管理 API 错误出口(统一信封 httpshared.ErrWriter)。
// writeErr/errStatus/localizeKnown/decodeJSON 独立成文件, 与路由(handler.go)
// 和业务方法(api.go)分离; Manager.Localize 导出供 GUI/外壳层直接调用。
package relay

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"mtls-gateway/internal/api"
	"mtls-gateway/internal/errs"
	"mtls-gateway/internal/httpshared"
	"mtls-gateway/internal/i18n"
)

// writeJSON 输出 JSON 成功响应(统一信封, httpshared 共享)。
func writeJSON(w http.ResponseWriter, v any) { httpshared.WriteJSON(w, v) }

// errStatus 错误→HTTP 状态码: ① 管理桥错误内嵌的 "HTTP NNN"(权威, 服务端已判定)
// → ② 结构化 errs.Kind(本地错误, 确定性映射) → ③ 关键字回退(存量/未标注错误)。
func errStatus(err error) int {
	raw := err.Error()
	if m := reHTTPStatus.FindStringSubmatch(raw); len(m) == 2 {
		if c, e := strconv.Atoi(m[1]); e == nil {
			return c
		}
	}
	if k := errs.KindOf(err); k != errs.KindUnknown {
		return api.StatusForKind(k)
	}
	return api.StatusFromKeywords(raw)
}

// errKindOf 提取 errs.Kind 为字符串(信封 kind 字段; 未标注返回空串)。
func errKindOf(err error) string { return string(errs.KindOf(err)) }

// writeErr 输出错误响应(统一 JSON 信封 httpshared.ErrWriter): 已知错误按请求
// 语言(X-Lang)翻译, 其余原样; 状态码走 errStatus; kind 随信封上传(GUI/外壳
// 可结构化识别, 不再依赖消息文本)。
var writeErr = httpshared.ErrWriter{
	Status:   errStatus,
	Localize: localizeKnown,
	Kind:     errKindOf,
}.Write

// decodeJSON 解码请求体; 失败写 400 并返回 false
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, httpshared.MaxBodyBytes) // 4MB 上限
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeErr(w, r, fmt.Errorf("bad request: %v", err))
		return false
	}
	return true
}

// 错误串提取正则(包级预编译; 每正则单捕获组, len(m)==2 判定)
var (
	reErrName       = regexp.MustCompile(`decrypt key (\S+)`)
	reErrNamePwd    = regexp.MustCompile(`private key needs password: (\S+)`)
	reErrNameCert   = regexp.MustCompile(`cert (\S+) not found`)
	reErrNameExist  = regexp.MustCompile(`certificate name (\S+) already exists`)
	reErrNameExist2 = regexp.MustCompile(`name (\S+) already exists`)
	reErrNameParse  = regexp.MustCompile(`parse (?:pem )?keypair (\S+):`)
	reErrRecord     = regexp.MustCompile(`\((\d+) record`)
	reHTTPStatus    = regexp.MustCompile(`HTTP ([45]\d{2})`)
)

// localizeKnown 已知错误按语言兜底翻译(所有 API 错误出口)。
// 结构化 errs.Kind 优先(确定性, 不依赖消息措辞; 线上错误经 AdminClient 信封
// 还原 kind, 本地错误直接带 kind); KindBadRequest 泛化类与未标注错误回退
// 下方子串匹配(存量兼容, 措辞变化仍可能漏译 — 新错误请标注 kind)。
func localizeKnown(lang string, err error) error {
	if err == nil {
		return nil
	}
	l := i18n.New("zh")
	if lang == "en" {
		l = i18n.New("en")
	}
	if k := errs.KindOf(err); k != errs.KindUnknown && k != errs.KindBadRequest {
		if localized := localizeKind(l, k, err.Error()); localized != nil {
			return localized
		}
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "private key needs password"), strings.Contains(s, "failed to parse private key"):
		return l.E("errPwdNeeded", errCertName(s))
	case strings.Contains(s, "decryption password incorrect"), strings.Contains(s, "password incorrect"):
		return l.E("errBadPwd", errCertName(s))
	case strings.Contains(s, "expired certificate"), strings.Contains(s, "certificate has expired"):
		return l.E("errExpired")
	case strings.Contains(s, "no certificates in source"), strings.Contains(s, "no client cert"):
		return l.E("errNoCert")
	case strings.Contains(s, "admin_addr not set"):
		return l.E("errNoAdminAddr")
	case strings.Contains(s, "server address not configured"):
		return l.E("errNoServerAddr")
	case strings.Contains(s, "name and purposes required"):
		return l.E("errNameRequired")
	case strings.Contains(s, "already exists"):
		n := 0
		if m := reErrRecord.FindStringSubmatch(s); len(m) == 2 {
			n, _ = strconv.Atoi(m[1])
		}
		return l.E("errNameExists", errCertName(s), n)
	case strings.Contains(s, "missing listen"):
		return l.E("errMapNoListen")
	case strings.Contains(s, "missing id"):
		return l.E("errMapMissingID")
	case strings.Contains(s, "duplicate listen"):
		return l.E("errListenDup", tailName(s))
	case strings.Contains(s, "duplicate service name"):
		return l.E("errSvcExists", tailName(s))
	case strings.Contains(s, "has no channels"):
		return l.E("errNoChannels", tailName(s))
	case strings.Contains(s, "immutable"):
		return l.E("errImmutable")
	case strings.Contains(s, "admin cert required"), strings.Contains(s, "admin required"):
		return l.E("errAdminDenied")
	case strings.Contains(s, "forbidden"):
		return l.E("errDenied")
	case strings.Contains(s, "not found"):
		return l.E("errNotFound", errCertName(s))
	case strings.Contains(s, "not registered"):
		return l.E("errNotFound", errCertName(s))
	case strings.Contains(s, "status=revoked"):
		return l.E("errRevoked") // 模板无 %s, 不传参
	case strings.Contains(s, "expired"):
		return l.E("errExpired") // 模板无 %s, 不传参
	}
	return err
}

// localizeKind errs.Kind → i18n 翻译(结构化路径; 参数仍从消息提取, 如证书名/记录数)。
// 无专属翻译的 kind 返回 nil, 由调用方回退子串匹配。
func localizeKind(l *i18n.L, k errs.Kind, s string) error {
	switch k {
	case errs.KindPwdNeeded:
		return l.E("errPwdNeeded", errCertName(s))
	case errs.KindBadPwd:
		return l.E("errBadPwd", errCertName(s))
	case errs.KindExpired:
		return l.E("errExpired")
	case errs.KindNoCert:
		return l.E("errNoCert")
	case errs.KindAdminDenied:
		return l.E("errAdminDenied")
	case errs.KindForbidden:
		return l.E("errDenied")
	case errs.KindNotFound:
		return l.E("errNotFound", errCertName(s))
	case errs.KindNotRegistered:
		return l.E("errNotFound", errCertName(s))
	case errs.KindRevoked:
		return l.E("errRevoked")
	case errs.KindImmutable:
		return l.E("errImmutable")
	case errs.KindConflict:
		n := 0
		if m := reErrRecord.FindStringSubmatch(s); len(m) == 2 {
			n, _ = strconv.Atoi(m[1])
		}
		return l.E("errNameExists", errCertName(s), n)
	}
	return nil
}

// Localize 导出错误本地化入口(GUI/外壳层前置): 已知错误按 lang 兜底翻译,
// 未收录原样返回。HTTP 出口(writeErr)已自动按 X-Lang 调用, 非 HTTP 场景
// (如 GUI 直接拿 Manager 错误展示)用本方法。
func (m *Manager) Localize(lang string, err error) error { return localizeKnown(lang, err) }

// errCertName 从错误消息提取证书名("decrypt key admin"/"cert admin not found"/"private key needs password: admin")
func errCertName(s string) string {
	for _, re := range []*regexp.Regexp{reErrName, reErrNamePwd, reErrNameCert, reErrNameExist, reErrNameExist2, reErrNameParse} {
		if m := re.FindStringSubmatch(s); len(m) == 2 {
			// reErrName 用 \S+ 会连尾部冒号一起捕获("admin:" / "C:\x.pem:"), 去掉之
			return strings.TrimSuffix(m[1], ":")
		}
	}
	return tailName(s)
}

// tailName 取错误消息最后一段(: 之后)
func tailName(s string) string {
	if i := strings.LastIndex(s, ": "); i >= 0 {
		return s[i+2:]
	}
	return s
}
