package httpshared

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestWriteJSON 统一 JSON 成功信封: Content-Type + 可解码
func TestWriteJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteJSON(rec, map[string]string{"status": "ok"})
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	if !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

// TestLangFromRequest X-Lang 解析: zh/en 生效, 其余/缺失默认 zh
func TestLangFromRequest(t *testing.T) {
	cases := []struct{ hdr, want string }{
		{"", "zh"},
		{"zh", "zh"},
		{"en", "en"},
		{"fr", "zh"}, // 未收录语言兜底 zh
		{"EN", "zh"}, // 大小写敏感(原实现语义): 非精确 en/zh 走默认
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		if c.hdr != "" {
			r.Header.Set("X-Lang", c.hdr)
		}
		if got := LangFromRequest(r); got != c.want {
			t.Errorf("LangFromRequest(%q) = %q, want %q", c.hdr, got, c.want)
		}
	}
	if got := LangFromRequest(nil); got != "zh" {
		t.Errorf("LangFromRequest(nil) = %q, want zh", got)
	}
}

// TestErrWriter 统一错误信封: JSON {"error":...} + 注入的状态码 + 本地化
func TestErrWriter(t *testing.T) {
	// 纯状态码映射(不本地化)
	ew := ErrWriter{Status: func(err error) int { return http.StatusConflict }}
	rec := httptest.NewRecorder()
	ew.Write(rec, httptest.NewRequest("GET", "/", nil), errors.New("certificate name x already exists"))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("Content-Type = %q", ct)
	}
	if !strings.Contains(rec.Body.String(), `"error"`) || !strings.Contains(rec.Body.String(), "already exists") {
		t.Fatalf("body = %q", rec.Body.String())
	}

	// 本地化注入 + 语言分流
	ewL := ErrWriter{
		Status: func(err error) int { return http.StatusBadRequest },
		Localize: func(lang string, err error) error {
			if lang == "en" {
				return errors.New("EN:" + err.Error())
			}
			return errors.New("ZH:" + err.Error())
		},
	}
	for lang, wantPrefix := range map[string]string{"en": "EN:", "zh": "ZH:"} {
		rec2 := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Lang", lang)
		ewL.Write(rec2, req, errors.New("boom"))
		if !strings.Contains(rec2.Body.String(), wantPrefix+"boom") {
			t.Fatalf("lang %s body = %q, want prefix %s", lang, rec2.Body.String(), wantPrefix)
		}
	}

	// Status 为 nil 时恒 500
	rec3 := httptest.NewRecorder()
	(ErrWriter{}).Write(rec3, nil, errors.New("x"))
	if rec3.Code != http.StatusInternalServerError {
		t.Fatalf("nil status 应 500, got %d", rec3.Code)
	}
}

// TestErrWriterOrder 状态码与本地化独立: 本地化结果不影响状态码映射
func TestErrWriterOrder(t *testing.T) {
	ew := ErrWriter{
		Status:   func(err error) int { return http.StatusNotFound },
		Localize: func(lang string, err error) error { return errors.New("本地化: " + err.Error()) },
	}
	rec := httptest.NewRecorder()
	ew.Write(rec, httptest.NewRequest("GET", "/", nil), errors.New("not found"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "本地化") {
		t.Fatalf("body = %q", rec.Body.String())
	}
}
