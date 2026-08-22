package errs

import (
	"errors"
	"fmt"
	"os"
	"testing"
)

// TestKindOf 提取: 直接标注 / %w 包装链 / 未标注
func TestKindOf(t *testing.T) {
	direct := New(KindConflict, "certificate name x already exists")
	if k := KindOf(direct); k != KindConflict {
		t.Fatalf("KindOf(direct) = %q, want conflict", k)
	}
	wrapped := fmt.Errorf("outer: %w", direct)
	if k := KindOf(wrapped); k != KindConflict {
		t.Fatalf("KindOf(wrapped) = %q, want conflict", k)
	}
	if k := KindOf(errors.New("plain error")); k != KindUnknown {
		t.Fatalf("KindOf(plain) = %q, want unknown", k)
	}
	if k := KindOf(nil); k != KindUnknown {
		t.Fatalf("KindOf(nil) = %q, want unknown", k)
	}
}

// TestWithKind 保留原始错误链: errors.Is 仍命中 os.ErrNotExist
func TestWithKind(t *testing.T) {
	orig := fmt.Errorf("cert x not found: %w", os.ErrNotExist)
	typed := WithKind(orig, KindNotFound)
	if !errors.Is(typed, os.ErrNotExist) {
		t.Fatal("WithKind 应保留原始错误链(errors.Is 命中)")
	}
	if typed.Error() != orig.Error() {
		t.Fatalf("消息应不变: %q != %q", typed.Error(), orig.Error())
	}
	if k := KindOf(typed); k != KindNotFound {
		t.Fatalf("KindOf = %q, want not_found", k)
	}
	// 链上更深处的 kind: WithKind(包装了 typed 的错误)仍能找到
	deeper := fmt.Errorf("reload: %w", typed)
	if k := KindOf(deeper); k != KindNotFound {
		t.Fatalf("KindOf(deeper) = %q, want not_found", k)
	}
	if WithKind(nil, KindForbidden) != nil {
		t.Fatal("WithKind(nil) 应返回 nil")
	}
}

// TestKindUnknownWrapper KindUnknown 标注不遮蔽链内真实 kind
func TestKindUnknownWrapper(t *testing.T) {
	inner := New(KindBadPwd, "decrypt key a: password incorrect")
	outer := WithKind(inner, KindUnknown) // 未分类包装
	if k := KindOf(outer); k != KindBadPwd {
		t.Fatalf("KindOf = %q, want bad_pwd(穿透未分类包装)", k)
	}
}

// TestIsKind 快捷判定
func TestIsKind(t *testing.T) {
	if !IsKind(New(KindImmutable, "config is immutable"), KindImmutable) {
		t.Fatal("IsKind 应命中")
	}
	if IsKind(errors.New("x"), KindImmutable) {
		t.Fatal("IsKind 不应误命中")
	}
}

// TestErrorBasics Error 接口与消息
func TestErrorBasics(t *testing.T) {
	e := New(KindBadRequest, "bad role name %q", "x!")
	if e.Error() != `bad role name "x!"` {
		t.Fatalf("Error() = %q", e.Error())
	}
	if e.KindOf() != KindBadRequest {
		t.Fatal("KindOf() 方法")
	}
}
