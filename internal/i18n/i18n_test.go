package i18n

import (
	"os"
	"strings"
	"testing"
)

func TestDetect(t *testing.T) {
	envs := []string{"LC_ALL", "LC_MESSAGES", "LANG"}
	// 保存并清理
	old := map[string]string{}
	for _, e := range envs {
		old[e] = os.Getenv(e)
		os.Unsetenv(e)
	}
	defer func() {
		for _, e := range envs {
			if old[e] == "" {
				os.Unsetenv(e)
			} else {
				os.Setenv(e, old[e])
			}
		}
	}()
	for _, e := range envs {
		os.Unsetenv(e)
	}
	cases := []struct {
		lcAll, lcMsg, lang string
		want               Lang
	}{
		{"zh_CN.UTF-8", "", "", Zh},
		{"", "zh_CN.UTF-8", "", Zh},
		{"", "", "zh_CN.UTF-8", Zh},
		{"en_US.UTF-8", "", "", En},
		{"", "", "en_US", En},
		{"", "", "", Zh}, // 全空 → 默认 zh
		{"fr_FR", "", "", Zh}, // 未知语言 → 默认 zh
	}
	for _, c := range cases {
		os.Setenv("LC_ALL", c.lcAll)
		os.Setenv("LC_MESSAGES", c.lcMsg)
		os.Setenv("LANG", c.lang)
		if got := Detect(); got != c.want {
			t.Errorf("Detect(%q,%q,%q) = %v, want %v", c.lcAll, c.lcMsg, c.lang, got, c.want)
		}
	}
}

func TestTranslateWarnings(t *testing.T) {
	in := []string{"admin 与其他用途混用, 已忽略其他用途, 仅保留 admin", "admin 不在首位, 已剔除 admin, 保留其他用途", "custom warning"}
	zh := TranslateWarnings(Zh, in)
	if len(zh[0]) < 5 {
		t.Fatalf("zh warn0: %q", zh[0])
	}
	en := TranslateWarnings(En, in)
	if en[0] == zh[0] {
		t.Fatalf("en/zh should differ: %q", en[0])
	}
	if en[2] != "custom warning" {
		t.Fatalf("unknown warning should pass through: %q", en[2])
	}
}

func TestLErrorArgs(t *testing.T) {
	l := New("zh")
	err := l.E("errPwdNeeded", "admin")
	if err == nil || !strings.Contains(err.Error(), "admin") {
		t.Fatalf("E with arg: %v", err)
	}
	l2 := New("en")
	if l2.E("errPwdNeeded", "admin").Error() == err.Error() {
		t.Fatal("zh/en should differ")
	}
	// 未知键 → missing 标记
	if got := l.S("no_such_key"); !strings.Contains(got, "no_such_key") {
		t.Fatalf("unknown key should contain key name: %q", got)
	}
}
