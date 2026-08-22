package atomicfile

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// 原子写: 内容完整落盘、无 tmp-* 残留、可回读
func TestWriteFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "cfg.json") // 子目录存在才可写(调用方负责 MkdirAll)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(path, []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != `{"a":1}` {
		t.Fatalf("round-trip: %q err=%v", data, err)
	}
	// 覆盖写(替换旧内容)
	if err := WriteFile(path, []byte(`{"a":2}`)); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); string(data) != `{"a":2}` {
		t.Fatalf("overwrite: %q", data)
	}
	// 无 tmp-* 残留
	entries, _ := os.ReadDir(filepath.Dir(path))
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("stale tmp: %s", e.Name())
		}
	}
	// 权限 0600(Unix; Windows Perm() 恒 0666 无意义)
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
			t.Fatalf("perm %v, want 0600", st.Mode().Perm())
		}
	}
}

// 目标目录不存在 → 报错(调用方负责 MkdirAll, 不静默创建)
func TestWriteFileMissingDir(t *testing.T) {
	if err := WriteFile(filepath.Join(t.TempDir(), "no", "x"), []byte("x")); err == nil {
		t.Fatal("缺目录应报错")
	}
}
