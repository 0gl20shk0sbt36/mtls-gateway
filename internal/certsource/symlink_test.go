package certsource

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// 高危(测试全面性审计): symlink 逃逸拒绝 — Load/LoadWithPassword 必须拒绝,
// List 必须跳过(与 Load 拒绝语义一致, 防"列出却加载失败"/目录被污染)。
func TestSymlinkEscapeRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.Symlink 需特殊权限, Windows 上跳过(防护逻辑平台无关)")
	}
	root := t.TempDir()
	outside := t.TempDir()
	tc := genTestCert(t, "issuer", "org", "dev")
	tc.writeDirCert(t, outside, "real") // outside/real/cert.pem+key.pem

	src, err := New(Dir, root)
	if err != nil {
		t.Fatal(err)
	}
	lp, ok := src.(LoaderWithPassword) // dir 源实现密码加载
	if !ok {
		t.Fatal("dir source should implement LoaderWithPassword")
	}

	// 1) 子目录条目本身是指向 root 外的 symlink → Load/LoadWithPassword 拒绝, List 跳过
	if err := os.Symlink(filepath.Join(outside, "real"), filepath.Join(root, "evil")); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Load("evil"); err == nil || !strings.Contains(err.Error(), "outside cert dir") {
		t.Fatalf("Load 应拒绝目录级 symlink 逃逸: %v", err)
	}
	if _, err := lp.LoadWithPassword("evil", ""); err == nil || !strings.Contains(err.Error(), "outside cert dir") {
		t.Fatalf("LoadWithPassword 应拒绝目录级 symlink 逃逸: %v", err)
	}
	if metas, err := src.List(); err != nil {
		t.Fatal(err)
	} else if len(metas) != 0 {
		t.Fatalf("List 应跳过目录级逃逸身份: %v", metas)
	}

	// 2) 目录内 cert.pem 是指向 root 外文件的 symlink → Load 拒绝, List 跳过
	tc.writeDirCert(t, root, "good") // 真实子目录
	if err := os.Remove(filepath.Join(root, "good", "cert.pem")); err != nil {
		t.Fatal(err)
	}
	outCert := filepath.Join(outside, "real", "cert.pem")
	if err := os.Symlink(outCert, filepath.Join(root, "good", "cert.pem")); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Load("good"); err == nil || !strings.Contains(err.Error(), "outside cert dir") {
		t.Fatalf("Load 应拒绝 cert.pem 文件级 symlink 逃逸: %v", err)
	}
	if _, err := lp.LoadWithPassword("good", ""); err == nil || !strings.Contains(err.Error(), "outside cert dir") {
		t.Fatalf("LoadWithPassword 应拒绝 cert.pem 文件级 symlink 逃逸: %v", err)
	}
	if metas, err := src.List(); err != nil {
		t.Fatal(err)
	} else if len(metas) != 0 {
		t.Fatalf("List 应跳过含逃逸 cert.pem 的身份: %v", metas)
	}
}

// 正常身份不受 symlink 防护误伤: 目录内真实文件照常加载/列出
func TestSymlinkProtectionDoesNotBlockLegit(t *testing.T) {
	root := t.TempDir()
	tc := genTestCert(t, "issuer", "org", "dev")
	tc.writeDirCert(t, root, "good")
	src, err := New(Dir, root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.Load("good"); err != nil {
		t.Fatalf("合法身份不应被误拒: %v", err)
	}
	if metas, err := src.List(); err != nil || len(metas) != 1 {
		t.Fatalf("合法身份应列出: %v err=%v", metas, err)
	}
}
