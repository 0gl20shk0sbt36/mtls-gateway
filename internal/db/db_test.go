package db

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
)

// TestOpenAndCRUD 测试数据库打开 + 证书记录 CRUD
func TestOpenAndCRUD(t *testing.T) {
	// 用临时文件数据库
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	// 空库
	if got := len(s.List()); got != 0 {
		t.Fatalf("empty db should have 0 certs, got %d", got)
	}

	// 新增
	rec := CertRecord{
		Serial:    "1001",
		Name:      "test-device",
		Purposes:  []string{"dsh"},
		TSIP:      "100.64.0.1",
		Status:    "enabled",
		ExpiresAt: "2027-01-01",
	}
	if err := s.Upsert(rec); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// 内存查表
	got, ok := s.Get("1001")
	if !ok {
		t.Fatal("get should find cert 1001")
	}
	if got.Name != "test-device" || !got.HasPurpose("dsh") {
		t.Fatalf("unexpected record: %+v", got)
	}

	// 重新打开 (验证 SQLite 持久化)
	s2, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	if _, ok := s2.Get("1001"); !ok {
		t.Fatal("reopened db should still have cert 1001")
	}
}

// TestRevoke 测试吊销: 内存立即生效 + 持久化
func TestRevoke(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	rec := CertRecord{Serial: "2001", Name: "dev", Purposes: []string{"app"}, TSIP: "100.64.0.2", Status: "enabled", ExpiresAt: "2027-01-01"}
	if err := s.Upsert(rec); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// 吊销
	if err := s.Revoke("2001"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	got, _ := s.Get("2001")
	if got.Status != "revoked" {
		t.Fatalf("expected revoked, got %q", got.Status)
	}

	// 吊销不存在的
	if err := s.Revoke("9999"); err == nil {
		t.Fatal("revoke missing should error")
	}
}

// TestUpsertOverwrite 测试同一 serial 更新 (改用途/状态)
func TestUpsertOverwrite(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	rec1 := CertRecord{Serial: "3001", Name: "dev", Purposes: []string{"app"}, TSIP: "100.64.0.3", Status: "enabled", ExpiresAt: "2027-01-01"}
	rec2 := CertRecord{Serial: "3001", Name: "dev", Purposes: []string{"admin"}, TSIP: "100.64.0.3", Status: "enabled", ExpiresAt: "2027-02-01"}
	if err := s.Upsert(rec1); err != nil {
		t.Fatalf("upsert1: %v", err)
	}
	if err := s.Upsert(rec2); err != nil {
		t.Fatalf("upsert2: %v", err)
	}
	got, _ := s.Get("3001")
	if !got.HasPurpose("admin") || got.ExpiresAt != "2027-02-01" {
		t.Fatalf("overwrite failed: %+v", got)
	}
	// 不应重复
	if n := len(s.List()); n != 1 {
		t.Fatalf("expected 1 record, got %d", n)
	}
}

// L2: FindByName 含吊销记录 + List 按签发时间排序
func TestFindByNameAndListOrder(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "f.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Upsert(CertRecord{Serial: "s2", Name: "dup", Status: "enabled", IssuedAt: "2026-08-01T00:00:00Z", ExpiresAt: "2026-09-01"}); err != nil {
		t.Fatal(err)
	}
	// DB 层 UNIQUE(name) 强制"禁止同名(含吊销)" — 任何状态同名都拒绝
	if err := s.Upsert(CertRecord{Serial: "s1", Name: "dup", Status: "revoked", IssuedAt: "2026-07-01T00:00:00Z", ExpiresAt: "2026-08-01"}); err == nil {
		t.Fatal("同名记录(含吊销)应被 UNIQUE(name) 拒绝")
	}
	if err := s.Upsert(CertRecord{Serial: "s3", Name: "other", Status: "enabled", IssuedAt: "2026-09-01T00:00:00Z", ExpiresAt: "2026-10-01"}); err != nil {
		t.Fatal(err)
	}
	recs := s.FindByName("dup")
	if len(recs) != 1 || recs[0].Serial != "s2" {
		t.Fatalf("FindByName(\"dup\") = %+v, want 仅 s2", recs)
	}
	all := s.List()
	if len(all) != 2 {
		t.Fatalf("List: %d", len(all))
	}
}

// 第八批: Get/List/FindByName Purposes 深拷贝 — 改返回切片不污染表
func TestPurposesDeepCopy(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rec := CertRecord{Serial: "1", Name: "dev", Purposes: []string{"dsh"}, Status: "enabled"}
	if err := s.Upsert(rec); err != nil {
		t.Fatal(err)
	}
	// Get
	g, _ := s.Get("1")
	g.Purposes[0] = "MUTATED"
	g2, _ := s.Get("1")
	if g2.Purposes[0] != "dsh" {
		t.Fatalf("Get Purposes polluted: %v", g2.Purposes)
	}
	// List
	ls := s.List()
	ls[0].Purposes[0] = "MUTATED2"
	l2 := s.List()
	if l2[0].Purposes[0] != "dsh" {
		t.Fatalf("List Purposes polluted: %v", l2[0].Purposes)
	}
	// FindByName
	fn := s.FindByName("dev")
	fn[0].Purposes[0] = "MUTATED3"
	f2 := s.FindByName("dev")
	if f2[0].Purposes[0] != "dsh" {
		t.Fatalf("FindByName Purposes polluted: %v", f2[0].Purposes)
	}
}

// 第九批: InsertUniqueName 原子性 — 并发同名只有一个成功
func TestInsertUniqueNameConcurrent(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var wg sync.WaitGroup
	okCount := 0
	var mu sync.Mutex
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			err := s.InsertUniqueName(CertRecord{Serial: fmt.Sprintf("%d", i), Name: "same", Purposes: []string{"dsh"}, Status: "enabled"})
			if err == nil {
				mu.Lock()
				okCount++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if okCount != 1 {
		t.Fatalf("concurrent same-name inserts: %d succeeded, want exactly 1", okCount)
	}
}

// TestReload 全量热重载: 管理进程(另一连接)写库后, Reload 重读可见新数据; 失败保持旧表
func TestReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	s1, err := Open(path) // 网关侧(只读消费者)
	if err != nil {
		t.Fatal(err)
	}
	defer s1.Close()
	s2, err := Open(path) // 管理进程侧(写者)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()

	rec := CertRecord{Serial: "2001", Name: "dev-a", Purposes: []string{"dsh"}, Status: "enabled", ExpiresAt: "2099-01-01"}
	if err := s2.Upsert(rec); err != nil { // 管理进程写库
		t.Fatal(err)
	}
	// 网关侧 reload 前不可见
	if _, ok := s1.Get("2001"); ok {
		t.Fatal("reload 前不应看到新记录")
	}
	if err := s1.Reload(); err != nil { // 网关 reload
		t.Fatal(err)
	}
	got, ok := s1.Get("2001")
	if !ok || got.Name != "dev-a" || !got.HasPurpose("dsh") {
		t.Fatalf("reload 后应看到新记录: %+v ok=%v", got, ok)
	}

	// 吊销(管理进程) → reload 后网关侧 status 同步
	if err := s2.Revoke("2001"); err != nil {
		t.Fatal(err)
	}
	if err := s1.Reload(); err != nil {
		t.Fatal(err)
	}
	if got, _ := s1.Get("2001"); got.Status != "revoked" {
		t.Fatalf("reload 后吊销状态应同步: %+v", got)
	}
}
