package db

import (
	"path/filepath"
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
		Purposes: []string{"dsh"},
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
