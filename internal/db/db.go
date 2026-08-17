// Package db 提供 SQLite 持久化 + 内存证书表。
// 设计: 内存为权威(请求验证零 IO), SQLite 只做落盘持久化。
package db

import (
	"database/sql"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// CertRecord 一条证书的完整记录(内存表 + SQLite 行)
type CertRecord struct {
	Serial      string `json:"serial"`      // 证书序列号 (主键)
	Name        string `json:"name"`        // 设备/证书名
	Purpose     string `json:"purpose"`     // 用途: admin | dsh | vaultwarden | ...
	TSIP        string `json:"ts_ip"`       // 绑定的 Tailscale IP (证书 SAN 也含此 IP)
	Status      string `json:"status"`      // enabled | revoked
	IssuedAt    string `json:"issued_at"`   // 签发时间
	ExpiresAt   string `json:"expires_at"`  // 过期时间
	Fingerprint string `json:"fingerprint"` // SHA-256 指纹
}

// Store 数据库 + 内存表
type Store struct {
	mu     sync.RWMutex
	sqlite *sql.DB
	table  map[string]CertRecord // serial -> record (内存权威)
}

// Open 打开 SQLite 并加载全量到内存
func Open(path string) (*Store, error) {
	sdb, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// WAL 模式, 并发读友好
	if _, err := sdb.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;`); err != nil {
		return nil, fmt.Errorf("pragma: %w", err)
	}
	if _, err := sdb.Exec(`
CREATE TABLE IF NOT EXISTS certs (
	serial      TEXT PRIMARY KEY,
	name        TEXT NOT NULL,
	purpose     TEXT NOT NULL,
	ts_ip       TEXT NOT NULL DEFAULT '',
	status      TEXT NOT NULL DEFAULT 'enabled',
	issued_at   TEXT NOT NULL,
	expires_at  TEXT NOT NULL,
	fingerprint TEXT NOT NULL DEFAULT ''
);`); err != nil {
		return nil, fmt.Errorf("create table: %w", err)
	}

	s := &Store{sqlite: sdb, table: make(map[string]CertRecord)}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// load 启动时全量加载到内存
func (s *Store) load() error {
	rows, err := s.sqlite.Query(`SELECT serial,name,purpose,ts_ip,status,issued_at,expires_at,fingerprint FROM certs`)
	if err != nil {
		return fmt.Errorf("load: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var r CertRecord
		if err := rows.Scan(&r.Serial, &r.Name, &r.Purpose, &r.TSIP, &r.Status, &r.IssuedAt, &r.ExpiresAt, &r.Fingerprint); err != nil {
			return fmt.Errorf("scan: %w", err)
		}
		s.table[r.Serial] = r
	}
	return rows.Err()
}

// Get 内存查表 (请求验证路径, 零 IO)
func (s *Store) Get(serial string) (CertRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.table[serial]
	return r, ok
}

// List 返回全部记录
func (s *Store) List() []CertRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]CertRecord, 0, len(s.table))
	for _, r := range s.table {
		out = append(out, r)
	}
	return out
}

// Upsert 新增或更新记录: 内存 + SQLite 同步
func (s *Store) Upsert(r CertRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.IssuedAt == "" {
		r.IssuedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if r.Status == "" {
		r.Status = "enabled"
	}
	_, err := s.sqlite.Exec(`INSERT INTO certs (serial,name,purpose,ts_ip,status,issued_at,expires_at,fingerprint)
		VALUES (?,?,?,?,?,?,?,?)
		ON CONFLICT(serial) DO UPDATE SET
			name=excluded.name, purpose=excluded.purpose, ts_ip=excluded.ts_ip,
			status=excluded.status, expires_at=excluded.expires_at, fingerprint=excluded.fingerprint`,
		r.Serial, r.Name, r.Purpose, r.TSIP, r.Status, r.IssuedAt, r.ExpiresAt, r.Fingerprint)
	if err != nil {
		return fmt.Errorf("upsert: %w", err)
	}
	s.table[r.Serial] = r
	return nil
}

// Revoke 吊销: 改内存 + 落库
func (s *Store) Revoke(serial string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.table[serial]
	if !ok {
		return fmt.Errorf("cert %s not found", serial)
	}
	r.Status = "revoked"
	if _, err := s.sqlite.Exec(`UPDATE certs SET status='revoked' WHERE serial=?`, serial); err != nil {
		return fmt.Errorf("revoke: %w", err)
	}
	s.table[serial] = r
	return nil
}

// Close 关闭数据库
func (s *Store) Close() error { return s.sqlite.Close() }
