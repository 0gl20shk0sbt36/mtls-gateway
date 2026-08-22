// Package db 提供 SQLite 持久化 + 内存证书表。
// 设计: 内存为权威(请求验证零 IO), SQLite 只做落盘持久化。
package db

import (
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// CertRecord 一条证书的完整记录(内存表 + SQLite 行)
// Purposes: 该身份可访问的应用列表 (admin, dsh, vaultwarden, ...)
// SQLite 存逗号分隔字符串, 内存中为 []string
type CertRecord struct {
	Serial      string   `json:"serial"`      // 证书序列号 (主键)
	Name        string   `json:"name"`        // 设备/证书名
	Purposes    []string `json:"purposes"`    // 可访问的用途列表 (身份→权限)
	TSIP        string   `json:"ts_ip"`       // 绑定的 Tailscale IP (证书 SAN 也含此 IP)
	Status      string   `json:"status"`      // enabled | revoked
	IssuedAt    string   `json:"issued_at"`   // 签发时间
	ExpiresAt   string   `json:"expires_at"`  // 过期时间
	Fingerprint string   `json:"fingerprint"` // SHA-256 指纹
}

// HasPurpose 该身份是否有指定用途权限
func (r *CertRecord) HasPurpose(p string) bool {
	for _, x := range r.Purposes {
		if x == p {
			return true
		}
	}
	return false
}

// purposesStr 内存 []string → SQLite 逗号分隔
func (r *CertRecord) purposesStr() string { return strings.Join(r.Purposes, ",") }

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
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_certs_name ON certs(name);`); err != nil {
		return nil, fmt.Errorf("create table/index: %w", err)
	}

	s := &Store{sqlite: sdb, table: make(map[string]CertRecord)}
	if err := s.Reload(); err != nil {
		return nil, err
	}
	return s, nil
}

// buildTable 从 SQLite 全量构建内存表(Open/Reload 共用; 不持锁, 调用方负责)
func (s *Store) buildTable() (map[string]CertRecord, error) {
	rows, err := s.sqlite.Query(`SELECT serial,name,purpose,ts_ip,status,issued_at,expires_at,fingerprint FROM certs`)
	if err != nil {
		return nil, fmt.Errorf("load: %w", err)
	}
	defer rows.Close()
	next := make(map[string]CertRecord)
	for rows.Next() {
		var r CertRecord
		var purposes string
		if err := rows.Scan(&r.Serial, &r.Name, &purposes, &r.TSIP, &r.Status, &r.IssuedAt, &r.ExpiresAt, &r.Fingerprint); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		if purposes != "" {
			r.Purposes = strings.Split(purposes, ",")
		}
		next[r.Serial] = r
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("load: %w", err)
	}
	return next, nil
}

// Reload 从 SQLite 全量重载内存表(管理进程变更后调用 /admin/reload)。
// 先构建新表再原子替换(失败保持旧表继续服务, 与"加载失败不切换"原则一致)。
// WAL 模式下读取最新已提交事务, 管理进程单写者不并发写。
func (s *Store) Reload() error {
	next, err := s.buildTable()
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.table = next
	s.mu.Unlock()
	return nil
}

// Get 内存查表 (请求验证路径, 零 IO)
func (s *Store) Get(serial string) (CertRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.table[serial]
	r.Purposes = append([]string(nil), r.Purposes...) // 深拷贝: 防调用方就地改写污染授权表
	return r, ok
}

// List 返回全部记录
func (s *Store) List() []CertRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]CertRecord, 0, len(s.table))
	for _, r := range s.table {
		r.Purposes = append([]string(nil), r.Purposes...) // 深拷贝: 防调用方就地改写污染授权表
		out = append(out, r)
	}
	return out
}

// InsertUniqueName 按名称唯一插入: 已有同名(含吊销)则失败 — 原子防并发同名签发 TOCTOU
func (s *Store) InsertUniqueName(r CertRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.table {
		if e.Name == r.Name {
			return fmt.Errorf("name %s already exists", r.Name)
		}
	}
	return s.upsertLocked(r)
}

// Upsert 新增或更新记录: 内存 + SQLite 同步
func (s *Store) Upsert(r CertRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.upsertLocked(r)
}

// upsertLocked 持锁前提的落库实现
func (s *Store) upsertLocked(r CertRecord) error {
	r.Purposes = append([]string(nil), r.Purposes...) // 深拷贝入表: 防调用方切片复用污染授权表
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
		r.Serial, r.Name, r.purposesStr(), r.TSIP, r.Status, r.IssuedAt, r.ExpiresAt, r.Fingerprint)
	if err != nil {
		return fmt.Errorf("upsert: %w", err)
	}
	s.table[r.Serial] = r
	return nil
}

// FindByName 按名称查所有记录(含吊销的; 禁止同名签发用)
func (s *Store) FindByName(name string) []CertRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []CertRecord
	for _, r := range s.table {
		if r.Name == name {
			r.Purposes = append([]string(nil), r.Purposes...) // 深拷贝: 防调用方就地改写污染授权表
			out = append(out, r)
		}
	}
	return out
}

// Delete 删除记录(签发 finalize 失败回滚用: 防幽灵记录/名字占坑)
// 顺序: SQL 先成功、再删内存(与 Revoke/Upsert 一致, 防 DB 失败时内存/DB 分叉)
func (s *Store) Delete(serial string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.sqlite.Exec(`DELETE FROM certs WHERE serial=?`, serial); err != nil {
		return fmt.Errorf("delete cert %s: %w", serial, err)
	}
	delete(s.table, serial)
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
