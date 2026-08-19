// Package eventlog 事件日志: 只记事件与元数据(证书身份/通道/方法/路径/字节数/状态码),
// 不记录具体传输的数据内容。按大小滚动落盘。
package eventlog

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Logger 事件日志(滚动 writer)
type Logger struct {
	mu      sync.Mutex
	path    string
	maxSize int64 // 单文件上限(字节)
	maxFile int   // 保留份数(不含当前)
	f       *os.File
	size    int64
}

// New 打开事件日志; path 为空 → 返回 nil(禁用)
// maxSizeMB: 单文件上限 MB; maxFiles: 保留的历史份数
func New(path string, maxSizeMB, maxFiles int) (*Logger, error) {
	if path == "" {
		return nil, nil
	}
	if maxSizeMB <= 0 {
		maxSizeMB = 10
	}
	if maxFiles < 0 {
		maxFiles = 5
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("eventlog mkdir: %w", err)
		}
	}
	l := &Logger{path: path, maxSize: int64(maxSizeMB) << 20, maxFile: maxFiles}
	if err := l.open(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *Logger) open() error {
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	st, _ := f.Stat()
	if st != nil {
		l.size = st.Size()
	}
	l.f = f
	return nil
}

// rotate 超过上限时滚动: 当前文件 → .1, 旧文件顺延, 删最老
func (l *Logger) rotate() {
	l.f.Close()
	// 删除最老
	if l.maxFile > 0 {
		oldest := l.path + fmt.Sprintf(".%d", l.maxFile)
		os.Remove(oldest)
	}
	// 顺延
	for i := l.maxFile - 1; i >= 1; i-- {
		os.Rename(l.path+fmt.Sprintf(".%d", i), l.path+fmt.Sprintf(".%d", i+1))
	}
	os.Rename(l.path, l.path+".1")
	l.open()
}

// Event 一条事件记录
type Event struct {
	Time    time.Time `json:"time"`
	Type    string    `json:"type"` // start|stop|tunnel_add|tunnel_del|config_change|cert_issue|cert_revoke|access|deny
	Cert    string    `json:"cert,omitempty"`
	Serial  string    `json:"serial,omitempty"`
	Role    string    `json:"role,omitempty"`
	Channel string    `json:"channel,omitempty"`
	Method  string    `json:"method,omitempty"`
	Path    string    `json:"path,omitempty"`
	Status  int       `json:"status,omitempty"`
	BytesIn int64     `json:"bytes_in,omitempty"`
	BytesOut int64    `json:"bytes_out,omitempty"`
	Msg     string    `json:"msg,omitempty"`
}

// Write 写一条事件(JSON 行)
func (l *Logger) Write(ev Event) {
	if l == nil {
		return
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	b = append(b, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return
	}
	if l.size+int64(len(b)) > l.maxSize {
		l.rotate()
	}
	n, _ := l.f.Write(b)
	l.size += int64(n)
}

// Close 关闭日志
func (l *Logger) Close() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil {
		l.f.Close()
		l.f = nil
	}
}

// Files 当前日志文件列表(当前 + 历史)
func (l *Logger) Files() []string {
	if l == nil {
		return nil
	}
	dir := filepath.Dir(l.path)
	base := filepath.Base(l.path)
	entries, _ := os.ReadDir(dir)
	var out []string
	for _, e := range entries {
		name := e.Name()
		if name == base || (strings.HasPrefix(name, base+".") && !e.IsDir()) {
			out = append(out, filepath.Join(dir, name))
		}
	}
	sort.Strings(out)
	return out
}
