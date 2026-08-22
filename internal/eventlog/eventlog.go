// Package eventlog 事件日志: 只记事件与元数据(证书身份/通道/方法/路径/字节数/状态码),
// 不记录具体传输的数据内容。按大小滚动落盘。
package eventlog

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Logger 事件日志(滚动 writer)
type Logger struct {
	mu       sync.Mutex
	path     string
	maxSize  int64 // 单文件上限(字节)
	maxFile  int   // 保留份数(不含当前)
	f        *os.File
	size     int64
	textMode bool // true=纯文本行(标准日志); false=JSON 事件行
}

// New 打开事件日志(JSON 行式); path 为空 → 返回 nil(禁用)
// maxSizeMB: 单文件上限 MB; maxFiles: 保留的历史份数
func New(path string, maxSizeMB, maxFiles int) (*Logger, error) {
	return open(path, maxSizeMB, maxFiles, false)
}

// NewText 打开纯文本日志(标准 log 输出落盘, 与 JSON 事件日志同滚动策略);
// path 为空 → 返回 nil(禁用)。
func NewText(path string, maxSizeMB, maxFiles int) (*Logger, error) {
	return open(path, maxSizeMB, maxFiles, true)
}

func open(path string, maxSizeMB, maxFiles int, textMode bool) (*Logger, error) {
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
	l := &Logger{path: path, maxSize: int64(maxSizeMB) << 20, maxFile: maxFiles, textMode: textMode}
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

// rotate 超过上限时滚动: 当前文件 → .1, 旧文件顺延, 删最老。
// 保留语义: maxFile 份历史 + 当前 = maxFile+1 份(与文档"保留 maxFile 份历史"一致)。
func (l *Logger) rotate() {
	l.f.Close()
	if l.maxFile > 0 {
		oldest := l.path + fmt.Sprintf(".%d", l.maxFile)
		if err := os.Remove(oldest); err != nil && !os.IsNotExist(err) {
			log.Printf("eventlog rotate remove %s: %v", oldest, err)
		}
	}
	for i := l.maxFile - 1; i >= 1; i-- {
		if err := os.Rename(l.path+fmt.Sprintf(".%d", i), l.path+fmt.Sprintf(".%d", i+1)); err != nil && !os.IsNotExist(err) {
			log.Printf("eventlog rotate rename %s: %v", l.path+fmt.Sprintf(".%d", i), err)
		}
	}
	if err := os.Rename(l.path, l.path+".1"); err != nil && !os.IsNotExist(err) {
		log.Printf("eventlog rotate rename %s: %v", l.path, err)
	}
	if err := l.open(); err != nil {
		// 滚动后重开失败: 置 nil 让 appendLine 下次写入重试(不再永久静默 — L3 债)
		log.Printf("eventlog rotate open %s: %v (日志暂停, 下次写入重试)", l.path, err)
		l.f = nil
	}
}

// Event 一条事件记录
type Event struct {
	Time       time.Time `json:"time"`
	Type       string    `json:"type"` // start|stop|tunnel_add|tunnel_del|config_change|cert_issue|cert_revoke|access|deny
	Cert       string    `json:"cert,omitempty"`
	Serial     string    `json:"serial,omitempty"`
	Role       string    `json:"role,omitempty"`
	Channel    string    `json:"channel,omitempty"`
	Method     string    `json:"method,omitempty"`
	Path       string    `json:"path,omitempty"`
	Status     int       `json:"status,omitempty"`
	BytesIn    int64     `json:"bytes_in,omitempty"`
	BytesOut   int64     `json:"bytes_out,omitempty"`
	Remote     string    `json:"remote,omitempty"`      // 来源 IP(安全取证: 谁从哪访问了什么)
	DurationMS int64     `json:"duration_ms,omitempty"` // 请求耗时(ms, 性能排查)
	Msg        string    `json:"msg,omitempty"`
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
	l.appendLine(append(b, '\n'))
}

// WriteString 写一行纯文本(标准日志输出; 自动补换行)
func (l *Logger) WriteString(s string) {
	if l == nil {
		return
	}
	if s == "" {
		return
	}
	if s[len(s)-1] != '\n' {
		s += "\n"
	}
	l.appendLine([]byte(s))
}

// textWriter 把 Logger 适配为 io.Writer(文本模式, 供 log.SetOutput 双写)。
// 不能直接实现 io.Writer: 与 Write(Event) 签名冲突。
type textWriter struct{ l *Logger }

func (w textWriter) Write(p []byte) (int, error) {
	w.l.WriteString(string(p))
	return len(p), nil
}

// TextWriter 返回把 Logger 当 io.Writer 的适配器(文本模式); l 为 nil 返回 nil。
func (l *Logger) TextWriter() io.Writer {
	if l == nil {
		return nil
	}
	return textWriter{l}
}

// appendLine 追加一行(文本或 JSON), 超限滚动
func (l *Logger) appendLine(b []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return
	}
	if l.size+int64(len(b)) > l.maxSize {
		l.rotate()
	}
	n, err := l.f.Write(b)
	if err != nil || n != len(b) {
		log.Printf("eventlog write: n=%d err=%v", n, err)
	}
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

// StatusWriter 包装 http.ResponseWriter: 记录状态码与响应字节数(访问/界面事件日志用)
type StatusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

// NewStatusWriter 包装一个 ResponseWriter
func NewStatusWriter(w http.ResponseWriter) *StatusWriter {
	return &StatusWriter{ResponseWriter: w}
}

// WriteHeader 记录状态码并转发(幂等: 只记首次)
func (w *StatusWriter) WriteHeader(c int) {
	if w.status != 0 {
		return
	}
	w.status = c
	w.ResponseWriter.WriteHeader(c)
}

// Write 记录响应字节数并转发
func (w *StatusWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return n, err
}

// Status 实际状态码(未写时 200)
func (w *StatusWriter) Status() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

// Bytes 响应字节数
func (w *StatusWriter) Bytes() int64 { return w.bytes }

// 透传底层能力: WebSocket 升级(101)与流式/大文件响应不被包装层破坏
func (w *StatusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying ResponseWriter is not a Hijacker")
	}
	if w.status == 0 {
		w.status = http.StatusSwitchingProtocols // 升级连接: 访问日志记 101
	}
	return hj.Hijack()
}

func (w *StatusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *StatusWriter) ReadFrom(r io.Reader) (int64, error) {
	if rf, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		n, err := rf.ReadFrom(r)
		w.bytes += n // 透传分支也要计字节
		if w.status == 0 {
			w.status = http.StatusOK
		}
		return n, err
	}
	// 回退: 经自身 Write 计数(不直接写底层)
	return io.Copy(struct{ io.Writer }{w}, r)
}
