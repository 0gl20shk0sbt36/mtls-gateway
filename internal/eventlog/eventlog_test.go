package eventlog

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteAndRotate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evt.log")
	// maxSize 1MB 但每次写 700KB → 两行即滚动
	l, err := New(path, 1, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	big := strings.Repeat("x", 700*1024)
	for i := 0; i < 3; i++ {
		l.Write(Event{Type: "access", Cert: "c1", Msg: big})
	}
	// 当前文件 + 至少 1 份历史
	files := l.Files()
	if len(files) < 2 {
		t.Fatalf("want rotated files, got %d (%v)", len(files), files)
	}
	// 每份文件都 < 1MB+margin
	for _, f := range files {
		st, _ := os.Stat(f)
		if st != nil && st.Size() > 1100*1024 {
			t.Fatalf("file %s too big: %d", f, st.Size())
		}
	}
}

func TestDisabled(t *testing.T) {
	l, err := New("", 10, 5)
	if err != nil || l != nil {
		t.Fatalf("empty path should disable: %v %v", l, err)
	}
}

func TestJSONShape(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evt.log")
	l, _ := New(path, 10, 3)
	defer l.Close()
	l.Write(Event{Type: "access", Cert: "e2e-a", Serial: "12058", Channel: ":29991", Method: "GET", Path: "/api/x", Status: 200, BytesIn: 42})
	data, _ := os.ReadFile(path)
	s := string(data)
	for _, want := range []string{`"type":"access"`, `"cert":"e2e-a"`, `"serial":"12058"`, `"channel":":29991"`, `"method":"GET"`, `"path":"/api/x"`, `"status":200`, `"bytes_in":42`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s in %s", want, s)
		}
	}
}

// L3: maxFiles 保留策略 — 超过后最旧被修剪
func TestRotatePrunesOldFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evt2.log")
	l, err := New(path, 1, 2) // 只留 2 份历史
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	big := strings.Repeat("y", 700*1024)
	for i := 0; i < 6; i++ {
		l.Write(Event{Type: "access", Cert: "c1", Msg: big})
	}
	files := l.Files()
	if len(files) > 3 { // 当前 + 2 份历史
		t.Fatalf("maxFiles=2 should keep <=3 files, got %d: %v", len(files), files)
	}
}

// 第十二批: StatusWriter 计数与透传(ReadFrom 计字节 / Hijack 安全断言)
func TestStatusWriterReadFromCounts(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := NewStatusWriter(rec)
	// httptest.ResponseRecorder 实现 ReaderFrom → 透传分支, bytes 应累加
	n, err := sw.ReadFrom(strings.NewReader("hello"))
	if err != nil || n != 5 {
		t.Fatalf("ReadFrom: n=%d err=%v", n, err)
	}
	if sw.Bytes() != 5 {
		t.Fatalf("bytes = %d, want 5", sw.Bytes())
	}
	if sw.Status() != 200 {
		t.Fatalf("status = %d, want 200", sw.Status())
	}
}

func TestStatusWriterHijackSafe(t *testing.T) {
	sw := NewStatusWriter(httptest.NewRecorder()) // 非 Hijacker
	if _, _, err := sw.Hijack(); err == nil {
		t.Fatal("Hijack on non-hijacker should error, not panic")
	}
}

// 第十三批: ReadFrom 回退分支(底层非 ReaderFrom → 经 Write 计字节)
func TestStatusWriterReadFromFallback(t *testing.T) {
	sw := NewStatusWriter(&noReaderFromWriter{})
	n, err := sw.ReadFrom(strings.NewReader("fallback-data"))
	if err != nil || n != 13 {
		t.Fatalf("fallback ReadFrom: n=%d err=%v", n, err)
	}
	if sw.Bytes() != 13 {
		t.Fatalf("bytes = %d, want 13", sw.Bytes())
	}
	if sw.Status() != 200 {
		t.Fatalf("status = %d, want 200", sw.Status())
	}
}

// noReaderFromWriter 仅实现 ResponseWriter(不含 ReaderFrom), 强制走回退分支
type noReaderFromWriter struct{ buf []byte }

func (w *noReaderFromWriter) Header() http.Header { return http.Header{} }
func (w *noReaderFromWriter) WriteHeader(int)     {}
func (w *noReaderFromWriter) Write(b []byte) (int, error) {
	w.buf = append(w.buf, b...)
	return len(b), nil
}

// 第十四批: WriteHeader 幂等(双写只记首次)
func TestStatusWriterWriteHeaderIdempotent(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := NewStatusWriter(rec)
	sw.WriteHeader(200)
	sw.WriteHeader(500) // 第二次忽略
	if sw.Status() != 200 {
		t.Fatalf("status = %d, want 200 (first wins)", sw.Status())
	}
	if rec.Code != 200 {
		t.Fatalf("recorder code = %d, want 200", rec.Code)
	}
}

// 第十七批: Hijack 成功路径记 101(真实 Hijacker)
type hijackerRecorder struct{ *httptest.ResponseRecorder }

func (h hijackerRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, nil // 模拟成功 hijack(只验证 status 记录)
}

func TestStatusWriterHijackRecords101(t *testing.T) {
	sw := NewStatusWriter(hijackerRecorder{httptest.NewRecorder()})
	if _, _, err := sw.Hijack(); err != nil {
		t.Fatalf("hijack: %v", err)
	}
	if sw.Status() != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", sw.Status())
	}
}

// 第二十九批: 文本模式(NewText/WriteString/TextWriter) — 标准日志落盘 + io.Writer 适配
func TestTextModeWriteAndWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stdout.log")
	l, err := NewText(path, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	l.WriteString("first line")
	l.WriteString("second line\n")
	// io.Writer 适配(双写场景: log.SetOutput(io.MultiWriter(os.Stderr, l.TextWriter())))
	if w := l.TextWriter(); w == nil {
		t.Fatal("TextWriter 不应为 nil")
	} else if n, err := w.Write([]byte("via writer\n")); err != nil || n != 11 {
		t.Fatalf("writer write: n=%d err=%v", n, err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	for _, want := range []string{"first line\n", "second line\n", "via writer\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("文本日志应含 %q: %q", want, got)
		}
	}
}

// 第二十九批: 文本模式滚动(超限 → .1)
func TestTextModeRotate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stdout.log")
	l, err := NewText(path, 1, 2) // 1MB 上限, 2 份历史
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	line := strings.Repeat("x", 512*1024) // 512KB
	l.WriteString(line)
	l.WriteString(line)
	l.WriteString(line)
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("超限应滚动出 .1: %v", err)
	}
}

// 第二十九批: 文本模式空路径 = 禁用(nil), WriteString 安全
func TestTextModeDisabled(t *testing.T) {
	l, err := NewText("", 1, 1)
	if err != nil || l != nil {
		t.Fatalf("空路径应返回 nil,nil: l=%v err=%v", l, err)
	}
	if l != nil {
		l.WriteString("x") // 不 panic
	}
	if w := (*Logger)(nil).TextWriter(); w != nil {
		t.Fatal("nil Logger 的 TextWriter 应为 nil")
	}
}
