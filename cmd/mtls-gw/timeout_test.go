package main

import (
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// TestWriteTimeoutCutsStreaming 复现 DSH 首次发送超时的根因机制:
// Go http.Server 的 WriteTimeout 是【绝对时限】(从头读完开始计时, 无论是否持续写, 到点强关连接)。
// 流式响应(SSE/LLM token 流)只要总时长超过 WriteTimeout 就被中途切断。
// 验证: WriteTimeout=300ms 时持续输出的 1s 响应被切; WriteTimeout=0(修复值)时完整送达。
func TestWriteTimeoutCutsStreaming(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fl, _ := w.(http.Flusher)
		for i := 0; i < 10; i++ {
			w.Write([]byte("x"))
			if fl != nil {
				fl.Flush()
			}
			time.Sleep(100 * time.Millisecond)
		}
	})

	// 绝对时限: 持续写也救不了, 300ms 到点被切
	srv := &http.Server{Handler: handler, WriteTimeout: 300 * time.Millisecond}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	defer srv.Close()
	resp, err := http.Get("http://" + ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if len(data) >= 10 {
		t.Fatalf("绝对 WriteTimeout 应切断流式响应, 却收到完整 %d 字节", len(data))
	}
	t.Logf("WriteTimeout=300ms: 响应被切, 收到 %d/%d 字节 (绝对时限根因复现)", len(data), 10)

	// 修复值 WriteTimeout=0: 完整送达
	srv2 := &http.Server{Handler: handler} // WriteTimeout 默认 0 = 不限制
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv2.Serve(ln2)
	defer srv2.Close()
	resp2, err := http.Get("http://" + ln2.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	data2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if len(data2) != 10 {
		t.Fatalf("WriteTimeout=0 应完整收到 10 字节, got %d", len(data2))
	}
}

// TestGatewayTimeoutConstants 防回归: 服务端转发超时参数必须保持
// WriteTimeout=0(不切长流式) + IdleTimeout>=300s(keep-alive 对齐浏览器)。
func TestGatewayTimeoutConstants(t *testing.T) {
	if gwWriteTimeout != 0 {
		t.Fatalf("gwWriteTimeout = %v, want 0 — 绝对时限会切断 LLM/SSE 长流式响应(DSH 首次发送超时根因)", gwWriteTimeout)
	}
	if gwIdleTimeout < 300*time.Second {
		t.Fatalf("gwIdleTimeout = %v, want >= 300s — 过短会让浏览器复用已被关闭的死连接", gwIdleTimeout)
	}
}
