package main

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// 第十八批: main.go statusWriter.Hijack 记 101(与 eventlog 侧对齐)
func TestStatusWriterHijack101(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: &hijackRec{rec}}
	if _, _, err := sw.Hijack(); err != nil {
		t.Fatalf("hijack: %v", err)
	}
	if sw.status != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", sw.status)
	}
}

type hijackRec struct{ *httptest.ResponseRecorder }

func (h *hijackRec) Hijack() (net.Conn, *bufio.ReadWriter, error) { return nil, nil, nil }
