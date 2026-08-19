package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/websocket"
)

// L4: WebSocket 升级透传(httputil.ReverseProxy 默认支持 101 升级)
func TestProxyWebSocket(t *testing.T) {
	// 后端 ws echo
	wsSrv := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		var msg string
		websocket.Message.Receive(ws, &msg)
		websocket.Message.Send(ws, "echo:"+msg)
	}))
	defer wsSrv.Close()
	u, _ := url.Parse(wsSrv.URL)
	rp := newReverseProxy(u)
	proxySrv := httptest.NewServer(rp)
	defer proxySrv.Close()

	wsURL := "ws" + strings.TrimPrefix(proxySrv.URL, "http")
	ws, err := websocket.Dial(wsURL+"/ws", "", "http://localhost/")
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	defer ws.Close()
	ws.SetDeadline(time.Now().Add(3 * time.Second))
	if err := websocket.Message.Send(ws, "ping"); err != nil {
		t.Fatalf("send: %v", err)
	}
	var reply string
	if err := websocket.Message.Receive(ws, &reply); err != nil {
		t.Fatalf("recv: %v", err)
	}
	if reply != "echo:ping" {
		t.Fatalf("ws echo mismatch: %q", reply)
	}
	_ = http.MethodGet
}
