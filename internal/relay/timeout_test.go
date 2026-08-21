package relay

import (
	"testing"
	"time"
)

// TestLocalHTTPIdleTimeout 防回归: 本地 HTTP 反代浏览器侧 keep-alive 空闲上限须与服务端对齐(>= 300s)。
// 过短(原 60s)会让浏览器复用已被关闭的死连接, 表现为隔一段时间后的第一次请求超时
// (与 2026-08-21 DSH 首次发送超时排查同源)。
func TestLocalHTTPIdleTimeout(t *testing.T) {
	if localHTTPIdleTimeout < 300*time.Second {
		t.Fatalf("localHTTPIdleTimeout = %v, want >= 300s", localHTTPIdleTimeout)
	}
}

// TestDefaultTCPIdle 防回归: TCP 透传的空闲超时默认值必须足够大(>= 1h),
// 否则空闲的 WebSocket 长连接(LLM 对话事件流, 无心跳帧)会被过早切断,
// 前端重连窗口内第一次发消息超时(2026-08-21 DSH 首次发送超时根因)。
// idle 杀机制本身由 tunnel_extra_test 注入短值覆盖, 此处只锁默认值。
func TestDefaultTCPIdle(t *testing.T) {
	if defaultTCPIdle < time.Hour {
		t.Fatalf("defaultTCPIdle = %v, want >= 1h — 过短会切断空闲 WS 长连接", defaultTCPIdle)
	}
}
