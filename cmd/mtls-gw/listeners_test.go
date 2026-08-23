package main

import (
	"net"
	"net/http"
	"testing"
	"time"
)

// O-1(pro 前瞻审计): 端口集合 diff 纯函数
func TestDiffPorts(t *testing.T) {
	cases := []struct {
		old, new        []string
		wantAdd, wantRm []string
	}{
		{[]string{"9601"}, []string{"9601"}, nil, nil},
		{[]string{"9601"}, []string{"9601", "9602"}, []string{"9602"}, nil},
		{[]string{"9601", "9602"}, []string{"9602"}, nil, []string{"9601"}},
		{[]string{"9601", "9602"}, []string{"9602", "9603"}, []string{"9603"}, []string{"9601"}},
		{nil, []string{"9601"}, []string{"9601"}, nil},
		{[]string{"9601"}, nil, nil, []string{"9601"}},
	}
	for _, c := range cases {
		add, rm := diffPorts(c.old, c.new)
		if len(add) != len(c.wantAdd) || len(rm) != len(c.wantRm) {
			t.Fatalf("diffPorts(%v,%v) = +%v -%v, want +%v -%v", c.old, c.new, add, rm, c.wantAdd, c.wantRm)
		}
		for i := range c.wantAdd {
			if add[i] != c.wantAdd[i] {
				t.Fatalf("diffPorts(%v,%v) added[%d]=%s, want %s", c.old, c.new, i, add[i], c.wantAdd[i])
			}
		}
		for i := range c.wantRm {
			if rm[i] != c.wantRm[i] {
				t.Fatalf("diffPorts(%v,%v) removed[%d]=%s, want %s", c.old, c.new, i, rm[i], c.wantRm[i])
			}
		}
	}
}

// O-1: 监听注册表动态增删 — 新增即监听可达, 删除即断连
func TestListenerRegistryDynamic(t *testing.T) {
	reg := newListenerRegistry()
	port := "58600"
	addr := "127.0.0.1:" + port

	// 新增: 起监听 → 端口可达
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	if err := reg.addGatewayPort("127.0.0.1", port, h, nil); err != nil {
		t.Fatalf("addGatewayPort: %v", err)
	}
	defer reg.remove("gw:" + port)
	ports := reg.gatewayPorts()
	if len(ports) != 1 || ports[0] != port {
		t.Fatalf("gatewayPorts = %v, want [%s]", ports, port)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("监听端口 %s 应可达(新增后动态生效), last err: %v", addr, err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// 删除: 端口关闭
	reg.remove("gw:" + port)
	if got := reg.gatewayPorts(); len(got) != 0 {
		t.Fatalf("删除后 gatewayPorts = %v, want 空", got)
	}
	// 关闭是异步的, 重试确认最终拒绝
	deadline = time.Now().Add(2 * time.Second)
	rejected := false
	for !rejected && time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err != nil {
			rejected = true
		} else {
			conn.Close()
			time.Sleep(50 * time.Millisecond)
		}
	}
	if !rejected {
		t.Fatalf("删除后端口 %s 应拒绝连接", addr)
	}
}
