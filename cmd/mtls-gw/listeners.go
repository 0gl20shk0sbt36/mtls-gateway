// listeners.go: 网关监听注册表 — 启动注册, reload 动态增删业务端口(O-1),
// 优雅退出全关。业务端口(gateway)随 mappings 集合热 diff; info/reload 端点是
// 固定结构端点(由 info_listen/reload_listen 决定), 不在动态管理范围。
package main

import (
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"mtls-gateway/internal/httpshared"
)

// gwListener 一个已注册的 mTLS http.Server。
type gwListener struct {
	key  string // "gw:<port>"(业务) | "info" | "reload" | "merged"
	srv  *http.Server
	name string
}

// listenerRegistry 监听注册表(线程安全)。
type listenerRegistry struct {
	mu        sync.Mutex
	listeners map[string]*gwListener
}

func newListenerRegistry() *listenerRegistry {
	return &listenerRegistry{listeners: map[string]*gwListener{}}
}

// add 注册并异步 Serve(监听已由调用方建立)。Serve 退出仅接受 ErrServerClosed,
// 其余错误记日志(端口被占用等启动期已在 listen 层 Fatal, 此处多为运行期异常)。
func (reg *listenerRegistry) add(key string, ln net.Listener, h http.Handler, name, detail string, tlsCfg *tls.Config) {
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// WriteTimeout=0: 流式响应(SSE/LLM token 流)可能持续数分钟, 60s 会在生成中途
		// 强制切断(表现: 消息超时一次, 重发命中缓存即好); 单用户内网挂连接风险可接受,
		// 反代侧 ResponseHeaderTimeout 仍保护响应头
		WriteTimeout: httpshared.WriteTimeout,
		IdleTimeout:  httpshared.IdleTimeout,
	}
	reg.mu.Lock()
	reg.listeners[key] = &gwListener{key: key, srv: srv, name: name}
	reg.mu.Unlock()
	log.Printf("mtls %s listening on %s (%s)", name, ln.Addr(), detail)
	go func() {
		if err := srv.Serve(tlsListener(ln, tlsCfg)); err != nil && err != http.ErrServerClosed {
			log.Printf("%s serve: %v", name, err)
		}
	}()
}

// remove 关闭一个监听(业务端口删除 = 直接断连, 长连接一并断开)。
func (reg *listenerRegistry) remove(key string) {
	reg.mu.Lock()
	l, ok := reg.listeners[key]
	if ok {
		delete(reg.listeners, key)
	}
	reg.mu.Unlock()
	if ok {
		log.Printf("mtls %s closed (port removed by reload)", l.name)
		l.srv.Close()
	}
}

// gatewayPorts 当前注册的业务端口(key "gw:" 前缀, 排序稳定)。
func (reg *listenerRegistry) gatewayPorts() []string {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	var out []string
	for k := range reg.listeners {
		if len(k) > 3 && k[:3] == "gw:" {
			out = append(out, k[3:])
		}
	}
	sort.Strings(out)
	return out
}

// addGatewayPort 为业务端口起 mTLS 监听并注册(reload 新增端口用)。
func (reg *listenerRegistry) addGatewayPort(bindHost, port string, h http.Handler, tlsCfg *tls.Config) error {
	addr := net.JoinHostPort(bindHost, port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	reg.add("gw:"+port, ln, h, "gateway", "mTLS", tlsCfg)
	return nil
}

// all 全部 server(优雅退出用)。
func (reg *listenerRegistry) all() []*http.Server {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	out := make([]*http.Server, 0, len(reg.listeners))
	for _, l := range reg.listeners {
		out = append(out, l.srv)
	}
	return out
}

// diffPorts 计算端口集合差(O-1): 返回 [新增, 删除]。纯函数, 可单测。
func diffPorts(oldPorts, newPorts []string) (added, removed []string) {
	oldSet := map[string]bool{}
	for _, p := range oldPorts {
		oldSet[p] = true
	}
	newSet := map[string]bool{}
	for _, p := range newPorts {
		newSet[p] = true
	}
	for p := range newSet {
		if !oldSet[p] {
			added = append(added, p)
		}
	}
	for p := range oldSet {
		if !newSet[p] {
			removed = append(removed, p)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}
