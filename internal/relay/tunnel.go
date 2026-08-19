package relay

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
)

// tunnelMetrics 单隧道运行指标
type tunnelMetrics struct {
	activeConns int64
	bytesIn     int64 // 本地→上游
	bytesOut    int64 // 上游→本地
	connsTotal  int64
	lastErr     atomic.Value // string
}

// tunnelRuntime 一条隧道的运行期状态
type tunnelRuntime struct {
	r        *Relay
	tunnel   Tunnel
	listener net.Listener
	srv      *http.Server // 本地路径模式时的 HTTP 服务
	ctx      context.Context
	cancel   context.CancelFunc
	metrics  tunnelMetrics
	mu       sync.Mutex
	conns    map[net.Conn]struct{}
}

// startTunnel 启动本地监听:
//   - 本地路由带路径 → HTTP 反代模式(剥本地前缀, 补通道前缀, mTLS 转发服务端通道)
//   - 无路径 → TCP 透传模式(管道到服务端通道端口)
func (r *Relay) startTunnel(t Tunnel) (*tunnelRuntime, error) {
	host := r.cfgListenHost()
	addr := net.JoinHostPort(host, t.LocalPort())
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(r.runCtx)
	rt := &tunnelRuntime{
		r:        r,
		tunnel:   t,
		listener: ln,
		ctx:      ctx,
		cancel:   cancel,
		conns:    make(map[net.Conn]struct{}),
	}
	if p := t.LocalPath(); p != "" {
		rt.srv = &http.Server{Handler: rt.localHTTPHandler(p)}
		go func() {
			if err := rt.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
				log.Printf("tunnel[%s] http serve: %v", t.ID(), err)
			}
		}()
	} else {
		go rt.acceptLoop()
	}
	return rt, nil
}

// localHTTPHandler 本地路径模式: 剥本地前缀 → 补通道前缀 → mTLS 转发服务端通道
func (rt *tunnelRuntime) localHTTPHandler(localPath string) http.Handler {
	upstream, err := url.Parse("https://" + net.JoinHostPort(rt.r.serverHost(), rt.tunnel.ChannelPort()) + rt.tunnel.ChannelPath())
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "bad upstream: "+err.Error(), http.StatusInternalServerError)
		})
	}
	tlsCfg, err := rt.r.dialTLSConfig(rt.tunnel.CertID)
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "load cert: "+err.Error(), http.StatusInternalServerError)
		})
	}
	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			rest := strings.TrimPrefix(req.URL.Path, localPath)
			if rest == "" {
				rest = "/"
			}
			req.URL.Scheme = upstream.Scheme
			req.URL.Host = upstream.Host
			req.URL.Path = joinSlash(upstream.Path, rest) // 补通道前缀(如 /admin + /x)
			req.URL.RawPath = ""
			req.Host = upstream.Host
		},
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !strings.HasPrefix(req.URL.Path, localPath) {
			http.Error(w, "local path prefix mismatch: "+req.URL.Path, http.StatusNotFound)
			return
		}
		rp.ServeHTTP(w, req)
	})
}

// joinSlash 拼接路径并去重斜杠 (nginx proxy_pass 语义)
func joinSlash(a, b string) string {
	switch {
	case a == "" || a == "/":
		return "/" + strings.TrimPrefix(b, "/")
	case b == "" || b == "/":
		return strings.TrimSuffix(a, "/") + "/"
	default:
		return strings.TrimSuffix(a, "/") + "/" + strings.TrimPrefix(b, "/")
	}
}

// acceptLoop accepts local connections and proxies each to the mTLS upstream.
func (rt *tunnelRuntime) acceptLoop() {
	defer rt.listener.Close()
	for {
		conn, err := rt.listener.Accept()
		if err != nil {
			select {
			case <-rt.ctx.Done():
				return // 关闭
			default:
				log.Printf("tunnel[%s] accept: %v", rt.tunnel.ID(), err)
				continue
			}
		}
		atomic.AddInt64(&rt.metrics.activeConns, 1)
		atomic.AddInt64(&rt.metrics.connsTotal, 1)
		rt.mu.Lock()
		rt.conns[conn] = struct{}{}
		rt.mu.Unlock()
		go rt.handleConn(conn)
	}
}

// handleConn proxies a single accepted local connection to the upstream.
func (rt *tunnelRuntime) handleConn(local net.Conn) {
	defer func() {
		local.Close()
		rt.mu.Lock()
		delete(rt.conns, local)
		rt.mu.Unlock()
		atomic.AddInt64(&rt.metrics.activeConns, -1)
	}()

	upstream, err := rt.r.relayDial(rt.ctx, rt.tunnel)
	if err != nil {
		rt.metrics.lastErr.Store(err.Error())
		log.Printf("tunnel[%s] dial upstream: %v", rt.tunnel.ID(), err)
		return
	}
	defer upstream.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, _ := io.Copy(upstream, local)
		atomic.AddInt64(&rt.metrics.bytesIn, n)
	}()
	go func() {
		defer wg.Done()
		n, _ := io.Copy(local, upstream)
		atomic.AddInt64(&rt.metrics.bytesOut, n)
	}()
	wg.Wait()
}

// stop closes the listener and all active connections for this tunnel.
func (rt *tunnelRuntime) stop() {
	rt.cancel()
	rt.listener.Close()
	if rt.srv != nil {
		rt.srv.Close()
	}
	rt.mu.Lock()
	for c := range rt.conns {
		c.Close()
	}
	rt.mu.Unlock()
}

// snapshot returns a status snapshot for this tunnel.
func (rt *tunnelRuntime) snapshot() TunnelStatus {
	s := TunnelStatus{
		ID:          rt.tunnel.ID(),
		Service:     rt.tunnel.Service,
		Channel:     rt.tunnel.Channel,
		Local:       rt.tunnel.Local,
		CertID:      rt.tunnel.CertID,
		Running:     true,
		ActiveConns: atomic.LoadInt64(&rt.metrics.activeConns),
		ConnsTotal:  atomic.LoadInt64(&rt.metrics.connsTotal),
		BytesIn:     atomic.LoadInt64(&rt.metrics.bytesIn),
		BytesOut:    atomic.LoadInt64(&rt.metrics.bytesOut),
	}
	if e, ok := rt.metrics.lastErr.Load().(string); ok {
		s.LastError = e
	}
	return s
}

// dialTLSConfig 构造带客户端证书的 TLS 配置(本地 HTTP 反代用)
func (r *Relay) dialTLSConfig(certID string) (*tls.Config, error) {
	cert, err := r.loadCert(certID)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      r.rootCAs,
		ServerName:   r.serverHost(),
	}, nil
}
