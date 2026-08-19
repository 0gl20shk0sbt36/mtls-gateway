package relay

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mtls-gateway/internal/pathutil"
)

// tunnelMetrics 单路由运行指标
type tunnelMetrics struct {
	activeConns int64
	bytesIn     int64 // 本地→上游
	bytesOut    int64 // 上游→本地
	connsTotal  int64
	lastErr     atomic.Value // string
}

// tunnelRuntime 一条展开路由(服务的一通道)的运行期状态
type tunnelRuntime struct {
	r           *Relay
	key         string // service@channel@local
	service     string
	idle        time.Duration // TCP 透传空闲超时
	route       TunnelRoute
	certID      string
	listener    net.Listener
	srv         *http.Server                   // 本地路径模式时的 HTTP 服务
	rpTransport atomic.Pointer[http.Transport] // 本地路径模式的反代 Transport(stop 时释放)
	ctx         context.Context
	cancel      context.CancelFunc
	metrics     tunnelMetrics
	mu          sync.Mutex
	conns       map[net.Conn]struct{}
}

// routeSpec 服务级隧道展开出的路由规格(轻量, 无锁)
type routeSpec struct {
	key     string // service@channel@local
	service string
	route   TunnelRoute
	certID  string
}

// tunnelRoutes 把服务级隧道展开为路由级规格
func tunnelRoutes(t Tunnel) []routeSpec {
	var out []routeSpec
	for _, rt := range t.Routes {
		out = append(out, routeSpec{
			key:     t.Service + "@" + rt.Channel + "@" + rt.Local,
			service: t.Service,
			route:   rt,
			certID:  t.CertID,
		})
	}
	return out
}

// startTunnel 启动一条展开路由:
//   - 本地路由带路径 → HTTP 反代模式(剥本地前缀, 补通道前缀, mTLS 转发服务端通道)
//   - 无路径 → TCP 透传模式(管道到服务端通道端口)
func (r *Relay) startTunnel(rt *tunnelRuntime) error {
	host := r.cfgListenHost()
	addr := net.JoinHostPort(host, rt.route.LocalPort())
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(r.runCtx)
	rt.listener = ln
	rt.ctx = ctx
	rt.cancel = cancel
	rt.conns = make(map[net.Conn]struct{})
	if p := rt.route.LocalPath(); p != "" {
		rt.srv = &http.Server{
			Handler:           rt.localHTTPHandler(p),
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		go func() {
			if err := rt.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
				log.Printf("tunnel[%s] http serve: %v", rt.key, err)
			}
		}()
	} else {
		go rt.acceptLoop()
	}
	return nil
}

// localHTTPHandler 本地路径模式: 剥本地前缀 → 补通道前缀 → mTLS 转发服务端通道
// upstream/tlsCfg/rp 惰性初始化(startTunnel 在 Start 持锁期间构造 handler,
// 此处同步调 serverHost()/dialTLSConfig() 会与 r.mu 重入死锁)。
// 初始化失败(证书瞬断/上游未就绪)不永久缓存 — 下次请求重试, 避免 sync.Once 毒化;
// serverAddr 或证书轮换后(≥1min)自动重建, 使 Reload 与证书续期对 HTTP 隧道生效
func (rt *tunnelRuntime) localHTTPHandler(localPath string) http.Handler {
	var (
		mu        sync.RWMutex
		rp        *httputil.ReverseProxy
		builtHost string
		builtAt   time.Time
	)
	init := func() {
		mu.Lock()
		defer mu.Unlock()
		host := rt.r.serverHost()
		// 重建条件: 未构建 / serverAddr 变化 / 超过证书轮换窗口(60s)
		if rp != nil && builtHost == host && time.Since(builtAt) < certCacheTTL {
			return
		}
		up, err := url.Parse("https://" + net.JoinHostPort(host, rt.route.ChannelPort()) + rt.route.ChannelPath())
		if err != nil {
			return // 下次请求重试
		}
		tc, err := rt.r.dialTLSConfig(rt.certID)
		if err != nil {
			return // 证书/网络瞬断: 不缓存错误, 下次重试
		}
		// 旧 rp 释放空闲连接(防重建累积)
		if rp != nil {
			if tr, ok := rp.Transport.(*http.Transport); ok {
				tr.CloseIdleConnections()
			}
		}
		// Director/Transport 捕获本地快照(up/tc 不可变), 避免共享变量被重建改写的错配
		upCopy, tcCopy := up, tc
		tr := &http.Transport{
			TLSClientConfig:       tcCopy,
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ResponseHeaderTimeout: 30 * time.Second,
			IdleConnTimeout:       90 * time.Second,
		}
		rt.rpTransport.Store(tr) // stop 时释放(stop 与 init 并发安全)
		rp = &httputil.ReverseProxy{
			Director: func(req *http.Request) {
				rest := strings.TrimPrefix(req.URL.Path, localPath)
				if rest == "" {
					rest = "/"
				}
				req.URL.Scheme = upCopy.Scheme
				req.URL.Host = upCopy.Host
				req.URL.Path = joinSlash(upCopy.Path, rest) // 补通道前缀(如 /admin + /x)
				req.URL.RawPath = ""
				req.Host = upCopy.Host
			},
			Transport: tr,
		}
		builtHost = host
		builtAt = time.Now()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// 匹配前规范化(dot-segment): 防 /admin/../x 逃逸; 前缀边界: /foo 不匹配 /foobar
		req.URL.Path = pathutil.CleanDotSegments(req.URL.Path)
		p := req.URL.Path
		if !(p == localPath || strings.HasPrefix(p, localPath+"/")) {
			http.Error(w, "local path prefix mismatch: "+p, http.StatusNotFound)
			return
		}
		// double-checked locking: 快路径只读锁判断是否需重建(serverAddr 变化/证书轮换窗口)
		mu.RLock()
		need := rp == nil || builtHost != rt.r.serverHost() || time.Since(builtAt) >= certCacheTTL
		r := rp
		mu.RUnlock()
		if need {
			init() // 重建(写锁内)
			mu.RLock()
			r = rp
			mu.RUnlock()
		}
		if r == nil {
			http.Error(w, "upstream not ready (retry later)", http.StatusBadGateway)
			return
		}
		r.ServeHTTP(w, req)
	})
}

// joinSlash 拼接路径并去重斜杠 (nginx proxy_pass 语义)
func joinSlash(a, b string) string {
	var joined string
	switch {
	case a == "" || a == "/":
		joined = "/" + strings.TrimPrefix(b, "/")
	case b == "" || b == "/":
		joined = strings.TrimSuffix(a, "/") + "/"
	default:
		joined = strings.TrimSuffix(a, "/") + "/" + strings.TrimPrefix(b, "/")
	}
	// 仅移除 .. 段(不折叠 //、不丢尾斜杠 — 两者都有语义), 防路径逃逸
	return pathutil.CleanDotSegments(joined)
}

// acceptLoop accepts local connections and proxies each to the mTLS upstream.
func (rt *tunnelRuntime) acceptLoop() {
	defer rt.listener.Close()
	var backoff time.Duration
	for {
		conn, err := rt.listener.Accept()
		if err != nil {
			select {
			case <-rt.ctx.Done():
				return // 关闭
			default:
				// 临时错误(EMFILE 等): 指数退避, 防 100% CPU 自旋 + 刷屏
				if backoff == 0 {
					backoff = 10 * time.Millisecond
				} else if backoff < time.Second {
					backoff *= 2
				}
				log.Printf("tunnel[%s] accept: %v (retry in %v)", rt.key, err, backoff)
				select {
				case <-time.After(backoff):
				case <-rt.ctx.Done():
					return
				}
				continue
			}
		}
		backoff = 0
		atomic.AddInt64(&rt.metrics.activeConns, 1)
		atomic.AddInt64(&rt.metrics.connsTotal, 1)
		rt.mu.Lock()
		rt.conns[conn] = struct{}{}
		rt.mu.Unlock()
		go rt.handleConn(conn)
	}
}

// handleConn proxies a single accepted local connection to the upstream.
// TCP 透传: 空闲超时(防连接/goroutine 永久占用) + 半关闭传播(客户端 EOF 传导上游)
func (rt *tunnelRuntime) handleConn(local net.Conn) {
	defer func() {
		local.Close()
		rt.mu.Lock()
		delete(rt.conns, local)
		rt.mu.Unlock()
		atomic.AddInt64(&rt.metrics.activeConns, -1)
	}()

	upstream, err := rt.r.relayDial(rt.ctx, rt.key, rt.certID, rt.route)
	if err != nil {
		rt.metrics.lastErr.Store(err.Error())
		log.Printf("tunnel[%s] dial upstream: %v", rt.key, err)
		return
	}
	defer upstream.Close()

	// 空闲超时: rt.idle 无数据传输则关闭(按需建连; 活跃连接不受限; idle<=0 = 不监控)
	idle := rt.idle
	var lastActive atomic.Int64
	lastActive.Store(time.Now().UnixNano())
	touch := func() { lastActive.Store(time.Now().UnixNano()) }
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := local.Read(buf)
			if n > 0 {
				if _, werr := upstream.Write(buf[:n]); werr != nil {
					return
				}
				atomic.AddInt64(&rt.metrics.bytesIn, int64(n))
				touch()
			}
			if err != nil {
				// 本地 EOF: 半关闭传播到上游(tls.Conn/TCPConn 均支持), 让对端读到 EOF
				if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
					cw.CloseWrite()
				}
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := upstream.Read(buf)
			if n > 0 {
				if _, werr := local.Write(buf[:n]); werr != nil {
					return
				}
				atomic.AddInt64(&rt.metrics.bytesOut, int64(n))
				touch()
			}
			if err != nil {
				return
			}
		}
	}()
	// 空闲超时监控: 超过 idle 无数据流动才关闭; 有流动则继续; idle<=0 跳过
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	if idle <= 0 {
		<-done
		return
	}
	for {
		select {
		case <-done:
			return
		case <-time.After(idle):
			if time.Since(time.Unix(0, lastActive.Load())) >= idle {
				local.Close()
				upstream.Close()
				<-done
				return
			}
		}
	}
}

// stop closes the listener and all active connections for this tunnel.
func (rt *tunnelRuntime) stop() {
	if tr := rt.rpTransport.Load(); tr != nil {
		tr.CloseIdleConnections() // 反代空闲连接释放
	}
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
		ID:          rt.key,
		Service:     rt.service,
		Channel:     rt.route.Channel,
		Local:       rt.route.Local,
		CertID:      rt.certID,
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
		RootCAs:      r.rootCAsCopy(),
		ServerName:   r.serverHost(),
		MinVersion:   tls.VersionTLS12, // 纵深防御: 与服务端强制下限一致
	}, nil
}
