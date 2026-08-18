package relay

import (
	"context"
	"io"
	"log"
	"net"
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
	ctx      context.Context
	cancel   context.CancelFunc
	metrics  tunnelMetrics
	mu       sync.Mutex
	conns    map[net.Conn]struct{}
}

// start starts the local listener for the tunnel and serves.
// Returns after listener is bound, or error.
func (r *Relay) startTunnel(t Tunnel) (*tunnelRuntime, error) {
	host := r.cfgListenHost()
	addr := net.JoinHostPort(host, itoa(t.LocalPort))
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
	go rt.acceptLoop()
	return rt, nil
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
				log.Printf("tunnel[%s] accept: %v", rt.tunnel.ID, err)
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
		log.Printf("tunnel[%s] dial upstream: %v", rt.tunnel.ID, err)
		return
	}
	defer upstream.Close()

	// 双向复制
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
	rt.mu.Lock()
	for c := range rt.conns {
		c.Close()
	}
	rt.mu.Unlock()
}

// snapshot returns a status snapshot for this tunnel.
func (rt *tunnelRuntime) snapshot() TunnelStatus {
	s := TunnelStatus{
		ID:          rt.tunnel.ID,
		LocalPort:   rt.tunnel.LocalPort,
		RemoteAddr:  rt.tunnel.RemoteAddr,
		Purpose:     rt.tunnel.Purpose,
		CertID:      rt.tunnel.CertID,
		Running:     true, // snapshot 只在运行中的 runtime 上调用
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

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
