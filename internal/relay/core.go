package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	"mtls-gateway/internal/certsource"
	"mtls-gateway/internal/i18n"
)

// Relay 客户端中继核心: 单实例, 同时服务多条隧道(端口)。
// 持有一个证书来源(source), 各隧道通过 CertID 从该来源选证书;
// 证书按 CertID 缓存, 多条隧道引用同一证书时复用一份 tls.Certificate。
type Relay struct {
	cfgPath string
	mu      sync.Mutex

	listenHost string                     // 当前配置的本地监听地址 (Start/Reload 更新)
	serverAddr string                     // 服务端 /info 发现端点 (Start/Reload 更新; 亦可用 SetServerAddr)
	serverCA   string                     // 网关 CA 文件路径 (验服务器证书; 空=系统根)
	rootCAs    *x509.CertPool             // 由 serverCA 构建; nil=系统根
	src        certsource.Source          // 证书来源 (由外层/daemon 注入)
	certCache  map[string]tls.Certificate // source-CertID -> 证书 (复用)

	ctx       context.Context
	cancel    context.CancelFunc
	runCtx    context.Context // 当前运行周期上下文 (Start 时重建)
	runCancel context.CancelFunc
	tunnels   map[string]*tunnelRuntime // tunnel ID -> runtime
	L         *i18n.L                   // 错误消息语言(zh/en, 默认 zh)
	started   bool
}

// SetLang 设置错误消息语言(zh/en)
func (r *Relay) SetLang(lang string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.L = i18n.New(lang)
}

// New 创建 Relay。cfg 可为空配置(后续通过管理 API 补隧道)。
// src 为证书来源(不得为 nil)。
func New(cfgPath string, src certsource.Source) *Relay {
	ctx, cancel := context.WithCancel(context.Background())
	return &Relay{
		cfgPath:   cfgPath,
		src:       src,
		certCache: make(map[string]tls.Certificate),
		ctx:       ctx,
		cancel:    cancel,
		tunnels:   make(map[string]*tunnelRuntime),
		L:         i18n.New("zh"),
	}
}

// localizeLoadErr 证书加载错误本地化(私钥需密码/证书不存在)
func (r *Relay) localizeLoadErr(certID string, err error) error {
	s := err.Error()
	switch {
	case strings.Contains(s, "private key needs password"), strings.Contains(s, "failed to parse private key"):
		return r.L.E("errPwdNeeded", certID)
	case strings.Contains(s, "not found"):
		return r.L.E("errCertNotFound", certID)
	case strings.Contains(s, "expired"):
		return r.L.E("errExpired")
	}
	return err
}

// cfgListenHost 返回当前本地监听地址
func (r *Relay) cfgListenHost() string {
	if r.listenHost == "" {
		return DefaultListenHost
	}
	return r.listenHost
}

// applyServerCA 设置网关 CA 并构建根池 (用于验证网关服务器证书)。
// serverCA 为空 = 用系统根 (根池 nil)。
func (r *Relay) applyServerCA(serverCA string) {
	r.serverCA = serverCA
	r.rootCAs = nil
	if serverCA == "" {
		return
	}
	pemBytes, err := os.ReadFile(serverCA)
	if err != nil {
		log.Printf("relay: read server_ca %s: %v (falling back to system roots)", serverCA, err)
		return
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		log.Printf("relay: parse server_ca %s failed (falling back to system roots)", serverCA)
		return
	}
	r.rootCAs = pool
}

// loadCert 从来源加载证书(CertID), 命中缓存则复用。
func (r *Relay) loadCert(certID string) (tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.certCache[certID]; ok {
		return c, nil
	}
	c, err := r.src.Load(certID)
	if err != nil {
		return tls.Certificate{}, r.localizeLoadErr(certID, err)
	}
	r.certCache[certID] = c
	return c, nil
}

// relayDial 建立一条到给定路由上游的 mTLS 连接。
func (r *Relay) relayDial(ctx context.Context, _ string, certID string, route TunnelRoute) (net.Conn, error) {
	cert, err := r.loadCert(certID)
	if err != nil {
		return nil, err
	}
	d := &Dialer{
		ServerAddr: net.JoinHostPort(r.serverHost(), route.ChannelPort()),
		ServerName: r.serverHost(),
		ClientCert: &cert,
		RootCAs:    r.rootCAs,
	}
	return d.Dial(ctx)
}

// serverHost 服务端发现端点的主机部分 (serverAddr = host:port → host)
func (r *Relay) serverHost() string {
	r.mu.Lock()
	addr := r.serverAddr
	r.mu.Unlock()
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

// Start 监听并启动所有隧道。
func (r *Relay) Start(cfg RelayConfig) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started {
		return errAlreadyStarted
	}
	// 每个运行周期一个独立上下文: 使 stop 后再 start 仍可正常工作。
	r.runCtx, r.runCancel = context.WithCancel(r.ctx)
	r.listenHost = cfg.ListenHost
	r.serverAddr = cfg.ServerAddr
	r.applyServerCA(cfg.ServerCAFile)
	var runtimes []*tunnelRuntime
	for _, t := range cfg.Tunnels {
		if !t.Enabled {
			continue
		}
		for _, spec := range tunnelRoutes(t) {
			rt := &tunnelRuntime{r: r, key: spec.key, service: spec.service, route: spec.route, certID: spec.certID, conns: map[net.Conn]struct{}{}}
			if err := r.startTunnel(rt); err != nil {
				// 回滚已启动的
				for _, t2 := range runtimes {
					t2.stop()
				}
				r.tunnels = map[string]*tunnelRuntime{}
				if r.runCancel != nil {
					r.runCancel()
					r.runCancel = nil
				}
				return err
			}
			runtimes = append(runtimes, rt)
			r.tunnels[rt.key] = rt
		}
	}
	r.started = true
	log.Printf("relay: started %d tunnel route(s)", len(runtimes))
	return nil
}

// Reload 增量应用隧道集变更: 新增/更新的隧道起监听, 已删的停止。
// 不改动仍在运行且未变的隧道(不做断流热切换)。
func (r *Relay) Reload(cfg RelayConfig) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.started {
		return errNotStarted
	}
	r.listenHost = cfg.ListenHost
	r.serverAddr = cfg.ServerAddr
	r.applyServerCA(cfg.ServerCAFile)
	next := map[string]bool{}
	for _, t := range cfg.Tunnels {
		if !t.Enabled {
			continue
		}
		for _, spec := range tunnelRoutes(t) {
			key := spec.key
			next[key] = true
			if _, ok := r.tunnels[key]; !ok {
				rt := &tunnelRuntime{r: r, key: spec.key, service: spec.service, route: spec.route, certID: spec.certID, conns: map[net.Conn]struct{}{}}
				if err := r.startTunnel(rt); err != nil {
					return err
				}
				r.tunnels[key] = rt
			}
		}
	}
	// 停止已从配置移除的隧道
	for id, rt := range r.tunnels {
		if !next[id] {
			rt.stop()
			delete(r.tunnels, id)
		}
	}
	return nil
}

// Stop 停止所有隧道 (暂停运行周期; 之后可再次 Start/Reload)。
func (r *Relay) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, rt := range r.tunnels {
		rt.stop()
	}
	r.tunnels = map[string]*tunnelRuntime{}
	r.started = false
	if r.runCancel != nil {
		r.runCancel()
		r.runCancel = nil
		r.runCtx = nil
	}
}

// Close 完全关闭(停隧道 + 取消根上下文, 之后不可再 Start)。
func (r *Relay) Close() {
	r.Stop()
	r.cancel()
}

// Status 返回所有隧道状态快照。
func (r *Relay) Status() []TunnelStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]TunnelStatus, 0, len(r.tunnels))
	for _, rt := range r.tunnels {
		out = append(out, rt.snapshot())
	}
	return out
}

// ListCertMeta 返回来源里可选的证书(供外壳/用户选择)。
func (r *Relay) ListCertMeta() ([]certsource.IdentityMeta, error) {
	return r.src.List()
}

// LoadCertWithPassword 加载证书; 若私钥被加密(需密码)则用 password 解锁。
// 需要密码而 password 为空时, 报"needs password"错误, 由调用方(WebUI)弹出密码框再试。
func (r *Relay) LoadCertWithPassword(certID, password string) (tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if with, ok := r.src.(certsource.LoaderWithPassword); ok {
		return with.LoadWithPassword(certID, password)
	}
	return r.loadCert(certID)
}

// SetServerAddr 设置服务端 /info 发现端点(供 Discover 在未 Start 时使用)。
func (r *Relay) SetServerAddr(addr string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.serverAddr = addr
}

// SetServerCA 设置并加载服务端 CA(供 Discover 在未 Start 时验证网关服务器证书)。
func (r *Relay) SetServerCA(caFile string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.applyServerCA(caFile)
}

var errAlreadyStarted = errString("relay already started")
var errNotStarted = errString("relay not started")

type errString string

func (e errString) Error() string { return string(e) }
