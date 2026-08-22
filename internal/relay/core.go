package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"mtls-gateway/internal/certsource"
	"mtls-gateway/internal/i18n"
	"mtls-gateway/internal/pathutil"
)

// Relay 客户端中继核心: 单实例, 同时服务多条隧道(端口)。
// 持有一个证书来源(source), 各隧道通过 CertID 从该来源选证书;
// 证书按 CertID 缓存, 多条隧道引用同一证书时复用一份 tls.Certificate。
type Relay struct {
	mu sync.Mutex

	listenHost string                    // 当前配置的本地监听地址 (Start/Reload 更新)
	serverAddr string                    // 服务端 /info 发现端点 (Start/Reload 更新; 亦可用 SetServerAddr)
	serverCA   string                    // 网关 CA 文件路径 (验服务器证书; 空=系统根)
	caSubject  string                    // 网关 CA 主题 (issuer 过滤系统证书源用; 空=未配置/未解析)
	rootCAs    *x509.CertPool            // 由 serverCA 构建; nil=系统根
	src        certsource.Source         // 证书来源 (由外层/daemon 注入; 亦可用 SetSource 热替换)
	certCache  map[string]certCacheEntry // source-CertID -> 证书 (复用, TTL 失效支持证书轮换)

	ctx          context.Context
	cancel       context.CancelFunc
	runCtx       context.Context // 当前运行周期上下文 (Start 时重建)
	runCancel    context.CancelFunc
	tunnels      map[string]*tunnelRuntime // tunnel ID -> runtime
	L            *i18n.L                   // 错误消息语言(zh/en, 默认 zh)
	started      bool
	idleTimeout  time.Duration // TCP 透传空闲超时(0=默认 120s; 测试可注入)
	certCacheTTL time.Duration // 证书缓存有效期(测试可注入缩短)
}

// 证书缓存有效期默认值: 到期重载, 支持证书轮换/续期(≤TTL 生效)
const defaultCertCacheTTL = 60 * time.Second

// defaultTCPIdle TCP 透传的空闲超时默认值。
// 原 120s 会杀掉空闲的长连接 —— 浏览器 WebSocket(dsh 等 LLM 对话工具的事件流)
// 空闲时无帧, 看回复/思考 > 120s 即被切断, 前端重连窗口内第一次发消息超时
// (2026-08-21 定位: 走 mTLS 时每次发送消息第一次超时, SSH 直连无 relay 层则不超时)。
// frp 对照: frp TCP 透传不杀空闲连接, 连接生命周期交对端, 死连接由 TCP keepalive 清理。
// 这里保留 12h 上限仅作极端防泄漏兜底(正常长连接不受影响)。
const defaultTCPIdle = 12 * time.Hour

type certCacheEntry struct {
	cert     tls.Certificate
	loadedAt time.Time
}

// SetLang 设置错误消息语言(zh/en)
func (r *Relay) SetLang(lang string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.L = i18n.New(lang)
}

// New 创建 Relay。src 为证书来源(不得为 nil); 配置经 Start/Reload 传入。
func New(src certsource.Source) *Relay {
	ctx, cancel := context.WithCancel(context.Background())
	return &Relay{
		src:          src,
		certCache:    make(map[string]certCacheEntry),
		ctx:          ctx,
		cancel:       cancel,
		tunnels:      make(map[string]*tunnelRuntime),
		L:            i18n.New("zh"),
		idleTimeout:  defaultTCPIdle,
		certCacheTTL: defaultCertCacheTTL,
	}
}

// certTTL 锁内读证书缓存有效期(测试可注入缩短; 并发读纪律 — flash 审计抓出锁外读)
func (r *Relay) certTTL() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.certCacheTTL
}

// localizeLoadErr 证书加载错误本地化(私钥需密码/证书不存在), 按给定语言
func localizeLoadErr(l *i18n.L, certID string, err error) error {
	s := err.Error()
	switch {
	case strings.Contains(s, "private key needs password"), strings.Contains(s, "failed to parse private key"):
		return l.E("errPwdNeeded", certID)
	case strings.Contains(s, "decryption password incorrect"), strings.Contains(s, "password incorrect"):
		return l.E("errBadPwd", certID)
	case strings.Contains(s, "not found"):
		return l.E("errCertNotFound", certID)
	case strings.Contains(s, "expired"):
		return l.E("errExpired")
	}
	return err
}

// loadCertLang 按指定语言加载证书(错误消息语言化); lang 空=进程默认
func (r *Relay) loadCertLang(certID, lang string) (tls.Certificate, error) {
	l := r.lang()
	if lang == "en" || lang == "zh" {
		l = i18n.New(lang)
	}
	r.mu.Lock()
	e, ok := r.certCache[certID]
	src := r.src
	r.mu.Unlock()
	if ok && time.Since(e.loadedAt) < r.certTTL() {
		return e.cert, nil
	}
	c, err := src.Load(certID)
	if err != nil {
		return tls.Certificate{}, localizeLoadErr(l, certID, err)
	}
	r.mu.Lock()
	// 换源防回填: SetSource 已换 src(清缓存)时, 本 goroutine 从旧源快照加载的证书
	// 不得写回新缓存(否则旧源身份残留 ≤TTL, pro 深度审计 F6); 返回调用方一次性使用
	if r.src != src {
		r.mu.Unlock()
		releaseCertKeyDelayed(c)
		return c, nil
	}
	if old, ok2 := r.certCache[certID]; ok2 {
		releaseCertKeyDelayed(old.cert) // 延迟释放旧 signer: 在途握手可能仍持旧句柄(pro 深度审计 F2)
	}
	r.certCache[certID] = certCacheEntry{cert: c, loadedAt: time.Now()}
	r.mu.Unlock()
	return c, nil
}

// keyReleaseDelay 旧 signer 延迟释放窗口: 缓存替换后, 在途 TLS 握手/旧 Transport
// 仍可能持有旧句柄, 立即释放 → NCryptSignHash 用已释放句柄(UAF, pro 深度审计 F2)。
// 延迟远超握手/连接建立时长(秒级), 覆盖全部在途窗口; 宁漏不 UAF(进程退出 OS 回收)。
const keyReleaseDelay = 30 * time.Second

// releaseCertKeyDelayed 延迟释放证书私钥资源(实现 io.Closer 的 signer, 如 Windows CNG NCRYPT 句柄)。
// fileSource/dirSource 的内存密钥无 Close, 静默忽略。
func releaseCertKeyDelayed(tc tls.Certificate) {
	if tc.PrivateKey == nil {
		return
	}
	if cl, ok := tc.PrivateKey.(io.Closer); ok {
		time.AfterFunc(keyReleaseDelay, func() { _ = cl.Close() })
	}
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
// 配置了 server_ca 但读取/解析失败 = 拒绝启动(降级系统根会被 MITM 冒充网关)。
func (r *Relay) applyServerCA(serverCA string) error {
	// 先构建新根池(失败不碰旧配置 — 绝不静默降级系统根):
	// 原实现先置 rootCAs=nil 再读文件, Reload 中 server_ca 变更失败会导致
	// 运行中隧道以系统根验证网关(违背防 MITM 意图)。
	newPool := (*x509.CertPool)(nil)
	newSubject := ""
	if serverCA != "" {
		pemBytes, err := os.ReadFile(serverCA)
		if err != nil {
			return fmt.Errorf("read server_ca %s: %w (拒绝降级系统根)", serverCA, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return fmt.Errorf("parse server_ca %s failed (拒绝降级系统根)", serverCA)
		}
		newPool = pool
		// 用 CA 主题过滤系统证书源: 只展示由该 CA 签发的身份(过滤 Adobe 等无关证书)
		if ca := firstCert(pemBytes); ca != nil {
			newSubject = ca.Subject.String()
		}
	}
	// 成功: 原子赋值(调用方持锁)
	r.serverCA = serverCA
	r.rootCAs = newPool
	r.caSubject = newSubject
	if newSubject != "" && r.src != nil {
		certsource.ApplyIssuerFilter(r.src, newSubject)
	}
	// 异步匿名引导: 无证书调服务端 /info(null 路由), 拿服务端 CA 自动过滤(server_ca 未配置时的兜底)
	go r.fetchCAAndFilter()
	return nil
}

// SetSource 热替换证书来源 (WebUI 连接设置改 cert_dir 后调用)。
// 立即生效: 清空证书缓存(释放旧 signer 资源 + 下次加载从新源取), 并按当前 server_ca 重新过滤系统证书源。
// 新来源构建失败由调用方负责(本方法只接受已构建好的源)。
func (r *Relay) SetSource(src certsource.Source) {
	r.mu.Lock()
	r.src = src
	for k, e := range r.certCache {
		releaseCertKeyDelayed(e.cert) // 延迟释放: 在途握手/旧 Transport 仍持旧句柄(pro 深度审计 F2)
		delete(r.certCache, k)
	}
	subject := r.caSubject
	r.mu.Unlock()
	if subject != "" {
		certsource.ApplyIssuerFilter(src, subject)
	}
	// 异步兜底: 重新匿名拉 /info CA 过滤(server_ca 未配置时换源后同样生效)
	go r.fetchCAAndFilter()
}

// fetchCAAndFilter 匿名调服务端 /info(不需要客户端证书, 服务端 null 路由),
// 用返回的 CA 过滤系统证书源; **仅在 server_ca 已配置(roots 非 nil)时运行** —
// 作为 applyServerCA 之后的兜底重过滤(服务端 CA 轮换时刷新 issuer 过滤);
// server_ca 未配置时 roots==nil 直接返回, 不做过滤(无信任锚可依据)。
func (r *Relay) fetchCAAndFilter() {
	r.mu.Lock()
	addr, caFile, roots, src := r.serverAddr, r.serverCA, r.rootCAs, r.src
	r.mu.Unlock()
	if addr == "" || roots == nil {
		return
	}
	cli := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: roots}, // 无客户端证书(匿名)
		},
	}
	resp, err := cli.Get("https://" + addr + "/info")
	if err != nil {
		log.Printf("anonymous /info 引导: %v (降级: 用本地 server_ca %s 过滤)", pathutil.SanitizeForLog(err.Error()), pathutil.SanitizeForLog(caFile))
		return
	}
	defer resp.Body.Close()
	var info struct {
		CA string `json:"ca"`
	}
	// 限流: 与 /info 成功路径一致, 防 MITM/误配服务端超大 JSON 耗尽内存
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxInfoBody)).Decode(&info); err != nil || info.CA == "" {
		return
	}
	if caCert := firstCert([]byte(info.CA)); caCert != nil {
		certsource.ApplyIssuerFilter(src, caCert.Subject.String())
		// subject 来自服务端 /info 响应(TLS 验证后), 失陷服务端可用 CN 注入文本日志 — 清洗
		log.Printf("anonymous /info 引导: 已用服务端 CA 过滤证书源 (%s)", pathutil.SanitizeForLog(caCert.Subject.String()))
	}
}

// firstCert 解析 PEM 里的第一张证书(用于提取 CA 主题)
func firstCert(pemBytes []byte) *x509.Certificate {
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil
		}
		return cert
	}
}

// loadCert 从来源加载证书(CertID), 命中缓存则复用; 与 loadCertLang 同逻辑(用默认语言)
func (r *Relay) loadCert(certID string) (tls.Certificate, error) {
	return r.loadCertLang(certID, "")
}

// relayDial 建立一条到给定路由上游的 mTLS 连接。
func (r *Relay) relayDial(ctx context.Context, certID string, route TunnelRoute) (net.Conn, error) {
	cert, err := r.loadCert(certID)
	if err != nil {
		return nil, err
	}
	d := &Dialer{
		ServerAddr: net.JoinHostPort(r.serverHost(), route.ChannelPort()),
		ServerName: r.serverHost(),
		ClientCert: &cert,
		RootCAs:    r.rootCAsCopy(),
	}
	return d.Dial(ctx)
}

// lang 锁内读当前语言(SetLang 并发写)
func (r *Relay) lang() *i18n.L {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.L
}

// serverHost 服务端发现端点的主机部分 (serverAddr = host:port → host)

// rootCAsCopy 锁内读根池(applyServerCA 并发写)
func (r *Relay) rootCAsCopy() *x509.CertPool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rootCAs
}

func (r *Relay) serverHost() string {
	r.mu.Lock()
	addr := r.serverAddr
	r.mu.Unlock()
	return stripPort(addr)
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
	if err := r.applyServerCA(cfg.ServerCAFile); err != nil {
		return err
	}
	var runtimes []*tunnelRuntime
	for _, t := range cfg.Tunnels {
		if !t.Enabled {
			continue
		}
		for _, spec := range tunnelRoutes(t) {
			rt := &tunnelRuntime{r: r, key: spec.key, service: spec.service, idle: r.idleTimeout, route: spec.route, certID: spec.certID, conns: map[net.Conn]struct{}{}}
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

// Reload 增量应用隧道集变更: 新增的起监听, 证书/路由变更的热切换, 已删的停止。
// 不改动仍在运行且未变的隧道(不做断流热切换)。
func (r *Relay) Reload(cfg RelayConfig) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.started {
		return errNotStarted
	}
	r.listenHost = cfg.ListenHost
	r.serverAddr = cfg.ServerAddr
	if err := r.applyServerCA(cfg.ServerCAFile); err != nil {
		return err
	}
	next := map[string]bool{}
	var reloadErrs []error
	for _, t := range cfg.Tunnels {
		if !t.Enabled {
			continue
		}
		for _, spec := range tunnelRoutes(t) {
			key := spec.key
			next[key] = true
			if old, ok := r.tunnels[key]; !ok {
				rt := &tunnelRuntime{r: r, key: spec.key, service: spec.service, idle: r.idleTimeout, route: spec.route, certID: spec.certID, conns: map[net.Conn]struct{}{}}
				if err := r.startTunnel(rt); err != nil {
					reloadErrs = append(reloadErrs, fmt.Errorf("tunnel %s: %w", key, err))
					continue // 坏隧道不卡死后续启动; 也保证下方清理循环执行
				}
				r.tunnels[key] = rt
			} else if old.certID != spec.certID || old.route != spec.route {
				// 证书/路由变更: 热切换。同端口无法共存, 先停旧释放端口, 起新失败则恢复旧隧道
				old.stop()
				rt := &tunnelRuntime{r: r, key: spec.key, service: spec.service, idle: r.idleTimeout, route: spec.route, certID: spec.certID, conns: map[net.Conn]struct{}{}}
				if err := r.startTunnel(rt); err != nil {
					// 回滚: 恢复旧隧道(避免服务中断 + 状态虚报); metrics 归零符合"重启归零"语义
					oldRT := &tunnelRuntime{r: r, key: spec.key, service: spec.service, idle: r.idleTimeout, route: old.route, certID: old.certID, conns: map[net.Conn]struct{}{}}
					if rerr := r.startTunnel(oldRT); rerr != nil {
						delete(r.tunnels, key) // 恢复也失败: 删除条目, 不虚报 Running
					} else {
						r.tunnels[key] = oldRT
					}
					reloadErrs = append(reloadErrs, fmt.Errorf("tunnel %s (update): %w", key, err))
					continue
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
	// 复用 route 的宿主整口被删除后, 重新起独立监听(否则端口永久变暗)
	for id, rt := range r.tunnels {
		if rt.listener == nil && !r.hasWholePortRuntime(rt.service, rt.route.LocalPort()) {
			if err := r.startTunnel(rt); err != nil {
				reloadErrs = append(reloadErrs, fmt.Errorf("rebuild reused tunnel %s: %w", id, err))
			}
		}
	}
	if len(reloadErrs) > 0 {
		return fmt.Errorf("reload: %d tunnel(s) failed, first: %w", len(reloadErrs), reloadErrs[0])
	}
	return nil
}

// hasWholePortRuntime 本隧道组(同 service)是否已有整口(LocalPath="")route 监听该端口
// (复用 route 的宿主判定; 与 hasLocalPort 同按 service 隔离 — 跨组同端口已在 Start 拒绝, 对称化防回归)
func (r *Relay) hasWholePortRuntime(service, port string) bool {
	for _, rt := range r.tunnels {
		if rt.service == service && rt.listener != nil && rt.route.LocalPath() == "" && rt.route.LocalPort() == port {
			return true
		}
	}
	return false
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
	r.mu.Lock()
	src := r.src
	r.mu.Unlock()
	return src.List()
}

// LoadCertWithPassword 加载证书; 若私钥被加密(需密码)则用 password 解锁。
// 需要密码而 password 为空时, 报"needs password"错误, 由调用方(WebUI)弹出密码框再试。
// 注意: 不持 r.mu 外层锁 — loadCert 内部自锁, 再锁会重入死锁(sync.Mutex 不可重入)。
func (r *Relay) LoadCertWithPassword(certID, password string) (tls.Certificate, error) {
	r.mu.Lock()
	src := r.src
	r.mu.Unlock()
	if with, ok := src.(certsource.LoaderWithPassword); ok {
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
// 配置的 CA 不可用 → 返回错误(拒绝降级系统根, 防 MITM)
func (r *Relay) SetServerCA(caFile string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.applyServerCA(caFile)
}

var errAlreadyStarted = errString("relay already started")
var errNotStarted = errString("relay not started")

type errString string

func (e errString) Error() string { return string(e) }
