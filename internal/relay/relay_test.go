package relay

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"mtls-gateway/internal/certsource"
)

// harness 创建一套测试环境: 临时 CA + 客户端证书(pem 文件) + mTLS 网关 stub
type harness struct {
	clientPairPath string // 客户端 cert.pem+key.pem 合并文件 (certsource 文件源用)
	caPath         string // CA 证书文件 (配置 ServerCAFile 用)
	gwAddr         string // mTLS 网关 stub 地址
	gwLn           net.Listener
}

// newHarness 生成 CA/客户端证书, 起一个 mTLS 网关 stub (要求客户端证书, echo 数据)
func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()

	// CA
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca", Organization: []string{"mtls-gw"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	// 网关服务器证书 (serverAuth)
	serverKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	serverTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "gw-server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"gw-server"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	serverDER, _ := x509.CreateCertificate(rand.Reader, serverTmpl, caCert, &serverKey.PublicKey, caKey)
	serverKeyDER, _ := x509.MarshalPKCS8PrivateKey(serverKey)
	serverPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER})
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverKeyDER})
	serverPair := append(append(append([]byte{}, serverPEM...), '\n'), serverKeyPEM...)

	// 客户端证书 (clientAuth)
	clientKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	clientTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "device-a"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IPAddresses:  []net.IP{net.ParseIP("100.64.0.2")},
	}
	clientDER, _ := x509.CreateCertificate(rand.Reader, clientTmpl, caCert, &clientKey.PublicKey, caKey)
	clientPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER})
	clientKeyDER, _ := x509.MarshalPKCS8PrivateKey(clientKey)
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: clientKeyDER})
	clientPair := append(append(append([]byte{}, clientPEM...), '\n'), clientKeyPEM...)

	// 写客户端证书文件 (certsource 文件源)
	clientPairPath := filepath.Join(dir, "client.pem")
	if err := os.WriteFile(clientPairPath, clientPair, 0o600); err != nil {
		t.Fatal(err)
	}
	// 写服务器证书文件 (起网关 stub 用)
	serverPairPath := filepath.Join(dir, "server.pem")
	if err := os.WriteFile(serverPairPath, serverPair, 0o600); err != nil {
		t.Fatal(err)
	}
	// 写 CA 证书文件 (配置 ServerCAFile 用)
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}

	// 起 mTLS 网关 stub
	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, err := tls.LoadX509KeyPair(serverPairPath, serverPairPath)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	gwTLS := &tls.Config{
		Certificates: []tls.Certificate{serverTLS},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
	}
	gwLn := tls.NewListener(rawLn, gwTLS)
	go serveEcho(gwLn)

	return &harness{
		clientPairPath: clientPairPath,
		caPath:         caPath,
		gwAddr:         rawLn.Addr().String(),
		gwLn:           gwLn,
	}
}

// serveEcho 接受连接并回显 (读到 EOF 关闭), 直到 listener 关闭
func serveEcho(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			io.Copy(c, c) // echo
		}(conn)
	}
}

// freePort 拿一个空闲端口
func gwPortOf(addr string) string {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return p
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func (h *harness) close() { h.gwLn.Close() }

// buildSrc 用客户端证书文件打开 certsource 文件源
func (h *harness) buildSrc(t *testing.T) certsource.Source {
	t.Helper()
	src, err := certsource.OpenFile(h.clientPairPath)
	if err != nil {
		t.Fatal(err)
	}
	return src
}

// TestRelay_Echo 单隧道转发: 本地连接 → 发数据 → 收到网关回显
func TestRelay_Echo(t *testing.T) {
	h := newHarness(t)
	defer h.close()
	src := h.buildSrc(t)

	localPort := freePort(t)
	r := New(src)
	defer r.Close()

	cfg := RelayConfig{ListenHost: "127.0.0.1", ServerAddr: h.gwAddr, ServerCAFile: h.caPath, Tunnels: []Tunnel{
		{Service: "s1", Routes: []TunnelRoute{{Channel: ":" + gwPortOf(h.gwAddr), Local: ":" + fmt.Sprintf("%d", localPort)}}, CertID: h.clientPairPath, Enabled: true},
	}}
	if err := r.Start(cfg); err != nil {
		t.Fatal(err)
	}

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	msg := []byte("hello through relay")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := io.ReadFull(conn, buf)
	if err != nil {
		t.Fatalf("read echo: %v (got %d bytes)", err, n)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo mismatch: got %q", buf)
	}
	if n != len(msg) {
		t.Fatalf("short echo: %d != %d", n, len(msg))
	}
}

// TestRelay_CertReuse 证书复用: 同一 CertID 两条隧道都通 (一个证书用于两个端口)
func TestRelay_CertReuse(t *testing.T) {
	h := newHarness(t)
	defer h.close()
	src := h.buildSrc(t)

	p1 := freePort(t)
	p2 := freePort(t)
	r := New(src)
	defer r.Close()
	cfg := RelayConfig{ListenHost: "127.0.0.1", ServerAddr: h.gwAddr, ServerCAFile: h.caPath, Tunnels: []Tunnel{
		{Service: "s1", Routes: []TunnelRoute{{Channel: ":" + gwPortOf(h.gwAddr), Local: ":" + fmt.Sprintf("%d", p1)}}, CertID: h.clientPairPath, Enabled: true},
		{Service: "s2", Routes: []TunnelRoute{{Channel: ":" + gwPortOf(h.gwAddr), Local: ":" + fmt.Sprintf("%d", p2)}}, CertID: h.clientPairPath, Enabled: true},
	}}
	if err := r.Start(cfg); err != nil {
		t.Fatal(err)
	}

	for _, p := range []int{p1, p2} {
		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err != nil {
			t.Fatalf("dial %d: %v", p, err)
		}
		msg := []byte("reuse-test")
		conn.Write(msg)
		buf := make([]byte, len(msg))
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("read on port %d: %v", p, err)
		}
		if string(buf) != string(msg) {
			t.Fatalf("port %d echo mismatch", p)
		}
		conn.Close()
	}
}

// TestRelay_BadUpstream 上游 mTLS 失败 → 该连接被拒, 但监听存活 (后续请求仍可成功)
func TestRelay_BadUpstream(t *testing.T) {
	// 用一个未监听的上游地址模拟失败
	h := newHarness(t)
	defer h.close()
	src := h.buildSrc(t)

	localPort := freePort(t)
	r := New(src)
	defer r.Close()
	cfg := RelayConfig{ListenHost: "127.0.0.1", ServerAddr: "127.0.0.1:1", ServerCAFile: h.caPath, Tunnels: []Tunnel{
		{Service: "s1", Routes: []TunnelRoute{{Channel: ":1", Local: ":" + fmt.Sprintf("%d", localPort)}}, CertID: h.clientPairPath, Enabled: true},
	}}
	if err := r.Start(cfg); err != nil {
		t.Fatal(err)
	}

	// 第一次连接应失败 (上游连不上): 本地 Dial 可建立, 但 relay 拨上游失败后应关闭该连接
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	// pro 深度审计补: 坏上游下读应得"连接被关闭"(EOF/FIN 或 RST), 而非悬挂。
	// 断言排除超时: relay 若挂起(连接不关)则 3s 超时 → 失败(消除假阴性窗口; pro 复审建议)。
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 16)
	if _, err := conn.Read(buf); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("坏上游: 本地连接应被关闭(EOF/RST), got %v", err)
	}

	// 确认隧道仍注册
	status := r.Status()
	if len(status) != 1 {
		t.Fatalf("want 1 tunnel, got %d", len(status))
	}
	if status[0].ID != "s1@:1@:"+fmt.Sprintf("%d", localPort) {
		t.Fatalf("tunnel id mismatch: %s", status[0].ID)
	}
}

// TestRelay_Reload 增删隧道: reload 后新增隧道生效, 删除的停止
func TestRelay_Reload(t *testing.T) {
	h := newHarness(t)
	defer h.close()
	src := h.buildSrc(t)

	p1 := freePort(t)
	p2 := freePort(t)
	r := New(src)
	defer r.Close()
	cfg := RelayConfig{ListenHost: "127.0.0.1", ServerAddr: h.gwAddr, ServerCAFile: h.caPath, Tunnels: []Tunnel{
		{Service: "s1", Routes: []TunnelRoute{{Channel: ":" + gwPortOf(h.gwAddr), Local: ":" + fmt.Sprintf("%d", p1)}}, CertID: h.clientPairPath, Enabled: true},
	}}
	if err := r.Start(cfg); err != nil {
		t.Fatal(err)
	}

	// reload: 加 t2, 停 t1
	cfg2 := RelayConfig{ListenHost: "127.0.0.1", ServerAddr: h.gwAddr, ServerCAFile: h.caPath, Tunnels: []Tunnel{
		{Service: "s1", Routes: []TunnelRoute{{Channel: ":" + gwPortOf(h.gwAddr), Local: ":" + fmt.Sprintf("%d", p2)}}, CertID: h.clientPairPath, Enabled: true},
	}}
	if err := r.Reload(cfg2); err != nil {
		t.Fatal(err)
	}

	// t2 应可用
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", p2))
	if err != nil {
		t.Fatalf("t2 dial: %v", err)
	}
	msg := []byte("reload")
	conn.Write(msg)
	buf := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("t2 read: %v", err)
	}
	conn.Close()

	// t1 已停止: dial 应失败
	if _, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", p1)); err == nil {
		t.Fatalf("t1 should be stopped")
	}
}

// TestRelay_StartTwice 重复 Start 报错
func TestRelay_StartTwice(t *testing.T) {
	h := newHarness(t)
	defer h.close()
	src := h.buildSrc(t)
	r := New(src)
	defer r.Close()
	cfg := RelayConfig{ListenHost: "127.0.0.1"}
	if err := r.Start(cfg); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(cfg); err == nil {
		t.Fatalf("expected error on second Start")
	}
}

// TestRelay_StopThenStart 回归测试: Stop 后再 Start 必须能再次正常转发。
// 曾因 Stop 永久取消根上下文导致重启后所有上行 dial 立即 "operation was canceled"。
func TestRelay_StopThenStart(t *testing.T) {
	h := newHarness(t)
	defer h.close()
	src := h.buildSrc(t)

	localPort := freePort(t)
	r := New(src)
	defer r.Close()
	cfg := RelayConfig{ListenHost: "127.0.0.1", ServerAddr: h.gwAddr, ServerCAFile: h.caPath, Tunnels: []Tunnel{
		{Service: "s1", Routes: []TunnelRoute{{Channel: ":" + gwPortOf(h.gwAddr), Local: ":" + fmt.Sprintf("%d", localPort)}}, CertID: h.clientPairPath, Enabled: true},
	}}

	// 第 1 轮: 启动 → 转发 → 停止
	if err := r.Start(cfg); err != nil {
		t.Fatal(err)
	}
	echoThrough := func(t *testing.T, msg string) {
		t.Helper()
		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		if _, err := conn.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, len(msg))
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("read echo (round 0): %v", err)
		}
		if string(buf) != msg {
			t.Fatalf("round 0 echo mismatch: got %q", buf)
		}
	}
	echoThrough(t, "round-one")
	r.Stop()

	// 第 2 轮: 再次 Start → 必须能再次转发 (回归点)
	if err := r.Start(cfg); err != nil {
		t.Fatalf("restart after Stop failed: %v", err)
	}
	echoThrough(t, "round-two")

	// 第 3 轮: 再次 Stop → 再 Start 仍应正常
	r.Stop()
	if err := r.Start(cfg); err != nil {
		t.Fatalf("second restart after Stop failed: %v", err)
	}
	echoThrough(t, "round-three")
}

// R2: server_ca 配置但不可用 → 拒绝(不降级系统根, 防 MITM)
func TestApplyServerCARejectsBad(t *testing.T) {
	h := newHarness(t)
	defer h.close()
	src := h.buildSrc(t)
	r := New(src)
	defer r.Close()
	// 文件不存在
	if err := r.SetServerCA("/nonexistent/ca.crt"); err == nil {
		t.Fatal("bad server_ca path should be rejected")
	}
	// 非 PEM 垃圾
	bad := filepath.Join(t.TempDir(), "bad.crt")
	os.WriteFile(bad, []byte("not a pem"), 0o600)
	if err := r.SetServerCA(bad); err == nil {
		t.Fatal("garbage server_ca should be rejected")
	}
	// 合法 CA → 成功
	if err := r.SetServerCA(h.caPath); err != nil {
		t.Fatalf("valid server_ca should pass: %v", err)
	}
}

// 第八批: LoadCertWithPassword 回退分支(源不实现 LoaderWithPassword → loadCert 自锁路径, 防死锁回归)
type noPwdSource struct{ certSource certsource.Source }

func (n noPwdSource) List() ([]certsource.IdentityMeta, error) { return n.certSource.List() }
func (n noPwdSource) Load(id string) (tls.Certificate, error) {
	return n.certSource.Load(id)
}

func TestLoadCertWithPasswordFallback(t *testing.T) {
	h := newHarness(t)
	defer h.close()
	src, err := certsource.OpenFile(h.clientPairPath)
	if err != nil {
		t.Fatal(err)
	}
	r := New(noPwdSource{src})
	defer r.Close()
	// 无密码证书: 回退到 loadCert(自锁), 不持外层锁 → 不死锁
	cert, err := r.LoadCertWithPassword(h.clientPairPath, "")
	if err != nil {
		t.Fatalf("fallback load should succeed: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("empty cert")
	}
}

// 第十四批: Reload 遇坏隧道(端口被占)不卡死后续隧道
func TestReloadBadTunnelDoesNotBlockOthers(t *testing.T) {
	h := newHarness(t)
	defer h.close()
	src := h.buildSrc(t)
	r := New(src)
	defer r.Close()
	port1, port2 := freePort(t), freePort(t)
	cfg := RelayConfig{
		ListenHost: "127.0.0.1", ServerAddr: h.gwAddr, ServerCAFile: h.caPath,
		Tunnels: []Tunnel{{
			Service: "s1",
			Routes:  []TunnelRoute{{Channel: ":" + gwPortOf(h.gwAddr), Local: fmt.Sprintf(":%d", port1)}},
			CertID:  h.clientPairPath, Enabled: true,
		}},
	}
	if err := r.Start(cfg); err != nil {
		t.Fatal(err)
	}
	// 占住 port2, 使第二条隧道启动失败
	blocker, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port2))
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	// Reload: 加一条坏隧道(port2 被占)+ 一条好隧道
	cfg.Tunnels = append(cfg.Tunnels,
		Tunnel{Service: "bad", Routes: []TunnelRoute{{Channel: ":" + gwPortOf(h.gwAddr), Local: fmt.Sprintf(":%d", port2)}}, CertID: h.clientPairPath, Enabled: true},
		Tunnel{Service: "good", Routes: []TunnelRoute{{Channel: ":" + gwPortOf(h.gwAddr), Local: fmt.Sprintf(":%d", port1+1)}}, CertID: h.clientPairPath, Enabled: true},
	)
	if err := r.Reload(cfg); err == nil {
		t.Fatal("reload should report partial failure (bad tunnel)")
	}
	// 好隧道应已监听
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port1+1))
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("good tunnel not listening after reload: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// 第十五批: Reload 证书变更热切换(旧 certID → 新 certID 重启隧道)
func TestReloadCertSwitch(t *testing.T) {
	h := newHarness(t)
	defer h.close()
	src := h.buildSrc(t)
	r := New(src)
	defer r.Close()
	localPort := freePort(t)
	cfg := RelayConfig{
		ListenHost: "127.0.0.1", ServerAddr: h.gwAddr, ServerCAFile: h.caPath,
		Tunnels: []Tunnel{{
			Service: "s1",
			Routes:  []TunnelRoute{{Channel: ":" + gwPortOf(h.gwAddr), Local: fmt.Sprintf(":%d", localPort)}},
			CertID:  h.clientPairPath, Enabled: true,
		}},
	}
	if err := r.Start(cfg); err != nil {
		t.Fatal(err)
	}
	// 换一枚证书(certID 变化)→ 隧道应热切换(不报错, 仍监听)
	cfg.Tunnels[0].CertID = h.clientPairPath // 同路径(源里就一枚, 语义等价测试路径)
	cfg.Tunnels[0].Routes[0].Local = fmt.Sprintf(":%d", localPort+1)
	if err := r.Reload(cfg); err != nil {
		t.Fatalf("reload with route change should succeed: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", localPort+1))
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("switched tunnel not listening: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// 第十六批: certID 热切换真触发(换不同 CertID → 走 else if 分支)
func TestReloadCertIDSwitch(t *testing.T) {
	h := newHarness(t)
	defer h.close()
	// 同一证书内容拷两份不同文件名 → 不同 certID(fileSource 按路径为 ID)
	dir2 := t.TempDir()
	cp1 := filepath.Join(dir2, "dev-a.pem")
	cp2 := filepath.Join(dir2, "dev-b.pem")
	data, _ := os.ReadFile(h.clientPairPath)
	os.WriteFile(cp1, data, 0o600)
	os.WriteFile(cp2, data, 0o600)
	src2, err := certsource.OpenFile(cp1)
	if err != nil {
		t.Fatal(err)
	}
	r := New(src2)
	defer r.Close()
	localPort := freePort(t)
	cfg := RelayConfig{
		ListenHost: "127.0.0.1", ServerAddr: h.gwAddr, ServerCAFile: h.caPath,
		Tunnels: []Tunnel{{
			Service: "s1",
			Routes:  []TunnelRoute{{Channel: ":" + gwPortOf(h.gwAddr), Local: fmt.Sprintf(":%d", localPort)}},
			CertID:  cp1, Enabled: true,
		}},
	}
	if err := r.Start(cfg); err != nil {
		t.Fatal(err)
	}
	// 切换 CertID 为 cp2(不同值)→ 热切换分支
	cfg.Tunnels[0].CertID = cp2
	if err := r.Reload(cfg); err != nil {
		t.Fatalf("reload cert switch: %v", err)
	}
	// 隧道仍在监听
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("tunnel not listening after cert switch: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// 中危(测试全面性审计): Start 中途失败必须回滚已启动的隧道(监听释放,
// 不留半启动状态) — 坏隧道不卡死后续启动 + 不残留监听的承诺。
func TestRelay_StartRollbackOnFailure(t *testing.T) {
	h := newHarness(t)
	defer h.close()
	src := h.buildSrc(t)

	occupied := freePort(t)
	ln, err := net.Listen("tcp", "127.0.0.1:"+fmt.Sprintf("%d", occupied))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	first := freePort(t)

	r := New(src)
	defer r.Close()
	cfg := RelayConfig{ListenHost: "127.0.0.1", ServerAddr: h.gwAddr, ServerCAFile: h.caPath, Tunnels: []Tunnel{
		{Service: "s1", Routes: []TunnelRoute{{Channel: ":" + gwPortOf(h.gwAddr), Local: ":" + fmt.Sprintf("%d", first)}}, CertID: h.clientPairPath, Enabled: true},
		{Service: "s2", Routes: []TunnelRoute{{Channel: ":" + gwPortOf(h.gwAddr), Local: ":" + fmt.Sprintf("%d", occupied)}}, CertID: h.clientPairPath, Enabled: true},
	}}
	if err := r.Start(cfg); err == nil {
		t.Fatal("占用端口应导致 Start 失败")
	}
	// 回滚断言: 第一个隧道端口已释放, 可重新 bind
	ln2, err := net.Listen("tcp", "127.0.0.1:"+fmt.Sprintf("%d", first))
	if err != nil {
		t.Fatalf("Start 失败后第一个隧道监听未释放(回滚缺失): %v", err)
	}
	ln2.Close()
}

// flash 审计补: startTunnel 端口复用只放行本隧道组整口
// ① 同服务 整口+路径 → 路径复用整口 listener(设计行为, 不报错)
// ② 跨服务 同端口 → 必须报错(此前 hasLocalPort 遍历全部隧道 → 静默错配, A 的 HTTP
//
//	监听吞掉 B 的整口流量 / 字节错送 — flash 横向审计抓出, 补回归护栏)
func TestRelay_PortReuseScoping(t *testing.T) {
	h := newHarness(t)
	defer h.close()
	src := h.buildSrc(t)
	ch := ":" + gwPortOf(h.gwAddr)

	// ① 同服务: 整口 + 同端口路径 → 复用放行, Start 成功
	p := freePort(t)
	r := New(src)
	cfg := RelayConfig{ListenHost: "127.0.0.1", ServerAddr: h.gwAddr, ServerCAFile: h.caPath, Tunnels: []Tunnel{
		{Service: "s1", Routes: []TunnelRoute{{Channel: ch, Local: ":" + fmt.Sprintf("%d", p)}}, CertID: h.clientPairPath, Enabled: true},
		{Service: "s1", Routes: []TunnelRoute{{Channel: ch, Local: ":" + fmt.Sprintf("%d", p) + "/admin"}}, CertID: h.clientPairPath, Enabled: true},
	}}
	if err := r.Start(cfg); err != nil {
		t.Fatalf("同服务整口+路径应复用放行: %v", err)
	}
	r.Close()

	// ② 跨服务同端口 → 报错(不再静默复用)
	p2 := freePort(t)
	r2 := New(src)
	defer r2.Close()
	cfg2 := RelayConfig{ListenHost: "127.0.0.1", ServerAddr: h.gwAddr, ServerCAFile: h.caPath, Tunnels: []Tunnel{
		{Service: "s1", Routes: []TunnelRoute{{Channel: ch, Local: ":" + fmt.Sprintf("%d", p2)}}, CertID: h.clientPairPath, Enabled: true},
		{Service: "s2", Routes: []TunnelRoute{{Channel: ch, Local: ":" + fmt.Sprintf("%d", p2)}}, CertID: h.clientPairPath, Enabled: true},
	}}
	if err := r2.Start(cfg2); err == nil {
		t.Fatal("跨服务同端口应报错(不再静默错配)")
	}
}

// flash 复审补: 同服务两个整口同端口必须报错(复用条件要求新 route 为路径 route;
// 否则第二个整口变惰性条目静默吞配置错误 — flash 复审抓出)
func TestRelay_PortReuseWholePortConflict(t *testing.T) {
	h := newHarness(t)
	defer h.close()
	src := h.buildSrc(t)
	ch := ":" + gwPortOf(h.gwAddr)
	p := freePort(t)
	r := New(src)
	defer r.Close()
	cfg := RelayConfig{ListenHost: "127.0.0.1", ServerAddr: h.gwAddr, ServerCAFile: h.caPath, Tunnels: []Tunnel{
		{Service: "s1", Routes: []TunnelRoute{{Channel: ch, Local: ":" + fmt.Sprintf("%d", p)}}, CertID: h.clientPairPath, Enabled: true},
		{Service: "s1", Routes: []TunnelRoute{{Channel: ch, Local: ":" + fmt.Sprintf("%d", p)}}, CertID: h.clientPairPath, Enabled: true},
	}}
	if err := r.Start(cfg); err == nil {
		t.Fatal("同服务两个整口同端口应报错")
	}
}

// flash 复审补: Reload 删除宿主整口后, 复用的路径 route 应重建独立监听
// (hasWholePortRuntime 判定路径; 否则端口永久变暗)
func TestRelay_PortReuseRebuildAfterHostDeleted(t *testing.T) {
	h := newHarness(t)
	defer h.close()
	src := h.buildSrc(t)
	ch := ":" + gwPortOf(h.gwAddr)
	p := freePort(t)
	local := ":" + fmt.Sprintf("%d", p)
	pathLocal := local + "/admin"
	r := New(src)
	defer r.Close()
	cfg := RelayConfig{ListenHost: "127.0.0.1", ServerAddr: h.gwAddr, ServerCAFile: h.caPath, Tunnels: []Tunnel{
		{Service: "s1", Routes: []TunnelRoute{{Channel: ch, Local: local}}, CertID: h.clientPairPath, Enabled: true},
		{Service: "s1", Routes: []TunnelRoute{{Channel: ch, Local: pathLocal}}, CertID: h.clientPairPath, Enabled: true},
	}}
	if err := r.Start(cfg); err != nil {
		t.Fatalf("同服务整口+路径应复用放行: %v", err)
	}
	// 初始: 路径 route 复用整口 listener → Running=false(状态不虚报)
	key := "s1@" + ch + "@" + pathLocal
	find := func() (TunnelStatus, bool) {
		for _, s := range r.Status() {
			if s.ID == key {
				return s, true
			}
		}
		return TunnelStatus{}, false
	}
	if s, ok := find(); !ok || s.Running {
		t.Fatalf("初始路径 route 应复用(非 Running): %+v ok=%v", s, ok)
	}
	// Reload 删除整口宿主 → 路径 route 应重建独立监听并 Running
	cfg2 := RelayConfig{ListenHost: "127.0.0.1", ServerAddr: h.gwAddr, ServerCAFile: h.caPath, Tunnels: []Tunnel{
		{Service: "s1", Routes: []TunnelRoute{{Channel: ch, Local: pathLocal}}, CertID: h.clientPairPath, Enabled: true},
	}}
	if err := r.Reload(cfg2); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	s, ok := find()
	if !ok || !s.Running {
		t.Fatalf("宿主整口删除后路径 route 应重建独立监听并 Running: %+v ok=%v", s, ok)
	}
}
