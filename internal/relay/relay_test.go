package relay

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
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
	r := New("", src)
	defer r.Close()

	cfg := RelayConfig{ListenHost: "127.0.0.1", ServerCAFile: h.caPath, Tunnels: []Tunnel{{
		ID: "t1", LocalPort: localPort, RemoteAddr: h.gwAddr,
		ServerName: "gw-server", CertID: h.clientPairPath, Enabled: true,
	}}}
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
	r := New("", src)
	defer r.Close()
	cfg := RelayConfig{ListenHost: "127.0.0.1", ServerCAFile: h.caPath, Tunnels: []Tunnel{
		{ID: "t1", LocalPort: p1, RemoteAddr: h.gwAddr, ServerName: "gw-server", CertID: h.clientPairPath, Enabled: true},
		{ID: "t2", LocalPort: p2, RemoteAddr: h.gwAddr, ServerName: "gw-server", CertID: h.clientPairPath, Enabled: true},
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
	r := New("", src)
	defer r.Close()
	cfg := RelayConfig{ListenHost: "127.0.0.1", ServerCAFile: h.caPath, Tunnels: []Tunnel{{
		ID: "t1", LocalPort: localPort,
		RemoteAddr: "127.0.0.1:1", // 通常不可达
		ServerName: "gw-server", CertID: h.clientPairPath, Enabled: true,
	}}}
	if err := r.Start(cfg); err != nil {
		t.Fatal(err)
	}

	// 第一次连接应失败 (上游连不上), 但 listener 存活
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		t.Fatal(err)
	}
	conn.Write([]byte("x"))
	conn.Close() // 本地连接可建立, 上行失败在 goroutine 内

	// 确认隧道仍注册
	status := r.Status()
	if len(status) != 1 {
		t.Fatalf("want 1 tunnel, got %d", len(status))
	}
	if status[0].ID != "t1" {
		t.Fatalf("tunnel id mismatch")
	}
}

// TestRelay_Reload 增删隧道: reload 后新增隧道生效, 删除的停止
func TestRelay_Reload(t *testing.T) {
	h := newHarness(t)
	defer h.close()
	src := h.buildSrc(t)

	p1 := freePort(t)
	p2 := freePort(t)
	r := New("", src)
	defer r.Close()
	cfg := RelayConfig{ListenHost: "127.0.0.1", ServerCAFile: h.caPath, Tunnels: []Tunnel{
		{ID: "t1", LocalPort: p1, RemoteAddr: h.gwAddr, ServerName: "gw-server", CertID: h.clientPairPath, Enabled: true},
	}}
	if err := r.Start(cfg); err != nil {
		t.Fatal(err)
	}

	// reload: 加 t2, 停 t1
	cfg2 := RelayConfig{ListenHost: "127.0.0.1", ServerCAFile: h.caPath, Tunnels: []Tunnel{
		{ID: "t2", LocalPort: p2, RemoteAddr: h.gwAddr, ServerName: "gw-server", CertID: h.clientPairPath, Enabled: true},
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
	r := New("", src)
	defer r.Close()
	cfg := RelayConfig{ListenHost: "127.0.0.1"}
	if err := r.Start(cfg); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(cfg); err == nil {
		t.Fatalf("expected error on second Start")
	}
}
