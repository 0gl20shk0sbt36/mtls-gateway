// Package relay 实现客户端 mTLS 中继层核心 (客户端侧的网关)。
//
// 形态: 单实例 daemon, 同时监听并转发所有配置的端口(隧道)。
// 每条隧道 = 本地端口 + 远端(网关后端) + 用途 + 绑定一个证书;
// 一个证书可通过 CertID 复用于多条隧道(缓存复用)。
//
// 外壳(CLI/WebUI/GUI)都是本核心的客户端, 经本地管理 API 操作它,
// 与服务端 mtls-gw 的 "核心 daemon + 管理 API + 对等壳" 结构一致。
package relay

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// CertSel 证书选择 (一证书可复用于多条隧道)
type CertSel struct {
	ID     string `json:"id"`     // Windows thumbprint | 目录相对路径 | 文件路径
	Source string `json:"source"` // certsource.SourceType: "system" | "dir" | "file"
	Arg    string `json:"arg"`    // 非 system 来源时的目录/文件路径 (system 时忽略)
}

// TunnelRoute 服务的一条通道 + 本地路由
type TunnelRoute struct {
	Channel string `json:"channel"` // 服务端入口 :port[/path]
	Local   string `json:"local"`   // 本地路由 :port[/path] (默认同 channel; 带路径=HTTP反代模式)
}

// Tunnel 一条服务级隧道记录 = 一个服务的全部通道(增删都以整个服务为单位)
type Tunnel struct {
	Service string        `json:"service"` // 服务名 (唯一)
	CertID  string        `json:"cert_id"` // 绑定的证书身份
	Routes  []TunnelRoute `json:"routes"`  // 该服务的所有通道 + 本地路由
	Enabled bool          `json:"enabled"` // 是否启用
}

// ID 隧道唯一标识 = 服务名
func (t Tunnel) ID() string { return t.Service }

// FindRoute 按服务端入口找路由
func (t Tunnel) FindRoute(channel string) *TunnelRoute {
	for i := range t.Routes {
		if t.Routes[i].Channel == channel {
			return &t.Routes[i]
		}
	}
	return nil
}

// LocalPort 路由本地监听端口 (":8080/foo" → "8080")
func (r TunnelRoute) LocalPort() string { return portOfListen(r.Local) }

// LocalPath 路由本地路径前缀 (":8080/foo" → "/foo"; 空=TCP 透传模式)
func (r TunnelRoute) LocalPath() string { return pathOfListen(r.Local) }

// ChannelPort 路由服务端入口端口 (":9445/admin" → "9445")
func (r TunnelRoute) ChannelPort() string { return portOfListen(r.Channel) }

// ChannelPath 路由服务端入口路径前缀
func (r TunnelRoute) ChannelPath() string { return pathOfListen(r.Channel) }

// RelayConfig 持久化配置: 允许多条隧道, 证书可复用
type RelayConfig struct {
	ServerAddr         string   `json:"server_addr,omitempty"` // 服务端 /info 发现端点, 如 gw.example:9499
	AdminAddr          string   `json:"admin_addr,omitempty"`  // 服务端 admin 端点, 如 gw.example:9444 (证书管理)
	ListenHost         string   `json:"listen_host"`           // 本地监听地址, 默认 127.0.0.1
	ServerCAFile       string   `json:"server_ca,omitempty"`   // 网关 CA 文件路径 (验证网关服务器证书; 空=系统根)
	WebUILogFile       string   `json:"webui_log_file,omitempty"`    // WebUI 界面事件日志(短时大量, 单独文件); 空=关
	WebUILogMaxSizeMB  int      `json:"webui_log_max_size,omitempty"` // 单文件上限 MB (默认 10)
	WebUILogMaxFiles   int      `json:"webui_log_max_files,omitempty"` // 保留份数 (默认 5)
	Lang               string   `json:"lang,omitempty"`               // 错误消息语言: zh | en (默认 zh)
	Tunnels            []Tunnel `json:"tunnels"`
}

// DefaultListenHost 默认本地监听地址 (仅回环, 不暴露局域网)
const DefaultListenHost = "127.0.0.1"

// LoadConfig 从 JSON 文件加载配置; 文件不存在返回默认空配置
func LoadConfig(path string) (RelayConfig, error) {
	cfg := RelayConfig{ListenHost: DefaultListenHost}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("read config %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config %s: %w", path, err)
	}
	if cfg.ListenHost == "" {
		cfg.ListenHost = DefaultListenHost
	}
	return cfg, nil
}

// SaveConfig 将配置写回 JSON 文件 (目录自动创建)
func SaveConfig(path string, cfg RelayConfig) error {
	if cfg.ListenHost == "" {
		cfg.ListenHost = DefaultListenHost
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("mkdir config dir: %w", err)
	}
	// 原子替换: CreateTemp 真唯一临时文件 + rename(防并发写同一 tmp 踩踏; 避免崩溃留半截 JSON)
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp config: %w", err)
	}
	defer os.Remove(tmp.Name()) // rename 失败/异常时清理残留
	if _, err := tmp.Write(data); err != nil { // 用句柄写(避免二次打开 + fd 泄漏)
		tmp.Close()
		return fmt.Errorf("write config %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp config: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("replace config %s: %w", path, err)
	}
	return nil
}

// FindTunnel 按 ID 查找隧道
func (c *RelayConfig) FindTunnel(id string) (*Tunnel, bool) {
	for i := range c.Tunnels {
		if c.Tunnels[i].ID() == id {
			return &c.Tunnels[i], true
		}
	}
	return nil, false
}

// UpsertTunnel 新增或覆盖隧道 (按 ID)
func (c *RelayConfig) UpsertTunnel(t Tunnel) {
	for i := range c.Tunnels {
		if c.Tunnels[i].ID() == t.ID() {
			c.Tunnels[i] = t
			return
		}
	}
	c.Tunnels = append(c.Tunnels, t)
}

// DelTunnel 删除隧道 (按 ID), 返回是否删除
func (c *RelayConfig) DelTunnel(id string) bool {
	for i := range c.Tunnels {
		if c.Tunnels[i].ID() == id {
			c.Tunnels = append(c.Tunnels[:i], c.Tunnels[i+1:]...)
			return true
		}
	}
	return false
}
