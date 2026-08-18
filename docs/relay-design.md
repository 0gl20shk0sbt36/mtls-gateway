# mtls-relay — 客户端 mTLS 中转层 设计方案

> 方案状态:**已审批(2026-08-18)**。实施优先级调整见 §13(先 CLI/WebUI,最后 GUI)。

## 0. 定位:客户端侧的网关(结构对称于服务端 mtls-gw)

`mtls-relay` 本质是**客户端侧的网关**,与服务端 `mtls-gw` 结构镜像对称:

| | 服务端 mtls-gw(已有) | 客户端 mtls-relay(本方案) |
|---|---|---|
| 角色 | 把 mTLS 请求**送进后端** | 把本地明文程序**送进 mTLS** |
| 核心 daemon | 单实例,多 mTLS 端口 | 单实例,多明文端口 |
| 认证 | mTLS 客户端证书 | 选证书做 mTLS 客户端(上行) |
| 管理 API | 独立 `admin_listen` + Unix socket | 本地管理接口(loopback) |
| 外壳 | CLI(有)+ Web 面板(规划中) | CLI / WebUI / GUI(全做) |

一句话:**服务端网关负责"把 mTLS 变成后端可接受的请求",客户端中继负责"把本地程序变成 mTLS"**。两者是同一范式的两个方向——**核心 daemon + 管理 API + 对等壳**,两边共用同一套理念、同一套 Go 代码风格、可复用若干组件。

```
本地程序(不支持 mTLS) ──明文──► [mtls-relay 客户端 daemon] ──mTLS──► [mtls-gw 服务端] ──反代──► 后端服务
                            (把明文送进 mTLS)             (把 mTLS 送进后端)
```

---

## 1. 核心形态(需求澄清后)

1. **单实例 daemon**:mtls-relay 只运行**一个进程**,它同时监听并转发**所有配置好的端口**——不是每个端口一个进程。
2. **「端口 ↔ 证书」是隧道粒度绑定**:
   - 每个**隧道 = 本地端口 + 远端(网关端口/purpose)+ 绑定一个证书**
   - **一个证书可被多个隧道复用**(一证书 → 多端口);约束:一个端口只绑一个证书。
3. **单实例转发所有接口**:daemon 内维护一张**多隧道表**,统一监听、统一转发、统一状态。
4. **外壳(CLI/WebUI/GUI)是 daemon 的客户端**:它们不各自起 Core,而是通过本地管理接口对**同一个** daemon 增删隧道、选证书、起停、看状态——完全对应服务端"CLI/Web 面板都是管理 API 的对等壳"。

---

## 2. 总体架构

```
                     ┌──────────────────────────────────────────────────┐
                     │   mtls-relay 单实例 daemon (客户端网关)          │
                     │                                                  │
  程序A──►127.0.0.1:p1──┐                                               │
  程序B──►127.0.0.1:p2──┼────► Relay Core ──► mTLS 上行(绑证书①)──► │ 网关
  程序C──►127.0.0.1:p3──┘  (隧道表/转发所有端口)  (证书按 CertID 缓存复用)│
                     │   证书① 用于 p1,p2;  证书② 用于 p3               │
                     │                                                  │
                     │   ▲ 本地管理 API(增删隧道/选证书/起停/状态)       │
             ┌───────┼──────────┬─────────────┐                        │
             │       │          │              │                       │
             ▼       ▼          ▼              │                       │
        ┌────────┐┌────────┐┌────────┐        ▼                       │
        │  CLI   ││  WebUI ││  GUI   │  ┌──────────────┐               │
        └────────┘└────────┘└────────┘  │ mtls-gw 网关  │              │
         (外壳 = daemon 客户端)           │(后端端口,mTLS)│             │
                                       └──────────────┘               │
```

- **单实例 daemon** 负责所有隧道端口的监听与转发
- **外壳是 daemon 的客户端**,通过本地管理接口操作;不各自起 Core
- **证书缓存复用**:同 `CertID` 只加载一次,多个隧道/连接共用一份 `tls.Certificate`

### 分层与平台范围

| 层 | 内容 | 平台 |
|----|------|------|
| **核心层 Core** | 多隧道 TCP 转发、mTLS 上行、证书来源抽象、生命周期、状态 | **跨平台(Windows + Linux)** |
| **管理 API** | 本地管理接口,外壳唯一入口 | 跨平台 |
| **外壳 Shell** | CLI(终端)、WebUI(浏览器)、GUI(Windows 窗口) | CLI/WebUI 跨平台;**GUI 仅 Windows** |

> Linux 与 Windows "证书从哪里找"天然不同:Windows 有系统证书库,Linux 无统一身份库(见 §5)。Core 用统一 `Source` 接口 + build tag 隔离,上层不感知差异。

---

## 3. 目录与包规划(新增)

```
cmd/mtls-relay        # 客户端网关 daemon 入口: 加载持久化配置, 起 Core + 管理 API
cmd/mtls-relay-cli    # CLI 外壳 (daemon 的客户端, 与 mtls-gw-cli 风格一致)
internal/relay        # == 核心层 core (纯逻辑, 跨平台) ==
    core.go           # Relay: 多隧道编排, 统一监听/转发/状态
    tunnel.go         # 单个隧道: 本地监听 + 双向 io.Copy + 优雅关闭
    dialer.go         # mTLS 上行拨号器 (客户端证书)
    config.go         # 隧道表 + 证书选择 (多隧道, 证书可复用)
    status.go         # 运行状态: 各隧道 per-port 统计
    api.go            # 本地管理 API (REST/JSON), 外壳唯一入口
internal/certsource   # 证书来源 (核心层依赖, 平台用 build tag 隔离)
    certsource.go     # 接口: List() []IdentityMeta, Load(id) tls.Certificate
    certsource_windows.go  # Windows 系统证书库 (tg123/certstore)  [windows]
    certsource_linux.go    # Linux 统一证书目录扫描                  [linux]
    certsource_file.go     # 文件 pem/p12 来源 (跨平台兜底)
internal/relayweb     # WebUI 外壳: 本地 HTTP server + 内嵌静态页
    server.go         # 代理到 Core 管理 API + 静态前端
    web/              # 单页 JS (go:embed, 无 Node 构建也可)
internal/gui          # GUI 外壳 (仅 Windows, build tag windows)
    app.go            # Wails 应用: 加载 WebUI 前端 + 调 Core 管理 API
```

> Core 不 import 任何 GUI/WebUI;`internal/certsource` 平台实现用 build tag 隔离。管理 API 是核心对外唯一接口(对应服务端 admin API 的角色)。

---

## 4. 核心层详细设计 (internal/relay)

### 4.1 数据模型 (config.go):多隧道 + 证书复用

```go
// 证书选择 (一证书可复用于多条隧道)
type CertSel struct {
    ID     string // Windows thumbprint | Linux 相对路径 | 文件路径
    Source string // "system" | "dir" | "file"
}

// 一条隧道 = 本地端口 + 远端 + 用途 + 绑定证书
type Tunnel struct {
    ID          string  // 隧道 ID (stable)
    LocalPort   int     // 本地监听端口 (程序连这里)
    RemoteAddr  string  // 远端网关后端, 如 gw.example:9443 (对应一用途端口)
    Purpose     string  // 用途 (记录用, 与远端端口对应)
    CertID      string  // 绑定的证书身份 (同一 CertID 可出现在多条隧道 → 复用)
    Enabled     bool    // 是否启用
}

// 持久化配置: 允许多条隧道, 证书可复用
type RelayConfig struct {
    ListenHost string   // 本地监听地址, 默认 127.0.0.1
    Tunnels    []Tunnel
}
```

- **证书复用实现**:Core 以 `CertID` 为 key 做证书缓存 map;加载一次后,多条隧道/多个拨号器共用同一份 `tls.Certificate`
- 配置持久化到本地(如 `~/.mtls-relay/config.json`),daemon 启动自动加载全部隧道

### 4.2 隧道引擎 (tunnel.go / core.go)

- `core.go`:启动时为 `config.Tunnels` 里每一条启用的隧道 `go startTunnel(t)`
- `tunnel.go`:
  - 本地 `net.Listener` 监听 `ListenHost:LocalPort`(默认仅回环)
  - 每来一连接:`acceptLocal` → `dialUpstream(mTLS)` → 双向 `io.Copy`
  - 用该隧道绑定的 `CertID` 取证书 → 构造 Dialer
  - 连接失败:记错误、监听持续存活
  - 优雅关闭:`context` 取消 + `Close()` 关闭所有 listener 与连接池
- **增删隧道/改绑定在 V1 采用"改配置 → 重载隧道集"**(daemon 收到管理 API 变更后增量起/停对应隧道,不必整进程重启;但**不做断流热切换既有连接的证书**)

### 4.3 mTLS 上行拨号器 (dialer.go)

```go
type Dialer struct {
    ServerAddr string          // 网关后端地址
    ServerName string          // TLS SNI (可选)
    ClientCert *tls.Certificate // 取自证书缓存 (按 CertID)
    InsecureSkipVerify bool    // 默认 false: 验证网关服务器证书
}
```

- `tls.DialWithDialer` 建立 mTLS 连接,`ClientCert` 放进 `tls.Config.Certificates`

---

## 5. 证书来源 (internal/certsource)

```go
type IdentityMeta struct {
    ID       string   // Win thumbprint | Linux 相对路径 | 文件路径
    CommonName string
    Issuer   string
    ValidFrom, ValidUntil string
    FoundIn  string   // "system:My" | "dir:~/.mtls-gw/certs" | "file:path"
}
type Source interface {
    List() ([]IdentityMeta, error)
    Load(id string) (tls.Certificate, error)
}
```

**统一「系统证书源」语义**:`Source` 在 Windows/Linux 都代表"从系统找证书",底层实现不同,用 build tag 隔离,Core 不感知。

**Windows(`certsource_windows.go`, build tag `windows`):**
- 基于 `github.com/tg123/certstore`(MIT,去 cgo 版)
- `certstore.Open()` 打开「个人/My」→ `Identities()` 列出所有带私钥身份
- `identity.Certificate()` + `identity.Signer()`(返回 `crypto.Signer`)→ 组 `tls.Certificate{PrivateKey:signer, ...}` 用于 mTLS
- 过滤:默认只展示 Issuer/O 含 `mtls-gw`(或配置 org)签发的身份;可开关「显示全部」

**Linux(`certsource_linux.go`, build tag `linux`):**
- Linux **无统一身份证书库**(`/etc/ssl/certs/` 只含 CA 信任锚、基本无私钥,不能用于 mTLS 客户端认证)→ 用**约定统一证书目录**作为"库":
  - 用户级 `~/.mtls-gw/certs/`(对齐 mtls-gw-cli 导出目录的客户端侧约定)
  - 系统级 `/etc/mtls-gw/certs/`(只读,可选)
- 扫描:`<name>/cert.pem`+`<name>/key.pem`(每子目录一证书),或顶层 `*.p12`
- `ID` = 相对路径;`Load(id)` 读文件加载 `tls.Certificate`
- 同样按 O/Issuer 过滤(可开关「显示全部」)
- 可选增强(非 V1):GNOME Keyring / Secret Service(`org.freedesktop.Secrets`)或 `p11-kit`

**文件(`certsource_file.go`, 跨平台兜底):**
- 从单个 pem / p12 加载(复用 `internal/api/p12.go` 的 p12 解码)
- Windows/Linux 都可用,便于 CLI 手动指定

---

## 6. 本地管理 API (internal/relay/api.go)

对应服务端 admin API 的角色,是外壳唯一入口:

```
GET  /api/status        # daemon 存活 + 各隧道 per-port 状态(流量/连接/错误)
GET  /api/certs         # 列出可用证书 (certsource.List)
POST /api/tunnels       # 新增隧道 (本地端口/远端/用途/绑 CertID)
PUT  /api/tunnels/{id}  # 改隧道 (含换证书绑定)
DELETE /api/tunnels/{id}# 删除隧道
POST /api/reload        # 应用隧道表变更 (增量起/停)
POST /api/start | /api/stop
```

- 只监听 loopback(`127.0.0.1` + 可选本地 socket),不暴露局域网
- 外壳(CLI/WebUI/GUI)全部经此接口操作同一个 daemon

---

## 7. 外壳层(shell)

### 7.1 CLI (cmd/mtls-relay-cli)
与 mtls-gw-cli 一致的风格与 i18n 思路:
```
mtls-relay-cli certs                       # 列出可用证书
mtls-relay-cli tunnel add --local 18080 --remote gw:9443 --purpose dsh --cert <id>
mtls-relay-cli tunnel del <id>
mtls-relay-cli tunnel list
mtls-relay-cli reload
mtls-relay-cli status
```
- `--source system|dir|file`

### 7.2 WebUI (internal/relayweb)
- 本地 HTTP server(仅 loopback),单页
- 流程:①列证书 → ②选证书 ③加隧道(本端口/远端/用途)④起/停/增删隧道 ⑤看各端口流量
- `go:embed` 静态页,V1 用原生 HTML+JS(无 Node 构建);前端调管理 API

### 7.3 GUI (internal/gui, 仅 Windows)
**技术选型(待审批,推荐 Wails v2)**:
- Go 核心 + 内嵌 Web 前端 → 原生 Windows 窗口(WebView2,Win10/11 自带)
- 与 WebUI **复用同一套前端页面**,维护成本低;纯 Go 核心跨平台不受影响
- 界面:配置面板(证书 + 隧道表)+ 起停 + 流量状态;可常驻托盘

替代方案:Wails / Fyne(纯 Go 跨平台,Windows 观感一般、打包大)/ Walk(原生控件,较老、维护弱)/ Electron(重)。

---

## 8. 进程模式(核心决策)

因"单实例转发所有端口"与"外壳是 daemon 客户端",采用 **daemon + 多壳客户端**:

| 进程 | 说明 |
|------|------|
| `mtls-relay` (daemon) | 常驻单实例:Core + 本地管理 API;服务端模式下可加 `systemd`/Windows 服务托管 |
| `mtls-relay-cli` | 客户端,连 daemon 管理 API |
| WebUI | daemon 自己带的 loopback 管理页,或用独立进程连管理 API |
| GUI | Windows 程序,连 daemon 管理 API |

与 mtls-gw 完全同构:**核心 daemon + 管理 API + 对等壳**,且天然解决"一个实例转发所有接口"。

---

## 9. 数据流与安全

```
程序 → 本地 TCP(明文,仅回环) → Core 校验来源(仅 ListenHost) → mTLS 上行 → 服务端网关
```

- 本地明文仅回环(`127.0.0.1`),不暴露局域网
- **认证不降级**:中继层就是那个 mTLS 客户端,服务端对其认证与对浏览器/CLI 完全一致(证书链 + IP 预检 + serial 在册)
- **IP 预检联动**:证书 SAN 绑定的设备 IP 由服务端网关校验;中继上行来源 IP 即本机 TS IP → 应与证书 SAN 一致
- 上行**默认验证网关服务器证书**(`ServerName`),不做全局跳过
- 证书私钥:Windows 在系统库内受保护;Linux/文件源注意文件权限 600

---

## 10. 测试策略(沿用项目自建 CA 约定)

- `internal/relay`:自建临时 CA + 服务端网关 stub + 后端 echo,覆盖
  - 多隧道并发转发正确性(每隧道独立端口/证书)
  - **证书复用**:同一 CertID 用于两条隧道都通
  - 双向字节流、并发多连接
  - 上行 mTLS 失败 → 隧道拒绝、监听存活
  - 增删隧道 reload
  - IP 预检失败(错 IP 证书 → 被网关拒)
- `internal/certsource`:文件源/linux 目录源可测;Windows 系统源用 mock Source 测 Core 侧,真库在 CI(windows runner)验证编译
- CLI/WebUI 冒烟测
- CI:扩展现有 GitHub Actions — linux runner 跑 relay 测试;`windows-latest` runner 编译(含 GUI build tag)

---

## 11. 依赖与许可

| 依赖 | 用途 | 许可 |
|------|------|------|
| `github.com/tg123/certstore` | Windows 系统证书库(mTLS 身份) | MIT |
| `software.sslmate.com/src/go-pkcs12` | 文件 p12 来源 | MPL-2.0(已在用) |
| GUI: `wails.io` | Windows 原生窗口 + 嵌入 Web | MIT |

> 核心层**无新增**依赖;证书来源加 certstore;GUI 加 Wails(仅 `internal/gui`,build tag 隔离,不影响跨平台核心)。

---

## 12. 待审批决策点

| # | 决策 | 推荐 | 说明 |
|---|------|------|------|
| D1 | **进程模式** | **daemon 单实例 + 多壳客户端** | 满足"一实例转发所有端口";与服务端 mtls-gw 同构 |
| D2 | **GUI 技术** | **Wails v2** | 复用 WebUI、纯 Go 核心、WebView2 原生;仅 Windows |
| D3 | **证书来源跨平台** | **Windows 系统库(My)+ Linux 统一目录**;两者带文件兜底 | 核心必须跨平台(Win+Linux) |
| D4 | **隧道/绑定变更生效** | **改配置 → reload 增量起/停**;不做断流热切换 | 简单可靠 |
| D5 | **管理 API & 监听范围** | **仅 127.0.0.1**(+可选本地 socket) | 安全默认 |
| D6 | **证书过滤** | 默认只列 mtls-gw 签发,可「显示全部」 | 减少选择干扰 |

---

## 13. 实施阶段(已审批;GUI 最后做)

> 用户决定:**GUI 外壳最后实施**——先完成核心层 / daemon / CLI / WebUI,GUI 等其余全部做完再动手。阶段顺序相应调整。

**阶段 1(核心层,跨平台)**:`internal/certsource`(接口+文件源+Linux 目录源)→ `internal/relay`(数据模型/隧道引擎/拨号/状态/管理 API)+ 单测(linux 测文件/目录源)
**阶段 2(证书源 Win)**:`certsource_windows.go`(certstore)+ 过滤
**阶段 3(daemon 入口)**:`cmd/mtls-relay`(加载配置、起 Core + 管理 API;systemd/Windows 服务托管)
**阶段 4(CLI)**:`cmd/mtls-relay-cli`(certs/tunnel/reload/status;Win+Linux)
**阶段 5(WebUI)**:`internal/relayweb`(loopback server + 单页)——**用户在 GUI 之前优先完成 WebUI**
**阶段 6(GUI Windows 专用,最后做)**:`internal/gui`(Wails 壳,复用 WebUI 前端,仅 Windows build tag)——**其余阶段全部完成后才实施**
**阶段 7(文档/CI)**:README 增 §客户端中继、CI 加 windows-latest 编译(含 GUI)+ linux 跑 relay 测试、Release 加 mtls-relay 系列产物

---

## 14. 不做什么(V1 边界)

- 不做 SOCKS/HTTP 代理协议转化(只做透明 TCP 字节流中继)
- 不做 TLS 终止/上层协议解析(透明字节流)
- 不做证书断流热切换(改绑定走 reload)
- GUI 仅 Windows;核心层 + CLI/WebUI 跨平台(Win+Linux)
- Linux 不接 GNOME Keyring / p11-kit(V1 用统一证书目录)
- 服务端 Web 管理面板(网关的 WebUI)不属于本方案,仍为 mtls-gw 的未来项(用户确认不急)
- 不改变 mtls-gw 核心的认证流程
