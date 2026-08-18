# mtls-gw — 通用 mTLS 网关

> English version: [README.en.md](README.en.md)

基于 mTLS 客户端证书的通用访问网关。为自建服务提供**设备级认证 + 按用途路由**的统一入口,
不绑定任何特定应用——任何自建服务都可复用。

```
设备(持有设备证书)
  → [mtls-gw] (mTLS 验证 + IP 预检 + 授权 + 路由)
      ├─ 应用A → http://127.0.0.1:3080
      ├─ 应用B → http://127.0.0.1:8081   (未来应用, 配置加一行即可)
      └─ 管理端口 (admin_listen) → 管理 API (仅 admin 证书)
```

---

## 1. 核心设计

### 1.1 证书 = 身份, 数据库 = 权限 (职责分离)

| 层 | 承载 | 说明 |
|----|------|------|
| **证书** | 身份 | serial(序列号, 唯一主键) + SAN 绑定设备 IP |
| **SQLite** | 权限 | serial → {name, purpose, status, expires} |

- 证书里**不写用途/权限字段**——"admin 判断"完全靠内部数据库,不靠证书 CN/字段
- 用途是列表: `admin` / `app-a` / 未来任意用途
- 吊销/改权限只改数据库,不用重签证书

### 1.2 验证流程 (每次请求)

```
1. TLS 握手 → 证书链验证 (ClientCAs = 受信 CA 池)
   └─ 这只是最低门槛: 证书必须由受信 CA 签发, 但不代表有权限
2. IP 预检: 证书 SAN IP == 来源 IP? 不等 → 立即拒绝 (不碰数据库)
   └─ 防私钥复制: 证书拷到别的设备, 来源 IP 不匹配 → 拒绝
3. 内存查表: serial → 记录 (纳秒级, 零 IO)
   ├─ serial 不在数据库 → 拒绝 (即使 CA 签发, 未登记也进不来)
   ├─ status=revoked → 拒绝
   └─ 过期 → 拒绝
4. 按 purpose 授权 → 路由到对应后端
```

> 安全模型是**双重门槛**: ①证书链验证(CA 签发) ②数据库登记(serial 在册)。
> 单有其一不够——CA 签了但没登记, 或登记了但证书不是该 CA 签的, 都会被拒。

### 1.3 内存即权威 (性能设计)

- 启动时全量加载 SQLite → 内存 map (serial → record)
- **请求验证只查内存** (纳秒级, 不碰磁盘)
- 变更操作 (签发/吊销) 同步更新内存 + 写 SQLite
- 数据量小 (几十条证书), 无缓存一致性问题

### 1.4 管理双通道

| 通道 | 用途 | 认证 |
|------|------|------|
| Unix socket | 本机 CLI | 文件权限 600 = 直接 admin |
| TCP (mTLS) | 远程 Web 面板 (未来) | admin 用途证书 |

### 1.5 免改后端的 Host/Origin 改写

mtls-gw 反代时把 `Host` 和 `Origin` 改写为后端的 loopback 地址:

```
浏览器请求: Host: gw.example:9443, Origin: https://gw.example:9443
mtls-gw 改写 → Host: 127.0.0.1:3080, Origin: https://127.0.0.1:3080
后端信任围栏: 看到 loopback → 特权方法天然放行
```

→ **完全不需要修改后端源码, 升级无忧**

---

## 2. 部署

### 2.1 构建

```bash
cd mtls-gateway
go build -o mtls-gw ./cmd/mtls-gw
go build -o mtls-gw-cli ./cmd/mtls-gw-cli
```

### 2.2 安装

```bash
sudo cp mtls-gw /usr/local/bin/
sudo cp mtls-gw-cli /usr/local/bin/
sudo mkdir -p /var/lib/mtls-gw/certs
sudo chown -R $(whoami):$(whoami) /var/lib/mtls-gw
sudo mkdir -p /etc/mtls-gw
```

### 2.3 配置 `/etc/mtls-gw/config.json`

```json
{
  "listen": "0.0.0.0:9443",
  "admin_listen": "0.0.0.0:9444",
  "ca": "/etc/mtls-gw/ca.crt",
  "ca_key": "/etc/mtls-gw/ca.key",
  "server_cert": "/etc/mtls-gw/server.crt",
  "server_key": "/etc/mtls-gw/server.key",
  "cert_dir": "/var/lib/mtls-gw/certs",
  "sock_path": "/run/mtls-gw/mtls-gw.sock",
  "org": "my-org",
  "ou": "device",
  "default_days": 365,
  "admin_days": 30,
  "require_ip_bind": true,
  "backends": {
    "app-a": {
      "target": "http://127.0.0.1:3080",
      "listen": "0.0.0.0:9443"
    }
  }
}
```

- `admin_listen`: 管理 API 端口 (admin 证书)
- `require_ip_bind`: 是否强制证书 SAN IP == 来源 IP (true/false)
- `org` / `ou`: 签发证书的 O/OU 字段 (默认 "mtls-gw"/"device")
- `default_days`: 普通用途默认有效期 (默认 365)
- `admin_days`: admin 用途默认有效期 (默认 30)
- `backends`: **用途 → {target, listen}** 映射。`target`=后端上游地址, `listen`=该用途的 mTLS 监听地址 (多端口一用途一端口), 加新应用就加一个用途块

### 配置分工 (哪些放配置, 哪些用参数)

| 内容 | 位置 | 理由 |
|------|------|------|
| 监听地址/CA 路径/服务器证书 | 配置文件 | 部署级, 一次定 |
| 证书模板 (org/ou/默认天数) | 配置文件 | 全局统一 |
| 设备名/用途/TS-IP | CLI 参数 | 每次签发不同 |
| 有效期天数/密码 | CLI 参数 (可选) | 按需覆盖默认 |

### 2.4 systemd 服务 `/etc/systemd/system/mtls-gw.service`

```ini
[Unit]
Description=mtls-gw — 通用 mTLS 网关
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=<运行用户>
WorkingDirectory=/home/<用户>
RuntimeDirectory=mtls-gw
RuntimeDirectoryMode=0750
ExecStart=/usr/local/bin/mtls-gw -config /etc/mtls-gw/config.json -db /var/lib/mtls-gw/mtls-gw.db -sock /run/mtls-gw/mtls-gw.sock
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now mtls-gw
```

---

## 3. 使用 (CLI)

```bash
# 签发证书 (本机 = 直接 admin, 走 Unix socket)
mtls-gw-cli issue admin --purpose admin --ts-ip <管理机IP> --days 30
mtls-gw-cli issue device-1 --purpose app-a --ts-ip <设备1IP> --days 365

# 吊销证书
mtls-gw-cli revoke <serial>

# 列出所有证书
mtls-gw-cli list

# 健康检查
mtls-gw-cli health

# 自定义 socket (非默认路径时)
mtls-gw-cli --sock /run/mtls-gw/mtls-gw.sock list
```

签发产出:
- `/var/lib/mtls-gw/certs/<name>/cert.pem` — 证书
- `/var/lib/mtls-gw/certs/<name>/key.pem` — 私钥
- `/var/lib/mtls-gw/certs/<name>/device.p12` — 浏览器/手机导入用 (密码打印在 CLI 输出)

---

## 4. 客户端接入

### 4.1 浏览器 (Windows/macOS)

导入 p12 (certmgr 或 `Import-PfxCertificate`) 后, 访问网关地址 → 弹出证书选择 → 选设备证书 → 进入。

### 4.2 手机

- Android: 设置 → 安全 → 安装证书 → 选 device.p12
- iOS: 传输 p12 → 安装描述文件 → 信任

### 4.3 命令行工具

```bash
curl --cert cert.pem --key key.pem https://<网关地址>:9443/
```

> 注: Windows schannel 在 TLS 1.3 + 客户端证书有兼容问题 (SEC_E_INTERNAL_ERROR),
> 浏览器 (BoringSSL) 不受影响; 命令行建议用 TLS 1.2 或直接浏览器。

---

## 5. 安全模型

| 威胁 | 防御 |
|------|------|
| 私钥复制到别的设备 | IP 预检: 证书 SAN IP ≠ 来源 IP → 拒绝 |
| 证书泄露/设备丢失 | 吊销单个证书 (数据库改状态, 立即生效) |
| 证书过期 | 签发时设有效期 (admin 建议短周期) |
| 设备证书攻击管理面 | 权限分离: 管理 API 仅在 admin_listen 端口, 仅 admin 用途 |
| 未注册证书 | 内存表查不到 serial → 拒绝 |
| DNS rebinding / CSRF (后端) | Host/Origin 改写为 loopback, 围栏天然通过 |

### 已知限制

- **IP 绑定网络**: SAN 绑定的是设备 IP, 设备必须走绑定网络 (如 tailnet) 才能通过 IP 预检
- 若需要多网络访问, 可给证书 SAN 加多个 IP 或改用 TrustSource 抽象 (见下)

---

## 6. 未来扩展

### 6.1 TrustSource 抽象 (规划)

当前 IP 预检绑定特定网络 IP。计划抽象为可插拔的信任源:

```
TrustSource (接口) ── authorize(请求) → {设备标识} | 拒绝
    ├─ IPBindSource     ← 当前: SAN IP 绑定
    ├─ LanSource        ← 纯局域网 IP 白名单
    └─ (未来) 其他网络...
```

### 6.2 Web 管理面板 (规划)

CLI 和 Web 面板都是核心进程的壳, 都调核心 API (不是 Web 调 CLI):

```
核心进程 (mtls-gw daemon) ── 管理 API (受控操作 + 审计)
    ├─ CLI (壳)
    └─ Web 面板 (壳, 经 admin 证书)
```

### 6.3 对接更多应用

`config.json` 的 `backends` 加一行即可:

```json
"backends": {
  "app-a": { "target": "http://127.0.0.1:3080", "listen": "0.0.0.0:9443" },
  "app-b": { "target": "http://127.0.0.1:8081", "listen": "0.0.0.0:9445" }
}
```

对应签发证书 `--purpose app-b`。

---

## 7. 开发踩坑记录

1. **Go flag 遇非 flag 参数即停**: `--purpose admin` 在位置参数后不解析 → 需手动分类参数
2. **/run 根目录无写权限**: 普通用户 bind Unix socket 失败 → 用 systemd `RuntimeDirectory`
3. **管理面路径冲突**: 早期管理 API 在业务端口用 `/admin/` 前缀 (与后端 `/api/` RPC 冲突); 已重构为独立管理端口 `admin_listen` (如 9444), 彻底避开前缀冲突
4. **Origin 头必须同步改写**: 只改 Host 不改 Origin → 浏览器请求 403
5. **旧进程未重启**: 改 json tag 后 daemon 不重启, API 返回旧格式

---

## 8. 单元测试

```bash
go test ./...          # 全部测试
go test -v ./...       # 详细输出
go test -cover ./...   # 覆盖率
```

共 26 个测试, `go test ./...` 全部通过。实测覆盖率:

| 包 | 覆盖率 |
|----|--------|
| `internal/db` | 83.6% |
| `internal/proxy` | 84.4% |
| `internal/auth` | 67.9% |
| `internal/api` | 59.6% |
| `cmd/mtls-gw`, `cmd/mtls-gw-cli`, `internal/i18n` | 0% (命令入口 / 纯消息表, 低优) |

> CLI 提示语言自动检测: `LC_ALL` > `LC_MESSAGES` > `LANG`, 默认中文; 消息表集中在 `internal/i18n`。

测试要点:
- 测试内自建临时 CA + 服务器证书, 不依赖部署环境
- `TestAuthorizeIPMismatch` 验证私钥复制到别的设备会被拒 (IP 预检)
- `TestHostRewrite` / `TestOriginRewrite` 验证反代头改写 (免改后端的关键)

---

## 9. 客户端中继 (mtls-relay)

`mtls-relay` 是**客户端侧的中继层(客户端网关)**, 为**不支持 mTLS 的本地程序**提供到 `mtls-gw` 受保护服务的透明转发:

```
本地程序(不支持 mTLS) ──明文──► [mtls-relay 客户端 daemon] ──mTLS──► [mtls-gw 服务端] ──反代──► 后端服务
                            (把明文送进 mTLS)              (把 mTLS 送进后端)
```

- **单实例 daemon**, 同时监听并转发所有配置的端口(隧道), 不是每端口一个进程。
- **端口 ↔ 证书是隧道粒度绑定**: 每隧道 = 本地端口 + 远端(网关后端) + 绑一个证书; **一个证书可复用绑定多个端口**(同一 `CertID` 复用于多条隧道)。
- 结构与服务端 mtls-gw 对称: **核心 daemon + 本地管理 API + 对等壳(CLI/WebUI/GUI)**。

### 9.1 构成

| 命令/包 | 说明 |
|---------|------|
| `cmd/mtls-relay` | 客户端 daemon: 加载配置, 起核心 + 本地管理 API + WebUI |
| `cmd/mtls-relay-cli` | CLI 外壳: certs / tunnel / reload / start / stop / status / config |
| `internal/relay` | 核心层(跨平台): 多隧道转发生命周期, mTLS 上行, 管理 API |
| `internal/certsource` | 证书来源抽象: Windows 系统证书库 / Linux 统一目录 / 文件(pem/p12) |
| `internal/relayweb` | WebUI 外壳: 本地单页面板(go:embed, 无 Node 构建) |
| `internal/gui` | GUI 外壳(仅 Windows, 规划/最后实施) |

### 9.2 使用

```bash
# 构建
go build -o mtls-relay ./cmd/mtls-relay
go build -o mtls-relay-cli ./cmd/mtls-relay-cli

# 启动 daemon (默认证书来源=系统: Windows 个人库 / Linux ~/.mtls-gw/certs)
./mtls-relay -config ~/.mtls-relay/config.json -listen-admin 127.0.0.1:18081

# 用 CLI 选证书 + 加隧道
mtls-relay-cli certs
mtls-relay-cli tunnel add --id dsh --local 18080 --remote gw.example:9443 --cert <ID>
mtls-relay-cli reload          # 或 start(首次)
mtls-relay-cli status

# 文件来源(跨平台兜底)
./mtls-relay -source file -source-arg /path/to/client.pem
```

- WebUI: 浏览器打开 `http://127.0.0.1:18081/`(仅本机回环)。
- 证书来源可用 `--source system|dir|file`; `--filter-org` 只展示指定 org 签发的证书, `--show-all` 显示全部。
- 本地默认仅监听 `127.0.0.1`, 不暴露局域网; 上行默认验证网关服务器证书(可用 `server_ca` 配置网关 CA, 否则用系统根)。

### 9.3 客户端中继的测试

核心层 `internal/relay` 与 `internal/certsource` 自建临时 CA + mTLS 网关 stub(echo) 覆盖:
- 单隧道/多隧道转发、并发
- **证书复用**(同一 CertID 用于两条隧道都通)
- 上行 mTLS 失败 → 该连接被拒但监听存活
- 增删隧道 reload、路径穿越防护、org 过滤
