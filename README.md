# mtls-gw — 通用 mTLS 网关

基于 mTLS 客户端证书的**通用访问网关**: 设备级认证 + 按角色路由, 不绑定特定应用, 任何自建服务可复用。

> **项目缘起**: 最初为 **DSH(自托管 DeepSeek 对话服务)** 设计, 解决"只让自家设备访问"的问题;
> 随后抽象为通用 mTLS 网关, 对接任意 HTTP 服务只需加一个 `mappings` 通道 + `services` 声明 + 签对应 `roles` 证书。

## 架构一句话

**证书 = 身份, SQLite = 权限**。每次请求过双重门槛: ① TLS 证书链验证(CA 签发) ② 数据库登记(serial 在册 + 未吊销 + 未过期)。**内存即权威**: 启动全量载入 SQLite → map, 请求验证只查内存零 IO, 变更同步写 DB。

```
客户端(带设备证书) ──mTLS──▶ mtls-gw ──▶ 后端服务
                              │
                              ├─ /info 端口: 服务发现(任一已登记证书)
                              ├─ /admin/reload: 全量热重载(仅 admin_role 证书, 管理进程调用)
                              └─ 业务端口: 按 mappings 路由 + services 角色授权

mtls-admin(独立管理进程): admin 端口 签发/吊销/配置(仅 admin_role 证书) + Unix socket(本机 CLI)
```

---

## 1. 核心设计

### 1.1 证书 = 身份, 数据库 = 权限(职责分离)

- 证书里**不写用途/权限字段**; 权限全在 SQLite。吊销/改权限只改 DB, 不用重签证书。
- 证书 SAN 绑定设备 IP(TS IP), 私钥复制到别的设备会因 IP 不匹配被拒(`require_ip_bind=true`)。
- 一张证书可授予**多个角色**(`roles` 列表), 一个角色可访问多个服务。

### 1.2 映射与授权模型(双表)

**mappings(通道)** = 唯一路由实体, 判重靠 `listen`:

```toml
[[mappings]]
id = "dsh-main"                    # 助记符(服务用 id 引用)
listen = ":9443"                   # 入口 :端口[/路径]
target = "http://127.0.0.1:3080"   # 后端地址(URL 带路径=前缀替换, nginx proxy_pass 语义)
```

**services(服务)** = 所有服务必须声明, 授权靠角色交集:

```toml
[[services]]
name = "dsh"
channels = ["dsh-main"]            # 本服务的通道(mapping id)
roles = ["dsh"]                    # 允许访问的角色; "any" = 任一已登记证书
```

授权规则: 请求命中映射后, 证书 `roles` 与引用该映射的所有服务 `roles` 并集有交集(或含 `any`)才放行, 否则 403。

### 1.3 路由与转发

- 同端口多路径**最长前缀匹配**, 无路径 = 整口兜底。
- 前缀替换: `listen` 的路径前缀剥掉, 换成 `target` 的路径前缀。
- **Host/Origin 自动改写**为后端 loopback 地址, 免改后端信任围栏。
- WebSocket 透传(Hijacker 透传)。
- 匹配前规范化请求路径(清理 `..`/`.` dot-segment + 反斜杠, 防路径穿越)。

### 1.4 验证流程(每次请求)

1. mTLS 握手(TLS 1.2+, 客户端证书链验 CA)
2. IP 预检(证书 SAN IP == 来源 IP, `require_ip_bind=true` 时)
3. serial 查内存表(在册 + `enabled` + 未过期)
4. 命中映射 + 角色授权判定
5. 反向代理转发

### 1.5 管理双通道(独立管理进程 mtls-admin)

管理功能运行在**独立进程 mtls-admin** 中(与网关 mtls-gw 读同一 config.toml):
网关是纯数据面(认证+路由+转发), 管理进程是唯一写者(DB/配置), 变更后调网关 `POST /admin/reload`
全量热重载(内存副本只读, 原子替换)。

| 通道 | 访问方式 | 权限 |
|---|---|---|
| Unix socket(本机 CLI) | 文件权限 600 | 直接 admin(仅 Linux) |
| TCP admin API | mTLS 证书 | 仅 `admin_role` 证书 |

CLI 与 Web 面板都是管理 API 的**对等壳**, Web 不直接调 CLI; 两者均连 mtls-admin。

### 1.6 术语与概念(速查)

| 术语 | 含义 |
|---|---|
| **mTLS 网关** | 本项目服务端总称: 设备级证书认证 + 按角色路由, 不绑定特定应用 |
| **mtls-gw / mtls-admin** | 服务端**两个进程**: 网关=纯数据面(认证+路由+转发), 管理进程=唯一写者(签发/吊销/改配置)。读同一 config.toml, 各自忽略无关字段 |
| **证书 = 身份, SQLite = 权限** | 证书只证明"你是谁"(CA 签发 + SAN 绑 IP), 权限(角色)全在数据库; 改权限/吊销不用重签证书 |
| **roles vs purposes** | **同一个概念的两个名字**: 配置里叫 `roles`(服务声明/签发校验), DB 字段叫 `purposes`(证书的角色列表)。二者是同一角色体系, 不是两套东西 |
| **角色(role)** | 角色名 `[A-Za-z0-9_-]+`; 服务 roles 与签发 purposes 都必须在配置 `roles` 声明列表中 |
| **`any` 角色** | 服务声明里写 `any` = 任意**已登记**证书可访问(仍要过 mTLS + 登记校验); 禁止声明为普通角色/签发给证书 |
| **`null` 路由** | 服务 roles 里写 `null` = **匿名放行**(无需证书, 任意来源可访问); 部署方负责端口暴露面 |
| **`admin_role`** | 内置管理角色(默认 `mtls-superadmin`): 证书持该角色即管理权限; 禁止出现在服务 roles / roles 声明列表(防提权) |
| **TS IP** | 证书 SAN 绑定的设备 IP(`--ts-ip` 参数, 通常是 Tailscale 分配的 100.x 地址); `require_ip_bind=true` 时来源 IP 必须匹配, 防私钥复制到别的设备 |
| **mapping / service** | 通道(唯一路由实体, `listen` 判重) / 服务注册(`channels` 引用 mapping id + `roles` 授权); 授权=证书 roles 与引用该映射的所有服务 roles 并集有交集 |
| **整口 vs 路径路由** | `listen` 无路径 = 整口兜底(客户端 relay 走 TCP 透传); 带路径 = 前缀匹配(HTTP 反代, nginx proxy_pass 语义); 同端口多路径共享监听 |
| **relay(客户端)** | **relay 是客户端**: 主动用设备证书外拨到网关(服务端), 把网关服务映射成本机端口; 拓扑方向是"客户端 → 网关", 不要被包名 `relay` 误读为服务端 |
| **`/info` 服务发现** | 网关匿名端点: 无证书返回 CA(客户端据此过滤证书源), 有证书返回该证书可访问的服务列表; relay 只需配一个 `server_addr` |
| **config_mode 三态** | `mutable`(改+落盘备份, 默认) / `ephemeral`(只改内存不落盘, 测试/临时用) / `immutable`(只读, 配置 CRUD 拒绝); 改后需重启两进程生效 |
| **X-Auth-Purpose** | 管理 API **内部信任头**: 仅在外层 mTLS 认证 + admin_role 校验通过后由 mtls-admin 设置; 内层据此放行, 客户端伪造无效(外层先拦) |
| **网关独立运行** | mtls-gw 不依赖 mtls-admin: 最小配置(仅数据面字段)即可独立启动, 认证/路由/转发/日志全可用; 只是无法签发证书/在线改配置(建议配 `immutable`) |

---

## 2. 快速开始

### 2.1 构建

```bash
go build ./cmd/mtls-gw ./cmd/mtls-gw-cli ./cmd/mtls-relay
```

### 2.2 配置

```bash
cp config.example.toml /etc/mtls-gw/config.toml
# 编辑: 填 CA/证书路径、mappings、services
```

完整字段见 [config.example.toml](./config.example.toml)。核心字段:

| 字段 | 说明 |
|---|---|
| `bind_host` | 所有监听(业务/管理/发现)的绑定地址 |
| `ca` / `ca_key` | CA 证书/私钥(签发用; 私钥 600) |
| `server_cert` / `server_key` | 网关自身 TLS 证书 |
| `admin_role` | 内置管理角色名(默认 `mtls-superadmin`; 别用常用名) |
| `info_listen` | `/info` 服务发现端口(任一已登记证书) |
| `reload_listen` | 网关 `/admin/reload` 端口(管理进程调用, 仅 admin_role 证书; 空=与 info 同端口合并) |
| `admin_listen` | 管理 API 端口(仅 admin_role 证书; 属于 mtls-admin 进程) |
| `config_mode` | `mutable`(落盘, 默认) / `ephemeral`(仅内存) / `immutable`(只读) |
| `lang` | 错误消息语言 `zh` / `en`(默认 zh) |
| `key_type` / `key_bits` | 签发密钥: rsa 2048/3072/4096 或 ecdsa 256/384/521 |
| `default_days` / `admin_days` | 普通/管理证书默认有效期 |

### 2.3 启动(两个进程)

```bash
/usr/local/bin/mtls-gw   -config /etc/mtls-gw/config.toml   # 网关(纯数据面)
/usr/local/bin/mtls-admin -config /etc/mtls-gw/config.toml  # 管理进程(签发/吊销/配置)
```

### 2.4 签发证书(本机 CLI, 连 mtls-admin 的 Unix socket)

```bash
mtls-gw-cli -sock /run/mtls-gw/mtls-gw.sock issue \
  -name dev-laptop -purpose dsh -ts-ip 100.64.0.10
mtls-gw-cli revoke -serial <serial>
mtls-gw-cli list
```

> Unix socket 由 mtls-admin 提供(与网关读同一 config, sock_path 一致)。
> Windows 无 Unix socket, 签发走 TCP admin API(需 admin 证书, admin_addr 指向 mtls-admin)。

---

## 3. 客户端接入

### 3.1 客户端中继(mtls-relay)

客户端设备跑 relay daemon: `/info` 发现 → 按服务建本地隧道 → WebUI 管理。

```bash
mtls-relay -config ~/.mtls-relay/relay.json
# 或 WebUI: 选证书 → 验证 → 加服务隧道
```

relay 配置(`relay.json`):

```json
{
  "server_addr": "gw.example:9499",
  "admin_addr": "gw.example:9444",
  "server_ca": "/path/to/ca.crt",
  "listen_host": "127.0.0.1",
  "cert_dir": "/path/to/certs",
  "tunnels": [
    {"service": "dsh", "cert_id": "dev-laptop", "routes": [{"channel": ":9443", "local": ":9443"}]}
  ]
}
```

- `server_addr` = `/info` 发现端点; `admin_addr` = admin 端点(证书管理, 独立)
- `cert_dir` = 客户端证书源: 空=系统证书库(平台原生身份库: Windows 系统证书库「个人/My」CNG / Linux 约定目录 `~/.mtls-gw/certs` / Android 应用私有目录), 非空=目录源(每子目录一个证书); 配置优先于启动参数 `-source`/`-source-arg`
- `log_file` = 运行日志路径(隧道/证书/连接事件, **终端+文件双写**; 空=分平台默认: Windows exe 目录/`mtls-relay` 组件子目录 / Linux `~/.cache/mtls-relay`)
- 隧道按**服务**建(一个服务含多个通道), 本地路由可覆盖端口/路径
- 证书轮换/服务端地址变化自动重建隧道

### 3.2 WebUI

relay 自带 WebUI(`--listen-admin :28083`):

- **运行控制 + 隧道表**(按服务聚合, 状态/流量)
- **证书选择**(选中后 `/info` 发现该证书可访问的服务)
- **新增隧道**(按服务选 → 自动带出本地路由)
- **证书管理台**(默认锁定: 选 admin 证书 → 密码解锁 → 经 admin_addr 签发/吊销)

### 3.3 浏览器 / 手机

把 p12 证书(含私钥+密码)导入浏览器/手机即可, 无需额外软件。

---

## 4. 安全模型

- **双向 mTLS**: 客户端验网关 CA, 网关验客户端 CA 链
- **证书 SAN 绑 IP**: 私钥复制到别的设备因 IP 不匹配被拒
- **角色最小授权**: 证书角色与服务角色交集; admin_role 证书只能进管理 API, 不能访问业务
- **管理面隔离**: 业务/管理/发现三个端口分离; 管理 API 独立于业务端口
- **DNS rebinding 防护**: relay 管理 API 强制 loopback + Origin 校验
- **server_ca 不可用拒绝启动**: 防降级系统根被 MITM 冒充网关
- **启动权限预检(Linux)**: 启动时检查配置引用的全部文件/目录权限(CA/DB/证书/日志/sock/落盘目录), 不足拒绝启动并输出到 stderr(尽力写事件日志) — 防"目录不可写带病运行"致落盘失败/内存分叉。密钥文件额外要求 `mode&0o007==0`(禁 world 可读/写); **0640(group 可读)放行** — 权衡: 单用户/可信组部署常见, 若要"仅属主可读"请自行收紧为 0600
- **同名证书禁止**: 签发前查重(含已吊销), 防同名混淆
- **错误脱敏**: 认证失败只回 `forbidden`, 细节仅写事件日志
- **超时/体积限制**: 全端口 ReadTimeout/WriteTimeout/IdleTimeout + 请求体 MaxBytesReader 4MB

### 已知限制

- Windows 无 Unix socket, CLI 签发走 TCP admin API
- 证书有效期按 `yyyy-mm-dd` 字符串比较(到期日当天仍有效)
- 未配置 `gateway_reload_addr` 时, 运行时新增证书需手动调网关 `/admin/reload`(或重启)才能被 `/info` 获取; 配置了则 mtls-admin 在每次签发/吊销后自动 reload 网关

---

## 5. 测试

```bash
go test -race ./...          # Go 单测/集成(235 个测试函数, -race 全绿)
go vet ./...
gofmt -l cmd internal        # 应为空(CI 强制)

# 前端
node --test internal/relayweb/web/test/*.test.js   # 单元测试 8 例
# E2E(需先跑 setup.sh 生成环境)
bash internal/relayweb/web/e2e/setup.sh /tmp/mtls-e2e
node --test internal/relayweb/web/e2e/*.test.mjs   # 15 例
```

- 测试内**自建临时 CA + 服务器证书**, 不依赖部署环境。
- CI(GitHub Actions): 双 Go 版本(1.25/1.26) build+vet+gofmt+test+race / WebUI 单测 / playwright E2E / windows 真机测试 / windows+android 交叉编译; 打 tag 自动多平台编译发 Release。

---

## 6. 项目结构

| 目录 | 职责 |
|---|---|
| `cmd/mtls-gw` | 网关守护进程(纯数据面: 认证 + 路由 + 转发 + /info + reload) |
| `cmd/mtls-admin` | 独立管理进程(签发/吊销/配置 CRUD, 与网关读同一配置, 变更后调网关 reload) |
| `cmd/mtls-gw-cli` | 本机管理 CLI(Unix socket) |
| `cmd/mtls-relay` | 客户端中继 daemon(/info 发现 → 隧道 + WebUI) |
| `internal/db` | SQLite 持久化 + 内存权威表 |
| `internal/auth` | 授权判定(IP 预检 + SAN + serial 查表 + 角色) |
| `internal/proxy` | 反向代理(映射路由 + 前缀替换 + Host/Origin 改写) |
| `internal/api` | 管理 API(签发/吊销/列表 + p12) |
| `internal/relay` | 客户端核心(证书源/隧道/管理桥) |
| `internal/relayweb` | 客户端 WebUI(go:embed) |
| `internal/i18n` | 中/英错误消息表 |
| `internal/pathutil` | 路径工具(dot-segment 清理) |

## 7. 审计历史

完整的审计变更记录见 [docs/AUDIT-CHANGELOG.md](./docs/AUDIT-CHANGELOG.md)(31 批 pro × 3 专项 + 2 轮 flash 横向扫描, 修复 30+ 真实 bug + 25+ 安全加固)。未完成项见 [TODO.md](./TODO.md)。
