# AGENTS.md — mtls-gw 通用 mTLS 网关

给在本仓库改代码的 agent/harness 的项目约定。用户手册见 README.md。

## 这是什么
基于 mTLS 客户端证书的**通用访问网关**: 设备级认证 + 按用途路由, 不绑特定应用, 任何自建服务可复用。

## 架构一句话
**证书 = 身份, SQLite = 权限**; 每次请求双重门槛: ① TLS 证书链验证(CA 签发) ② 数据库登记(serial 在册 + 未吊销 + 未过期); **内存即权威**(启动全量 load SQLite → map, 请求验证只查内存零 IO, 变更同步写 DB)。

## 包职责
| 包 | 职责 |
|----|------|
| `cmd/mtls-gw` | 守护进程入口: 解析 config, 起多端口 mTLS 监听 + 管理 API 端口 |
| `cmd/mtls-gw-cli` | 管理 CLI: 走 Unix socket(本机 admin, 文件权限 600) |
| `internal/db` | SQLite 持久化 serial→{name,purpose,status,expires}; 启动全量载入内存 |
| `internal/auth` | 授权判定: IP 预检 + SAN 校验 + serial 查表 + 吊销/过期 |
| `internal/proxy` | 反向代理: **映射路由**(mappings: listen `:port[/path]` → target + services[], 最长前缀匹配 + 前缀替换), Host/Origin 改写为后端 loopback, WebSocket 透传 |
| `internal/api` | 管理 API: 签发/吊销/列表/health + p12 生成 |
| `cmd/mtls-relay` | 客户端中继 daemon: /info 发现 → 按映射建隧道; WebUI+API 一体(`--listen-admin`) |
| `internal/relay` | 客户端核心: 证书源(certstore/dir/file + 密码加载)、隧道、管理桥(admin_client 调服务端 /admin/*) |
| `internal/relayweb` | 客户端 WebUI 面板(go:embed): 隧道管理 + 证书管理台(admin 验证解锁→签发/吊销) |
| `internal/i18n` | 中/英消息表; 语言检测 `LC_ALL` > `LC_MESSAGES` > `LANG`, 默认中文 |

## 关键约定(改代码必读)
- **证书里不写用途/权限字段**; 权限全在 DB。吊销/改权限只改 DB, 不用重签证书。
- **映射(mappings)模型**: `bind_host` 全局 + `mappings[] {listen:":port[/path]", target, services[]}`; listen 字符串判重(完全相同=报错); 同端口按路径最长前缀匹配, 无路径=整口兜底; `services` = 允许的用途(交集), `["any"]` = 任一已登记证书。管理 API 独立端口 `admin_listen`(不与业务端口共用路径)。
- **Host 和 Origin 必须同步改写**为后端的 loopback 地址, 否则后端信任围栏返回 403。
- **CLI / Web 面板都是管理 API 的对等壳**, Web 不直接调 CLI; 新增前端同样走管理 API(Web 调 CLI 会变成"直接用 shell", 违反安全边界)。
- **客户端管理台**: relay WebUI"证书管理"默认锁定; 选 admin 证书(可带密码)→ 验证解锁后经 `admin_addr` 调服务端 `/admin/certs/issue|revoke`; 服务端是唯一真闸(非 admin → 403)。
- **通用组件要求**: 证书内容/路径/模板全可配置, 不写死; 公开发布代码/文档不含任何个人内容(IP/用户名/证书)。证书私钥 → 本地 600 文件或 Vaultwarden, 不进仓库。
- **证书 SAN 绑定设备 IP**(TS IP), 私钥复制到别的设备会因 IP 不匹配被拒。
- **Windows 注意**: `mtls-gw-cli` 走 Unix socket 仅 Linux; Windows 上签发走 TCP admin API(admin 证书)。`-db` 是 flag 不是 config 字段。

## 构建 / 测试 / CI
```bash
go build ./cmd/mtls-gw ./cmd/mtls-gw-cli
go test ./...    # 26 个测试
go vet ./...
```
- 测试内**自建临时 CA + 服务器证书**, 不依赖部署环境(改动可直接测)。
- CI (GitHub Actions): build + vet + test + race, Go 1.25 + 1.26 双版本; 打 tag 自动多平台编译发 Release。

## 未来方向(规划中, 未实现)
- **TrustSource 抽象**: 把 IP 绑定抽成可插拔接口 `TrustSource.authorize(req) → 设备标识|拒绝`(IPBindSource / LanSource / 未来网络)。
- **Web 管理面板**: 经 admin 证书连管理 API, 是管理 API 的对等壳(不是调 CLI)。
- **对接更多应用**: `backends` 加一个用途块 + 签对应 `--purpose` 证书即可。

## 部署参考(生产现状)
本机 TS `100.64.0.1`: dsh(9443) + admin(9444)。配置 `/etc/mtls-gw/config.json`, 二进制 `/usr/local/bin/mtls-gw`, systemd `mtls-gw.service`。完整步骤见 README.md §2。
