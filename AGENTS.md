# AGENTS.md — mtls-gw 通用 mTLS 网关

给在本仓库改代码的 agent/harness 的项目约定。用户手册见 README.md。

## 这是什么
基于 mTLS 客户端证书的**通用访问网关**: 设备级认证 + 按角色路由, 不绑特定应用, 任何自建服务可复用。

## 架构一句话
**证书 = 身份, SQLite = 权限**; 每次请求双重门槛: ① TLS 证书链验证(CA 签发) ② 数据库登记(serial 在册 + 未吊销 + 未过期); **内存即权威**(启动全量 load SQLite → map, 请求验证只查内存零 IO, 变更同步写 DB)。

## 包职责
| 包 | 职责 |
|----|------|
| `cmd/mtls-gw` | 守护进程入口: 解析 config(TOML), 起多端口 mTLS 监听 + 管理 API 端口 |
| `cmd/mtls-gw-cli` | 管理 CLI: 走 Unix socket(本机 admin, 文件权限 600; Windows 走 TCP admin) |
| `internal/db` | SQLite 持久化 serial→{name,purposes(角色列表),status,expires}; 启动全量载入内存 |
| `internal/auth` | 授权判定: IP 预检 + SAN 校验 + serial 查表 + 吊销/过期 |
| `internal/proxy` | 反向代理: **映射路由**(mappings: listen `:port[/path]` → target, 最长前缀匹配 + 前缀替换), Host/Origin 改写为后端 loopback, WebSocket 透传, 匹配前规范化 dot-segment |
| `internal/api` | 管理 API: 签发/吊销/列表/health + p12 生成 |
| `cmd/mtls-relay` | 客户端中继 daemon: /info 发现 → 按服务建隧道; WebUI+API 一体(`--listen-admin`) |
| `internal/relay` | 客户端核心: 证书源(certstore/dir/file + 密码加载)、隧道、管理桥(admin_client 调服务端 /admin/*) |
| `internal/relayweb` | 客户端 WebUI 面板(go:embed): 隧道管理 + 证书管理台(admin 验证解锁→签发/吊销) |
| `internal/i18n` | 中/英消息表; 错误语言 = 请求头 `X-Lang`(前端注入) + 进程默认 `lang`(默认 zh) |
| `internal/pathutil` | 路径工具: `CleanDotSegments`(清 `..`/`.` + 反斜杠归一化, 防路径穿越) |

## 关键约定(改代码必读)
- **证书里不写用途/权限字段**; 权限全在 DB。吊销/改权限只改 DB, 不用重签证书。DB 字段名仍叫 `purposes`, 但概念上是"角色列表"(roles)。
- **映射/服务双表模型**: `mappings[] {id, listen, target}`(唯一路由实体, 判重靠 listen) + 独立 `services[] {name, channels[], roles[]}`(服务声明, channels 引用 mapping id); 授权 = 证书 roles 与引用该映射的所有服务 roles 并集有交集(或含 `any`)。管理 API 独立端口 `admin_listen`。
- **角色规则**: 角色名 `[A-Za-z0-9_-]+`; 内置 `any`(仅服务声明可用, 禁入 roles 列表/禁签发); `admin_role`(默认 `mtls-superadmin`)禁入业务服务 roles。
- **config_mode 三态**: `mutable`(落盘, 默认) / `ephemeral`(仅内存) / `immutable`(只读, 配置 CRUD 拒绝)。
- **Host 和 Origin 必须同步改写**为后端的 loopback 地址, 否则后端信任围栏返回 403。
- **CLI / Web 面板都是管理 API 的对等壳**, Web 不直接调 CLI; 新增前端同样走管理 API(Web 调 CLI 会变成"直接用 shell", 违反安全边界)。
- **客户端管理台**: relay WebUI"证书管理"默认锁定; 选 admin 证书(可带密码)→ 验证解锁后经 `admin_addr` 调服务端 `/admin/certs/issue|revoke`; 服务端是唯一真闸(非 admin → 403)。
- **通用组件要求**: 证书内容/路径/模板全可配置, 不写死; 公开发布代码/文档不含任何个人内容(IP/用户名/证书)。证书私钥 → 本地 600 文件或 Vaultwarden, 不进仓库。
- **证书 SAN 绑定设备 IP**(TS IP), 私钥复制到别的设备会因 IP 不匹配被拒。
- **Windows 注意**: `mtls-gw-cli` 走 Unix socket 仅 Linux; Windows 上签发走 TCP admin API(admin 证书, admin_addr 指向 mtls-admin)。
- **热重载范围**: `/admin/reload` 只重载 DB + mappings/services; `admin_role`/`require_ip_bind`/`tls_min_version` 等安全字段改后需重启两个进程。
- **错误消息由后端按语言返回**: 前端 `api()` 注入 `X-Lang` 头, 后端在错误出口按 X-Lang 兜底翻译; 未收录错误原样返回。

## 构建 / 测试 / CI
```bash
go build ./cmd/mtls-gw ./cmd/mtls-gw-cli ./cmd/mtls-relay
go test -race ./...    # 235 个测试函数(Go 单测/集成随被测包放置)
go vet ./...
gofmt -l cmd internal  # 应为空(CI 强制)
```
- 测试内**自建临时 CA + 服务器证书**, 不依赖部署环境(改动可直接测)。
- 前端测试: 单测 `internal/relayweb/web/test/`(8 例) + E2E `internal/relayweb/web/e2e/`(15 例, setup.sh 生成环境; E2E 端口段 57xxx, 与生产/常用段隔离)。
- CI (GitHub Actions): 双 Go 版本(1.25/1.26) build+vet+gofmt+test+race / WebUI 单测 / playwright E2E / windows 真机测试(CNG + 平台差异) / windows+android 交叉编译; 打 tag 自动多平台编译发 Release。

## 审计流程(agent 协作范式, 改代码前先审 / 大改后必审)

用户指定的审计工作方式, 所有 agent/子代理必须遵守:

1. **并行分派**: 一次审计轮按类别拆分(如 安全 / 正确性 / 并发 / 平台 / 测试覆盖 / 代码质量 / 运维一致性), **每个类别一个独立子代理**, 同一批消息内**并行**派出。子代理只读(read/glob/grep, 不可改文件), 互相独立、不被告知彼此的见解(防同质化)。
2. **flash 循环迭代**: 用 flash 模型子代理做横向全库通读审计 → 收集发现 → 修复(必须修 + 建议修) → 全量测试(-race + 五平台 + 前端单测 + E2E) → **单次提交** → 再派 flash 复审(同类目并行)验证修复。反复迭代, 直到 flash 报告"无必须修/无新发现"。
3. **flash 审不出 → 交 pro**: flash 收敛后升级给 pro 模型子代理**独立深挖复审**——验证 flash 的修复是否正确, 并找 flash 遗漏的同类缺陷(历史教训: flash 只修了 Windows 枚举失败分支的 UAF, pro 抓到成功路径的同类 UAF/double-free)。pro 的发现 → 再修 → 再验证, 直到 pro 也报"无必须修"。
4. **闭环判定**: 收敛 = 连续一轮(或多轮)复审无必须修; 每轮修复后都要跑全量测试并单次提交(不推送除非用户指示)。
5. **留痕**: 每轮审计/复审的发现与修复提交追加到 `docs/AUDIT-CHANGELOG.md`(批号/提交号/发现清单); TODO.md 同步未修项与完成项。

## 审计历史
pro 审计变更记录见 `docs/AUDIT-CHANGELOG.md`(31 批 × 3 专项 + flash 横向扫描 + 2026-08-22 三轮子代理复审迭代 + CI 首跑修复 + 2026-08-22 flash→pro 循环审计轮)。

## 未来方向(规划中, 未实现)
- **TrustSource 抽象**: 把 IP 绑定抽成可插拔接口 `TrustSource.authorize(req) → 设备标识|拒绝`(IPBindSource / LanSource / 未来网络)。
- **对接更多应用**: `mappings` 加一个通道块 + `services` 加一个服务块 + 签对应 `roles` 证书即可。

## 部署参考(生产现状)
本机 TS `100.64.0.1`: dsh(9443) + admin(9444)。配置 `/etc/mtls-gw/config.toml`, 二进制 `/usr/local/bin/mtls-gw`, systemd `mtls-gw.service`。完整步骤见 README.md。
