# Changelog

项目变更历史。审计驱动的大规模修复记录见 [docs/AUDIT-CHANGELOG.md](./docs/AUDIT-CHANGELOG.md), 此处仅列版本级里程碑。

## [未发布] — 当前 master(全本地未推)

v4 架构 + 三轮深度审计收敛:

- **v4 架构**: config 从 JSON 迁 TOML; `mappings`/`services` 双表 + `roles` 授权模型; `config_mode` 三态; 错误消息 `X-Lang` 双语; 客户端 relay 服务级隧道 + 证书管理台。
- **relay 证书源可配置**: 连接设置新增 `cert_dir` 字段(空=系统证书库 / 非空=目录源), 保存即热换源(SetSource: 清缓存 + 按 server_ca 重新过滤); 启动时配置优先于 `-source` 参数; 连接设置移除重复的 lang 输入框(header 语言下拉保留)。
- **configmgr 落盘失败回滚(22:18 生产事件根因修复)**: 原 CRUD 在 persist 失败时内存不回滚 → 内存/磁盘分叉(生产表现为内存 services 变空、重启才恢复)。抽 `mutate(apply, rollback)` 统一 9 个 CRUD, rebuild/persist 任一步失败整体回滚 + 重建旧 router; 新增复现测试 `TestConfigManagerPersistFailureRollback`。
- **启动前文件/目录权限预检(Linux)**: 启动时用 `unix.Access` 检查配置引用的全部路径(CA/私钥/证书/DB/签发目录/sock/日志/落盘配置目录), 权限不足拒绝启动(stderr 必有输出, 尝试写事件日志, 无权限则跳过) — 防 22:18 类"目录不可写带病运行"事件。跨平台: 非 Linux 跳过。
- **Windows 系统证书库源重写(CNG)**: 弃用 certstore(2021 停更, RSACng 私钥签名失败)。零新依赖用 x/sys/windows 自实现 — CertOpenStore/CertEnumCertificatesInStore 枚举 CurrentUser\My, CryptAcquireCertificatePrivateKey(强制 CNG)拿密钥, 自声明 NCryptSignHash 包装 crypto.Signer(RSA PKCS1/PSS + ECDSA raw→DER, 参考 google/certtostore); 支持 RSACng 软件私钥与 TPM/智能卡硬件私钥。跨平台兼容层: system 源语义矩阵(Windows=系统证书库/Linux=约定目录/Android=应用私有目录预留/macOS=未支持), 过滤规则抽公共 acceptCert; relay 证书缓存替换时释放旧 signer 防句柄泄漏。
- **日志系统重构(分平台路径 + 双写)**: 新增 `internal/logging` 分平台默认日志目录(Windows=exe 同目录便携 / Linux=~/.cache/<组件>)。mtls-gw 补 `stdout_log_file`(标准日志: 认证/启动/隧道/错误等 log.Printf, **终端+文件双写**)并给 log_file/access_log_file 分平台默认路径; relay 补 `log_file` 运行日志(双写), DefaultWebUILogPath 统一到 helper。eventlog 加文本模式(NewText/WriteString/TextWriter, 与 JSON 事件日志同滚动策略)。拆分评估: 事件(JSON)/访问(JSON)/标准(文本双写)三文件职责不同保持独立; WebUI 操作日志与运行日志独立。
- **请求头改写配置化 + 证书身份注入(headers)**: mapping 新增 `headers` 规则(op=set/del + value 支持动态变量 `{cert_name}`/`{cert_serial}`/`{cert_roles}`/`{remote_ip}`), 认证后求值 — 供后端二级授权/独立管理模块识别 mTLS 证书身份。安全: 默认防伪造基线(9 个转发头删除)始终执行; set 先删后设防客户端伪造身份头; 匿名(null 路由)时证书变量为空不注入。dsh 身份头示例仅放 config.example.toml(默认配置不含)。
- **网关瘦身(管理服务拆分阶段 3)**: mtls-gw 移除全部管理功能(api.Manager 装配/签发吊销/配置 CRUD/Unix socket), 仅保留数据面: 认证 + 路由 + 转发 + /info 服务发现 + POST /admin/reload(管理进程调用)。mtls-gw-cli 走管理进程 Unix socket(sock_path 一致零改动); relay admin_addr 指向管理进程(证书管理台), server_addr 不变; config_mode 三态由管理进程执行(configmgr 共用)。
- **mtls-admin 独立管理进程(管理服务拆分阶段 2)**: 新 cmd/mtls-admin 与网关读同一 config.toml — SQLite 写者(签发/吊销) + CA 私钥 + 配置管理(configmgr 抽离 internal/configmgr 共用, CRUD 落盘) + Unix socket/TCP admin(mTLS admin 证书)。变更(签发/配置)后经 reloadClient(admin 证书 mTLS)调网关 POST /admin/reload 全量热重载(gateway_reload_addr/reload_cert/reload_key 配置)。internal/config 增加管理进程专属字段。
- **网关 reload API(管理服务拆分阶段 1)**: `POST /admin/reload`(admin 证书)全量热重载 — `db.Store.Reload()`(重读 SQLite 重建内存表, 原子替换失败保持旧) + `ConfigManager.ReloadFromDisk()`(重读 config.toml → 校验 → 新 Router, 失败不切换) + `auth.Gateway.Reload()`。`loadConfig` 抽离为 `parseConfig`(启动 fatal 包装 / reload 返回 error, 配置文件缺失 reload 必报错不静默清空路由)。完整拆分方案见 `docs/arch-management-split.md`(网关纯数据面 + 独立管理进程)。
- **DSH 首次发送超时修复(转发机制, 二次定位)**: 主根因是 relay TCP 透传 120s 空闲杀连接切断空闲 WebSocket 长连接(dsh 回复经 WS 事件流推送, 无心跳帧; 看回复 >120s → WS 断 → 重连窗口内第一次发消息超时; SSH 直连无 relay 层则不超时)。`defaultTCPIdle 120s→12h`(frp 对照: frp 不杀空闲连接) + Dialer 显式 TCP KeepAlive 15s; 服务端 4 个 http.Server 同步 `WriteTimeout→0` + `IdleTimeout→300s`。新增防回归断言 `TestDefaultTCPIdle`/`TestGatewayTimeoutConstants`。
- **审计收敛**: 31 批 pro 三专项 + 2 轮 flash 横向扫描, 修复 30+ 真实 bug + 25+ 安全加固。
- **测试基线**: 178 个 Go 测试函数(-race 全绿) + 前端单测 8 + E2E 14 + 两个 CLI 黑盒测试 14。
- 详见 [docs/AUDIT-CHANGELOG.md](./docs/AUDIT-CHANGELOG.md) 与 [TODO.md](./TODO.md)。

## [v0.1.0] — 2026-08

首个发布版本:

- 多端口 mTLS 反向代理 + 证书签发/吊销 + SQLite 授权
- 客户端 relay(服务发现 → 隧道)+ WebUI
- 单元测试 27 例 + GitHub Actions CI(Go 1.25/1.26 双版本)自动多平台编译发 Release
