# Changelog

项目变更历史。审计驱动的大规模修复记录见 [docs/AUDIT-CHANGELOG.md](./docs/AUDIT-CHANGELOG.md), 此处仅列版本级里程碑。

## [未发布] — 当前 master(全本地未推)

v4 架构 + 三轮深度审计收敛:

- **v4 架构**: config 从 JSON 迁 TOML; `mappings`/`services` 双表 + `roles` 授权模型; `config_mode` 三态; 错误消息 `X-Lang` 双语; 客户端 relay 服务级隧道 + 证书管理台。
- **relay 证书源可配置**: 连接设置新增 `cert_dir` 字段(空=系统证书库 / 非空=目录源), 保存即热换源(SetSource: 清缓存 + 按 server_ca 重新过滤); 启动时配置优先于 `-source` 参数; 连接设置移除重复的 lang 输入框(header 语言下拉保留)。
- **configmgr 落盘失败回滚(22:18 生产事件根因修复)**: 原 CRUD 在 persist 失败时内存不回滚 → 内存/磁盘分叉(生产表现为内存 services 变空、重启才恢复)。抽 `mutate(apply, rollback)` 统一 9 个 CRUD, rebuild/persist 任一步失败整体回滚 + 重建旧 router; 新增复现测试 `TestConfigManagerPersistFailureRollback`。
- **启动前文件/目录权限预检(Linux)**: 启动时用 `unix.Access` 检查配置引用的全部路径(CA/私钥/证书/DB/签发目录/sock/日志/落盘配置目录), 权限不足拒绝启动(stderr 必有输出, 尝试写事件日志, 无权限则跳过) — 防 22:18 类"目录不可写带病运行"事件。跨平台: 非 Linux 跳过。
- **DSH 首次发送超时修复(转发机制, 二次定位)**: 主根因是 relay TCP 透传 120s 空闲杀连接切断空闲 WebSocket 长连接(dsh 回复经 WS 事件流推送, 无心跳帧; 看回复 >120s → WS 断 → 重连窗口内第一次发消息超时; SSH 直连无 relay 层则不超时)。`defaultTCPIdle 120s→12h`(frp 对照: frp 不杀空闲连接) + Dialer 显式 TCP KeepAlive 15s; 服务端 4 个 http.Server 同步 `WriteTimeout→0` + `IdleTimeout→300s`。新增防回归断言 `TestDefaultTCPIdle`/`TestGatewayTimeoutConstants`。
- **审计收敛**: 31 批 pro 三专项 + 2 轮 flash 横向扫描, 修复 30+ 真实 bug + 25+ 安全加固。
- **测试基线**: 178 个 Go 测试函数(-race 全绿) + 前端单测 8 + E2E 14 + 两个 CLI 黑盒测试 14。
- 详见 [docs/AUDIT-CHANGELOG.md](./docs/AUDIT-CHANGELOG.md) 与 [TODO.md](./TODO.md)。

## [v0.1.0] — 2026-08

首个发布版本:

- 多端口 mTLS 反向代理 + 证书签发/吊销 + SQLite 授权
- 客户端 relay(服务发现 → 隧道)+ WebUI
- 单元测试 27 例 + GitHub Actions CI(Go 1.25/1.26 双版本)自动多平台编译发 Release
