# Changelog

项目变更历史。审计驱动的大规模修复记录见 [docs/AUDIT-CHANGELOG.md](./docs/AUDIT-CHANGELOG.md), 此处仅列版本级里程碑。

## [未发布] — 当前 master(全本地未推)

v4 架构 + 三轮深度审计收敛:

- **v4 架构**: config 从 JSON 迁 TOML; `mappings`/`services` 双表 + `roles` 授权模型; `config_mode` 三态; 错误消息 `X-Lang` 双语; 客户端 relay 服务级隧道 + 证书管理台。
- **审计收敛**: 31 批 pro 三专项 + 2 轮 flash 横向扫描, 修复 30+ 真实 bug + 25+ 安全加固。
- **测试基线**: 178 个 Go 测试函数(-race 全绿) + 前端单测 8 + E2E 14 + 两个 CLI 黑盒测试 14。
- 详见 [docs/AUDIT-CHANGELOG.md](./docs/AUDIT-CHANGELOG.md) 与 [TODO.md](./TODO.md)。

## [v0.1.0] — 2026-08

首个发布版本:

- 多端口 mTLS 反向代理 + 证书签发/吊销 + SQLite 授权
- 客户端 relay(服务发现 → 隧道)+ WebUI
- 单元测试 27 例 + GitHub Actions CI(Go 1.25/1.26 双版本)自动多平台编译发 Release
