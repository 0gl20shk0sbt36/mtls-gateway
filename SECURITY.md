# Security Policy

## 安全模型

mtls-gw 是**设备级认证 + 按角色路由**的通用 mTLS 网关。核心安全保证:

1. **证书 = 身份, 数据库 = 权限** — 证书里不写权限字段, 授权全在 SQLite, 吊销/改权限只改 DB 不重签证书。
2. **双向 mTLS** — 客户端验网关 CA, 网关验客户端 CA 链, 全链路无 `InsecureSkipVerify`。
3. **证书 SAN 绑定设备 IP** — 私钥复制到别的设备因 IP 不匹配被拒(`require_ip_bind=true`)。
4. **角色最小授权** — 证书 roles 与服务 roles 交集才放行; admin_role 证书只能进管理 API, 不能访问业务。
5. **管理面隔离** — 业务/管理/发现三端口分离; relay 管理 API 默认强制 loopback + DNS rebinding 防护。
6. **server_ca 不可用拒绝启动** — 防降级系统根被 MITM 冒充网关。

审计历史(含 20+ 安全加固)见 [docs/AUDIT-CHANGELOG.md](./docs/AUDIT-CHANGELOG.md)。

## 已知边界(威胁模型内, 非漏洞)

- **relay 管理 API 无鉴权** — 仅绑定 loopback, 同机进程可调用(本机已被入侵时提权无意义; 纯内网部署)。
- **隧道 `listen_host` 可配非 loopback** — 误配 `0.0.0.0` 会暴露隧道到局域网, 默认 127.0.0.1 安全。

## 报告漏洞

本项目为个人自用项目, 暂无公开漏洞奖励计划。如发现安全问题:

1. **请勿公开**细节。
2. 通过 GitHub issue 或直接联系维护者报告, 附复现步骤与影响评估。

我们会在确认后尽快修复并发布新版本。
