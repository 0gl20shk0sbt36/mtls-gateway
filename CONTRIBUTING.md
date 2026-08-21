# Contributing

感谢参与 mtls-gw。本项目是个人自用项目, 但欢迎 issue 与 PR。

## 开发约定

改代码前请先读 [AGENTS.md](./AGENTS.md)(项目约定: 架构、包职责、关键约束)。

## 提交规范

- 每部分一 commit, 便于回滚
- commit message 描述"改了什么 + 为什么"(中文)

## 测试要求

```bash
go test -race ./...    # 全部 Go 测试(-race 必须绿)
go vet ./...
gofmt -l cmd internal  # 必须为空(CI 强制)

# 前端
node --test internal/relayweb/web/test/*.test.js   # 单元测试 8 例
bash internal/relayweb/web/e2e/setup.sh /tmp/mtls-e2e  # 先建环境
node --test internal/relayweb/web/e2e/*.test.mjs   # E2E 14 例
```

- 测试内自建临时 CA, 不依赖部署环境
- 涉及安全边界(路径/授权/mTLS)的改动必须配测试

## 安全

改动涉及认证/授权/路径处理/密钥管理时, 参考 [SECURITY.md](./SECURITY.md) 的安全模型, 并确保不破坏:

- 证书 = 身份、DB = 权限的职责分离
- 路径穿越防护(dot-segment + 反斜杠)
- 管理面隔离(三端口 + loopback)

## 文档

- 对外文档中英双语(中文块在前, 英文块在后), 见 [README.md](./README.md) / [README.en.md](./README.en.md)
- 公开发布代码/文档**不含任何个人内容**(IP/用户名/证书)
