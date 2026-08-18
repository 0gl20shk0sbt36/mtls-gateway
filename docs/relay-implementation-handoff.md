# mtls-relay 实施交接(会话中断)

本文件由实施中的会话在中断前写入,供新会话(或人工)无缝接续。
方案文档见 [`docs/relay-design.md`](docs/relay-design.md)(已审批)。
**提示**: 本 repo 在 DSH 沙箱下 `/tmp` 为每次 bash 调用独立的 tmpfs,不持久;
且默认 GOPATH/GOCACHE 目录不可写。所有 go 命令须先 `. ./goenv.sh`(在仓库根目录),
它在 `.gopath`/`.gocache` 内建立可写 GOPATH/GOCACHE。

## 已完成(全部验证: go build ./... 通过、go vet 通过、go test ./... 通过、Windows 交叉编译通过)

- **阶段1 核心层(跨平台)**
  - `internal/certsource/certsource.go` — Source 接口 + IdentityMeta(json tag)+ new/ApplyGwFilter
  - `internal/certsource/certsource_file.go` — 单文件 pem/p12 源
  - `internal/certsource/certsource_dir.go` — 目录扫描源(每子目录 cert.pem+key.pem / *.p12)
  - `internal/certsource/certsource_linux.go` — Linux 统一证书目录源
  - `internal/certsource/load.go` — 通用加载(pem/p12/元数据/org 过滤)
  - `internal/certsource/test_helpers_test.go` + `certsource_test.go` — 测试(通过)
  - `internal/relay/*` — config.go(隧道/配置持久化)、dialer.go(mTLS 上行,
    支持 RootCAs 验网关服务器证书)、core.go(Relay: 多隧道编排/证书缓存复用/Start/Reload/Stop)、
    tunnel.go(单隧道转发/指标)、status.go、api.go(Manager: 管理 API + 便捷方法)
  - `internal/relay/relay_test.go` — 单测(通过): echo 转发、证书复用、坏上游、
    reload、重复启动
- **阶段2 证书源 Win**
  - `internal/certsource/certsource_windows.go` — certstore(Windows 系统库 My)实现
- **阶段3 daemon 入口**
  - `cmd/mtls-relay/main.go` — 加载配置、起 Core+管理 API+WebUI,信号优雅退出
  - 本地冒烟通过: admin API /api/config, /api/status, /api/certs 正常
- **阶段4 CLI**
  - `cmd/mtls-relay-cli/main.go` — certs/tunnel add|del|list/reload/start/stop/status/config
  - 端到端冒烟通过: certs 列证书、tunnel add、tunnel list、start、status、stop
- **阶段5 WebUI**
  - `internal/relayweb/server.go`(go:embed)+ `web/index.html` + `web/app.js`
  - daemon 已改为 `relayweb.NewHandler(mgr)` 同源提供页面+API
  - 冒烟通过: GET / 返回 HTML、/app.js 正确 mime、/api/certs 返回 JSON

## 关键 API/设计要点

- 证书来源: `certsource.Source` 接口 `List() ([]IdentityMeta, error)` /
  `Load(id) (tls.Certificate, error)`;类型 `system|dir|file`,工厂 `certsource.New`。
- Relay(核心): `relay.New(cfgPath, src)`;`relay.NewManager(r, cfgPath)` 返回 Manager。
  配置文件默认 `~/.mtls-relay/config.json`(`listen_host` 默认 `127.0.0.1`);
  隧道字段 `{id, local_port, remote_addr, purpose, cert_id, server_name, enabled}`;
  证书复用 = 多条隧道引用同一 `cert_id`(Core 内缓存一次)。
- 管理 API(mgr.Handler(), loopback): `GET /api/status|certs|config`,
  `POST /api/tunnels`(JSON body=Tunnel)、`DELETE /api/tunnels/{id}`、
  `POST /api/start|stop|reload`。
- 网关服务器证书验证: `RelayConfig.ServerCAFile`(`server_ca`)——自建 mtls-gw 用私有 CA,
  客户端中继须配置该 CA 文件验服务器证书;为空则用系统根。
- Windows 证书 thumbprint 用 SHA1 冒号分隔大写(在 certsource_windows.go 的 certThumbprint)。
- daemon flag: `--config --listen-admin(默认 127.0.0.1:18081) --source --source-arg
  --filter-org(默认 mtls-gw) --show-all`。

## 尚未完成

- **阶段6 GUI(用户明确: 所有其他阶段完成后最后做)**:
  - `internal/gui/`(Windows, build tag windows): 方案推荐 Wails v2。
    复用 WebUI 前端,连 daemon 管理 API。可推迟到后续会话/人工。
- **停靠点**: 阶段7 README/CI 已完成,但**尚未 git add/commit**。
- 待办收尾:
  1. `.gomodcache/`(遗留缓存目录)已删除; 确认 `.gitignore` 已含
     `/.gopath/ / .gocache/ /.smoke/` 与 4 个 relay 二进制(已加,可复核)。
  2. 可选: gofmt 全仓(`gofmt -l .`)、`go test ./...` 复核。
  3. git add + commit(未执行)。

## 已知工作区说明

- `goenv.sh`、`.gopath/`、`.gocache/` 是沙箱构建辅助,已在 .gitignore 忽略。
- `internal/api/p12.go` 是服务端既有代码,未改动;中继 p12 解码在
  `internal/certsource/load.go`(用 `pkcs12.Decode/DecodeChain`)。
- go.mod 新增直接依赖 `github.com/tg123/certstore v0.1.3`。
