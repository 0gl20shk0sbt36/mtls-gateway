# mtls-gateway / mtls-relay — 规则路由与 /info 规格(v2)

本文档是"路由改为规则模型 + 服务端 /info + 客户端基于 /info 配置"的实现依据。
实施顺序(用户确认): **① 服务端 → ② 客户端核心 → ③ CLI → ④ WebUI**。
关联: `docs/relay-design.md`(客户端中继 v1)、`docs/relay-implementation-handoff.md`(交接)。

---

## 1. 服务端(mtls-gw)路由模型: 规则 + 前缀替换

### 1.1 概念
mtls-gw 不再是"一端口一用途", 而是**一组转发规则**, 每条规则可有**入口前缀**和**目标前缀**, 本质是 **nginx `location` + `proxy_pass`** 的语义(前缀替换)。

### 1.2 规则 Schema(config.json)
```json
{
  "rules": [
    { "name": "svc-a",    "listen": "0.0.0.0:1111", "path": "/a",        "target": "http://127.0.0.1:1112" },
    { "name": "svc-b",    "listen": "0.0.0.0:1111", "path": "/b",        "target": "http://127.0.0.1:1113" },
    { "name": "plain",    "listen": "0.0.0.0:1114",                     "target": "http://127.0.0.1:1115" },
    { "name": "prepend",  "listen": "0.0.0.0:1116",                     "target": "http://127.0.0.1:1117", "targetPath": "/a" }
  ]
}
```
- `name`: 服务/规则名(供 /info 与客户端选择; 旧场景可放用途名)。
- `listen`: 入口 `host:port`(mTLS 监听)。
- `path?`: **入口前缀, 可选**。多个带前缀规则可共享同一 `listen` 端口, 按**最长前缀匹配**分发。
- `target`: 后端目标地址(可 http/https)。
- `targetPath?`: **目标前缀, 可选**。转发时做**前缀替换**: 去掉命中的入口前缀, 换成 `targetPath`。
  - 有 `path`、无 `targetPath` → 剥前缀( `/a/x` → 后端 `/x` )。
  - 有 `targetPath`、无 `path` → 补前缀( `/x` → 后端 `/a/x` )。
  - 都无 → 整口透传、不改路径。
- 兼容: 旧 `backends{用途:{target,listen}}` 可迁移为"无 path 的规则"(`name=用途`)。

### 1.3 匹配规则
- 同一 `listen` 端口的带前缀规则, 按前缀长度**降序**匹配; 用 `strings.HasPrefix` 首个命中即定(最长优先)。
- 不含前缀的规则(整口)为该端口的兜底。
- 命中无规则 → 404。
- 覆盖 `/a` + `/a/b` 嵌套: `/a/b/c` → `/a/b`; `/a/x` → `/a`; 均可。

### 1.4 反向代理行为
- mtls-gw 需解析 HTTP 请求行(Host + path)以路由 + 改写 —— 变成**真·HTTP 反向代理**(不再是纯连接级转发)。
- 保留既有 Host/Origin 改写为后端 loopback 的能力(免改后端的信任围栏放行)。
- WebSocket 升级透传; 长连接正确回写。
- mTLS 认证流程不变(证书链 + IP 预检 + 内存查表), 仅路由维度从"端口"改为"端口+前缀"。

---

## 2. 服务端 /info 接口(无需 admin)

### 2.1 目的
让客户端能**发现 & 直接选择**服务, 而不是手填 host:port。

### 2.2 位置与鉴权
- 建议新增用途/端口 `info`(如 `0.0.0.0:9499`), 或独立监听端口。
- 鉴权: **任何"已登记设备证书 + IP 绑定通过"即可访问**, **不需要 admin 用途**(仅暴露服务元数据; 未登记/私钥复制的设备依旧进不来)。

### 2.3 返回(JSON)
```json
{ "rules": [
    { "name":"svc-a", "listen_port":1111, "path":"/a", "target_path":"", "target":"http://127.0.0.1:1112" }
  ]
}
```
(客户端据此: 服务名 + 入口端口(+前缀) → 选择; 不含敏感信息。)

---

## 3. 客户端(mtls-relay)改动

### 3.1 配置极简化
- **客户端只需配置**:
  - `server_addr`(服务端网关地址, 可启动参数 `--server <addr>` 或配置文件)
  - 设备证书来源(沿用 certsource)
- 其余(服务列表/入口端口)从服务端 `/info` 拉。

### 3.2 隧道创建
- 加隧道时: 从 `/info` 取服务列表 → **下拉/选择服务名** → 自动填充:
  - `remote_addr` = `server_addr:<该服务listen_port>`
  - `local_port` = **默认 = 服务端 listen_port, 但允许改**
- 不再自由输入 host:port(除非列表外手动加)。

### 3.3 处理
- 中继依旧**透明 TCP 字节流**(不改 HTTP, 前缀匹配在服务端做)。
- 新增 `/info` 拉取与缓存、服务选择逻辑。

---

## 4. 客户端 CLI 范围(按用户偏好: 管理走 WebUI, 不用 CLI)
- **客户端 CLI = 启动 daemon**(启动参数即可, 不建管理命令集):
  - `mtls-relay --server <网关地址> --source <证书来源> --source-arg <路径> [--config <路径>] [--listen-admin <addr>]`
- **一切管理(选服务 / 加减隧道 / 启停 / 证书)由 WebUI 承担**(手机/浏览器友好), CLI 不重复做。
- `cmd/mtls-relay-cli` 砍到最轻: 仅 `status`/`stop`(运维应急), 或并入 daemon 启动, 不再维护 certs/tunnel 完整命令集。

## 5. WebUI(internal/relayweb)
- "远端"输入框改为**服务下拉**(从 /info), 自动带出目标/端口; 本地端口默认一致可改。
- 显示发现的服务列表; 其余沿用现有面板逻辑。

---

## 6. 实施顺序与验收
1. 服务端: 规则模型 + 前缀替换路由 + /info + 迁移 config + 单测(最长前缀/替换/共存)。
2. 客户端核心: config 只留 server_addr + 证书; tunnel 从 /info 选择; 管理 API 完备(供 WebUI 用)。
3. WebUI: 从 /info 的服务选择 + 完整管理(手机友好); CLI 仅 daemon 启动 + status/stop。
4. 验收: go build/vet/test 全绿 + 端到端(临时CA → mtls-gw 规则 → relay 从 /info 选服务 → curl 走本地口到后端)。

## 7. 不做什么(V2 边界)
- 不做 SOCKS/HTTP 代理协议转化(中继仍透明字节流)。
- 不改 mTLS 认证流程。
- 前缀路由仅作用于 mtls-gw(反向代理侧)。
