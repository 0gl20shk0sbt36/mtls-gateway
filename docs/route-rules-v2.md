# mtls-gateway / mtls-relay — 映射(mappings)路由与证书管理规格 (v3 最终)

本文档为"映射路由 + 服务端 /info + 客户端基于 /info 配置 + WebUI 证书管理"的实现依据(最终版)。

## 1. 服务端配置(mtls-gw config.json)
```json
{
  "bind_host": "0.0.0.0",           // 全局绑定地址
  "info_listen": ":9499",           // /info 发现端口 (任一已登记证书); 空=关
  "admin_listen": ":9444",          // 管理 API (仅 admin 证书)
  "mappings": [
    { "listen": ":9443",              "target": "http://127.0.0.1:3080", "services": ["dsh"] },
    { "listen": ":9445/admin",        "target": "http://127.0.0.1:8080/", "services": ["vaultwarden"] },
    { "listen": ":9446",              "target": "http://127.0.0.1:5001",  "services": ["any"] }
  ]
}
```
- `listen` = `:端口[/路径]`(路径合并进 listen, host 由 bind_host 决定)。
- `target` = 完整 URL, 其路径为"目标前缀"(前缀替换: 剥入口 path、补目标 path, 斜杠去重, nginx proxy_pass 语义)。
- `services` = 本映射允许的用途; 证书用途与之有交集才放行; `["any"]` = 任一已登记证书。
- **重复判定: 两条 listen 字符串完全相同 → 加载报错**; 同 target 不同 listen 合法; 同端口前缀重叠 → 最长匹配优先(不报错); 同端口一条带 path 一条无 path → 带 path 按前缀, 无 path 整口兜底。

## 2. 授权与发现
- 认证: mTLS(CA 验证 + 序列号登记 + 可选 IP 绑定)→ 按映射 `services` 授权(或 any)。
- `/info`: 按调用证书用途**过滤**, 只返回该证书可访问的映射(最小暴露); 客户端据此选入口、默认本地端口=入口端口(可改)。

## 3. 客户端(mtls-relay)
- 配置只留: `server_addr`(服务端 /info)+ `admin_addr`(服务端 admin)+ 证书来源。
- 隧道: 从 /info 选映射 → 本地端口默认同入口端口可改; 中继保持透明(路径前缀由应用 URL 携带, 服务端路由)。
- 证书源: system / dir / file; 支持**密码证书**(加密私钥/p12 → `load_pwd` 解锁, 密码不落盘)。

## 4. WebUI 证书管理台
- "证书管理"入口一直可见, 默认锁定; 选 admin 证书 → (密码) → **验证并解锁**(调服务端 admin 探活)→ 解锁签发/吊销。
- 签发: 名称/用途/TS IP/**可选 p12 密码** → `POST /admin/certs/issue`; 吊销: 序列号 → `POST /admin/certs/revoke`。
- 权限保障: 服务端为唯一真闸(非 admin 证书调 /admin/* → 403), 前端只是 UX。

## 5. Windows 说明
- `mtls-gw-cli` 走 Unix socket → **仅 Linux**; Windows 上签发/登记走 **TCP admin API(admin 证书, mTLS)**。
- `-db` 是 flag 不是 config 字段, 多实例必须显式指定。

## 6. 测试
- 单元: proxy 路由/前缀替换/判重/Allows; admin_client mTLS 往返; 密码证书加载。
- E2E(Linux 已验证): /info 过滤、整口/最长前缀转发、any、403 权限拒绝。
