# TODO — 未完成项清单

按优先级排序。已完成项见 [docs/AUDIT-CHANGELOG.md](./docs/AUDIT-CHANGELOG.md)。

## 高优先级(功能/发布相关)

- [ ] **重写 `certsource_windows.go`(系统证书库源)** — certstore v0.1.3(2021 停更)对 RSACng 私钥签名失败(`bad private key`), 导致 `-source system` 在 Windows 上无法做 mTLS。改为直接用 x/sys/windows 的 CNG API(NCryptSignHash 需自声明), 枚举 CurrentUser\My + 过滤 issuer。当前 Windows relay 已改用文件证书(dir 源)顶住
- [ ] **WebUI 连接设置加"客户端证书源"字段** — `cert_dir`(填路径=文件源 dir, 留空=系统证书库); 改配置后热重建证书源(relay 需加 SetSource)。配套: relay 启动时配置优先于 `-source` 参数
- [ ] **WebUI 连接设置去掉 lang 输入框** — 设置界面已有"语言"选项(重复); 后端 settings API 保留 lang 字段
- [ ] **统一授权模型(管理端点 vs 业务路由两套概念)** — /info、/admin 是内置硬编码端点, 业务走 mappings+roles。目标: /info 角色可配置(默认 ["null"] 匿名)、admin 强制 admin_role、全部走同一 Authorize。改动较大(用户已定: 交接给另一个 agent 做, 见 docs/handoff-20260821.md)
- [ ] **服务端 config 备份权限 bug** — 2026-08-21 22:18 日志 `config backup failed: open /etc/mtls-gw/config.toml.bak-*: permission denied (仍继续写入)`: /etc/mtls-gw 目录写备份失败(服务以何身份运行?目录权限?)
- [ ] **服务端内存 Router 与磁盘不一致(22:18 事件)** — 配置写入后内存 services 变空(重启才恢复, 磁盘配置完好)。疑 configmgr 热重载在落盘失败时状态不一致, 需排查根因(潜在复现)
- [ ] **admin 证书到期重签** — admin/gw-admin 证书 2026-09-16 前后到期, 到期前用 mtls-gw-cli 重签(admin_days=30)
- [ ] **推送代码到云端** — 150+ 提交全本地未推(用户纪律: 不主动推送, 等指示)
- [ ] **部署最新二进制到 Windows** — win2 常驻进程(mtls-e2e/mtls-gw2/mtls-echo)仍是旧版
- [ ] **生产 mtls-gw.service 重部署** — v4 TOML 重写后未部署(当前 DSH 9443 下线)
- [ ] **README.en.md 同步** — 英文版仍是 v3 旧模型(README.md 已 v4)
- [ ] **阶段 6 GUI(Wails v2)** — 从未开始
- [ ] **other-svc 演示服务是否删除** — 待用户确认

## 中优先级(可读性 P2 高风险重构 — 不影响功能)

重复代码型债, 跨包抽取收益递减风险递增, 建议配一次 pro 深挖设计后再动:

- [ ] `cmd/mtls-gw/main.go` http.Server 三段复制 → 抽 `startServer(addr, handler, name)` 助手
- [ ] `cmd/mtls-gw/configmgr.go` 9 个 CRUD 模板 → 抽 `mutate(func() error)` 助手
- [ ] `internal/relay/admin.go` 复制 `api.IssueRequest/IssueResponse` + `proxy.Mapping` → 抽共享 types 包
- [ ] 角色名校验 4 份(proxy.ValidRoleName / api.validName / configmgr 内联 / 前端 RE_NAME)规则微差 → 统一
- [ ] 路径拼接两包(proxy.substitute/joinURLPath vs relay.joinSlash)→ 统一
- [ ] ResponseWriter 包装器两份(main.go statusWriter vs eventlog.StatusWriter)→ 共用
- [ ] 原子写文件两处(configmgr.persist vs relay.SaveConfig)→ 抽 helper
- [ ] 跨端 tunnel key 格式耦合(Go 拼 service@channel@local, 前端 app.js 再拼一遍)→ 前端读 status 的 id 字段

## 低优先级(并发 L3 — 健壮性, 不影响正确性)

- [ ] Reload/Start 持大锁执行隧道启停(锁粒度偏大, 可只保护 tunnels map)
- [ ] 循环内 `time.After` 未 Stop(每连接退出残留 1 timer)
- [ ] db.Store 持写锁执行 SQLite IO(可内存先行 + 锁外落库)
- [ ] 优雅退出不彻底(单 5s ctx 顺序 Shutdown; relay 用 Close 非 Shutdown)
- [ ] ConfigManager.persist 持锁做备份+落盘 IO
- [ ] 每请求重建 ServeMux(mgr.HTTPHandler 每次 new ServeMux)
- [ ] eventlog rotate 后 open 失败永久静默(应重试或回退 stderr)
- [ ] HTTP 反代模式每 60s 重建 Transport(可复用 Transport 仅重建 TLSClientConfig)

## 低优先级(flash 报的其他低危, 已记录未修)

- [ ] CLI 手写 flag 解析(mtls-gw-cli issue 的 needValue 表 + 不支持 `--sock=x` 形式)
- [ ] WebUI 无 CSP / X-Frame-Options 头(已修 Google Fonts 外链, CSP 未加)
- [ ] `go:embed` 已修, 但前端 `esc()` 双份(app.js + i18n.js)、`style="..."` 内联 CSS 混写
- [ ] `4<<20` 等魔法数字无常量(3 文件 10 处)

## 已决策不做(用户明确)

- [x] ~~M1 relay 管理 API 无鉴权(同机提权)~~ — 用户: 纯内网 + 已入侵本机则提权无所谓, 不管
- [x] ~~M2 隧道 listen_host 无 loopback 校验~~ — 用户: 先不管
