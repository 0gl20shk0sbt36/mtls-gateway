# TODO — 未完成项清单

按优先级排序。已完成项见 [docs/AUDIT-CHANGELOG.md](./docs/AUDIT-CHANGELOG.md)。

## 高优先级(功能/发布相关)

- [x] **重写 `certsource_windows.go`(系统证书库源, 代码完成, 待 win2 真机验证 RSACng)** — 弃用 certstore(2021 停更, RSACng 签名失败)。零新依赖用 x/sys/windows 自实现: CertOpenStore/CertEnumCertificatesInStore 枚举 CurrentUser\My + CryptAcquireCertificatePrivateKey(CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG 强制 CNG) + 自声明 NCryptSignHash(签名包装参考 google/certtostore: RSA PKCS1/PSS padding + ECDSA raw→DER)。配套跨平台兼容层: system 源语义矩阵(Windows=My 存储 / Linux=约定目录 / Android=应用私有目录预留 / macOS=未支持), 过滤规则抽公共 acceptCert; relay 证书缓存替换时释放旧 signer(io.Closer, 防 NCRYPT 句柄泄漏)。三平台(linux/windows/android)编译+vet 通过
- [x] **WebUI 连接设置加"客户端证书源"字段** — `cert_dir`(填路径=文件源 dir, 留空=系统证书库); 改配置后热重建证书源(relay 加 SetSource: 清缓存+按 server_ca 重新过滤)。配套: relay 启动时配置优先于 `-source` 参数(ResolveCertSource)
- [x] **WebUI 连接设置去掉 lang 输入框** — 设置界面已有"语言"选项(header 下拉); 后端 settings API 保留 lang 字段
- [ ] **统一授权模型(管理端点 vs 业务路由两套概念)** — /info、/admin 是内置硬编码端点, 业务走 mappings+roles。目标: /info 角色可配置(默认 ["null"] 匿名)、admin 强制 admin_role、全部走同一 Authorize。改动较大(用户已定: 交接给另一个 agent 做, 见 docs/handoff-20260821.md)
- [ ] **服务端 config 备份权限 bug(22:18 事件, 根因已定位+代码已修)** — `/etc/mtls-gw` 目录属主 `nobody:nogroup` 755, 但 systemd 服务 `User=yyx` → yyx 无目录写权限, 备份 + 主写入全失败。代码侧已加**启动前权限预检**(Linux unix.Access: CA/DB/证书/日志/sock/落盘目录, 不足拒绝启动, stderr 必有输出 + 尽力写日志, 见 `cmd/mtls-gw/permissioncheck_linux.go`); **待运维**: `sudo chown yyx:yyx /etc/mtls-gw` + 重部署新二进制
- [ ] **服务端内存 Router 与磁盘不一致(22:18 事件, 代码已修)** — 根因: configmgr CRUD 在 `persist()` 失败(目录不可写)时**不回滚内存 cfg**(router 已 rebuild 成新状态, 磁盘没写成) → 内存/磁盘分叉直到重启。已抽 `mutate(apply, rollback)` 统一 9 个 CRUD, persist/rebuild 失败整体回滚 + 重建旧 router; 新增 `TestConfigManagerPersistFailureRollback` 复现 22:18 场景(ReplaceAll 空 services + 落盘失败 → 内存/路由保持原状)。**待部署新二进制生效**
- [ ] **DSH 首次发送超时(根因已定位+代码已修, 待部署验证)** — **实为 relay TCP 透传 120s 空闲杀连接**切断空闲 WebSocket 长连接: dsh 回复经 WS downlink(events/mux+host, 无心跳帧)推送, 走 mTLS 时 WS 经 relay TCP 透传(:9443 无路径), 看回复/思考 >120s 即被 relay 切断 → 前端重连窗口内第一次发消息超时(重连后流式正常); SSH 直连无 relay 层则不超时。已修: `defaultTCPIdle 120s→12h`(frp 对照: frp 不杀空闲连接, 死连接靠 TCP keepalive) + Dialer 显式 KeepAlive 15s(防 NAT 静默回收); 另服务端 4 个 http.Server `WriteTimeout:60s→0`(绝对时限会切 LLM 长流式) + `IdleTimeout:60s→300s`。**待部署新二进制验证**
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

## 管理服务拆分(方案见 docs/arch-management-split.md)

- [x] **阶段 0: 请求头改写配置化 + 证书身份注入** — mapping.headers + {cert_*} 变量(04d04d9)
- [x] **阶段 1: 网关 reload API** — POST /admin/reload(admin 证书): db.Store.Reload(全量重读重建 map, 原子替换) + ConfigManager.ReloadFromDisk(重读配置+新 router, 失败保持旧) + auth.Gateway.Reload; parseConfig 抽离(启动 fatal/reload 返回 error)
- [ ] **阶段 2: mtls-admin 独立进程** — 搬 api.Manager + 配置写(TOML) + 变更后调网关 /admin/reload; 共享 config.toml(字段划分见方案)
- [ ] **阶段 3: CLI/Web/relay 适配** — admin_addr 指向管理进程; config_mode 三态迁移到管理进程
