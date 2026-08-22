# TODO — 未完成项清单

按优先级排序。已完成项见 [docs/AUDIT-CHANGELOG.md](./docs/AUDIT-CHANGELOG.md)。

## 高优先级(功能/发布相关)

- [x] **重写 `certsource_windows.go`(系统证书库源, 代码完成, 待 win2 真机验证 RSACng)** — 弃用 certstore(2021 停更, RSACng 签名失败)。零新依赖用 x/sys/windows 自实现: CertOpenStore/CertEnumCertificatesInStore 枚举 CurrentUser\My + CryptAcquireCertificatePrivateKey(CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG 强制 CNG) + 自声明 NCryptSignHash(签名包装参考 google/certtostore: RSA PKCS1/PSS padding + ECDSA raw→DER)。配套跨平台兼容层: system 源语义矩阵(Windows=My 存储 / Linux=约定目录 / Android=应用私有目录预留 / macOS=未支持), 过滤规则抽公共 acceptCert; relay 证书缓存替换时释放旧 signer(io.Closer, 防 NCRYPT 句柄泄漏)。三平台(linux/windows/android)编译+vet 通过
- [x] **WebUI 连接设置加"客户端证书源"字段** — `cert_dir`(填路径=文件源 dir, 留空=系统证书库); 改配置后热重建证书源(relay 加 SetSource: 清缓存+按 server_ca 重新过滤)。配套: relay 启动时配置优先于 `-source` 参数(ResolveCertSource)
- [x] **WebUI 连接设置去掉 lang 输入框** — 设置界面已有"语言"选项(header 下拉); 后端 settings API 保留 lang 字段
- [ ] **统一授权模型(管理端点 vs 业务路由两套概念)** — /info、/admin 是内置硬编码端点, 业务走 mappings+roles。目标: /info 角色可配置(默认 ["null"] 匿名)、admin 强制 admin_role、全部走同一 Authorize。改动较大(用户已定: 交接给另一个 agent 做)
- [ ] **服务端 config 备份权限 bug(22:18 事件, 根因已定位+代码已修)** — `/etc/mtls-gw` 目录属主 `nobody:nogroup` 755, 但 systemd 服务 `User=yyx` → yyx 无目录写权限, 备份 + 主写入全失败。代码侧已加**启动前权限预检**(Linux unix.Access: CA/DB/证书/日志/sock/落盘目录, 不足拒绝启动, stderr 必有输出 + 尽力写日志, 见 `cmd/mtls-gw/permissioncheck_linux.go`); **待运维**: `sudo chown yyx:yyx /etc/mtls-gw` + 重部署新二进制
- [ ] **服务端内存 Router 与磁盘不一致(22:18 事件, 代码已修)** — 根因: configmgr CRUD 在 `persist()` 失败(目录不可写)时**不回滚内存 cfg**(router 已 rebuild 成新状态, 磁盘没写成) → 内存/磁盘分叉直到重启。已抽 `mutate(apply, rollback)` 统一 9 个 CRUD, persist/rebuild 失败整体回滚 + 重建旧 router; 新增 `TestConfigManagerPersistFailureRollback` 复现 22:18 场景(ReplaceAll 空 services + 落盘失败 → 内存/路由保持原状)。**待部署新二进制生效**
- [ ] **DSH 首次发送超时(根因已定位+代码已修, 待部署验证)** — **实为 relay TCP 透传 120s 空闲杀连接**切断空闲 WebSocket 长连接: dsh 回复经 WS downlink(events/mux+host, 无心跳帧)推送, 走 mTLS 时 WS 经 relay TCP 透传(:9443 无路径), 看回复/思考 >120s 即被 relay 切断 → 前端重连窗口内第一次发消息超时(重连后流式正常); SSH 直连无 relay 层则不超时。已修: `defaultTCPIdle 120s→12h`(frp 对照: frp 不杀空闲连接, 死连接靠 TCP keepalive) + Dialer 显式 KeepAlive 15s(防 NAT 静默回收); 另服务端 4 个 http.Server `WriteTimeout:60s→0`(绝对时限会切 LLM 长流式) + `IdleTimeout:60s→300s`。**待部署新二进制验证**
- [ ] **admin 证书到期重签** — admin/gw-admin 证书 2026-09-16 前后到期, 到期前用 mtls-gw-cli 重签(admin_days=30)
- [x] ~~**推送代码到云端**~~ — 2026-08-22 已推 origin master(90a2efa..d10a3f2), CI 首跑验证中
- [ ] **部署最新二进制到 Windows** — win2 常驻进程(mtls-e2e/mtls-gw2/mtls-echo)仍是旧版
- [ ] **生产 mtls-gw.service 重部署** — v4 TOML 重写后未部署(当前 DSH 9443 下线)
- [x] ~~**README.en.md 同步**~~ — 2026-08-22 已对齐 v4 双进程架构(与 README.md 逐节一致)
- [ ] **阶段 6 GUI(Wails v2)** — 从未开始
- [ ] **other-svc 演示服务是否删除** — 待用户确认

## 中优先级(可读性 P2 高风险重构 — 不影响功能)

重复代码型债, 跨包抽取收益递减风险递增, 建议配一次 pro 深挖设计后再动:

- [ ] - [x] ~~`cmd/mtls-gw/main.go` http.Server 三段复制 → 抽 `startServer(addr, handler, name)` 助手~~ — 已做(0fc0bcf 闭包收敛 4 段构造)
- [x] ~~`cmd/mtls-gw/configmgr.go` 9 个 CRUD 模板 → 抽 `mutate(func() error)` 助手~~ — 已做(mutate 已抽, 包已迁 internal/configmgr)
- [ ] - [ ] `internal/relay/admin.go` 复制 `api.IssueRequest/IssueResponse` + `proxy.Mapping` → 抽共享 types 包(仍待)
- [ ] - [x] ~~角色名校验 Go 侧统一~~ — api.validName 委托 proxy.ValidRoleName(0fc0bcf); 前端 RE_NAME 为 JS 侧独立, 字符集一致
- [ ] - [ ] ~~路径拼接两包统一~~ — 刻意不做: proxy 折叠斜杠 vs relay 保留 // 与尾斜杠, 语义不同, 合并有回归风险(记录)
- [x] ~~ResponseWriter 包装器两份(main.go statusWriter vs eventlog.StatusWriter)→ 共用~~ — 已做(第一轮删 statusWriter 改用 eventlog.StatusWriter)
- [ ] - [x] ~~原子写文件两处~~ — 抽 internal/atomicfile(0fc0bcf), configmgr/relay 共用
- [ ] - [x] ~~跨端 tunnel key 格式耦合~~ — 前端按 status 自身字段建索引, 不再拼 Go 复合 key(0fc0bcf)

## 低优先级(并发 L3 — 健壮性, 不影响正确性)

- [ ] Reload/Start 持大锁执行隧道启停(锁粒度偏大, 可只保护 tunnels map)
- [ ] - [x] ~~循环内 time.After 未 Stop~~ — NewTimer + Stop/Reset(8dd5d4b)
- [ ] db.Store 持写锁执行 SQLite IO(可内存先行 + 锁外落库)
- [ ] 优雅退出不彻底(单 5s ctx 顺序 Shutdown; relay 用 Close 非 Shutdown)
- [ ] ConfigManager.persist 持锁做备份+落盘 IO
- [ ] - [x] ~~每请求重建 ServeMux~~ — HTTPHandler 构建一次缓存(8dd5d4b)
- [ ] - [x] ~~eventlog rotate 后 open 失败永久静默~~ — 置 nil + 下次写入重试(8dd5d4b)
- [ ] HTTP 反代模式每 60s 重建 Transport(可复用 Transport 仅重建 TLSClientConfig)

## 低优先级(flash 报的其他低危, 已记录未修)

- [ ] - [ ] CLI 手写 flag 解析(mtls-gw-cli issue 的 needValue 表; `--sock=`/`--admin=` 等号形式已支持)
- [ ] - [x] ~~WebUI 无 CSP / X-Frame-Options 头~~ — 已加 CSP/X-Frame-Options/X-Content-Type-Options(8dd5d4b)
- [ ] - [ ] `go:embed` 已修; esc() 双份已去重(8dd5d4b), 内联 CSS 混写仍待
- [x] ~~`4<<20` 等魔法数字无常量(3 文件 10 处)~~ — 第二轮已抽 maxBodyBytes/maxInfoBody 常量

## 已决策不做(用户明确)

- [x] ~~M1 relay 管理 API 无鉴权(同机提权)~~ — 用户: 纯内网 + 已入侵本机则提权无所谓, 不管
- [x] ~~M2 隧道 listen_host 无 loopback 校验~~ — 用户: 先不管

## 管理服务拆分(方案见 docs/arch-management-split.md)

- [x] **阶段 0: 请求头改写配置化 + 证书身份注入** — mapping.headers + {cert_*} 变量(04d04d9)
- [x] **阶段 1: 网关 reload API** — POST /admin/reload(admin 证书): db.Store.Reload(全量重读重建 map, 原子替换) + ConfigManager.ReloadFromDisk(重读配置+新 router, 失败保持旧) + auth.Gateway.Reload; parseConfig 抽离(启动 fatal/reload 返回 error)
- [x] **阶段 2: mtls-admin 独立进程** — cmd/mtls-admin(读同一 config.toml): db 写者 + CA 签发(api.Manager) + 配置 CRUD(configmgr 共用, 已抽 internal/configmgr) + Unix socket/TCP admin(mTLS) + 变更后调网关 /admin/reload(reloadClient, gateway_reload_addr/reload_cert/reload_key); internal/config 加管理字段
- [x] **阶段 3: 网关瘦身 + CLI/Web/relay 适配** — 网关移除管理功能(api.Manager 装配/配置 CRUD/证书管理), 仅留认证+路由+转发+/info+POST /admin/reload; mtls-gw-cli 走管理进程 Unix socket(sock_path 一致, 零代码改动); relay admin_addr 指向管理进程(证书管理台), server_addr 不变(网关 /info); config_mode 由管理进程 configmgr 执行(共用包)

## 审计第一轮(7 大类只读审计)已修复项(详见 git 提交 2026-08-22)
🔴 全修: admin_role 校验缺口(拒 null/ValidRoleName/不与 roles 声明重叠) / SetDeclaredRoles 热更新 / certsource+relay.src 数据竞争 / applyServerCA 失败降级系统根 / 双进程 admin_listen 端口冲突(reload_listen) / config.example 缺 roles 声明 / cert_issue|cert_revoke 事件 / isAddrInUse Windows / 权限预检(mode+reload_cert+mtls-admin 复用)
🟡 大部分: 配置文件缺失拒绝启动 / reload 降级+失败事件 / 网关 stop 事件 / 管理面认证失败日志 / 日志分进程 / IPv6 ResolveListen / listen 判重规范化 / 热重载新端口告警 / DB UNIQUE(name) / UpdateSettings 先应用后落盘 / 访问日志 IP+耗时 / CLI 状态码 / Origin 断言 / certsource darwin 兜底 / CI windows test+android build
🟢 部分: 死代码/误导注释/rotate 修正/数字索引警告/symlink 防护//info ReadAll 上限/日期缓存/ResponseWriter 去重

## 审计第一轮未修(记录, 第二轮复审评估)
- [ ] 错误本地化 M1 三处碎片化(结构化 error 重构, 大改高风险 — 第二轮复审判定"可缓": 状态码映射已统一为 api.StatusFromKeywords 单一权威表, 剩余碎片漂移方向 fail-closed)
- [ ] relay 管理桥 9 函数样板(M3) / HTTP mTLS client 构造重复(M4) / listen 解析两套(M5) / main 包 handler 拆分(M8) — 第二轮复审全部判定"可缓/长期搁置"
- [ ] 前端 app.js 单测(靠 E2E 兜底) / i18n 占位符一致性(键集合测试抓不到占位符取值差异, 建议 logic.test.js 加占位符静态检查)
- [ ] 热重载动态起停监听(当前显式告警已防呆, 需求出现再实现) / p12 密码 stdin(威胁面≈0, 改 stdin 破坏脚本化, 不值) / 过期 RFC3339 统一(格式与比较逻辑自洽, 建议注释写明语义)

## 审计第二轮(4 个复审子代理, 2026-08-22)已修复(提交 6e0a456)
🔴 高: permissioncheck mode 检查**平台门控回归** — mode&0o077 检查原在平台无关层, Windows 上 os.Stat 的 Perm() 恒 0666 → 双进程一旦有密钥文件就拒绝启动; 已收口到 access_linux.go 的 modePerm(非 Linux 恒 0) + 新增 `!linux` 测试断言(随 CI windows-test 执行防再漏) + ModeRestrict 0o077→0o007(0640 group 可读不再误拒, 新增 TestKeyModeGroupReadableOK)
🟡 中: loadFirstCert 无锁读 r.src 数据竞争(SetSource 热替换并发) / LoadWithPassword+子目录 cert.pem/key.pem symlink 逃逸(含 List 一致性: 逃逸身份不展示) / /info 成功路径 + fetchCAAndFilter 无界 JSON 解码(限流补齐, maxInfoBody=1MB) / 审计事件下沉 api.Manager(SetAudit, unix socket 与 TCP 双通道统一 cert_issue|cert_revoke, CLI 签发/吊销不再漏记) / mtls-admin 日志分离强制组件路径(显式共享路径也替换 — 共享=滚动竞态源, config.example 部署场景生效)
🟢 低: config.Parse roles 拒 "any"(与 NewRouter/configmgr 一致) / TestResolveListen IPv6 回归用例("::"→"[::]:9444") / certsource_other.go 注释措辞(android 走真实检查) / proxy ErrorHandler 日志路径 CRLF 清洗(CWE-117) / 魔法数字抽常量(maxBodyBytes 3 文件 + maxInfoBody) / webUILogger sync.Once 毒化 → mutex 失败重试

## 审计第二轮未修(记录, 均为复审判定可缓/低危)
- [ ] UpdateSettings 三个边缘: SetLang 失败不回滚 / 并发回滚覆盖 / SaveConfig 失败内存已应用(反向半提交) — 单用户本地 API 概率极低
- [ ] eventlog maxFile=0 仍保留 .1 一份历史(既有行为, 与"0=不留历史"语义不符)
- [x] ~~README 2.2 端口表漏 reload_listen 一行~~ — 文档收尾已补; 存量合并端口配置(info==admin)升级需迁移配置(新示例已分离端口)仍待运维侧注意
- [ ] 存量重名库打开报原始 SQLite 错误(UNIQUE 索引在 db.Open 失败; 功能仍正确拒绝, 提示不友好)
- [x] ~~windows-test job 首次真实 runner 观察~~ — 2026-08-22 CI 首跑 3 轮修复后全绿(8.3 短名 EvalSymlinks 误判/CLI .exe/JSON 转义/Unix 权限断言守卫; AF_UNIX 黑盒测试在 Windows Server 2022 正常)

## 审计第三轮(3 个复审子代理复审 6e0a456, 2026-08-22)— 收敛
安全/正确性/平台三复审均报**无必须再修**; 已顺手收编其建议(提交 8e8cf9a + b629c0f):
- logging.DefaultDir Windows 分支加组件子目录(exe 目录下) — 否则 mtls-gw 与 mtls-admin 默认日志路径相同, 强制替换在 Windows 上失效
- mtls-admin 三个日志字段替换均 log.Printf 提示(覆盖显式配置可观测性)
- certsource List 逃逸符号链接一次性告警(warnSymlinkEscape, 目录被污染留痕不刷屏)
- sanitizeLogPath 扩滤全部 C0 控制字符(\x00-\x1F 含 ANSI ESC), 不止 CR/LF; 清洗函数抽公共 pathutil.SanitizeForLog(relay core.go CA subject/err 同套用)
- ci.yml android-build 注释实证澄清(GOOS=android 满足 //go:build linux, 走 access_linux.go)
- 平台复审"android 走非 Linux 路径"判断与 go list 实证不符, 未采纳(第一轮判断正确)
- **b629c0f(复审发现收尾)**: configmgr 落盘污染 — mtls-admin 日志路径替换后的 cfg 传入 configmgr, persist 整份 Encode 会把 admin 组件路径写回共享 config.toml, 网关下次启动日志重新合流; 改传原始 cfg(origCfg), 替换只影响本进程; 另修 warnSymlinkEscape 新引入的文本日志注入面(文件名可含 \n) + sanitizeLogPath 单测

## 文档一致性(第 8 大类, 2026-08-22)— 一次性收尾完成(本提交)
- README: 2.2 端口表补 reload_listen; 安全模型补 ModeRestrict 权衡(0640 放行, 要"仅属主"用 0600); Windows 日志路径陈旧描述修正; 测试计数 →235(实测)
- config.example.toml: 日志段说明 mtls-admin 强制组件路径(替换不落盘); 安全段补私钥权限预检说明; Windows 默认路径描述修正
- internal/relay/config.go + internal/logging 注释陈旧修正(组件子目录, 命名空间补 mtls-admin)
- CHANGELOG: 补三轮审计收敛与关键修复; 测试基线 →235(实测)
- docs/arch-management-split.md: log_* 行注明强制组件路径不落盘
- i18n 占位符一致性: 后端 39 键 + 前端 115 键 zh/en 全量比对 0 错配(静态检查, 无需修)
- README.en.md 全量对齐 v4 双进程架构(6995416)
