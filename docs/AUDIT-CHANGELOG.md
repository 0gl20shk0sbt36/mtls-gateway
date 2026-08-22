# 审计变更日志 (Audit Changelog)

从第 1 次 pro 审计到第 31 批 + flash 横向扫描 + 2026-08-22 三轮子代理复审迭代的完整变更记录。
审计方式演进: ① pro 三专项(测试覆盖率/代码质量/安全漏洞)每批并行, 子代理限只读静态审计;
② flash 横向通读扫盲; ③ 2026-08-22 起 7 大类只读审计 + 复审迭代闭环。每批发现 → 修复 → 提交 → 下一批, 直到收敛。

> 注: 提交全部在本地(未推送云端), 每批一 commit 便于回滚。

---

## 方法论
- **三专项并行**: 测试覆盖率 / 代码质量 / 安全漏洞, 每专项独立子代理(deepseek-v4-pro)
- **只读审计**: 子代理仅 `read_file` + `search_files`(工具白名单), 不能跑命令/写文件
- **迭代闭环**: 每批发现分级问题 → 修复 → 补测试 → `go test -race ./...` 全绿 → commit
- **安全面**: 第 19 批起宣告"安全面达标", 后续各批只剩低危/测试项

---

## 批次变更明细

### 第 1 批 (pro 审计第 1 批)
**代码质量 + 测试:**
- ✅ statusWriter 实现 Hijacker/Flusher/ReaderFrom(透传底层能力)
- ✅ WebSocket 经网关集成测试(101 升级)
- ✅ relay API decode 错误检查统一 `decodeJSON`(10 处, 400)
- ✅ writeErr 按语义映射状态码(400/404/403/500, 保持 JSON 体)
- ✅ loadConfig 解析错误 Fatal(不再静默默认值)
- ✅ 非 loopback 监听警告 + Server 超时
- ✅ i18n 警告固定文案(翻译可命中)
- ✅ 证书缓存 TTL 60s
- ✅ 签发回滚清理孤儿文件
- ✅ randPassword 无模偏差(crypto/rand.Int)
- ✅ 落盘原子写 + 备份限量
- ✅ TCP 隧道半关闭 + 空闲超时 + Accept 退避
- ✅ IsAdminPurpose 参数化、死代码清理
- ✅ ADMIN_PWD 声明 / toast 去重 / 轮询暂停 / i18n 变量转义

### 第 2 批 (pro 复查)
- ✅ 隧道半关闭接口断言(CloseWrite) + 真空闲超时(原子 lastActive)
- ✅ relay 管理 API 强制 loopback(`--allow-remote` 放行)
- ✅ Origin/Host 校验防 DNS rebinding
- ✅ applyServerCA 失败拒绝启动(防 MITM 降级系统根)
- ✅ 隧道本地 HTTP 超时、403 响应脱敏、randPassword 熵源失败 Fatal

### 第 3 批
- ✅ sameOrigin 加 Host loopback 白名单(修 DNS rebinding 绕过)
- ✅ SetDeclaredRoles 加锁、configmgr getter 深拷贝
- ✅ proxy ErrorHandler 脱敏(后端错误细节不返客户端)
- ✅ 服务端 apiErrStatus 状态码映射(400/409/403/500)
- ✅ relay-cli 适配 v4 模型(service/locals)
- ✅ ReadTimeout/WriteTimeout + MaxBytesReader
- ✅ Fingerprint 改 SHA-256、gw 优雅退出(SIGINT/SIGTERM)、多 IP SAN 任一命中、eventlog 写错误检查
- ✅ 测试 R1-R7(隧道空闲超时/半关闭/applyServerCA 失败/sameOrigin 集成/writeErr 状态码/isLoopbackAddr/403 脱敏/admin 桥成功)

### 第 4 批
- 🔴 **Delete\*/Update\* 回滚数据损坏**(`[:0]` 复用污染 old)→ 深拷贝
- ✅ apiErrStatus 补未声明角色 400
- ✅ localHTTPHandler Transport 超时 + rp 按 serverAddr/证书轮换重建
- ✅ L/rootCAs 锁内读(修竞态)
- ✅ MaxBytesReader 全覆盖(io.ReadAll 限流 + CRUD 6 端点)
- ✅ gw 优雅退出 Shutdown 全部 server + 关闭 store/日志
- ✅ idle<=0 跳过监控、多 IP SAN 用 net.IP.Equal、SaveConfig 原子写
- ✅ 测试: TestTunnelIdleTimeout 修复注入时序(Start 前)

### 第 5 批
- ✅ SaveConfig 原子写补生效
- ✅ gw 优雅退出修 log.Fatalf(ErrServerClosed 判断 ×3)+ servers append 加锁 + 删双重 Close
- ✅ localHTTPHandler rp 读锁 + Director 闭包快照(修重建错配竞态)+ 旧 rp 关连接
- ✅ rootCAs/L 裸读统一访问器(tunnel/api/discover)
- ✅ writeErr 保留字→400/已存在→409(与 apiErrStatus 对齐)
- ✅ AddTunnel/DelTunnel 落盘深拷贝、i18n t() `$` 序列函数替换修复

### 第 6 批
- ✅ AddTunnel/DelTunnel 落盘深拷贝真正落地
- ✅ discover/api rootCAs/L 裸读统一访问器
- ✅ SaveConfig/persist 唯一 tmp 名 + chmod
- ✅ Router 深拷贝斩断别名(修 /info 竞态)、servers 快照读锁
- ✅ writeErr/apiErrStatus 对齐(未声明→400/admin required→403/已存在→409, 删死代码)
- ✅ Days 上限 3650

### 第 7 批
- 🔴 **LoadCertWithPassword 重入死锁**(去外层锁; sync.Mutex 不可重入, Windows 证书源必死)
- ✅ SaveConfig/persist 改 CreateTemp 真唯一 tmp + defer 清理
- ✅ db Get/List Purposes 深拷贝、writeErr Content-Type 先于 WriteHeader
- ✅ Router 内层 Roles/Channels 深拷贝(测试逼出)

### 第 8 批
- 🔴 **SaveConfig/persist fd 泄漏**(CreateTemp 句柄写 + Close)
- ✅ persist CreateTemp 真落地(修固定 .tmp symlink 跟随 + defer 清理)
- ✅ db Get/FindByName Purposes 深拷贝(授权热路径)
- ✅ ConfigManager.Services 内层深拷贝、api 层 JSON 端点 Content-Type

### 第 9 批
- ✅ persist() CreateTemp 真落地(三审确认此前未落地)
- ✅ issue/health 端点 Content-Type 补齐、db Upsert 入参深拷贝
- ✅ InsertUniqueName 原子防同名 TOCTOU(并发同名仅一成功)
- ✅ 备份时间戳纳秒级

### 第 10 批
- 🔴 **并发同名签发文件回滚竞态**(唯一临时目录 `.tmp-serial` + 登记成功后才 rename, 败者不误删胜者文件)
- ✅ Manager.Config Routes 内层深拷贝、InsertUniqueName 错误去计数
- ✅ loadCert 三段式锁外 IO、eventlog.StatusWriter 补 Flusher/Hijacker/ReaderFrom

### 第 11 批
- 🔴 **rename 失败幽灵记录**(Store.Delete 回滚 + validName 长度 ≤64 防 ENAMETOOLONG)
- ✅ loadFirstCert 锁外 IO、dialTLSConfig MinVersion TLS12
- ✅ KeyPEM 远程通道不返回、persist 失败日志警告(内存权威)、启动清理孤儿 .tmp-\*

### 第 12 批
- ✅ Store.Delete 改 SQL 先成功再删内存(防 DB 失败分叉)
- ✅ StatusWriter Hijack 安全断言 + ReadFrom 计字节
- ✅ DelTunnel 落盘失败也 reloadTunnels(与 AddTunnel 对齐)
- ✅ dot-segment 规范化(cleanDotSegments 只清 .. 不碰 // 和尾斜杠, proxy+tunnel)

### 第 13 批
- 🔴 **服务端 proxy.go 接入 cleanDotSegments**(第 12 轮只改 tunnel, 服务端漏 → `/admin/../secret` 逃逸 target 前缀)
- ✅ cleanDotSegments 根钳制(.. 不丢前导斜杠)
- ✅ localHTTPHandler 前缀边界(/foo 不匹配 /foobar)
- ✅ StatusWriter.WriteHeader 幂等、Reload 部分失败 continue

### 第 14 批
- ✅ Reload continue 真落地(坏隧道不卡死 + 保证清理循环执行)
- ✅ main.go statusWriter 幂等 + status0 兜底 200、proxy Serve 清 RawPath

### 第 15 批
- ✅ gofmt 全量清理(19 文件, CI 加 gofmt 检查)
- 🔴 **Reload 吞错 → 聚合错误返回 + 证书/路由变更热切换**
- ✅ Hijack 记 101、infoHandler status0 兜底
- ✅ cleanDotSegments 抽 internal/pathutil(消除双份重复)

### 第 16 批
- 🔴 **匹配前规范化请求路径**(gatewayHandler + localHTTPHandler, 防 /admin/../secret 逃逸)
- ✅ 热切换改先停旧起新失败恢复旧隧道(防僵尸虚报 Running)
- ✅ CI gofmt 检查真落地(ci+release workflow)、reflect.DeepEqual 改直接比较

### 第 17 批
- 🔴 **main.go statusWriter.Hijack 记 101**(真漏, 网关访问日志 WebSocket 记 200 而非 101)
- ✅ CleanDotSegments 反斜杠归一化 + 短路优化(防 Windows 后端 `\..\` 逃逸)
- ✅ stop 释放 HTTP 反代空闲连接(rpTransport)、release.yml 加 gofmt

### 第 18 批
- 🔴 **rpTransport 真赋值**(atomic.Pointer, 之前死代码 stop 不释放)
- 🔴 **localHTTPHandler 重建死代码修复**(每次请求走 init, 证书轮换/serverAddr 变化才真正生效)
- ✅ metrics 复用删除(atomic.Value 复制违约)

### 第 19 批
- ✅ localHTTPHandler 改 double-checked locking(快路径只读锁, 修每请求写锁性能回归)
- ✅ 短路冗余清理、测试: serverAddr 变化触发 HTTP 反代重建

### 第 20 批
- ✅ 修复假阳性测试 TestTunnelHTTPRebuildOnServerAddrChange(改用 HTTP mTLS 网关 stub + host 变化触发重建)

### 第 21 批
- ✅ certCacheTTL 改 Relay 字段可注入(修结构性不可测, 带 TTL 轮换重建测试)
- ✅ Discover 默认路径测试、AdminClient 配置 CRUD 测试

### 第 22 批
- 🔴 **ListMappings 解码类型修复**(真 bug: []ServiceInfo → []MappingInfo 对齐服务端契约)
- ✅ stub 契约对齐、TestTunnelHTTPCertRotation 断言加强、writeErr 死代码清理

### 第 23 批
- 🔴 **writeErr 状态码改按原始错误判定**(英文路径 404/403 不再错标 500)
- 🔴 **serverOverride 接入 adminAddr**(修 --server 覆盖死代码)
- ✅ 正则包级预编译、AdminService 桥测试

### 第 24 批
- 🔴 **errCertName 提取回归修复**(多组正则合并致 len(m)==2 恒假 → 拆回单捕获组预编译)
- 🔴 **serverOverride 语义纠错**(admin 桥必须走独立 admin_addr, 防假成功解锁管理台)

### 第 25 批
- 🔴 **--server 覆盖注入 StartWith**(Start 无条件用配置文件值覆盖的失效修复)
- ✅ errCertName 补 parse keypair 模式、localizeKnown 补 auth 错误串分支

### 第 26 批
- 🔴 **errRevoked/errExpired 模板无 %s 传参修复**(%!(EXTRA) 垃圾)
- 🔴 **--server 覆盖 Reload 回退修复**(Manager 层 serverOverride, Config()/reloadTunnels 应用 + 不落盘)
- ✅ 正则补 parse pem keypair 变体

### 第 27 批
- 🔴 **writeErr 状态码增强**(优先解析 HTTP NNN 权威状态码 + admin cert required→403 + 密码错误→400)
- ✅ localizeKnown 补 admin cert required→errAdminDenied
- ✅ gwErr 复用 api.ErrStatus(修固定 400, 导出 ErrStatus)
- ✅ CLI --days 默认 0(修 admin 证书 365 天绕过 AdminDays)
- ✅ errCertName 用 \S+ 防 Windows 盘符路径截断
- ✅ reHTTPStatus 正则锚定 4xx/5xx(修 HTTP 2xx 吞状态码边界)

### 第 28 批
- 🔴 **ErrStatus 补配置管理词汇**(duplicate/immutable/bad role/missing/has no channels → 409/403/400, 修 gwErr 复用引入的 500 回归)

### 第 29 批
- 🔴 **抽 `StatusFromKeywords` 单一权威表** —— 根治 writeErr(relay)/ErrStatus(api) 两套关键字表反复漂移的根因, relay 复用 api 表
- 🔴 补 `bad role %q`/`bad port`/`too long`/`needs password` 等关键字(修 3 处 500 回落)
- ✅ 删 4 个死 i18n 键(errBadRole/errRoleUndeclared/errMapExists/errChannelRef)
- ✅ 测试: 真实错误串变体 + HTTP 层精确断言(dup→409 / bad role→400)

### 第 30 批
- 🔴 `"拒绝"` 关键字收窄为 `"拒绝访问"`(修 server_ca "拒绝降级系统根" 被误标 403)
- ✅ 删 4 个死 i18n 键(usage/ok/issue_usage/revoke_usage)

### 第 31 批(pro 收敛确认)
- ✅ 补 `"拒绝"` 收窄回归护栏(拒绝访问→403 / 拒绝降级→500)
- ✅ **pro 三专项宣告收敛**: 测试无 P1/P2、代码质量无新实质问题、安全面达标

---

## flash 审计(独立视角, 与 pro 正交)

flash 用**横向通读全库**策略(非 pro 的深度迭代), 扫出了 pro 31 批漏掉的缺陷。两轮: low+25 轮 / max+50 轮。

### flash low/25 轮(3 专项)
**核心发现(pro 漏掉的):**
- 🔴 **数字型 mapping ID 歧义** — `channels:["1"]` 被 `strconv.Atoi` 当索引而非 id, 可把 A 服务权限静默授给 B 服务(权限错配)
- 🔴 **`m.relay.L` 裸读 data race** — api.go:294 裸读 vs core.go:56 SetLang 裸写
- 🔴 **relay 上行 TLS 握手无超时** — 僵尸端点永久挂起 goroutine
- 🔴 **admin_role 热更新绕过** — 只在启动时校验, 管理 API 可把 admin_role 写进服务 roles
- 🟠 **网关无条件覆盖 Origin** — 后端依赖 Origin 的 CSRF 防护失效
- 🟠 **转发头清理不全** — Forwarded/X-Original-URL/X-Rewrite-URL/X-Forwarded-Server/Via 可伪造直达后端
- 测试盲区: 两个 CLI 整包零测试、Unix socket 通道零覆盖、Dialer 零直测

### flash max/50 轮(3 专项)
**新增实质发现(low 档没报的):**
- 🔴 **`AddTunnel` 启动失败被吞** — API 谎报 `ok:true` 但隧道没起, 坏配置已落盘
- 🔴 **mutable 落盘失败仅打日志** — API 返回成功, 重启丢配置
- 🔴 **`randPassword` 熵源故障 `log.Fatalf`** — 杀死整个网关(含业务端口)
- 🔴 **`SanitizeHeader`(防伪造转发头)零测试**
- 🟠 尾斜杠 listen 前缀匹配失效(`:9443/a/` 永远不匹配)
- 🟠 `admin_role` 配成 `any` 破坏角色语义(任何 any 证书变管理员)
- 🟠 前端 `{adminRole}` 占位符从未替换(界面显示字面量)
- 🟠 WebUI 无 CSP + 外链 Google Fonts
- 🟠 `go:embed web/*` 把 test/e2e 测试 JS 打进生产二进制
- 安全 M1: relay 管理 API 无鉴权, 同机进程可借 daemon 身份加载任意证书(窃身份→提权签发)
- 安全 M2: 隧道 `listen_host` 无 loopback 校验, 误配即暴露到局域网

### flash vs pro 对比结论
- flash 不是 pro 的加强版, 是**正交补集**: 横向通读扫盲区, 但单轮质量弱于 pro(PR 审计基准 pro 89% vs flash 68%; 审全库场景无直接数据)
- 思考强度 max 有杠杆(多挖出 4 真 bug + 边界), 但不质变 —— 能力差异是模型本身, 非时长
- 混合模式最优: pro 深度专项 + flash 横向扫盲

---

## 汇总统计

### 真实 bug(审计逼出, 共 20+)
| 类别 | bug |
|---|---|
| 网络/协议 | WebSocket 被 statusWriter 破坏; localHTTPHandler 启动死锁; rp nil Transport |
| 并发/竞态 | 重入死锁; 回滚数据损坏; 并发同名删胜者文件; 落盘竞态; rp 竞态; servers append 竞态; L/rootCAs 裸读; atomic.Value 复制违约 |
| 一致性 | rename 幽灵记录; 同名 TOCTOU; ListMappings 类型错; errCertName 提取失效; %!(EXTRA) 垃圾 |
| 安全 | 服务端 dot-segment 逃逸; 英文路径 404→500; --server 失效 ×2; KeyPEM 远程泄露; admin 证书 365 天绕过; gwErr 500 回归 |
| 死代码 | rpTransport 未赋值; localHTTPHandler 重建不可达; serverOverride 无读取 |

### 安全加固(20+)
DNS rebinding 防护、server_ca 拒绝降级、管理 API 强制 loopback、403 脱敏、KeyPEM 远程不返回、同名签发原子、有效期上限、--days 默认 0、路径穿越清理(斜杠 + 反斜杠)、MaxBytesReader 全覆盖

### 测试基础设施
- 抽 internal/pathutil 包、certCacheTTL 可注入、CI gofmt 检查
- 新增 60+ 测试函数(并发 -race、边界、回滚、契约对齐、假阳性修复)

### 最终状态
- `go test -race ./...` 全绿 / gofmt+vet 净 / E2E 14/14 / 前端单测 8/8
- 安全面第 19 批起达标

---

## flash 审计发现 → 修复落地(第 29 批之后)

flash 两轮审计报的 11 项问题全部修复:

| 问题 | 修复 |
|---|---|
| 🔴 数字型 mapping ID 歧义(权限错配) | 先按 id 精确匹配再回退索引, 抽 `resolveChannelIndex` |
| 🔴 AddTunnel 启动失败吞错(谎报 ok) | 如实上报(未启动=不算错) |
| 🔴 mutable 落盘失败静默 | 8 处 persist 改返回 error |
| 🔴 randPassword 熵源 Fatalf 杀进程 | 改返回 error |
| 🔴 `m.relay.L` 裸读 data race | 改 `lang()` 锁内读 |
| 🔴 TLS 握手无超时 | 握手加 timeout |
| 🔴 admin_role 热更新绕过 + 配 any | rebuild 统一校验 + AddRole/loadConfig 拒绝 |
| 🔴 转发头清理不全 | SanitizeHeader 补 5 个转发头 + 测试 |
| Origin scheme 硬编码 / 尾斜杠前缀 / 前端 {adminRole} | target.Scheme / parseListen 去尾斜杠 / applyI18n 替换 |
| 🔴 隧道同端口多路径重复 bind(修吞错暴露的既有缺陷) | 整口占用时路径 route 复用 listener |
| go:embed 打包 test/e2e 进二进制 | 显式列 4 个运行时文件 |
| Google Fonts 外链(隐私外泄) | 自托管 latin 子集 woff2 |
| 两个 CLI 整包零测试 | 14 例黑盒测试(编译子进程 + 假 daemon) |

---

## 并发正确性 + 资源生命周期专项(flash 横向扫 → pro 深挖 → 修)

**flash 横向扫出 L2×4 + L3×8; pro 深挖逐条验证(纠正 flash 两处过度判断)。**

### 确认并修复的 3 条 L2
1. 🔴 **端口复用顺序反转**(flash修复⑤引入的双向缺陷): 复用=no-op, 路径在前则整口语义丢、整口在前则路径语义丢; 删宿主不重建。修: ①`tunnelRoutes` 整口优先稳定排序 ②宿主删除后复用 route 重建 ③`listener==nil` 状态标 Running=false(不再虚报)
2. 🔴 **僵尸上游**: stop() 只关本地连接不关 upstream, copy goroutine 在上游不响应 FIN 时阻塞(生产默认 idle=120s 是有界残留, idle≤0 才永久)。修: upstream 纳入 `rt.conns` 关闭集合
3. 🔴 **连接泄漏**: Discover/AdminClient 每次新建无 IdleConnTimeout 的 Transport(有界 ≤60s)。修: 加 `IdleConnTimeout` + `CloseIdleConnections` + AdminClient.Close

### pro 深挖的关键纠正
- flash 报"永久 goroutine 泄漏"→ 实为"生产默认 idle=120s 有界残留"(idle≤0 仅测试可达)
- flash 报"无 IdleConnTimeout 泄漏"→ 实为"≤服务端 IdleTimeout 60s 有界"

### L3(未修, 记录)
锁粒度(Reload 持大锁/persist 持锁 IO/db 写锁 SQLite)、循环内 time.After 未 Stop、优雅退出不彻底、每请求重建 ServeMux、eventlog rotate 失败静默、HTTP 反代每 60s 重建 Transport。

---

## 可读性/可维护性专项(flash 横向扫 → 修)

### P1 高优先级(4 条全修)
1. 手写标准库替代: `containsCI`/`lowerExt` → `strings.EqualFold`/`filepath.Ext`(删 30 行 + 修 ASCII-only 不支持 Unicode)
2. deprecated API(`x509.IsEncryptedPEMBlock`/`DecryptPEMBlock`): 加迁移注释(DEK-Info 加密私钥暂无标准替代)
3. 错误本地化三套机制: gwErr 注释如实描述(只认 errImmutable + 三处分散的坑)
4. host:port/listen 解析多份: relay 包内统一(stripPort 复用 + splitListen 抽取)

### P2 低风险(4 项已修)
角色交集 `Allows`/`rolesMatch` 合一、证书加载 `loadCert`/`loadCertLang` 合一、两个 CLI 的 HTTP 客户端三份 → 抽 `do()`、http.Serve 退出日志噪音。

### P2 高风险(未修, 见 TODO.md)
http.Server 三段复制、configmgr 9 CRUD 模板、DTO 复制、角色名校验 4 份、路径拼接两包、ResponseWriter 两份、原子写两处、跨端 tunnel key 格式耦合 —— 均为"重复代码"型债, 不影响功能, 跨包重构收益递减风险递增。

---

## 2026-08-22 三轮子代理复审迭代(7 大类只读审计 → 复审 → 收敛)

新范式: 7 个只读子代理并行审计(安全/正确性/并发/平台/测试覆盖/质量/运维) → 修复 → 4 复审 → 修复 → 3 复审(无必须再修) → 收编 → 2 验证复审。全程 read/glob/grep 只读; 每轮全量测试(19 包 -race + 五平台构建 + 前端 8/8)后单次提交, 均未推送。

### 第一轮(7 并行只读审计 → 修复 17cba8f, 44 文件 +1146/-657)
- 🔴 全修: admin_role 校验缺口(拒 null/ValidRoleName/不与 roles 声明重叠) / SetDeclaredRoles 热更新 / certsource+relay.src 数据竞争 / applyServerCA 失败降级系统根 / 双进程 admin_listen 端口冲突(reload_listen) / config.example 缺 roles 声明 / cert_issue|cert_revoke 事件 / isAddrInUse Windows / 权限预检(mode+reload_cert+mtls-admin 复用)
- 🟡 大部分: 配置文件缺失拒绝启动 / reload 降级+失败事件 / 网关 stop 事件 / 管理面认证失败日志 / 日志分进程 / IPv6 ResolveListen / listen 判重规范化 / 热重载新端口告警 / DB UNIQUE(name) / UpdateSettings 先应用后落盘 / 访问日志 IP+耗时 / CLI 状态码 / Origin 断言 / certsource darwin 兜底 / CI windows-test+android-build
- 🟢 部分: 死代码/误导注释/rotate 修正/数字索引警告/symlink 防护//info ReadAll 上限/日期缓存/ResponseWriter 去重

### 第二轮(4 复审 → 修复 6e0a456, 17 文件 +257/-115)
- 🔴 高: **permissioncheck mode 检查平台门控回归** — Windows os.Stat 的 Perm() 恒 0666, mode&0o077 检查在平台无关层会把全部密钥文件误判"权限过宽"拒启; 收口到 access_linux.go modePerm(非 Linux 恒 0) + 新增 !linux 断言测试(随 CI windows-test 执行防再漏) + ModeRestrict 0o077→0o007(0640 group 可读放行)
- 🟡 中: loadFirstCert 无锁读 r.src(与 SetSource 热替换竞争) / LoadWithPassword+子目录 cert.pem/key.pem symlink 逃逸 / /info 成功路径+fetchCAAndFilter 无界 JSON 解码 / 审计事件下沉 api.Manager.SetAudit(unix socket/TCP 双通道统一) / mtls-admin 日志分离强制组件路径(共享路径=滚动竞态源)
- 🟢 低: config 拒 "any" / TestResolveListen IPv6 用例 / certsource_other 注释 / proxy 日志路径 CRLF 清洗 / 魔法数字抽 maxBodyBytes/maxInfoBody / webUILogger sync.Once 毒化改 mutex 重试

### 第三轮(3 复审 → 8e8cf9a + b629c0f, 均报"无必须再修")
- 8e8cf9a: logging.DefaultDir Windows 组件子目录(否则 gw/admin 默认日志路径相同, 强制替换在 Windows 失效) / 三日志字段替换 log.Printf / certsource List 逃逸符号链接一次性告警 / sanitizeLogPath 扩滤全部 C0 控制字符
- b629c0f: **configmgr 落盘污染** — 日志路径替换后的 cfg 传入 configmgr, persist 整份 Encode 把 admin 组件路径写回共享 config.toml → 网关重启日志合流; 改传原始 cfg(origCfg), 替换只影响本进程 / warnSymlinkEscape 新引入文本日志注入面(Linux 文件名可含 \n, CWE-117) / 清洗函数抽公共 pathutil.SanitizeForLog(relay CA subject 同套用) / sanitizeLogPath 单测

### 最终验证(2 复审 3b26f1a7/1a5e2e9b)
平台/安全双复审对 8e8cf9a 均报无必须再修; 文档一致性收尾 e7271cf(README 端口表 reload_listen/ModeRestrict 权衡/config.example 日志段说明/CHANGELOG/arch/TODO + i18n 占位符后端 39 键前端 115 键 0 错配静态校验)

### 测试全面性专项(独立审计, 2026-08-22 派发 → 已收敛)审计测试场景设计是否全面(负面路径/边界值/安全断言/失败回滚/并发/平台矩阵/回归护栏), 非覆盖率数字。
**结论**: 护栏整体完备(22:18 落盘回滚/DSH 超时/日志注入/admin_role 启动校验/转发头伪造/403 脱敏/并发同名签发/configmgr 回滚/permissioncheck/E2E 主流程), 但有 4 高危 + 9 中危"有功能但零测试"缺口。
**已补(本提交)**: SetAudit 审计回调触发与失败不触发 / IssueCert 保留字+未声明角色实测 / symlink 逃逸三处拒绝(List/Load/LoadWithPassword) + 合法身份不误伤 / api+relay 两侧 4MB 请求体上限 / UpdateSettings SetServerCA 失败回滚 / Start 中途失败回滚(监听释放) / db.Reload 失败保持旧表 / /info 吊销证书 403 + 匿名引导 200 / eventlog maxFiles=1 / NewManager 坏 CA/key / configmgr null+admin_role 禁声明+any 禁删 / /info 超 1MB 响应限流回归 / **新增 Windows 门控冒烟测试**(certsource_windows_test.go, 随 CI windows-test 真机跑 CNG 枚举, 填补"Windows CNG 零直接测试"缺口)。
**补测发现的真实缺口**: `PUT /api/settings` 直接 json.Decode 绕过 MaxBytesReader 4MB 限流(5MB body 返回 200)→ 已改 decodeJSON 修复。
**记录待补(低危/复杂)**: Reload 热切换失败恢复旧隧道(需起真实隧道+冲突端口编排, 成本高)、E2E 配置成功保存路径、accessEvent 字段断言、rolesMu 并发 -race、等价 listen 写法判重、Discover 失败路径。

---

## CI 首跑(2026-08-22 推送后, 3 轮修复 → 7/7 全绿)

推送 183 个本地提交后 GitHub Actions 首次真机执行, 连续抓出本地无法暴露的问题:

1. **windows-test 第 1 轮**: 管理桥测试字符串拼接 Windows 路径进 JSON(`\U` 非法转义) / CLI 黑盒测试 exec 路径缺 `.exe`(go build -o 在 Windows 自动追加)。
2. **WebUI E2E setup.sh 单进程架构**(管理拆分遗留): 脚本只起 gw 经其 socket 签发, 拆分后签发在 mtls-admin → 必失败。重写为双进程: 两阶段 admin(先起签发 → 追加 reload 配置并重启激活 reload 客户端 → 再起 gw 全量载入)。端口 469xx→57xxx(与生产在用网关冲突, 永久避开); TOML 追加键放 [[services]] 之后会被当 service 字段吞掉 → awk 插到 [[mappings]] 前; relay.json 显式配 cert_dir(否则 UI 保存发空值触发 OpenSystem 失败)。
3. **真功能缺口(管理拆分数据流)**: 证书签发/吊销从不触发网关 reload(只有 config CRUD 接 changed()) → api.Manager 加 SetPostChange 回调, mtls-admin 接 rc.Trigger(); 网关/管理进程预检前 MkdirAll 日志目录(新机器默认路径目录不存在 → 拒启)。
4. **windows-test 第 2 轮**: certsource checkWithinRoot 的 EvalSymlinks 在 Windows 展开 8.3 短名(RUNNER~1)→ 合法证书全被误判 symlink 逃逸 → root 也先解析再比较; 另修 3 处 Windows 不兼容测试断言(JSON 反斜杠转义/Unix 0600 权限)。

**结果**: 7 job 全绿(Test 1.25/1.26、windows-test、WebUI unit、WebUI E2E、windows/android build), E2E 本地 15/15 也真实跑通。
