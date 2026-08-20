# 审计变更日志 (Audit Changelog)

从第 1 次 pro 审计到第 28 批的完整变更记录。审计方式: 三专项(测试覆盖率 / 代码质量 / 安全漏洞)每批并行, 子代理限 `read_file` + `search_files` 只读静态审计; 每批发现 → 修复 → 提交 → 下一批, 直到收敛。

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
