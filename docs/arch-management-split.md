# 管理服务拆分方案 — 网关纯数据面 + 独立管理进程

> 2026-08-22 规划。目标: 把管理功能(证书签发/吊销/配置管理/服务发现)从 mtls-gw 进程
> 拆为独立进程(mtls-admin), 网关退化为纯数据面(认证 + 路由 + 转发), 管理接口与业务接口
> 走完全相同的"角色→能否访问"管道。

## 1. 架构

```
客户端 / relay ──mTLS──▶ mtls-gw (纯数据面)
                          ├─ 业务端口: 认证 + 路由(mappings/services) + 反代
                          ├─ /admin/reload (admin 证书): 管理进程调用, 全量热重载
                          └─ 只读消费者: 启动/reload 时读 DB+配置, 之后只用内存副本(只读)

mtls-admin (独立进程, 新二进制)
  ├─ 持有: SQLite DB(写) + CA 私钥(签发) + 配置(改) + 管理 API
  ├─ Unix socket (CLI) + admin_listen (TCP/Web)
  └─ 变更后 → 调 mtls-gw /admin/reload

CLI / Web 面板 / relay-admin ──▶ mtls-admin 管理 API
```

**核心约束**: 网关与管理**不同时操作**同一文件。网关是纯只读消费者(加载时读,
之后零 IO 只读内存副本); 管理进程是唯一写者(写 DB/配置后触发 reload)。

## 2. 配置(同一 config.toml, 两进程各取所需)

`mtls-gw -config X.toml` 与 `mtls-admin -config X.toml` 读同一文件:

| 字段 | 网关 | 管理 | 说明 |
|---|---|---|---|
| db | ✅ 只读(Reload 全量读) | ✅ 读写 | 共享 SQLite 文件 |
| ca | ✅ 验证客户端链 | ✅ 签发 | CA 公钥共用 |
| ca_key | ❌ | ✅ | 私钥只归管理 |
| server_cert/server_key | ✅ | ❌ | 网关 TLS |
| mappings/services/roles | ✅ 路由+授权 | ✅ 查看/改(写 TOML) | 管理改后调 reload |
| admin_listen / sock_path / cert_dir / 签发参数 | ❌ | ✅ | 管理面 |
| log_* | ✅ | ✅ | 各自日志(分平台默认) |
| reload 配置(阶段2): gateway_reload_addr | ❌ | ✅ | 管理调网关 reload 的地址 |

## 3. 数据流

1. **启动**: 两进程读同一 config.toml; 网关全量 load DB → map + 构建 Router(现状机制);
   管理进程持 DB/CA, 起管理 API。
2. **变更**(签发/吊销/改配置/改角色): 管理进程写 DB/配置文件 → 调网关
   `POST /admin/reload`(admin 证书)。
3. **网关 reload**(阶段 1 交付): 全量重读 DB → 构建新 map; 重读配置 → 构建新 Router;
   **原子替换引用**(旧副本继续服务, 新请求用新副本); 任一步失败保持旧副本并返回错误
   (与 22:18 落盘回滚同一原则: 失败不切换)。

## 4. 网关 reload API(阶段 1)

- 端点: `POST /admin/reload`(挂在现有 adminHandler, admin 证书保护; 阶段 2 拆分后可迁独立端口)
- 动作: `db.Store.Reload()`(重读 SQLite 重建 map) + `ConfigManager.ReloadFromDisk()`
  (重读 config.toml → 校验 → 新 Router → 替换)
- 幂等, 可重复调用; 量小(证书几十~几百条 + 配置几十行), 全量重载毫秒级

## 5. 身份传递(已交付)

管理进程作为网关后的后端, 经 mapping `headers` 规则 + `{cert_*}` 变量注入
`X-Client-Cert/Serial/Roles`, 识别请求的 mTLS 证书身份(先删后设, 不可伪造)。

## 6. 阶段划分

| 阶段 | 内容 | 状态 |
|---|---|---|
| 0 | 请求头改写配置化 + 证书身份注入 | ✅ 已交付(04d04d9) |
| 1 | 网关 reload API(db.Store.Reload + ConfigManager.ReloadFromDisk + /admin/reload) | ▶ 本阶段 |
| 2 | mtls-admin 进程(搬 api.Manager + 配置写 + 调 reload) | 待 |
| 3 | CLI/Web/relay 适配(admin_addr 指向管理进程) + config_mode 迁移 | 待 |

## 7. 安全

- reload 端点 admin 证书保护(仅管理进程持有 admin 证书可调)
- 网关不再持有 CA 私钥(签发面收窄, 泄露面减小)
- 管理进程写 DB 是唯一写者(SQLite 单写者天然一致); 网关 reload 为快照读
- 身份头先删后设, 后端只信网关(loopback 来源)
