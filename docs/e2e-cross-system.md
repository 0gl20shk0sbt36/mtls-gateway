# 跨系统 E2E 验证 (Cross-System E2E)

本文件记录 mtls-gateway 跨操作系统 E2E 矩阵的拓扑、验证步骤与结果。
CI 无法复现双机环境, 此文档 + `scripts/cross-system/` 复跑脚本保证"人可复跑、审计可追溯"。

## 矩阵与结果

| 组合 | 服务端 (gw) | 客户端 (relay) | verify | 转发 | mTLS 壳 | 结果 |
|---|---|---|---|---|---|---|
| L-L | Linux 100.64.0.1 | Linux | ✅ | ✅ | ✅ | 通过 |
| W-W | Windows 100.64.0.2 | Windows | ✅ | ✅ | ✅ | 通过 |
| W-L | Windows 100.64.0.2 | Linux | ✅ | ✅ | ✅ | 通过 (2026-08-20) |
| L-W | Linux 100.64.0.1 | Windows | ✅ | ✅ | ✅ | 通过 (2026-08-20) |

验证日期: 2026-08-20 (W-L / L-W 为新增实测, L-L/W-W 为既有演示环境)。

## 拓扑

```
Windows 100.64.0.2 (Tailscale)          Linux VM 100.64.0.1 (Tailscale)
├─ mtls-gw.exe  (gw-win2.toml)             ├─ mtls-gw2     (m2-gw.toml)
│   info :29998  admin :29999              │   info :39998  admin :39999
│   映射 :29991[/admin] :29992(any) :29993 │   映射 :39991[/admin] :39992(any) :39993
│   db: gw.db (admin 7541 + 10 枚)         │   db: /var/lib/mtls-gw/mtls-gw.db (admin+e2e-a)
├─ echo 9087 (schtasks mtls-echo)          ├─ python http.server 9087
└─ certs 目录 (共享, 见下)                 └─ certs 目录
```

- 证书/CA 共享: `D:\temporary\mtls-e2e\win2\` ⇔ `/mnt/host-temporary/mtls-e2e/win2/` (SMB 挂载)
- 客户端证书源: `certs/{admin,e2e-a,cross-b}` (admin 私钥加密, e2e-a/cross-b 无密码)
- 服务端证书 `server.crt` SAN 必须含 `127.0.0.1, localhost, 两个 Tailscale IP`
  (跨系统 TLS 验证服务器证书的关键; 缺任一 IP 会 `x509: certificate is valid for 127.0.0.1, not <ip>`)
- 两 gw 的 `bind_host` 必须绑各自 Tailscale IP (127.0.0.1 只接受本机)

## 关键前置 (踩坑记录)

1. **gw bind_host**: 127.0.0.1 → 绑 Tailscale IP, 否则跨机 connect 超时
2. **server.crt SAN**: 必须含对端访问用的 IP
3. **certs 目录同步**: 挂载点与本地拷贝是两个目录, 改证书要两边同步
4. **加密证书不能建隧道** (设计): 业务隧道须用无密码证书 (WebUI 建隧道时前端已有提示)
5. **Windows relay 常驻**: 用 schtasks 起 (SSH Job 会杀子进程), 任务: mtls-e2e (28083), mtls-relay-lw (28184), mtls-gw2, mtls-echo

## 复跑步骤

### 方向 W-L (Windows gw + Linux relay)

```bash
bash scripts/cross-system/verify-wl.sh
```

验证内容: Linux relay 连 Windows gw → admin 证书验证 (密码 dandan070804)
→ 签发无密码业务证书 → 建隧道 → 本地路由转发 → Windows echo 9087 → 无证书/坏 CA 直连被拒。

### 方向 L-W (Linux gw + Windows relay)

```bash
bash scripts/cross-system/verify-lw.sh
```

验证内容: Windows relay (28184) 连 Linux gw → e2e-a 证书验证 → 建隧道
→ 本地路由转发 → Linux echo 9087 → 无证书直连被拒 / 带证书直连 200。

## 结果判定标准

- verify: 返回服务列表 (该证书角色可见的最小暴露面)
- 转发: `HTTP 200` 且响应为 echo 后端内容 (Directory listing / 自定义 body)
- mTLS 壳: 无客户端证书 → TLS 握手失败 (curl 000 / connection reset);
  错误 CA 证书 → 握手失败; 合法证书直连 → 200

## 已知限制 (显式声明)

1. **Windows 系统证书库 (certsource system) 冒烟已验证 (2026-08-20)** — `relay -source system` 在 Windows
   正常启动并列出系统 My 存储 4 枚证书 (含 yyx-windows, issuer "yyx Root CA"); 完整建隧道闭环依赖
   系统库私钥可导出性 (GUI 导入选项), 记为部分验证; `certsource_windows.go` 其余路径仍仅交叉编译验证
2. 跨系统矩阵为手工/脚本验证, 不进 CI (双机 + Tailscale 环境无法在 GitHub Actions 复现)
3. 证书过期边界: DB `ExpiresAt` (日期字符串) 与 x509 `NotAfter` 两套机制, 单测覆盖 DB 侧
   (auth 包 TestCertExpiryBoundary), x509 侧由 TLS 库保证
