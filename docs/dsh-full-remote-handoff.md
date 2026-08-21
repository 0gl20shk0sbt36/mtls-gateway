# Handoff: dsh-full-remote isLoopback 注入逻辑抽离 + 适配 mtls-gateway

给 dsh(编程主力)的任务上下文。目标:**用户不起 Windows 端 relay 客户端, 直接经 mtls-gw(https://100.104.135.63:9443)访问 dsh, 设置/模型界面可用(不再报 "settings are unavailable in this browser")**。

## 背景(问题本质)

dsh 前端 `dsh-client-connection/lib/client.js:10282`:
```js
isLoopback: pageLocation === void 0 || isLoopbackHostname(pageLocation.hostname)
```
- 前端**只认浏览器地址 hostname 是 loopback(127.x/localhost)** 才允许 settings 持久化(host 模式)
- 用户经 `100.104.135.63:9443`(非 loopback)访问 → 前端把 settings persistence 设为 memory → 设置界面不可用
- 服务端围栏已被 mtls-gw 改写 Host 绕过(settings.describe 返回 200), **卡住的是前端这层浏览器本地检测**(mtls-gw 网络层够不到 location.hostname)

## 参考库(已拉取, v0.3.7)

`/home/yyx/projects/dsh-full-remote`(JUANWANG-BUAA/dsh-full-remote)

它解决了同样的问题, 机制是**注入 isLoopback 信任**(不是只改写 Host)。

## 要抽离的"修改部分"(3 个文件, 共 224 行)

1. **`src/page-bootstrap.ts`(114 行)** —— 核心注入脚本(PAGE_BOOTSTRAP_SOURCE, IIFE):
   - 设置 `globalThis.__DSH_FULL_REMOTE_TRUSTED__ = 1`
   - **包装 `__ModuleLoader__.load`**(wrapApply): 官方 connection 插件 `apply()` 之后, `Object.defineProperty(connection, "isLoopback", {value:true,...})` 钉住
   - randomUUID / AbortSignal.any polyfill(兼容)
   - 关键坑: Harness 模块系统 queue→live 切换时会**重新赋值 `__ModuleLoader__.load`**, 一次性包装会被覆盖(issue #14), 需用 accessor 持续包装
2. **`src/client/trust-settings.ts`(83 行)** —— 备份 wrap: 若 pin 未生效, 包装 `settingsScope.bind`, bind 时临时钉 isLoopback=true(官方 settings 插件 apply 时读到 loopback → 持久化 host), 完事恢复
3. **`src/hosts.ts`(27 行)** —— `isLoopbackHost`(与 Harness 对齐的 loopback 分类)

注入方式: 服务端(index-tap)把 PAGE_BOOTSTRAP_SOURCE 注入到 dsh 的 index.html(可参考 src/proxy.ts / src/index-enhancements.ts 的注入实现)。

## 适配目标(mtls-gateway)

- 仓库: `/home/yyx/projects/mtls-gateway`(Go)
- 要求: 用户经 mtls-gw 9443 访问 dsh 时, 注入等效的前端信任(让前端认为 loopback), settings 可用
- 思路(自选, 需说明选型): 
  a. **mtls-gw 反代响应改写**(Go): 对 dsh 的 index.html 注入等效 IIFE(注意只对 text/html 注入、不缓存、Content-Length 重算/分块)
  b. 独立注入组件/脚本(dsh 侧部署, 不依赖 relay)
- 产出: 代码 + 单元测试 + 文档, 遵循项目现有规范(mtls-gw 是 Go, 测试随包)

## 验证

- 注入后: 浏览器经 100.104.135.63:9443 打开 dsh, 设置 → 模型界面不再报 "settings are unavailable"
- 回归: 本机 127.0.0.1:3080 直连 dsh 仍正常(注入不破坏 loopback 场景)
- 注意 dsh 前端 bundle 有 hash 缓存, 验证时可能需要硬刷新
