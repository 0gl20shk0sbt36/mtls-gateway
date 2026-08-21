// WebUI E2E 测试 — 操作真实网页(playwright) + 转发/mTLS/签发闭环实测, CI 可跑
// 用法: 先跑 e2e/setup.sh(每次全新环境), 再 node --test e2e/webui.e2e.test.mjs
// 环境变量: E2E_URL(默认 http://127.0.0.1:46990/), E2E_ADMIN_PWD(默认 ci-admin-pw), E2E_DIR(默认 /tmp/mtls-e2e-ci)
import { test, before, after } from "node:test";
import assert from "node:assert";
import { chromium } from "playwright-core";
import fs from "node:fs";
import http from "node:http";
import https from "node:https";

const URL = process.env.E2E_URL || "http://127.0.0.1:46990/";
const ADMIN_PWD = process.env.E2E_ADMIN_PWD || "ci-admin-pw";
const E2E_DIR = process.env.E2E_DIR || "/tmp/mtls-e2e-ci";
const GW_PORT = 46991;     // svc-a 整口通道(映射 echo 46987)
const LOCAL_PORT = 47991;  // 隧道本地路由(避开 gw 同端口)

let browser, page, errors;

before(async () => {
  browser = await chromium.launch({ headless: true });
  page = await browser.newPage();
  errors = [];
  page.on("pageerror", (e) => errors.push("PAGEERR: " + e.message));
  page.on("console", (m) => { if (m.type() === "error" && !m.text().includes("Failed to load resource")) errors.push("CONSOLE: " + m.text()); });
  await page.goto(URL);
  await page.waitForTimeout(600);
  await page.evaluate(() => localStorage.setItem("lang", "zh"));
  await page.reload();
  await page.waitForTimeout(600);
});

after(async () => { if (browser) await browser.close(); });

const pickOpt = async (listId, matcher) => {
  await page.evaluate(([id, m]) => {
    const items = [...document.querySelectorAll(`#${id} .opt`)];
    const it = items.find((o) => o.textContent.includes(m));
    if (!it) throw new Error(`选项不存在: ${m} in #${id}`);
    it.click();
  }, [listId, matcher]);
  await page.waitForTimeout(250);
};

const verifyWith = async (cert, pwd) => {
  await page.click("#adminCertBtn");
  await page.waitForTimeout(200);
  await pickOpt("adminCertList", cert);
  if (pwd) await page.fill("#adminPwd", pwd);
  await page.click("#adminVerify");
  // 轮询验证结果(取代固定 sleep, 抗慢机器)
  const hint = await page.evaluate(() => document.getElementById("adminCertHint").textContent);
  for (let i = 0; i < 20; i++) {
    const h = await page.evaluate(() => document.getElementById("adminCertHint").textContent);
    if (h !== hint) break;
    await page.waitForTimeout(250);
  }
  await page.waitForTimeout(500); // 等数据加载(服务列表/配置区)
};

const svcSelectState = async () => {
  await page.click("#newServiceBtn");
  await page.waitForTimeout(200);
  const opts = await page.evaluate(() => [...document.querySelectorAll("#newServiceList .opt")].map((o) => o.textContent));
  await page.mouse.click(400, 200);
  await page.waitForTimeout(150);
  return opts;
};

function httpGet(port, path) {
  return new Promise((resolve) => {
    const req = http.get({ host: "127.0.0.1", port, path: path || "/", timeout: 5000 }, (res) => {
      let b = "";
      res.on("data", (d) => (b += d));
      res.on("end", () => resolve({ status: res.statusCode, body: b }));
    });
    req.on("error", (e) => resolve({ error: e.message }));
    req.on("timeout", () => { req.destroy(); resolve({ error: "timeout" }); });
    req.end();
  });
}

function httpsGet(port, { withCert, withBadCert } = {}) {
  return new Promise((resolve) => {
    const opts = {
      host: "127.0.0.1", port, path: "/", method: "GET",
      ca: fs.readFileSync(`${E2E_DIR}/ca.crt`), // 验证服务器证书(M4: 不再绕过)
    };
    if (withCert) {
      opts.cert = fs.readFileSync(`${E2E_DIR}/certs/e2e-a/cert.pem`);
      opts.key = fs.readFileSync(`${E2E_DIR}/certs/e2e-a/key.pem`);
    }
    if (withBadCert) {
      // 错误 CA 签发的客户端证书 → 服务器应拒绝(unknown CA)
      opts.cert = fs.readFileSync(`${E2E_DIR}/bad-client.pem`);
      opts.key = fs.readFileSync(`${E2E_DIR}/bad-client.pem`);
    }
    const req = https.request(opts, (res) => {
      let b = "";
      res.on("data", (d) => (b += d));
      res.on("end", () => resolve({ status: res.statusCode, body: b }));
    });
    req.on("error", (e) => resolve({ error: e.message }));
    req.end();
  });
}

// ============ 测试 ============

test("1. 证书列表加载(admin + e2e-a)", async () => {
  const opts = await page.evaluate(() => [...document.querySelectorAll("#adminCertList .opt")].map((o) => o.textContent));
  assert.ok(opts.some((t) => t.includes("admin")), `应有 admin: ${opts}`);
  assert.ok(opts.some((t) => t.includes("e2e-a")), `应有 e2e-a: ${opts}`);
});

test("2. admin 验证 → 证书管理区(配置区/用途/吊销)", async () => {
  await verifyWith("admin", ADMIN_PWD);
  assert.equal(await page.evaluate(() => document.getElementById("adminSection").style.display), "");
  const rows = await page.evaluate(() => document.querySelectorAll('#cfgMappings input[data-cfg="m-id"]').length);
  assert.ok(rows >= 3, `配置区通道行应>=3: ${rows}`);
  assert.ok((await page.evaluate(() => document.querySelectorAll("#cfgRoles .chip").length)) >= 2, "角色chips应>=2");
  await page.click("#newPurposesBtn");
  await page.waitForTimeout(200);
  const purps = await page.evaluate(() => [...document.querySelectorAll("#newPurposesList .opt")].map((o) => o.textContent));
  assert.ok(purps.length >= 2, `用途选项应>=2: ${purps}`);
  await page.mouse.click(400, 200);
  await page.waitForTimeout(150);
  await page.click("#revokeCertBtn");
  await page.waitForTimeout(200);
  const revokes = await page.evaluate(() => [...document.querySelectorAll("#revokeCertList .opt")].map((o) => o.textContent));
  assert.ok(revokes.length >= 2, `吊销选项应>=2: ${revokes}`);
  await page.mouse.click(400, 200);
  await page.waitForTimeout(150);
});

test("3. 配置区: target 联动 + 非法 listen 红框 + 保存拦截", async () => {
  await page.evaluate(() => document.getElementById("cfgAddMap").click());
  await page.waitForTimeout(200);
  const n = await page.evaluate(() => document.querySelectorAll('#cfgMappings input[data-cfg="m-listen"]').length) - 1;
  assert.equal(await page.evaluate((i) => [...document.querySelectorAll('#cfgMappings input[data-cfg="m-target"]')][i].value, n), "http://127.0.0.1");
  await page.evaluate((i) => { const l = [...document.querySelectorAll('#cfgMappings input[data-cfg="m-listen"]')][i]; l.value = "29994"; l.dispatchEvent(new Event("input", { bubbles: true })); }, n);
  await page.waitForTimeout(150);
  assert.equal(await page.evaluate((i) => [...document.querySelectorAll('#cfgMappings input[data-cfg="m-listen"]')][i].classList.contains("err"), n), true);
  await page.evaluate((i) => { const l = [...document.querySelectorAll('#cfgMappings input[data-cfg="m-listen"]')][i]; l.value = ":46994"; l.dispatchEvent(new Event("input", { bubbles: true })); }, n);
  await page.waitForTimeout(150);
  assert.equal(await page.evaluate((i) => [...document.querySelectorAll('#cfgMappings input[data-cfg="m-target"]')][i].value, n), "http://127.0.0.1:46994");
  await page.click("#cfgSave");
  await page.waitForTimeout(300);
  const msg = await page.evaluate(() => document.getElementById("cfgResult").textContent);
  assert.ok(msg.includes("id 不能为空"), `保存应被拦截: ${msg}`);
});

test("4. 多选 any 互斥(选 any → 其他禁选)", async () => {
  await page.click("#svcRolesBtn0");
  await page.waitForTimeout(250);
  // 选项顺序: any 置顶
  const order = await page.evaluate(() => [...document.querySelectorAll("#svcRolesList0 .opt")].map((o) => o.textContent));
  assert.equal(order[0], "any", `any 应置顶: ${order}`);
  // 当前 svc-a 已选中; 点 any → 其他变 dis
  await page.evaluate(() => { [...document.querySelectorAll("#svcRolesList0 .opt")].find((o) => o.textContent === "any").click(); });
  await page.waitForTimeout(250);
  const classes = await page.evaluate(() => [...document.querySelectorAll("#svcRolesList0 .opt")].map((o) => o.className));
  assert.ok(classes.slice(1).every((c) => c.includes("dis")), `选中 any 后其他应禁选: ${classes}`);
  assert.ok(classes[0].includes("on"), `any 应选中: ${classes}`);
  // 取消 any → 恢复可选
  await page.evaluate(() => { [...document.querySelectorAll("#svcRolesList0 .opt")].find((o) => o.textContent === "any").click(); });
  await page.waitForTimeout(250);
  const classes2 = await page.evaluate(() => [...document.querySelectorAll("#svcRolesList0 .opt")].map((o) => o.className));
  assert.ok(!classes2.some((c) => c.includes("dis")), `取消 any 后应恢复: ${classes2}`);
  await page.mouse.click(400, 200);
  await page.waitForTimeout(150);
});

test("5. e2e-a 验证 → 添加隧道(本地路由 47991 避开 gw 同端口)", async () => {
  await page.reload();
  await page.waitForTimeout(600);
  await verifyWith("e2e-a", "");
  const svc = await page.evaluate(() => [...document.querySelectorAll("#newServiceList .opt")].map((o) => o.textContent));
  assert.ok(svc.includes("svc-a"), `应有 svc-a: ${svc}`);
  await page.click("#newServiceBtn");
  await page.waitForTimeout(200);
  await pickOpt("newServiceList", "svc-a");
  const rows = await page.evaluate(() => document.querySelectorAll("#svcChannelRows .svc-local").length);
  assert.ok(rows >= 2, `通道行应>=2: ${rows}`);
  await page.evaluate((base) => {
    [...document.querySelectorAll("#svcChannelRows .svc-local")].forEach((inp, i) => {
      inp.value = base + (i === 0 ? "" : "/admin");
      inp.dispatchEvent(new Event("input", { bubbles: true }));
    });
  }, `:${LOCAL_PORT}`);
  await page.waitForTimeout(200);
  await page.click("#addTunnel");
  await page.waitForTimeout(1500);
  const trs = await page.evaluate(() => document.querySelectorAll("#tunnelBody tr").length);
  assert.ok(trs >= 1, `隧道表应有行: ${trs}`);
});

test("6. 服务下拉过滤: 已建隧道的服务消失", async () => {
  const opts = await svcSelectState();
  assert.ok(!opts.includes("svc-a"), `svc-a 已建隧道应被过滤: ${opts}`);
  assert.ok(opts.some((t) => t.includes("any-svc")), `any-svc 应保留: ${opts}`);
});

test("7. ★转发真的转发: 隧道本地路由 → 网关 → echo 后端(整口 + /admin 路径通道)", async () => {
  let ok = false;
  for (let i = 0; i < 10; i++) {
    const r = await httpGet(LOCAL_PORT, "/");
    if (r.status === 200) { ok = true; break; }
    await new Promise((r2) => setTimeout(r2, 500));
  }
  assert.ok(ok, `本地路由 ${LOCAL_PORT} 应能访问`);
  const r = await httpGet(LOCAL_PORT, "/");
  assert.equal(r.status, 200, `转发状态码: ${JSON.stringify(r)}`);
  assert.ok(r.body.includes("Directory listing") || r.body.includes("<title>"), `应返回 echo 后端内容: ${r.body.slice(0, 80)}`);
  // 路径通道(:47991/admin → 网关 :46991/admin → 后端)
  const rp = await httpGet(LOCAL_PORT, "/admin/");
  assert.ok(rp.status === 200 || rp.status === 404, `路径通道应有后端响应(200/404 都证明链路通): ${JSON.stringify(rp).slice(0, 100)}`);
  if (rp.status === 200) {
    assert.ok(rp.body.includes("Directory listing"), `/admin/ 应返回后端目录列表: ${rp.body.slice(0, 60)}`);
  }
});

test("8. ★mTLS 壳真的套上: 无证书/坏证书被拒, 带证书通过(直连网关)", async () => {
  // 无客户端证书 → TLS 握手失败
  const bare = await httpsGet(GW_PORT);
  assert.ok(bare.error || !bare.status, `无证书应被拒: ${JSON.stringify(bare)}`);
  // 错误 CA 签发的客户端证书 → 服务器拒绝(unknown CA)
  const bad = await httpsGet(GW_PORT, { withBadCert: true });
  assert.ok(bad.error || !bad.status, `坏CA证书应被拒: ${JSON.stringify(bad)}`);
  // 带 e2e-a 客户端证书(服务器证书也真验证)→ 200
  const withCert = await httpsGet(GW_PORT, { withCert: true });
  assert.equal(withCert.status, 200, `带证书应通过: ${JSON.stringify(withCert).slice(0, 120)}`);
  // admin 管理端口同样无证书被拒
  const admBare = await httpsGet(46999);
  assert.ok(admBare.error || !admBare.status, `admin 端口无证书应被拒: ${JSON.stringify(admBare)}`);
});

test("9. 删除隧道 + 服务回归下拉", async () => {
  const delBtn = await page.evaluate(() => !!document.querySelector("#tunnelBody [data-del]"));
  if (delBtn) {
    page.once("dialog", (d) => d.accept());
    await page.click("#tunnelBody [data-del]");
    await page.waitForTimeout(1200);
  }
  const txt = await page.evaluate(() => document.querySelector("#tunnelBody").textContent);
  assert.ok(txt.includes("无隧道") || txt.includes("none") || txt.trim() === "", `删除后应为空表: ${txt}`);
  const opts = await svcSelectState();
  assert.ok(opts.includes("svc-a"), `删除后 svc-a 应回到下拉: ${opts}`);
});

test("10. ★异常: 错误密码 → 报错且管理区不解锁", async () => {
  await page.reload();
  await page.waitForTimeout(600);
  await verifyWith("admin", "wrong-password");
  assert.equal(await page.evaluate(() => document.getElementById("adminSection").style.display), "none", "错误密码不应解锁管理区");
  assert.equal(await page.evaluate(() => document.getElementById("tunnelSection").style.display), "none", "普通区也不应显示");
  const toast = await page.evaluate(() => document.getElementById("toast").textContent);
  assert.ok(toast.includes("验证失败") || toast.includes("密码"), `应有错误提示: ${toast}`);
});

test("11. ★签发闭环: 签发 → 装入证书源 → 新证书验证通过 → 吊销", async () => {
  await page.reload();
  await page.waitForTimeout(600);
  await verifyWith("admin", ADMIN_PWD);
  try {
    // 填写签发表单
    await page.fill("#newName", "e2e-ci-dev");
    await page.click("#newPurposesBtn");
    await page.waitForTimeout(200);
    await page.evaluate(() => { [...document.querySelectorAll("#newPurposesList .opt")].find((o) => o.textContent === "svc-a").click(); });
    await page.mouse.click(400, 200);
    await page.waitForTimeout(150);
    await page.click("#adminIssue");
    // 轮询: 签发成功 = 吊销下拉里出现 e2e-ci-dev(服务端事实, 不受渲染时机影响)
    let listed = false;
    for (let i = 0; i < 30; i++) {
      await page.click("#revokeCertBtn");
      await page.waitForTimeout(250);
      listed = await page.evaluate(() => [...document.querySelectorAll("#revokeCertList .opt")].some((o) => o.textContent.includes("e2e-ci-dev")));
      await page.mouse.click(400, 200);
      await page.waitForTimeout(150);
      if (listed) break;
    }
    assert.ok(listed, "签发后吊销列表应出现 e2e-ci-dev");
    // 装进 relay 证书源
    fs.mkdirSync(`${E2E_DIR}/certs/e2e-ci-dev`, { recursive: true });
    fs.copyFileSync(`${E2E_DIR}/issued/e2e-ci-dev/cert.pem`, `${E2E_DIR}/certs/e2e-ci-dev/cert.pem`);
    fs.copyFileSync(`${E2E_DIR}/issued/e2e-ci-dev/key.pem`, `${E2E_DIR}/certs/e2e-ci-dev/key.pem`);
    // 新证书验证 → 应能发现服务
    await page.reload();
    await page.waitForTimeout(600);
    await verifyWith("e2e-ci-dev", "");
    const svc = await page.evaluate(() => [...document.querySelectorAll("#newServiceList .opt")].map((o) => o.textContent));
    assert.ok(svc.includes("svc-a"), `新证书应能发现 svc-a: ${svc}`);
  } finally {
    // 无论如何吊销 e2e-ci-dev, 保持环境干净可重复运行
    await page.reload();
    await page.waitForTimeout(600);
    await verifyWith("admin", ADMIN_PWD);
    await page.click("#revokeCertBtn");
    await page.waitForTimeout(200);
    const has = await page.evaluate(() => [...document.querySelectorAll("#revokeCertList .opt")].some((o) => o.textContent.includes("e2e-ci-dev")));
    if (has) {
      await page.evaluate(() => { [...document.querySelectorAll("#revokeCertList .opt")].find((o) => o.textContent.includes("e2e-ci-dev")).click(); });
      await page.waitForTimeout(200);
      page.once("dialog", (d) => d.accept());
      await page.click("#adminRevoke");
      await page.waitForTimeout(1500);
    }
  }
});

test("12. ★异常: 吊销 e2e-a → 验证被拒(授权闭环, 自足场景)", async () => {
  // 先验证 e2e-a 可用(未被吊销)
  await page.reload();
  await page.waitForTimeout(600);
  await verifyWith("e2e-a", "");
  assert.equal(await page.evaluate(() => document.getElementById("tunnelSection").style.display), "", "e2e-a 应可验证");
  // admin 吊销 e2e-a
  await page.reload();
  await page.waitForTimeout(600);
  await verifyWith("admin", ADMIN_PWD);
  await page.click("#revokeCertBtn");
  await page.waitForTimeout(200);
  await page.evaluate(() => { [...document.querySelectorAll("#revokeCertList .opt")].find((o) => o.textContent.includes("e2e-a")).click(); });
  await page.waitForTimeout(200);
  page.once("dialog", (d) => d.accept());
  await page.click("#adminRevoke");
  await page.waitForTimeout(1500);
  // 吊销后 e2e-a 验证应失败
  await page.reload();
  await page.waitForTimeout(600);
  await page.click("#adminCertBtn");
  await page.waitForTimeout(200);
  await pickOpt("adminCertList", "e2e-a");
  await page.click("#adminVerify");
  await page.waitForTimeout(2500);
  const hint = await page.evaluate(() => document.getElementById("adminCertHint").textContent);
  assert.ok(hint.includes("重新验证"), `吊销后验证应失败: ${hint}`);
  assert.equal(await page.evaluate(() => document.getElementById("adminSection").style.display), "none");
  assert.equal(await page.evaluate(() => document.getElementById("tunnelSection").style.display), "none");
});

test("13. 语言切换 zh/en 生效", async () => {
  await page.click("#langSelBtn");
  await page.waitForTimeout(200);
  await pickOpt("langSelList", "English");
  assert.equal(await page.evaluate(() => document.querySelector('h2[data-i18n="runCtrl"]')?.textContent), "Run Control");
  await page.click("#langSelBtn");
  await page.waitForTimeout(200);
  await pickOpt("langSelList", "中文");
  await page.waitForTimeout(200);
});

test("14. 全程零 JS 错误", () => {
  assert.deepEqual(errors, [], `存在 JS 错误: ${errors.join(" | ")}`);
});

test("15. 连接设置: 读取 → 修改保存 → 热重载生效", async () => {
  await page.goto(URL);
  await page.waitForTimeout(800);
  const sa = await page.inputValue("#setServerAddr");
  assert.ok(sa.includes(":"), `连接设置卡片应显示 server_addr(当前: ${sa})`);
  const adminAddr = await page.inputValue("#setAdminAddr");
  assert.ok(adminAddr.includes(":"), `应显示 admin_addr(当前: ${adminAddr})`);
  // 修改 server_addr → 保存(热重载)
  await page.fill("#setServerAddr", "127.0.0.1:46999");
  await page.click("#btnSaveSettings");
  await page.waitForTimeout(900);
  const hint = await page.textContent("#settingsHint");
  assert.ok(hint && hint.trim(), "保存后应有成功提示(热重载)");
  // 服务端确认已落盘(经 /api/settings 读回)
  const res = await page.evaluate(() => fetch("/api/settings").then((r) => r.json()));
  assert.ok(res.server_addr === "127.0.0.1:46999", `落盘 server_addr 应为新值, got ${res.server_addr}`);
  // 恢复原值(避免影响环境)
  await page.fill("#setServerAddr", sa);
  await page.click("#btnSaveSettings");
  await page.waitForTimeout(600);
});
