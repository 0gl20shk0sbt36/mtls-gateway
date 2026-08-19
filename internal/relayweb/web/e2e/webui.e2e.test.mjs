// WebUI E2E 测试 — 操作真实网页(playwright), CI 可跑
// 用法: 先跑 e2e/setup.sh, 再 node --test e2e/webui.e2e.test.mjs
// 环境变量: E2E_URL(默认 http://127.0.0.1:46990/), E2E_ADMIN_PWD(默认 ci-admin-pw)
import { test, before, after } from "node:test";
import assert from "node:assert";
import { chromium } from "playwright-core";

const URL = process.env.E2E_URL || "http://127.0.0.1:46990/";
const ADMIN_PWD = process.env.E2E_ADMIN_PWD || "ci-admin-pw";

let browser, page, errors;

before(async () => {
  browser = await chromium.launch({ headless: true });
  page = await browser.newPage();
  errors = [];
  page.on("pageerror", (e) => errors.push("PAGEERR: " + e.message));
  page.on("console", (m) => { if (m.type() === "error") errors.push("CONSOLE: " + m.text()); });
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
  await page.waitForTimeout(2500);
};

test("1. 证书列表加载(admin + e2e-a)", async () => {
  const opts = await page.evaluate(() => [...document.querySelectorAll("#adminCertList .opt")].map((o) => o.textContent));
  assert.ok(opts.some((t) => t.includes("admin")), `应有 admin: ${opts}`);
  assert.ok(opts.some((t) => t.includes("e2e-a")), `应有 e2e-a: ${opts}`);
});

test("2. admin 验证 → 证书管理区(配置区渲染)", async () => {
  await verifyWith("admin", ADMIN_PWD);
  const disp = await page.evaluate(() => document.getElementById("adminSection").style.display);
  assert.equal(disp, "");
  const rows = await page.evaluate(() => document.querySelectorAll('#cfgMappings input[data-cfg="m-id"]').length);
  assert.ok(rows >= 3, `配置区通道行应>=3: ${rows}`);
  const chips = await page.evaluate(() => document.querySelectorAll("#cfgRoles .chip").length);
  assert.ok(chips >= 2, `角色chips应>=2: ${chips}`);
  // 用途/吊销下拉有数据
  await page.click("#newPurposesBtn");
  await page.waitForTimeout(200);
  const purps = await page.evaluate(() => [...document.querySelectorAll("#newPurposesList .opt")].map((o) => o.textContent));
  assert.ok(purps.length >= 2, `用途选项应>=2: ${purps}`);
  await page.mouse.click(400, 200); // 关闭
  await page.waitForTimeout(150);
  await page.click("#revokeCertBtn");
  await page.waitForTimeout(200);
  const revokes = await page.evaluate(() => [...document.querySelectorAll("#revokeCertList .opt")].map((o) => o.textContent));
  assert.ok(revokes.length >= 2, `吊销选项应>=2: ${revokes}`);
  await page.mouse.click(400, 200);
  await page.waitForTimeout(150);
});

test("3. 配置区: 新增通道 target 联动 + 非法 listen 红框 + 保存拦截", async () => {
  // 页面已处于 admin 已验证状态(上一个测试)
  await page.evaluate(() => document.getElementById("cfgAddMap").click());
  await page.waitForTimeout(200);
  const n = await page.evaluate(() => document.querySelectorAll('#cfgMappings input[data-cfg="m-listen"]').length) - 1;
  // 新行 target 默认
  const defT = await page.evaluate((i) => [...document.querySelectorAll('#cfgMappings input[data-cfg="m-target"]')][i].value, n);
  assert.equal(defT, "http://127.0.0.1");
  // 非法 listen → 红框
  await page.evaluate((i) => { const l = [...document.querySelectorAll('#cfgMappings input[data-cfg="m-listen"]')][i]; l.value = "29994"; l.dispatchEvent(new Event("input", { bubbles: true })); }, n);
  await page.waitForTimeout(150);
  assert.equal(await page.evaluate((i) => [...document.querySelectorAll('#cfgMappings input[data-cfg="m-listen"]')][i].classList.contains("err"), n), true, "非法 listen 应红框");
  // 合法 listen → 联动 target
  await page.evaluate((i) => { const l = [...document.querySelectorAll('#cfgMappings input[data-cfg="m-listen"]')][i]; l.value = ":46994"; l.dispatchEvent(new Event("input", { bubbles: true })); }, n);
  await page.waitForTimeout(150);
  const tgt = await page.evaluate((i) => [...document.querySelectorAll('#cfgMappings input[data-cfg="m-target"]')][i].value, n);
  assert.equal(tgt, "http://127.0.0.1:46994");
  // 保存: id 为空 → 本地拦截
  await page.click("#cfgSave");
  await page.waitForTimeout(300);
  const msg = await page.evaluate(() => document.getElementById("cfgResult").textContent);
  assert.ok(msg.includes("id 不能为空"), `保存应被拦截: ${msg}`);
});

test("4. e2e-a 验证 → 服务发现 → 添加隧道 → 删除", async () => {
  await page.evaluate(() => localStorage.setItem("lang", "zh"));
  await page.reload();
  await page.waitForTimeout(600);
  await verifyWith("e2e-a", "");
  // 服务列表(svc-a 应存在)
  const svc = await page.evaluate(() => [...document.querySelectorAll("#newServiceList .opt")].map((o) => o.textContent));
  assert.ok(svc.includes("svc-a"), `应有 svc-a: ${svc}`);
  // 选 svc-a → 通道行
  await page.click("#newServiceBtn");
  await page.waitForTimeout(200);
  await pickOpt("newServiceList", "svc-a");
  const rows = await page.evaluate(() => document.querySelectorAll("#svcChannelRows .svc-local").length);
  assert.ok(rows >= 2, `通道行应>=2: ${rows}`);
  // 添加
  await page.click("#addTunnel");
  await page.waitForTimeout(1500);
  const trs = await page.evaluate(() => document.querySelectorAll("#tunnelBody tr").length);
  assert.ok(trs >= 1, `隧道表应有行: ${trs}`);
  // 删除
  page.once("dialog", (d) => d.accept());
  await page.click("#tunnelBody [data-del]");
  await page.waitForTimeout(1200);
  const txt = await page.evaluate(() => document.querySelector("#tunnelBody").textContent);
  assert.ok(txt.includes("无隧道") || txt.includes("none") || txt.trim() === "", `删除后应为空表: ${txt}`);
});

test("5. 语言切换 zh/en 生效", async () => {
  await page.click("#langSelBtn");
  await page.waitForTimeout(200);
  await pickOpt("langSelList", "English");
  const title = await page.evaluate(() => document.querySelector('h2[data-i18n="runCtrl"]')?.textContent);
  assert.equal(title, "Run Control");
  await page.click("#langSelBtn");
  await page.waitForTimeout(200);
  await pickOpt("langSelList", "中文");
  await page.waitForTimeout(200);
});

test("6. 全程零 JS 错误", () => {
  assert.deepEqual(errors, [], `存在 JS 错误: ${errors.join(" | ")}`);
});
