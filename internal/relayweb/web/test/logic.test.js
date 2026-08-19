// WebUI 纯逻辑单元测试 — node --test internal/relayweb/web/test/
// 零依赖: 只用 node:test + node:assert
const { test } = require("node:test");
const assert = require("node:assert");
const L = require("../logic.js");
const { RE_LISTEN, RE_NAME, RE_TARGET, autoTarget, cfgFieldInvalid, cfgValidate, issueFormValidate, i18nKeyDiff } = L;

test("RE_LISTEN 格式", () => {
  for (const ok of [":29991", ":29991/admin", ":80", ":9445/a/b", ":65535/x_y-z.1"]) assert.ok(RE_LISTEN.test(ok), `应合法: ${ok}`);
  for (const bad of ["29991", "127.0.0.1:29991", ":", ":abc", ":999999", ":29991/", "x:29991"]) assert.ok(!RE_LISTEN.test(bad), `应非法: ${bad}`);
});

test("RE_NAME 格式", () => {
  for (const ok of ["svc-a", "dev_1", "mtls-superadmin", "a", "x-y_z9"]) assert.ok(RE_NAME.test(ok), `应合法: ${ok}`);
  for (const bad of ["", "a b", "a.b", "a/b", "a:b", "*", "中文", "a*"]) assert.ok(!RE_NAME.test(bad), `应非法: ${bad}`);
});

test("RE_TARGET 格式", () => {
  for (const ok of ["http://127.0.0.1:29991", "https://example.com", "http://127.0.0.1:29991/admin"]) assert.ok(RE_TARGET.test(ok));
  for (const bad of ["127.0.0.1:29991", "ftp://x", "http://", "//x"]) assert.ok(!RE_TARGET.test(bad), `应非法: ${bad}`);
});

test("autoTarget 联动", () => {
  assert.equal(autoTarget(""), "http://127.0.0.1");
  assert.equal(autoTarget(":29994"), "http://127.0.0.1:29994");
  assert.equal(autoTarget(":29994/admin"), "http://127.0.0.1:29994/admin");
  assert.equal(autoTarget("29994"), "http://127.0.0.1:29994"); // 没冒号自动补
});

test("cfgFieldInvalid 单字段", () => {
  assert.ok(cfgFieldInvalid("m-listen", "29991"));
  assert.ok(!cfgFieldInvalid("m-listen", ":29991"));
  assert.ok(cfgFieldInvalid("m-target", "x"));
  assert.ok(!cfgFieldInvalid("m-target", "http://127.0.0.1:9"));
  assert.ok(cfgFieldInvalid("m-id", "a b"));
  assert.ok(!cfgFieldInvalid("m-id", "svc-a"));
  assert.ok(cfgFieldInvalid("issue-tsip", "1.2.3"));
  assert.ok(!cfgFieldInvalid("issue-tsip", "100.100.135.63"));
  assert.ok(!cfgFieldInvalid("m-listen", "")); // 空不标红
});

test("cfgValidate 整体校验(服务端规则对齐)", () => {
  const base = {
    mappings: [
      { id: "m1", listen: ":9001", target: "http://127.0.0.1:1" },
      { id: "m2", listen: ":9001/admin", target: "http://127.0.0.1:1/" },
    ],
    services: [{ name: "s1", channels: ["m1", "m2"], roles: ["svc-a"] }],
    roles: ["svc-a"],
  };
  assert.deepEqual(cfgValidate(base.mappings, base.services, base.roles), []); // 合法零错误

  // id 重复
  let m = [{ id: "m1", listen: ":9001", target: "http://x" }, { id: "m1", listen: ":9002", target: "http://x" }];
  assert.ok(cfgValidate(m, [], []).some((e) => e.includes("id 重复")));
  // listen 重复
  m = [{ id: "m1", listen: ":9001", target: "http://x" }, { id: "m2", listen: ":9001", target: "http://x" }];
  assert.ok(cfgValidate(m, [], []).some((e) => e.includes("监听地址重复")));
  // listen 非法
  m = [{ id: "m1", listen: "9001", target: "http://x" }];
  assert.ok(cfgValidate(m, [], []).some((e) => e.includes("listen 格式")));
  // id 空 / target 空
  m = [{ id: "", listen: ":9001", target: "" }];
  assert.ok(cfgValidate(m, [], []).some((e) => e.includes("id 不能为空")));
  assert.ok(cfgValidate(m, [], []).some((e) => e.includes("target 不能为空")));
  // 服务: 无通道 / 通道引用不存在 / 角色未声明
  const svcBad = [{ name: "s1", channels: [], roles: [] }];
  assert.ok(cfgValidate(base.mappings, svcBad, base.roles).some((e) => e.includes("至少选一个通道")));
  const svcRef = [{ name: "s1", channels: ["ghost"], roles: ["svc-a"] }];
  assert.ok(cfgValidate(base.mappings, svcRef, base.roles).some((e) => e.includes("通道引用不存在 ghost")));
  const svcRole = [{ name: "s1", channels: ["m1"], roles: ["ghost"] }];
  assert.ok(cfgValidate(base.mappings, svcRole, base.roles).some((e) => e.includes("角色 ghost 未声明")));
  // any 角色无需声明
  const svcAny = [{ name: "s1", channels: ["m1"], roles: ["any"] }];
  assert.deepEqual(cfgValidate(base.mappings, svcAny, base.roles), []);
  // 服务名重复
  const svcDup = [{ name: "s1", channels: ["m1"], roles: ["any"] }, { name: "s1", channels: ["m2"], roles: ["any"] }];
  assert.ok(cfgValidate(base.mappings, svcDup, base.roles).some((e) => e.includes("服务名重复")));
});

test("issueFormValidate 签发表单(返回错误键)", () => {
  assert.deepEqual(issueFormValidate("", ["svc-a"], "", []), ["issueNeedName"]);
  assert.deepEqual(issueFormValidate("a b", ["svc-a"], "", []), ["issueBadName"]);
  assert.deepEqual(issueFormValidate("dev", [], "", []), ["issueNeedPurps"]);
  assert.deepEqual(issueFormValidate("dev", ["svc-a"], "1.2.3", []), ["issueBadIP"]);
  assert.deepEqual(issueFormValidate("dev", ["svc-a"], "", ["dev"]), [{ key: "issueNameExists", vars: { n: "dev" } }]);
  assert.deepEqual(issueFormValidate("dev", ["svc-a"], "100.100.135.63", ["other"]), []);
});

test("i18n 字典一致性(zh/en 键集合)", () => {
  const { L } = require("../i18n.js");
  const { onlyZh, onlyEn } = i18nKeyDiff(L.zh, L.en);
  assert.deepEqual(onlyZh, [], `zh 有而 en 无的键: ${onlyZh.join(",")}`);
  assert.deepEqual(onlyEn, [], `en 有而 zh 无的键: ${onlyEn.join(",")}`);
});
