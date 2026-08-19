// logic.js — WebUI 纯逻辑(无 DOM 依赖), 浏览器与 Node(node:test)共用
// 校验规则与服务端保持一致(proxy.NewRouter / configmgr / api.IssueCert)
(function () {
"use strict";

// listen 格式: ":端口[/路径]"
const RE_LISTEN = /^:\d{1,5}(\/[A-Za-z0-9_\-./]+)?$/;
// 名称格式: 字母/数字/下划线/连字符 (服务端 validName / 角色规则)
const RE_NAME = /^[A-Za-z0-9_-]+$/;
// target 格式: http(s)://...
const RE_TARGET = /^https?:\/\/\S+/;
// TS IP 格式: IPv4(4段) 或 IPv6(含冒号十六进制)
const RE_TSIP = /^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]+$/;

// 新建通道 target 自动联动: 填 listen 时拼到 http://127.0.0.1 后
function autoTarget(listen) {
  if (!listen) return "http://127.0.0.1";
  return "http://127.0.0.1" + (listen.startsWith(":") ? listen : ":" + listen);
}

// 单字段即时格式检查: 返回是否非法(供 UI 红框)
function cfgFieldInvalid(cfg, value) {
  const v = (value || "").trim();
  if (v === "") return false;
  switch (cfg) {
    case "m-listen": return !RE_LISTEN.test(v);
    case "m-target": return !RE_TARGET.test(v);
    case "m-id": return !RE_NAME.test(v);
    case "s-name": return !RE_NAME.test(v);
    case "issue-name": return !RE_NAME.test(v);
    case "issue-tsip": return !RE_TSIP.test(v);
  }
  return false;
}

// cfgValidate: 保存前整体校验(与服务端规则一致), 返回错误列表
function cfgValidate(mappings, services, roles) {
  const errs = [];
  const mIds = new Set(), listens = new Set(), svcNames = new Set();
  (mappings || []).forEach((m, i) => {
    if (!m.id.trim()) errs.push(`通道 ${i + 1}: id 不能为空`);
    else if (!RE_NAME.test(m.id)) errs.push(`通道 ${i + 1}: id 只允许字母/数字/下划线/连字符`);
    else if (mIds.has(m.id)) errs.push(`通道 id 重复: ${m.id}`);
    else mIds.add(m.id);
    if (!m.listen.trim()) errs.push(`通道 ${i + 1}: listen 不能为空`);
    else if (!RE_LISTEN.test(m.listen.trim())) errs.push(`通道 ${i + 1}: listen 格式应为 :端口[/路径]`);
    else if (listens.has(m.listen)) errs.push(`监听地址重复: ${m.listen}`);
    else listens.add(m.listen);
    if (!m.target.trim()) errs.push(`通道 ${i + 1}: target 不能为空`);
    else if (!RE_TARGET.test(m.target.trim())) errs.push(`通道 ${i + 1}: target 应为 http(s)://host:port`);
  });
  (services || []).forEach((s, i) => {
    if (!s.name.trim()) errs.push(`服务 ${i + 1}: name 不能为空`);
    else if (!RE_NAME.test(s.name)) errs.push(`服务 ${i + 1}: name 只允许字母/数字/下划线/连字符`);
    else if (svcNames.has(s.name)) errs.push(`服务名重复: ${s.name}`);
    else svcNames.add(s.name);
    if (!(s.channels || []).length) errs.push(`服务 ${s.name || i + 1}: 至少选一个通道`);
    (s.channels || []).forEach((c) => { if (!mIds.has(c)) errs.push(`服务 ${s.name}: 通道引用不存在 ${c}`); });
    (s.roles || []).forEach((r) => { if (r !== "any" && !(roles || []).includes(r)) errs.push(`服务 ${s.name}: 角色 ${r} 未声明`); });
  });
  return errs;
}

// 证书签发表单校验: 返回错误键列表(前端用 t() 翻译; 带参数项为 {key, vars})
function issueFormValidate(name, purposes, tsip, certNames) {
  const errs = [];
  if (!name) errs.push("issueNeedName");
  else if (!RE_NAME.test(name)) errs.push("issueBadName");
  if (!(purposes || []).length) errs.push("issueNeedPurps");
  if (name && (certNames || []).includes(name)) errs.push({ key: "issueNameExists", vars: { n: name } });
  if (tsip && !RE_TSIP.test(tsip)) errs.push("issueBadIP");
  return errs;
}

// i18n 字典完整性: zh/en 键集合必须一致(防漏翻)
function i18nKeyDiff(zhDict, enDict) {
  const zk = new Set(Object.keys(zhDict || {})), ek = new Set(Object.keys(enDict || {}));
  const onlyZh = [...zk].filter((k) => !ek.has(k));
  const onlyEn = [...ek].filter((k) => !zk.has(k));
  return { onlyZh, onlyEn };
}

// 浏览器: 挂全局; Node: module.exports
if (typeof module !== "undefined" && module.exports) {
  module.exports = { RE_LISTEN, RE_NAME, RE_TARGET, RE_TSIP, autoTarget, cfgFieldInvalid, cfgValidate, issueFormValidate, i18nKeyDiff };
} else {
  window.MTLS_LOGIC = { RE_LISTEN, RE_NAME, RE_TARGET, RE_TSIP, autoTarget, cfgFieldInvalid, cfgValidate, issueFormValidate, i18nKeyDiff };
}
})();
