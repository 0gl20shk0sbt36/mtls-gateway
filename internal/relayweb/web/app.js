// mtls-relay WebUI 前端 — 直接调用本地管理 API (/api/*)
const $ = (id) => document.getElementById(id);
const t = I18N.t;

// 全局状态(提前声明, 避免 TDZ: init 早于这些声明执行时抛 "Cannot access before initialization")
let SERVICES = [];
let CFG = null;
let DRAFT = null;
let CFG_ADMIN_ROLE = "mtls-superadmin";

// applyI18n: 批量应用 data-i18n / data-i18n-html / data-i18n-ph (动态渲染的容器内容不在内)
function applyI18n() {
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    el.textContent = t(el.dataset.i18n);
  });
  document.querySelectorAll("[data-i18n-html]").forEach((el) => {
    el.innerHTML = t(el.dataset.i18nHtml);
  });
  document.querySelectorAll("[data-i18n-ph]").forEach((el) => {
    el.placeholder = t(el.dataset.i18nPh);
  });
  const btn = $("langSelBtn");
  if (btn) btn.querySelector(".txt").textContent = I18N.currentLangLabel();
}

// —— 自绘下拉(替代原生 select, 暗色全浏览器可控) ——
const SEL = {};
function initSel(btnId, listId, onPick) {
  SEL[listId] = { current: "", list: [], onPick: onPick || null };
  const wrap = $(btnId).parentElement;
  $(btnId).onclick = (e) => {
    e.stopPropagation();
    const wasOpen = wrap.classList.contains("open");
    document.querySelectorAll(".sel.open").forEach((x) => x.classList.remove("open"));
    if (!wasOpen) wrap.classList.add("open");
  };
  const list = $(listId);
  list.onclick = (e) => {
    const d = e.target.closest(".opt");
    if (!d || d.dataset.idx == null) return;
    pickSel(listId, +d.dataset.idx);
    wrap.classList.remove("open");
  };
  return SEL[listId];
}
function setSel(listId, items) {
  const s = SEL[listId] || (SEL[listId] = { current: "", list: [], onPick: null });
  s.current = ""; s.list = items || [];
  const list = $(listId);
  list.innerHTML = "";
  if (!s.list.length) { list.innerHTML = '<div class="opt">(无条目)</div>'; setSelLabel(listId, ""); return; }
  s.list.forEach((it, i) => {
    const d = document.createElement("div");
    d.className = "opt"; d.dataset.idx = i; d.textContent = it.label;
    list.appendChild(d);
  });
  setSelLabel(listId, "");
}
function setSelLabel(listId, label) {
  const wrap = $(listId).parentElement;
  const txt = wrap.querySelector(".sel-btn .txt");
  if (txt) txt.textContent = label || "— 请选择 —";
}
function getSel(listId) { return (SEL[listId] || {}).current || ""; }
function pickSel(listId, idx) {
  const s = SEL[listId]; if (!s) return;
  const it = s.list[idx]; if (!it) return;
  s.current = it.value; setSelLabel(listId, it.label);
  if (s.onPick) s.onPick(it);
}
document.addEventListener("click", () =>
  document.querySelectorAll(".sel.open").forEach((x) => x.classList.remove("open")));

// —— 多选下拉(用途) ——
const SEL_MULTI = {};
const SEL_MULTI_LABEL = {};
function initMultiSel(btnId, listId, onChange) {
  SEL_MULTI[listId] = new Set();
  const wrap = $(btnId).parentElement;
  $(btnId).onclick = (e) => {
    e.stopPropagation();
    const was = wrap.classList.contains("open");
    document.querySelectorAll(".sel.open").forEach((x) => x.classList.remove("open"));
    if (!was) wrap.classList.add("open");
  };
  $(listId).onclick = (e) => {
    e.stopPropagation();
    const d = e.target.closest(".opt");
    if (!d || d.dataset.val == null) return;
    if (d.classList.contains("dis")) return; // 禁选(any 已选时)
    const s = SEL_MULTI[listId];
    const v = d.dataset.val;
    if (v === "any") {
      s.clear();
      s.add("any"); // any 互斥: 选中后清空其他
    } else {
      if (s.has("any")) return; // any 已选, 其他禁点(双保险)
      if (s.has(v)) s.delete(v); else s.add(v);
    }
    refreshMultiOpts(listId);
    updateMultiLabel(listId);
    if (onChange) onChange([...s]);
  };
}
function refreshMultiOpts(listId) {
  const s = SEL_MULTI[listId] || new Set();
  const anyOn = s.has("any");
  document.querySelectorAll("#" + listId + " .opt").forEach((d) => {
    d.classList.toggle("on", s.has(d.dataset.val));
    d.classList.toggle("dis", anyOn && d.dataset.val !== "any"); // any 选中 → 其他禁选
  });
}
function setMultiOpts(listId, items, selected) {
  SEL_MULTI[listId] = new Set(selected || []);
  const list = $(listId);
  list.innerHTML = "";
  (items || []).forEach((it) => {
    const d = document.createElement("div");
    d.className = "opt chk";
    d.dataset.val = it.value;
    d.textContent = it.label;
    list.appendChild(d);
  });
  refreshMultiOpts(listId);
  updateMultiLabel(listId);
}
function setMultiLabel(listId, fn) { SEL_MULTI_LABEL[listId] = fn; }
function updateMultiLabel(listId) {
  const vals = [...(SEL_MULTI[listId] || [])];
  const txt = $(listId).parentElement.querySelector(".sel-btn .txt");
  if (!txt) return;
  txt.textContent = SEL_MULTI_LABEL[listId] ? SEL_MULTI_LABEL[listId](vals) : (vals.length ? `已选 ${vals.length} 项` : "— 选择 —");
}
function getMultiSel(listId) { return [...(SEL_MULTI[listId] || [])]; }

function toast(msg, isErr) {
  const t2 = $("toast");
  t2.textContent = (isErr ? t("errPrefix") : "") + msg;
  t2.classList.toggle("error", !!isErr);
  t2.style.display = "block";
  setTimeout(() => (t2.style.display = "none"), 3000);
}

// localizeServerError: 服务端错误由后端按 lang 返回(不再前端翻译); 此函数保留用于兜底
function localizeServerError(msg) { return msg; }

async function api(path, opts) {
  // 携带当前界面语言 → 后端按 X-Lang 返回错误消息
  const headers = Object.assign({}, (opts && opts.headers) || {}, { "X-Lang": I18N.currentLang() });
  const resp = await fetch(path, Object.assign({}, opts, { headers }));
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error(data.error || ("HTTP " + resp.status));
  if (data && data.error) throw new Error(data.error);
  return data;
}
const jpost = (body) => ({
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});

function fmtBytes(n) {
  if (n == null) return "-";
  if (n < 1024) return n + " B";
  const u = ["KB", "MB", "GB"];
  let v = n / 1024, i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return v.toFixed(1) + " " + u[i];
}

async function loadCerts() {
  try {
    const certs = await api("/api/certs");
    const items = certs.map((c) => ({ value: c.id, label: `${c.common_name || "(无名)"}  [${c.id}]` }));
    setSel("adminCertList", items);
    $("adminCertHint").textContent = certs.length ? `共 ${certs.length} 个证书可用；选一枚点"验证"。` : "未找到证书。请检查 daemon 证书来源配置。";
  } catch (e) {
    toast(e.message, true);
  }
}

async function loadTunnels() {
  try {
    const sts = await api("/api/status");
    const cfg = await api("/api/config");
    const byId = {};
    for (const s of sts) byId[s.id] = s;
    const body = $("tunnelBody");
    body.innerHTML = "";
    const tunnels = (cfg.tunnels || []).slice().sort((a, b) => (a.service || "").localeCompare(b.service || ""));
    if (!tunnels.length) {
      body.innerHTML = '<tr><td colspan="8" class="hint">(无隧道)</td></tr>';
      return;
    }
    const delLabel = t("delService");
    for (const tn of tunnels) {
      // 聚合该服务所有路由的状态
      let running = false, conns = 0, bin = 0, bout = 0;
      (tn.routes || []).forEach((rt) => {
        const k = tn.service + "@" + rt.channel + "@" + rt.local;
        const s = byId[k] || {};
        if (s.running) running = true;
        conns += s.active_conns || 0;
        bin += s.bytes_in || 0;
        bout += s.bytes_out || 0;
      });
      const chans = (tn.routes || []).map((rt) => rt.channel).join(" · ");
      const locals = (tn.routes || []).map((rt) => rt.local).join(" · ");
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="mono">${esc(tn.service)}</td>
        <td class="mono" style="font-size:12px">${esc(chans)}</td>
        <td class="mono" style="font-size:12px">${esc(locals)}</td>
        <td>${running ? "●" : "○"}</td>
        <td>${conns}</td>
        <td>${fmtBytes(bin)}</td>
        <td>${fmtBytes(bout)}</td>
        <td><button class="danger" data-del="${esc(tn.service)}">${delLabel}</button></td>`;
      body.appendChild(tr);
    }
    for (const btn of body.querySelectorAll("[data-del]")) {
      btn.onclick = async () => {
        if (!confirm(t("delServiceConfirm", { s: btn.dataset.del }))) return;
        try {
          await api("/api/tunnels/" + encodeURIComponent(btn.dataset.del), { method: "DELETE" });
          toast(t("delDone"));
          loadTunnels();
          refreshServiceList(); // 服务回到下拉, 可重新添加
        } catch (e) { toast(e.message, true); }
      };
    }
    // 状态: 任一隧道运行视为 daemon on
    const up = sts.length > 0;
    $("daemonDot").classList.toggle("on", up);
    const pill = $("overallPill"), lbl = $("overallLabel");
    pill.classList.toggle("up", up); pill.classList.toggle("down", !up);
    lbl.textContent = up ? "在线 · " + sts.length + " 隧道" : "离线";
  } catch (e) {
    toast(e.message, true);
    $("daemonDot").classList.remove("on");
    const pill = $("overallPill"), lbl = $("overallLabel");
    pill.classList.add("down"); pill.classList.remove("up"); lbl.textContent = "离线";
  }
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

// 渲染选中服务的通道行: 每通道一行 [通道(只读) | 本地路由输入(默认=通道)]
function renderSvcChannels(svc) {
  const box = $("svcChannelRows");
  if (!svc || !svc.channels || !svc.channels.length) { box.innerHTML = ""; return; }
  let h = `<div class="hint" style="margin-top:10px">${t("tunnelMapping")}</div>`;
  h += `<div class="row" style="margin-top:4px;color:var(--text4);font-size:12px"><span style="width:160px">${t("thChannel")}</span><span style="width:18px"></span><span style="flex:1">${t("thLocal")}</span></div>`;
  svc.channels.forEach((ch) => {
    h += `<div class="row" style="margin-top:6px">
      <span class="mono" style="width:160px;align-self:center">${esc(ch.listen)}</span>
      <span style="width:18px;text-align:center;align-self:center;color:var(--text4)">→</span>
      <input class="svc-local" data-ch="${esc(ch.listen)}" value="${esc(ch.listen)}" placeholder=":端口[/路径]" style="flex:1;font-family:monospace">
    </div>`;
  });
  box.innerHTML = h;
}

async function init() {
  I18N.setLang(I18N.detect());
  // 语言下拉(当前语言显示; 选择即切换, 可扩展)
  initSel("langSelBtn", "langSelList", (it) => {
    I18N.setLang(it.value);
    applyI18n();
    loadTunnels();
    if (CFG) renderCfg();
    if (SERVICES.length) renderSvcChannels(SERVICES.find((s) => s.name === getSel("newServiceList")));
  });
  setSel("langSelList", I18N.langOptions().map((l) => ({ value: l.code, label: l.label })));
  pickSel("langSelList", I18N.langOptions().findIndex((l) => l.code === I18N.currentLang()));
  applyI18n();
  initSel("newServiceBtn", "newServiceList", (it) => renderSvcChannels(it.raw));
  initSel("adminCertBtn", "adminCertList", () => {
    // 切换证书 → 复位: 隐藏已显示的区域, 需重新验证
    $("tunnelSection").style.display = "none";
    $("adminSection").style.display = "none";
    $("adminPwd").value = "";
    SERVICES = [];
    setSel("newServiceList", []);
    $("serviceHint").textContent = "";
    $("adminCertHint").textContent = "已切换证书 — 请重新验证。";
  });
  $("adminVerify").onclick = verifyAdmin;
  $("adminPwd").onkeydown = (e) => { if (e.key === "Enter") verifyAdmin(); }; // 回车即验证
  $("adminIssue").onclick = adminIssue;
  // 证书管理表单即时校验(红框)
  $("newName").oninput = () => { const v = $("newName").value.trim(); $("newName").classList.toggle("err", v !== "" && !RE_NAME.test(v)); };
  $("newTSIP").oninput = () => { const v = $("newTSIP").value.trim(); $("newTSIP").classList.toggle("err", v !== "" && !/^[\d.:a-fA-F]+$/.test(v)); };
  $("adminRevoke").onclick = adminRevoke;
  $("cfgSave").onclick = cfgSave;
  $("cfgCancel").onclick = cfgCancel;
  initMultiSel("newPurposesBtn", "newPurposesList");
  initSel("pwdModeBtn", "pwdModeList", (it) => { $("newCertPwd").disabled = it.value !== "custom"; });
  setSel("pwdModeList", [
    { value: "none", label: t("pwdNone") },
    { value: "auto", label: t("pwdAuto") },
    { value: "custom", label: t("pwdCustom") },
  ]);
  pickSel("pwdModeList", 1); // 默认自动生成
  initSel("revokeCertBtn", "revokeCertList");
  $("btnStart").onclick = async () => { try { await api("/api/start", jpost(null)); toast("已启动"); loadTunnels(); } catch (e) { toast(e.message, true); } };
  $("btnReload").onclick = async () => { try { await api("/api/reload", jpost(null)); toast("已 reload"); loadTunnels(); } catch (e) { toast(e.message, true); } };
  $("btnStop").onclick = async () => { try { await api("/api/stop", jpost(null)); toast("已停止"); loadTunnels(); } catch (e) { toast(e.message, true); } };
  $("addTunnel").onclick = async () => {
    const service = getSel("newServiceList");
    const cert = getSel("adminCertList");
    if (!service) { toast(t("needService"), true); return; }
    if (!cert) { toast(t("needCertForTunnel"), true); return; }
    const body = { service, cert_id: cert, locals: {} };
    let bad = false;
    document.querySelectorAll("#svcChannelRows .svc-local").forEach((inp) => {
      const v = inp.value.trim();
      if (!v) { toast(t("routeEmpty", { c: inp.dataset.ch }), true); bad = true; return; }
      body.locals[inp.dataset.ch] = v;
    });
    if (bad) return;
    try {
      const r = await api("/api/tunnels", jpost(body));
      toast(t("addedService", { s: r.service, n: r.count }));
      loadTunnels();
      refreshServiceList(); // 已添加的服务移出下拉
    } catch (e) { toast(e.message, true); }
  };
  await Promise.all([loadCerts(), loadTunnels()]);
  setInterval(loadTunnels, 2000); // 状态轮询
}

init();

// refreshServiceList: 服务下拉过滤已建隧道的服务(防止重复添加); 保留当前选中
async function refreshServiceList() {
  if (!SERVICES.length) { setSel("newServiceList", []); return; }
  const prev = getSel("newServiceList");
  try {
    const cfg = await api("/api/config");
    const done = new Set((cfg.tunnels || []).map((t) => t.service));
    const list = SERVICES.filter((s) => !done.has(s.name));
    setSel("newServiceList", list.map((s) => ({ value: s.name, label: s.name, raw: s })));
    $("serviceHint").textContent = list.length ? t("svcHint", { n: list.length }) : t("svcHintNone");
    if (prev && list.some((s) => s.name === prev)) {
      pickSel("newServiceList", list.findIndex((s) => s.name === prev)); // 保留原选中
    } else {
      renderSvcChannels(null);
    }
  } catch (e) { /* 拉不到配置就不过滤 */ }
}

async function verifyAdmin() {
  const cert = getSel("adminCertList");
  if (!cert) { toast("请先选择证书", true); return; }
  ADMIN_PWD = $("adminPwd").value || "";
  try {
    const res = await api("/api/verify", jpost({ cert_id: cert, load_pwd: ADMIN_PWD }));
    // 服务列表(用该证书的 /info, v4: 服务+通道)
    SERVICES = res.services || [];
    await refreshServiceList(); // 过滤已建隧道的服务
    // 普通证书 → 新增隧道; admin 证书 → 证书管理
    if (res.admin) {
      $("tunnelSection").style.display = "none";
      $("adminSection").style.display = "";
      $("adminStatus").textContent = t("unlockAdmin");
      $("adminCertHint").textContent = t("verifiedAdmin", { c: cert });
      toast(t("verifyOkAdmin"));
      loadAdminData();
    } else {
      $("adminSection").style.display = "none";
      $("tunnelSection").style.display = "";
      $("adminCertHint").textContent = t("verifiedNormal", { c: cert });
      toast(t("verifyOkNormal"));
    }
    $("adminPwd").value = ""; // 验证成功即清空密码(失败保留)
  } catch (e) { toast(t("verifyFail", { m: e.message }), true); }
}
async function loadAdminData() {
  const cert = getSel("adminCertList");
  if (!cert) return;
  try {
    const [cfg, cs] = await Promise.all([
      api("/api/admin/config", jpost({ cert_id: cert, load_pwd: ADMIN_PWD })),
      api("/api/admin/certs", jpost({ cert_id: cert, load_pwd: ADMIN_PWD })),
    ]);
    CFG = cfg;
    CFG_ADMIN_ROLE = cfg.admin_role || CFG_ADMIN_ROLE;
    DRAFT = JSON.parse(JSON.stringify(cfg));
    renderCfg();
    // 用途选项: 声明角色 + admin_role (any 只用于服务声明, 不签发给证书)
    const purps = new Set([CFG_ADMIN_ROLE]);
    (cfg.roles || []).forEach((r) => purps.add(r));
    setMultiOpts("newPurposesList", [...purps].map((p) => ({ value: p, label: p })));
    // 吊销下拉: 服务端证书列表
    const arr = Array.isArray(cs) ? cs : (cs.certs || []);
    setSel("revokeCertList", arr.map((c) => ({ value: c.serial || "", label: `${c.name || "(无名)"} · ${c.serial || ""}` })));
  } catch (e) { /* 加载失败不阻塞 */ }
}

// 新建通道的 target 自动联动: 填 listen 时自动拼到 http://127.0.0.1 后面;
// target 被手动修改后(TARGET_TOUCHED)停止联动
const TARGET_TOUCHED = new WeakSet();
function autoTarget(listen) {
  if (!listen) return "http://127.0.0.1";
  return "http://127.0.0.1" + (listen.startsWith(":") ? listen : ":" + listen);
}

// ---- 配置区前端校验(本地即时 + 保存前整体) ----
const RE_LISTEN = /^:\d{1,5}(\/[A-Za-z0-9_\-./]+)?$/;
const RE_NAME = /^[A-Za-z0-9_-]+$/;

// 单字段即时格式检查: 非法→红框, 合法→移除
function cfgFieldCheck(inp) {
  const i = +inp.dataset.i;
  const k = inp.dataset.cfg;
  const v = inp.value.trim();
  let bad = false;
  if (k === "m-listen") bad = v !== "" && !RE_LISTEN.test(v);
  else if (k === "m-target") bad = v !== "" && !/^https?:\/\/\S+/.test(v);
  else if (k === "m-id") bad = v !== "" && !RE_NAME.test(v);
  else if (k === "s-name") bad = v !== "" && !RE_NAME.test(v);
  inp.classList.toggle("err", bad);
}

// cfgValidate: 保存前整体校验, 返回错误列表(与服务端规则一致)
function cfgValidate() {
  const errs = [];
  const mIds = new Set(), listens = new Set(), svcNames = new Set();
  (DRAFT.mappings || []).forEach((m, i) => {
    if (!m.id.trim()) errs.push(`通道 ${i + 1}: id 不能为空`);
    else if (!RE_NAME.test(m.id)) errs.push(`通道 ${i + 1}: id 只允许字母/数字/下划线/连字符`);
    else if (mIds.has(m.id)) errs.push(`通道 id 重复: ${m.id}`);
    else mIds.add(m.id);
    if (!m.listen.trim()) errs.push(`通道 ${i + 1}: listen 不能为空`);
    else if (!RE_LISTEN.test(m.listen.trim())) errs.push(`通道 ${i + 1}: listen 格式应为 :端口[/路径]`);
    else if (listens.has(m.listen)) errs.push(`监听地址重复: ${m.listen}`);
    else listens.add(m.listen);
    if (!m.target.trim()) errs.push(`通道 ${i + 1}: target 不能为空`);
    else if (!/^https?:\/\/\S+/.test(m.target.trim())) errs.push(`通道 ${i + 1}: target 应为 http(s)://host:port`);
  });
  (DRAFT.services || []).forEach((s, i) => {
    if (!s.name.trim()) errs.push(`服务 ${i + 1}: name 不能为空`);
    else if (!RE_NAME.test(s.name)) errs.push(`服务 ${i + 1}: name 只允许字母/数字/下划线/连字符`);
    else if (svcNames.has(s.name)) errs.push(`服务名重复: ${s.name}`);
    else svcNames.add(s.name);
    if (!(s.channels || []).length) errs.push(`服务 ${s.name || i + 1}: 至少选一个通道`);
    (s.channels || []).forEach((c) => { if (!mIds.has(c)) errs.push(`服务 ${s.name}: 通道引用不存在 ${c}`); });
    (s.roles || []).forEach((r) => { if (r !== "any" && !(DRAFT.roles || []).includes(r)) errs.push(`服务 ${s.name}: 角色 ${r} 未声明`); });
  });
  return errs;
}

function renderCfg() {
  const imm = CFG.mode === "immutable";
  $("cfgMode").textContent = CFG.mode + (imm ? " 🔒" : "");
  const dis = imm ? " disabled" : "";
  const m = DRAFT.mappings || [], s = DRAFT.services || [], rl = DRAFT.roles || [];
  // 通道
  let h = `<div class="hint">${t("cfgMappings")}</div>`;
  h += `<div class="row" style="margin-top:4px;color:var(--text4);font-size:12px"><span style="width:110px">id</span><span style="flex:1">${t("cfgHeaderM")}</span><span style="flex:1.6">target</span><span style="width:22px"></span></div>`;
  m.forEach((mm, i) => {
    h += `<div class="row" style="margin-top:6px">
      <input value="${esc(mm.id)}" placeholder="id" style="width:110px"${dis} data-cfg="m-id" data-i="${i}">
      <input value="${esc(mm.listen)}" placeholder=":端口[/路径]" style="flex:1"${dis} data-cfg="m-listen" data-i="${i}">
      <input value="${esc(mm.target)}" placeholder="target" style="flex:1.6"${dis} data-cfg="m-target" data-i="${i}">
      <button type="button" class="danger small" data-cfg="m-del" data-i="${i}"${dis}>×</button>
    </div>`;
  });
  h += `<div class="row" style="margin-top:6px"><button type="button" class="ghost small" id="cfgAddMap"${dis}>${t("addMap")}</button></div>`;
  $("cfgMappings").innerHTML = h;
  // 服务
  let sv = `<div class="hint" style="margin-top:8px">${t("cfgServices")}</div>`;
  sv += `<div class="row" style="margin-top:4px;color:var(--text4);font-size:12px"><span style="width:110px">name</span><span style="flex:1">${t("cfgHeaderS")}</span><span style="flex:1">${t("cfgHeaderRoles")}</span><span style="width:22px"></span></div>`;
  s.forEach((x, i) => {
    sv += `<div class="row" style="margin-top:6px">
      <input value="${esc(x.name)}" placeholder="name" style="width:110px"${dis} data-cfg="s-name" data-i="${i}">
      <div class="sel" style="flex:1">
        <button type="button" class="sel-btn" id="svcChBtn${i}"${dis}><span class="txt"></span><span class="arrow">▾</span></button>
        <div class="sel-list" id="svcChList${i}"></div>
      </div>
      <div class="sel" style="flex:1">
        <button type="button" class="sel-btn" id="svcRolesBtn${i}"${dis}><span class="txt"></span><span class="arrow">▾</span></button>
        <div class="sel-list" id="svcRolesList${i}"></div>
      </div>
      <button type="button" class="danger small" data-cfg="s-del" data-i="${i}"${dis}>×</button>
    </div>`;
  });
  sv += `<div class="row" style="margin-top:6px"><button type="button" class="ghost small" id="cfgAddSvc"${dis}>${t("addSvc")}</button></div>`;
  $("cfgServices").innerHTML = sv;
  // 角色
  let r = `<div class="hint" style="margin-top:8px">${t("cfgRoles")}</div>`;
  r += `<div id="cfgRoleChips">`;
  rl.forEach((name, i) => {
    r += `<span class="chip">${esc(name)}<button type="button" class="chip-x" data-cfg="role-del" data-i="${i}"${dis}>×</button></span>`;
  });
  r += `</div><div class="row" style="margin-top:6px">
    <button type="button" class="ghost small" id="cfgAddRole"${dis}>${t("addRole")}</button>
    <input id="cfgNewRole" placeholder="${t("cfgNewRole")}" style="width:130px;margin-left:8px;display:none"${dis}>
  </div>`;
  $("cfgRoles").innerHTML = r;
  if (!imm) {
    // 回车确认角色: 输入框原位变成 chip(与已有角色样式一致, 不可输入)
    function roleEnter(e) {
      if (e.key !== "Enter") return;
      const inp = $("cfgNewRole");
      if (!inp) return;
      const v = inp.value.trim();
      if (!v) return;
      if (!/^[A-Za-z0-9_-]+$/.test(v)) { toast("角色名仅限字母/数字/下划线/连字符", true); return; }
      if (v === "any") { toast("any 是内置角色, 无需声明", true); return; }
      if (DRAFT.roles.includes(v)) { toast("角色已存在", true); return; }
      DRAFT.roles.push(v);
      const chip = document.createElement("span");
      chip.className = "chip";
      chip.innerHTML = `${esc(v)}<button type="button" class="chip-x" data-cfg="role-del">×</button>`;
      chip.querySelector(".chip-x").onclick = () => {
        DRAFT.roles.splice(DRAFT.roles.indexOf(v), 1);
        chip.remove();
        cfgSync();
      };
      inp.replaceWith(chip); // 原位变成 chip, 无法再输入
      cfgSync();
    }
    $("cfgAddRole").onclick = () => {
      let inp = $("cfgNewRole");
      if (!inp) { // 输入框已被替换成 chip → 重新创建
        inp = document.createElement("input");
        inp.id = "cfgNewRole";
        inp.placeholder = t("cfgNewRole");
        inp.style.cssText = "width:130px;margin-left:8px";
        inp.onkeydown = roleEnter;
        $("cfgAddRole").insertAdjacentElement("afterend", inp);
      }
      inp.style.display = "";
      inp.value = "";
      inp.focus();
    };
    const nr = $("cfgNewRole");
    if (nr) nr.onkeydown = roleEnter;
    $("cfgAddMap").onclick = () => { DRAFT.mappings.push({ id: "", listen: "", target: "http://127.0.0.1" }); renderCfg(); };
    $("cfgAddSvc").onclick = () => { DRAFT.services.push({ name: "", channels: [], roles: [] }); renderCfg(); };
    // 服务行多选 (any 置顶; 互斥由组件处理)
    s.forEach((x, i) => {
      initMultiSel(`svcChBtn${i}`, `svcChList${i}`, (v) => { DRAFT.services[i].channels = v; cfgSync(); });
      setMultiLabel(`svcChList${i}`, (v) => v.join(",") || "— 通道 —");
      setMultiOpts(`svcChList${i}`, m.map((mm) => ({ value: mm.id, label: mm.id })), x.channels || []);
      initMultiSel(`svcRolesBtn${i}`, `svcRolesList${i}`, (v) => { DRAFT.services[i].roles = v; cfgSync(); });
      setMultiLabel(`svcRolesList${i}`, (v) => v.join(",") || "— 角色 —");
      setMultiOpts(`svcRolesList${i}`, ["any", ...rl].map((rr) => ({ value: rr, label: rr })), x.roles || []);
    });
  }
  cfgSync();
  // 输入 → DRAFT (listen 联动 target, 手动改过 target 后停止)
  document.querySelectorAll("input[data-cfg]").forEach((inp) => {
    inp.addEventListener("input", () => {
      const i = +inp.dataset.i;
      const k = inp.dataset.cfg;
      if (k.startsWith("m-")) {
        const obj = DRAFT.mappings[i];
        obj[k.slice(2)] = inp.value;
        if (k === "m-listen" && !TARGET_TOUCHED.has(obj)) {
          obj.target = autoTarget(inp.value); // 自动补 http://127.0.0.1 + listen
          const tgt = document.querySelector(`input[data-cfg="m-target"][data-i="${i}"]`);
          if (tgt) tgt.value = obj.target;
        }
      } else if (k.startsWith("s-")) DRAFT.services[i][k.slice(2)] = inp.value;
      if (k === "m-target") TARGET_TOUCHED.add(DRAFT.mappings[i]); // 手动改过 → 联动失效
      cfgFieldCheck(inp); // 即时格式校验(红框)
      cfgSync(); // 有变更才点亮保存
    });
  });
  // 行删除 → DRAFT
  document.querySelectorAll("button[data-cfg]").forEach((b) => {
    b.addEventListener("click", () => {
      const i = +b.dataset.i;
      if (b.dataset.cfg === "m-del") { DRAFT.mappings.splice(i, 1); renderCfg(); }
      else if (b.dataset.cfg === "s-del") { DRAFT.services.splice(i, 1); renderCfg(); }
      else if (b.dataset.cfg === "role-del") { DRAFT.roles.splice(i, 1); renderCfg(); }
    });
  });
}

// cfgSync: 保存按钮灰态 — 草稿与服务端状态有差异才点亮
function cfgSync() {
  const btn = $("cfgSave");
  if (!btn || !CFG || !DRAFT) return;
  const changed =
    JSON.stringify(DRAFT.mappings) !== JSON.stringify(CFG.mappings || []) ||
    JSON.stringify(DRAFT.services) !== JSON.stringify(CFG.services || []) ||
    JSON.stringify(DRAFT.roles) !== JSON.stringify(CFG.roles || []);
  btn.disabled = !changed || CFG.mode === "immutable";
}

function cfgSay(msg, err) { $("cfgResult").textContent = (err ? "✘ " : "✔ ") + msg; }
async function cfgSave() {
  const cert = getSel("adminCertList");
  if (!cert) return;
  // 保存前整体校验(本地, 与服务端规则一致)
  const errs = cfgValidate();
  if (errs.length) { cfgSay(errs[0], true); toast(errs[0], true); return; }
  try {
    await api("/api/admin/config", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ cert_id: cert, load_pwd: ADMIN_PWD, body: { mappings: DRAFT.mappings, services: DRAFT.services, roles: DRAFT.roles } }),
    });
    cfgSay("已保存(热重载生效)");
    await loadAdminData();
  } catch (e) { cfgSay(e.message, true); }
}

async function cfgCancel() { await loadAdminData(); }

async function adminIssue() {
  const cert = getSel("adminCertList");
  const name = $("newName").value.trim();
  const purps = getMultiSel("newPurposesList");
  // 本地校验(与服务端 IssueCert 规则一致)
  const errs = [];
  if (!cert) errs.push(t("needCertForTunnel"));
  if (!name) errs.push(t("issueNeedName"));
  else if (!RE_NAME.test(name)) errs.push(t("issueBadName"));
  if (!purps.length) errs.push(t("issueNeedPurps"));
  const tsip = $("newTSIP").value.trim();
  if (tsip && !/^[\d.:a-fA-F]+$/.test(tsip)) errs.push(t("issueBadIP"));
  if (errs.length) { toast(errs[0], true); return; }
  const pwdMode = getSel("pwdModeList") || "auto";
  const body = { cert_id: cert, load_pwd: ADMIN_PWD, name, purposes: purps, ts_ip: $("newTSIP").value.trim() };
  if (pwdMode === "none") body.no_password = true;
  else if (pwdMode === "custom") body.password = $("newCertPwd").value;
  try {
    const resp = await api("/api/admin/issue", jpost(body));
    const pwdTxt = pwdMode === "none" ? t("pwdNoneTxt") : t("pwdTxt", { p: resp.p12_password || "" });
    $("adminResult").textContent = t("issued", { n: resp.name, s: resp.serial, pwd: pwdTxt });
    toast(t("issueOk"));
    loadAdminData();
  } catch (e) { toast(t("issueFail", { m: e.message }), true); }
}

async function adminRevoke() {
  const cert = getSel("adminCertList");
  const serial = getSel("revokeCertList");
  if (!cert || !serial) { toast(t("revokeNeed"), true); return; }
  try {
    await api("/api/admin/revoke", jpost({ cert_id: cert, load_pwd: ADMIN_PWD, serial }));
    $("adminResult").textContent = t("revoked", { s: serial });
    toast(t("revokeOk"));
    loadAdminData();
  } catch (e) { toast(t("revokeFail", { m: e.message }), true); }
}
