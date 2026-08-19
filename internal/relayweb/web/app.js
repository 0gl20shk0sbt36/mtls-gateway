// mtls-relay WebUI 前端 — 直接调用本地管理 API (/api/*)
const $ = (id) => document.getElementById(id);

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
    const s = SEL_MULTI[listId];
    const v = d.dataset.val;
    if (s.has(v)) { s.delete(v); d.classList.remove("on"); }
    else { s.add(v); d.classList.add("on"); }
    updateMultiLabel(listId);
    if (onChange) onChange([...s]);
  };
}
function setMultiOpts(listId, items, selected) {
  SEL_MULTI[listId] = new Set(selected || []);
  const list = $(listId);
  list.innerHTML = "";
  (items || []).forEach((it) => {
    const d = document.createElement("div");
    d.className = "opt chk" + (SEL_MULTI[listId].has(it.value) ? " on" : "");
    d.dataset.val = it.value;
    d.textContent = it.label;
    list.appendChild(d);
  });
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
  const t = $("toast");
  t.textContent = (isErr ? "错误: " : "") + msg;
  t.classList.toggle("error", !!isErr);
  t.style.display = "block";
  setTimeout(() => (t.style.display = "none"), 3000);
}

async function api(path, opts) {
  const resp = await fetch(path, opts);
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
    for (const t of tunnels) {
      // 聚合该服务所有路由的状态
      let running = false, conns = 0, bin = 0, bout = 0;
      (t.routes || []).forEach((rt) => {
        const k = t.service + "@" + rt.channel + "@" + rt.local;
        const s = byId[k] || {};
        if (s.running) running = true;
        conns += s.active_conns || 0;
        bin += s.bytes_in || 0;
        bout += s.bytes_out || 0;
      });
      const chans = (t.routes || []).map((rt) => rt.channel).join(" · ");
      const locals = (t.routes || []).map((rt) => rt.local).join(" · ");
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="mono">${esc(t.service)}</td>
        <td class="mono" style="font-size:12px">${esc(chans)}</td>
        <td class="mono" style="font-size:12px">${esc(locals)}</td>
        <td>${running ? "●" : "○"}</td>
        <td>${conns}</td>
        <td>${fmtBytes(bin)}</td>
        <td>${fmtBytes(bout)}</td>
        <td><button class="danger" data-del="${esc(t.service)}">删除服务</button></td>`;
      body.appendChild(tr);
    }
    for (const btn of body.querySelectorAll("[data-del]")) {
      btn.onclick = async () => {
        if (!confirm(`删除整个服务 "${btn.dataset.del}" 的所有通道隧道?`)) return;
        try {
          await api("/api/tunnels/" + encodeURIComponent(btn.dataset.del), { method: "DELETE" });
          toast("已删除服务隧道");
          loadTunnels();
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

let SERVICES = [];

// 渲染选中服务的通道行: 每通道一行 [通道(只读) | 本地路由输入(默认=通道)]
function renderSvcChannels(svc) {
  const box = $("svcChannelRows");
  if (!svc || !svc.channels || !svc.channels.length) { box.innerHTML = ""; return; }
  let h = '<div class="hint">服务端入口 → 本地路由 (默认同入口, 含冒号; 可改端口/路径)</div>';
  svc.channels.forEach((ch) => {
    h += `<div class="row" style="margin-top:6px">
      <span class="mono" style="width:160px;align-self:center">${esc(ch.listen)}</span>
      <span style="align-self:center;color:var(--text4)">→</span>
      <input class="svc-local" data-ch="${esc(ch.listen)}" value="${esc(ch.listen)}" placeholder=":端口[/路径]" style="flex:1;font-family:monospace">
    </div>`;
  });
  box.innerHTML = h;
}

async function init() {
  $("refreshServices").onclick = verifyAdmin; // 刷新服务 = 重新验证
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
  $("adminIssue").onclick = adminIssue;
  $("adminRevoke").onclick = adminRevoke;
  $("cfgSave").onclick = cfgSave;
  $("cfgCancel").onclick = cfgCancel;
  initMultiSel("newPurposesBtn", "newPurposesList");
  initSel("pwdModeBtn", "pwdModeList", (it) => { $("newCertPwd").disabled = it.value !== "custom"; });
  setSel("pwdModeList", [
    { value: "none", label: "无密码" },
    { value: "auto", label: "自动生成" },
    { value: "custom", label: "自定义" },
  ]);
  pickSel("pwdModeList", 1); // 默认自动生成
  initSel("revokeCertBtn", "revokeCertList");
  $("btnStart").onclick = async () => { try { await api("/api/start", jpost(null)); toast("已启动"); loadTunnels(); } catch (e) { toast(e.message, true); } };
  $("btnReload").onclick = async () => { try { await api("/api/reload", jpost(null)); toast("已 reload"); loadTunnels(); } catch (e) { toast(e.message, true); } };
  $("btnStop").onclick = async () => { try { await api("/api/stop", jpost(null)); toast("已停止"); loadTunnels(); } catch (e) { toast(e.message, true); } };
  $("addTunnel").onclick = async () => {
    const service = getSel("newServiceList");
    const cert = getSel("adminCertList");
    if (!service) { toast("请先选择服务（需先选证书并验证）", true); return; }
    if (!cert) { toast("请先选择证书", true); return; }
    const body = { service, cert_id: cert, locals: {} };
    let bad = false;
    document.querySelectorAll("#svcChannelRows .svc-local").forEach((inp) => {
      const v = inp.value.trim();
      if (!v) { toast("本地路由不能为空: " + inp.dataset.ch, true); bad = true; return; }
      body.locals[inp.dataset.ch] = v;
    });
    if (bad) return;
    try {
      const r = await api("/api/tunnels", jpost(body));
      toast(`已添加服务 ${r.service}(${r.count} 个通道)`);
      loadTunnels();
    } catch (e) { toast(e.message, true); }
  };
  await Promise.all([loadCerts(), loadTunnels()]);
  setInterval(loadTunnels, 2000); // 状态轮询
}

init();

async function verifyAdmin() {
  const cert = getSel("adminCertList");
  if (!cert) { toast("请先选择证书", true); return; }
  ADMIN_PWD = $("adminPwd").value || "";
  try {
    const res = await api("/api/verify", jpost({ cert_id: cert, load_pwd: ADMIN_PWD }));
    // 服务列表(用该证书的 /info, v4: 服务+通道)
    SERVICES = res.services || [];
    setSel("newServiceList", SERVICES.map((s) => ({ value: s.name, label: s.name, raw: s })));
    $("serviceHint").textContent = SERVICES.length
      ? `已发现 ${SERVICES.length} 个服务；选中后为每个通道填本地路由(默认同服务端入口)。`
      : "该证书无可用服务（或非业务证书，仅 admin 用途）。";
    // 普通证书 → 新增隧道; admin 证书 → 证书管理
    if (res.admin) {
      $("tunnelSection").style.display = "none";
      $("adminSection").style.display = "";
      $("adminStatus").textContent = "已解锁：admin 证书已验证，可签发/吊销。";
      $("adminCertHint").textContent = `已验证 ${cert}：admin 证书 → 证书管理可用。`;
      toast("验证成功 · 管理台已解锁");
      loadAdminData();
    } else {
      $("adminSection").style.display = "none";
      $("tunnelSection").style.display = "";
      $("adminCertHint").textContent = `已验证 ${cert}：普通证书 → 可新增隧道（管理不可用）。`;
      toast("验证成功（普通证书）");
    }
    $("adminPwd").value = ""; // 验证成功即清空密码(失败保留)
  } catch (e) { toast("验证失败: " + e.message, true); }
}
let CFG = null;
let CFG_ADMIN_ROLE = "mtls-superadmin";
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

let DRAFT = null;
function renderCfg() {
  const imm = CFG.mode === "immutable";
  $("cfgMode").textContent = CFG.mode + (imm ? " 🔒" : "");
  const dis = imm ? " disabled" : "";
  const m = DRAFT.mappings || [], s = DRAFT.services || [], rl = DRAFT.roles || [];
  // 通道
  let h = '<div class="hint">通道 (mappings)</div>';
  h += '<div class="row" style="margin-top:4px;color:var(--text4);font-size:12px"><span style="width:110px">id</span><span style="flex:1">listen (:端口[/路径])</span><span style="flex:1.6">target</span><span style="width:22px"></span></div>';
  m.forEach((mm, i) => {
    h += `<div class="row" style="margin-top:6px">
      <input value="${esc(mm.id)}" placeholder="id" style="width:110px"${dis} data-cfg="m-id" data-i="${i}">
      <input value="${esc(mm.listen)}" placeholder=":端口[/路径]" style="flex:1"${dis} data-cfg="m-listen" data-i="${i}">
      <input value="${esc(mm.target)}" placeholder="target" style="flex:1.6"${dis} data-cfg="m-target" data-i="${i}">
      <button type="button" class="danger small" data-cfg="m-del" data-i="${i}"${dis}>×</button>
    </div>`;
  });
  $("cfgMappings").innerHTML = h;
  // 服务
  let sv = '<div class="hint" style="margin-top:8px">服务 (services)</div>';
  sv += '<div class="row" style="margin-top:4px;color:var(--text4);font-size:12px"><span style="width:110px">name</span><span style="flex:1">channels (多选)</span><span style="flex:1">roles (多选)</span><span style="width:22px"></span></div>';
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
  $("cfgServices").innerHTML = sv;
  // 角色
  let r = '<div class="hint" style="margin-top:8px">角色 (roles 声明; 内置 any 免声明, 仅服务可用)</div>';
  rl.forEach((name, i) => {
    r += `<span class="chip">${esc(name)}<button type="button" class="chip-x" data-cfg="role-del" data-i="${i}"${dis}>×</button></span>`;
  });
  r += `<input id="cfgNewRole" placeholder="新角色" style="width:120px;margin-left:8px"${dis}>
        <button type="button" class="ghost small" id="cfgAddRole"${dis}>＋ 角色</button>
        <button type="button" class="ghost small" id="cfgAddMap"${dis}>＋ 通道</button>
        <button type="button" class="ghost small" id="cfgAddSvc"${dis}>＋ 服务</button>`;
  $("cfgRoles").innerHTML = r;
  if (!imm) {
    $("cfgAddRole").onclick = () => {
      const v = $("cfgNewRole").value.trim();
      if (v && !DRAFT.roles.includes(v)) DRAFT.roles.push(v);
      $("cfgNewRole").value = "";
      renderCfg();
    };
    $("cfgAddMap").onclick = () => { DRAFT.mappings.push({ id: "", listen: "", target: "" }); renderCfg(); };
    $("cfgAddSvc").onclick = () => { DRAFT.services.push({ name: "", channels: [], roles: [] }); renderCfg(); };
    // 服务行多选
    s.forEach((x, i) => {
      initMultiSel(`svcChBtn${i}`, `svcChList${i}`, (v) => { DRAFT.services[i].channels = v; });
      setMultiLabel(`svcChList${i}`, (v) => v.join(",") || "— 通道 —");
      setMultiOpts(`svcChList${i}`, m.map((mm) => ({ value: mm.id, label: mm.id })), x.channels || []);
      initMultiSel(`svcRolesBtn${i}`, `svcRolesList${i}`, (v) => { DRAFT.services[i].roles = v; });
      setMultiLabel(`svcRolesList${i}`, (v) => v.join(",") || "— 角色 —");
      setMultiOpts(`svcRolesList${i}`, [...rl, "any"].map((rr) => ({ value: rr, label: rr })), x.roles || []);
    });
  }
  // 输入 → DRAFT
  document.querySelectorAll("input[data-cfg]").forEach((inp) => {
    inp.addEventListener("input", () => {
      const i = +inp.dataset.i;
      const k = inp.dataset.cfg;
      if (k.startsWith("m-")) DRAFT.mappings[i][k.slice(2)] = inp.value;
      else if (k.startsWith("s-")) DRAFT.services[i][k.slice(2)] = inp.value;
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

function cfgSay(msg, err) { $("cfgResult").textContent = (err ? "✘ " : "✔ ") + msg; }

async function cfgSave() {
  const cert = getSel("adminCertList");
  if (!cert) return;
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
  if (!cert || !name || !purps.length) { toast("需选 admin 证书 + 填设备名 + 至少一个用途", true); return; }
  const pwdMode = getSel("pwdModeList") || "auto";
  const body = { cert_id: cert, load_pwd: ADMIN_PWD, name, purposes: purps, ts_ip: $("newTSIP").value.trim() };
  if (pwdMode === "none") body.no_password = true;
  else if (pwdMode === "custom") body.password = $("newCertPwd").value;
  try {
    const resp = await api("/api/admin/issue", jpost(body));
    $("adminResult").textContent = `✔ 已签发：${resp.name}\n序列号: ${resp.serial}\n${pwdMode === "none" ? "无密码" : "p12 密码: " + (resp.p12_password || "")}`;
    toast("签发成功");
    loadAdminData();
  } catch (e) { toast("签发失败: " + e.message, true); }
}

async function adminRevoke() {
  const cert = getSel("adminCertList");
  const serial = getSel("revokeCertList");
  if (!cert || !serial) { toast("需选 admin 证书 + 选择要吊销的证书", true); return; }
  try {
    await api("/api/admin/revoke", jpost({ cert_id: cert, load_pwd: ADMIN_PWD, serial }));
    $("adminResult").textContent = `✔ 已吊销: ${serial}`;
    toast("已吊销");
    loadAdminData();
  } catch (e) { toast("吊销失败: " + e.message, true); }
}
