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
    const tunnels = cfg.tunnels || [];
    if (!tunnels.length) {
      body.innerHTML = '<tr><td colspan="8" class="hint">(无隧道)</td></tr>';
      return;
    }
    for (const t of tunnels) {
      const s = byId[t.id] || {};
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="mono">${esc(t.id)}</td>
        <td>127.0.0.1:${t.local_port}</td>
        <td class="mono">${esc(t.remote_addr)}</td>
        <td>${t.enabled ? "●" : "○"}</td>
        <td>${s.active_conns ?? 0}</td>
        <td>${fmtBytes(s.bytes_in)}</td>
        <td>${fmtBytes(s.bytes_out)}</td>
        <td><button class="danger" data-del="${esc(t.id)}">删</button></td>`;
      body.appendChild(tr);
    }
    for (const btn of body.querySelectorAll("[data-del]")) {
      btn.onclick = async () => {
        try {
          await api("/api/tunnels/" + encodeURIComponent(btn.dataset.del), { method: "DELETE" });
          toast("已删除隧道");
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

async function loadServices() {
  try {
    const list = await api("/api/services");
    SERVICES = Array.isArray(list) ? list : [];
    setSel("newServiceList", SERVICES.map((s) => {
      const svcTxt = (s.services || []).join(" · ") || "-";
      return { value: s.listen, label: `${s.listen}  ${svcTxt}`, raw: s };
    }));
    $("serviceHint").textContent = SERVICES.length
      ? `已发现 ${SERVICES.length} 个入口：如 ${SERVICES[0].listen}。选中后本地端口默认填同值(可改)，选证书→添加。`
      : "未发现服务 —— 请确认服务端已配 mappings + /info 可达";
  } catch (e) {
    $("serviceHint").textContent = "加载服务失败: " + e.message;
  }
}

async function init() {
  $("refreshServices").onclick = verifyAdmin; // 刷新服务 = 重新验证
  initSel("newServiceBtn", "newServiceList", (it) => {
    const l = (it.raw || {}).listen || "";
    const p = l.replace(/^:/, "").split("/")[0];
    if (p) $("newLocal").value = p;
  });
  initSel("adminCertBtn", "adminCertList");
  $("adminVerify").onclick = verifyAdmin;
  $("adminIssue").onclick = adminIssue;
  $("adminRevoke").onclick = adminRevoke;
  $("btnStart").onclick = async () => { try { await api("/api/start", jpost(null)); toast("已启动"); loadTunnels(); } catch (e) { toast(e.message, true); } };
  $("btnReload").onclick = async () => { try { await api("/api/reload", jpost(null)); toast("已 reload"); loadTunnels(); } catch (e) { toast(e.message, true); } };
  $("btnStop").onclick = async () => { try { await api("/api/stop", jpost(null)); toast("已停止"); loadTunnels(); } catch (e) { toast(e.message, true); } };
  $("addTunnel").onclick = async () => {
    const service = getSel("newServiceList");
    const local = parseInt($("newLocal").value, 10);
    const cert = getSel("adminCertList");
    if (!service) { toast("请先选择服务（需先选证书并验证）", true); return; }
    if (!local || isNaN(local)) { toast("请填写本地端口(选中服务会自动带出)", true); return; }
    if (!cert) { toast("请先选择证书", true); return; }
    const body = {
      service,
      local_port: local,
      server_name: $("newSNI").value.trim(),
      cert_id: cert,
      enabled: true,
    };
    try {
      await api("/api/tunnels", jpost(body));
      toast("已添加隧道, reload/start 生效");
      $("newLocal").value = "";
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
    // 服务列表(用该证书的 /info)
    SERVICES = res.services || [];
    setSel("newServiceList", SERVICES.map((s) => {
      const svcTxt = (s.services || []).join(" · ") || "-";
      return { value: s.listen, label: `${s.listen}  ${svcTxt}`, raw: s };
    }));
    $("serviceHint").textContent = SERVICES.length
      ? `已发现 ${SERVICES.length} 个入口：如 ${SERVICES[0].listen}。选中后本地端口默认填同值(可改)。`
      : "该证书无可用服务（或非业务证书，仅 admin 用途）。";
    // 普通证书 → 新增隧道; admin 证书 → 证书管理
    if (res.admin) {
      $("tunnelSection").style.display = "none";
      $("adminSection").style.display = "";
      $("adminStatus").textContent = "已解锁：admin 证书已验证，可签发/吊销。";
      $("adminCertHint").textContent = `已验证 ${cert}：admin 证书 → 证书管理可用。`;
      toast("验证成功 · 证书管理已解锁");
    } else {
      $("adminSection").style.display = "none";
      $("tunnelSection").style.display = "";
      $("adminCertHint").textContent = `已验证 ${cert}：普通证书 → 可新增隧道（证书管理不可用）。`;
      toast("验证成功（普通证书）");
    }
  } catch (e) { toast("验证失败: " + e.message, true); }
}
async function adminIssue() {
  const cert = getSel("adminCertList");
  const name = $("newName").value.trim();
  const purps = $("newPurposes").value.split(/[,，\s]+/).filter(Boolean);
  if (!cert || !name || !purps.length) { toast("需选 admin 证书 + 填设备名 + 用途", true); return; }
  try {
    const resp = await api("/api/admin/issue", jpost({ cert_id: cert, load_pwd: ADMIN_PWD, name, purposes: purps, ts_ip: $("newTSIP").value.trim(), password: $("newCertPwd").value }));
    $("adminResult").textContent = `✔ 已签发：${resp.name}\n序列号: ${resp.serial}\np12 密码: ${resp.p12_password || "（无）"}`;
    toast("签发成功");
  } catch (e) { toast("签发失败: " + e.message, true); }
}
async function adminRevoke() {
  const cert = getSel("adminCertList");
  const serial = $("revokeSerial").value.trim();
  if (!cert || !serial) { toast("需选 admin 证书 + 填序列号", true); return; }
  try {
    await api("/api/admin/revoke", jpost({ cert_id: cert, load_pwd: ADMIN_PWD, serial }));
    $("adminResult").textContent = `✔ 已吊销序列号: ${serial}`;
    toast("已吊销");
  } catch (e) { toast("吊销失败: " + e.message, true); }
}
