// mtls-relay WebUI 前端 — 直接调用本地管理 API (/api/*)
const $ = (id) => document.getElementById(id);

function toast(msg, isErr) {
  const t = $("toast");
  t.textContent = (isErr ? "错误: " : "") + msg;
  t.style.display = "block";
  setTimeout(() => (t.style.display = "none"), 3000);
}

async function api(path, opts) {
  const resp = await fetch(path, opts);
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error(data.error || ("HTTP " + resp.status));
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
    const sel = $("certSelect");
    sel.innerHTML = "";
    if (!certs.length) {
      sel.innerHTML = '<option value="">(无可用证书)</option>';
      $("certHint").textContent = "未找到证书。请检查 daemon 的证书来源配置。";
      return;
    }
    for (const c of certs) {
      const opt = document.createElement("option");
      opt.value = c.id;
      opt.textContent = `${c.common_name || "(无名)"}  [${c.id}]`;
      sel.appendChild(opt);
    }
    $("certHint").textContent = `共 ${certs.length} 个证书可用。`;
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
        <td>${t.local_port}</td>
        <td class="mono">${esc(t.remote_addr)}</td>
        <td>${esc(t.purpose || "-")}</td>
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
    // 状态点: 任一隧道运行视为 daemon on
    $("daemonDot").classList.toggle("on", sts.length > 0);
  } catch (e) {
    toast(e.message, true);
    $("daemonDot").classList.remove("on");
  }
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

async function init() {
  $("refreshCerts").onclick = loadCerts;
  $("btnStart").onclick = async () => { try { await api("/api/start", jpost(null)); toast("已启动"); loadTunnels(); } catch (e) { toast(e.message, true); } };
  $("btnReload").onclick = async () => { try { await api("/api/reload", jpost(null)); toast("已 reload"); loadTunnels(); } catch (e) { toast(e.message, true); } };
  $("btnStop").onclick = async () => { try { await api("/api/stop", jpost(null)); toast("已停止"); loadTunnels(); } catch (e) { toast(e.message, true); } };
  $("addTunnel").onclick = async () => {
    const local = parseInt($("newLocal").value, 10);
    const remote = $("newRemote").value.trim();
    const cert = $("certSelect").value;
    if (!local || !remote || !cert) { toast("请填写本地端口/远端/并选择证书", true); return; }
    const body = {
      id: "t" + local,
      local_port: local,
      remote_addr: remote,
      server_name: $("newSNI").value.trim(),
      purpose: $("newPurpose").value.trim(),
      cert_id: cert,
      enabled: true,
    };
    try {
      await api("/api/tunnels", jpost(body));
      toast("已添加隧道,执行 reload 或 start 生效");
      $("newLocal").value = ""; $("newRemote").value = "";
      loadTunnels();
    } catch (e) { toast(e.message, true); }
  };
  await Promise.all([loadCerts(), loadTunnels()]);
  setInterval(loadTunnels, 2000); // 状态轮询
}

init();
