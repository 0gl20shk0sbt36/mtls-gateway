// i18n: 轻量中英双语 (zh/en)。检测顺序: localStorage.lang → 浏览器语言 → zh。
(function () {
  const L = {
    zh: {
      langName: "中文",
      appTitle: "MTLS 中继面板",
      // 运行控制
      runCtrl: "运行控制",
      start: "启动",
      reload: "重载",
      stop: "停止",
      subLabel: "客户端 mTLS 中继",
      onlineN: "在线 · {n} 个通道",
      offline: "离线",
      // 隧道表
      tunnels: "隧道",
      thService: "服务",
      thChannel: "服务端入口",
      thLocal: "本地路由",
      thStatus: "状态",
      thConns: "连接",
      thIn: "流入",
      thOut: "流出",
      thOps: "操作",
      delService: "删除服务",
      delServiceConfirm: "删除整个服务 \"{s}\" 的所有通道隧道?",
      delDone: "已删除服务隧道",
      noTunnel: "(无隧道)",
      tunnelLegend: "服务端入口 = 中继拨号到的服务端网关通道；本地路由 = 你的程序要连的地址(:端口[/路径]，绑 127.0.0.1)。连接/流入/流出为实时指标。",
      // 证书选择
      certSelect: "证书选择",
      certHint: "选一枚证书并<b>验证</b>：普通证书 → 显示\"新增隧道\"；{adminRole} 证书 → 显示\"证书管理\"。未选证书前两者都不可用。",
      certCount: "共 {n} 个证书可用；选一枚点\"验证\"。",
      noCertFound: "未找到证书。请检查 daemon 证书来源配置。",
      chooseCert: "— 选择证书 —",
      certPwd: "证书密码(如有)",
      verify: "验证",
      verifiedAdmin: "已验证 {c}：管理证书 → 证书管理可用。",
      verifiedNormal: "已验证 {c}：普通证书 → 可新增隧道（管理不可用）。",
      switchCertReset: "已切换证书 — 请重新验证。",
      unlockAdmin: "已解锁：管理证书已验证，可签发/吊销。",
      verifyOkAdmin: "验证成功 · 管理台已解锁",
      verifyOkNormal: "验证成功（普通证书）",
      verifyFail: "验证失败: {m}",
      needCert: "请先选择证书",
      // 新增隧道
      addTunnel: "新增隧道",
      svcSelect: "服务选择",
      tunnelMapping: "隧道映射",
      chooseService: "— 选择服务 —",
      refresh: "刷新",
      add: "添加",
      svcHint: "已发现 {n} 个服务；选中后为每个通道填本地路由(默认同服务端入口)。",
      svcHintNone: "该证书无可用服务（或非业务证书，仅管理用途）。",
      routeHint: "服务端入口 → 本地路由 (默认同入口, 含冒号; 可改端口/路径)",
      routeEmpty: "本地路由不能为空: {c}",
      addedService: "已添加服务 {s}({n} 个通道)",
      needService: "请先选择服务（需先选证书并验证）",
      needCertForTunnel: "请先选择证书",
      // 证书管理
      certMgmt: "证书管理",
      issueName: "设备名 (如 dev-1)",
      issuePurposes: "选择用途",
      tsIp: "TS IP (可选)",
      pwdNone: "无密码",
      pwdAuto: "自动生成",
      pwdCustom: "自定义",
      issue: "签发",
      revokeSelect: "— 选择要吊销的证书 —",
      revoke: "吊销",
      issued: "✔ 已签发：{n}\n序列号: {s}\n{pwd}",
      pwdNoneTxt: "无密码",
      pwdTxt: "p12 密码: {p}",
      issueOk: "签发成功",
      issueFail: "签发失败: {m}",
      revoked: "✔ 已吊销: {s}",
      revokeConfirm: "确定吊销以下证书?此操作不可撤销:",
      revokeOk: "已吊销",
      revokeFail: "吊销失败: {m}",
      issueNeed: "需选管理证书 + 填设备名 + 至少一个用途",
      issueNeedName: "请填写设备名",
      issueBadName: "设备名只允许字母/数字/下划线/连字符",
      issueNeedPurps: "请至少选择一个用途",
      issueNameExists: "证书名 {n} 已存在，禁止同名签发(服务端同样拦截)",
      issueBadIP: "TS IP 格式无效(应为 IPv4/IPv6)",
      revokeNeed: "需选管理证书 + 选择要吊销的证书",
      // 服务端配置
      serverCfg: "服务端配置",
      cfgModeHint: "mutable=改后落盘 / ephemeral=仅内存 / immutable=只读(灰显, 服务端拦截修改)。改动后点底部<b>保存</b>统一生效(热重载)。",
      cfgMappings: "通道 (mappings)",
      cfgServices: "服务 (services)",
      cfgRoles: "角色 (roles 声明; 内置 any 免声明, 仅服务可用)",
      cfgHeaderM: "listen (:端口[/路径])",
      cfgHeaderS: "channels (多选)",
      cfgHeaderRoles: "roles (多选)",
      cfgNewRole: "新角色",
      addRole: "＋ 角色",
      addMap: "＋ 通道",
      addSvc: "＋ 服务",
      save: "保存",
      cancel: "取消",
      cfgSaved: "已保存(热重载生效)",
      cfgChannelsPh: "— 通道 —",
      cfgRolesPh: "— 角色 —",
      // 通用
      errPrefix: "错误: ",
      ok: "确定",
      // 服务端错误本地化
      errPwdNeeded: "私钥需要密码：{cert} —— 请在\"证书密码\"框输入密码后重新验证",
      errNoCert: "没有可用证书：证书源为空或证书加载失败",
      errExpired: "证书已过期，请联系管理员重新签发",
      errSvcNotFound: "服务端不存在该服务：{s}",
      errCertNotFound: "证书不存在：{s}",
      errImmutable: "服务端配置为只读模式（immutable），无法修改",
      errRevoked: "证书已被吊销",
      errAdminDenied: "管理权限被拒绝：当前证书不是管理证书",
      errDenied: "访问被拒绝（403）：证书角色无权访问",
      // 日志
      logCfg: "日志配置",
    },
    en: {
      langName: "English",
      appTitle: "MTLS Relay Panel",
      runCtrl: "Run Control",
      start: "Start",
      reload: "Reload",
      stop: "Stop",
      subLabel: "Client mTLS Relay",
      onlineN: "Online · {n} routes",
      offline: "Offline",
      tunnels: "Tunnels",
      thService: "Service",
      thChannel: "Server Entry",
      thLocal: "Local Route",
      thStatus: "Status",
      thConns: "Conns",
      thIn: "In",
      thOut: "Out",
      thOps: "Actions",
      delService: "Delete Service",
      delServiceConfirm: "Delete ALL tunnel routes of service \"{s}\"?",
      delDone: "Service tunnel deleted",
      noTunnel: "(none)",
      tunnelLegend: "Server Entry = the gateway channel the relay dials; Local Route = the address your app connects to (:port[/path], bound 127.0.0.1). Conns/In/Out are live metrics.",
      certSelect: "Certificate",
      certHint: "Pick a certificate and <b>verify</b>: normal cert → \"Add Tunnel\"; {adminRole} cert → \"Cert Management\". Both are disabled before verification.",
      certCount: "{n} certificates available; pick one and verify.",
      noCertFound: "No certificates found. Check the daemon cert source config.",
      chooseCert: "— Select certificate —",
      certPwd: "Cert password (if any)",
      verify: "Verify",
      verifiedAdmin: "Verified {c}: admin cert → management unlocked.",
      verifiedNormal: "Verified {c}: normal cert → add tunnels (management locked).",
      switchCertReset: "Certificate switched — please verify again.",
      unlockAdmin: "Unlocked: admin cert verified. Issue/revoke ready.",
      verifyOkAdmin: "Verified · management unlocked",
      verifyOkNormal: "Verified (normal cert)",
      verifyFail: "Verify failed: {m}",
      needCert: "Select a certificate first",
      addTunnel: "Add Tunnel",
      svcSelect: "Service",
      tunnelMapping: "Tunnel Mapping",
      chooseService: "— Select service —",
      refresh: "Refresh",
      add: "Add",
      svcHint: "{n} services discovered; pick one and fill the local route per channel (default = server entry).",
      svcHintNone: "No accessible services for this cert (or it's an admin-only cert).",
      routeHint: "Server entry → local route (default = same as entry, incl. colon; port/path editable)",
      routeEmpty: "Local route cannot be empty: {c}",
      addedService: "Added service {s} ({n} channels)",
      needService: "Select a service first (verify with a cert first)",
      needCertForTunnel: "Select a certificate first",
      certMgmt: "Cert Management",
      issueName: "Device name (e.g. dev-1)",
      issuePurposes: "Purposes",
      tsIp: "TS IP (optional)",
      pwdNone: "No password",
      pwdAuto: "Auto-generate",
      pwdCustom: "Custom",
      issue: "Issue",
      revokeSelect: "— Select cert to revoke —",
      revoke: "Revoke",
      issued: "✔ Issued: {n}\nSerial: {s}\n{pwd}",
      pwdNoneTxt: "no password",
      pwdTxt: "p12 password: {p}",
      issueOk: "Issued",
      issueFail: "Issue failed: {m}",
      revoked: "✔ Revoked: {s}",
      revokeConfirm: "Revoke this certificate? This cannot be undone:",
      revokeOk: "Revoked",
      revokeFail: "Revoke failed: {m}",
      issueNeed: "Need admin cert + device name + at least one purpose",
      issueNeedName: "Device name required",
      issueBadName: "Device name: letters/digits/underscore/hyphen only",
      issueNeedPurps: "Pick at least one purpose",
      issueNameExists: "Name {n} already exists — duplicate names not allowed (also blocked server-side)",
      issueBadIP: "Invalid TS IP (IPv4/IPv6 expected)",
      revokeNeed: "Need admin cert + pick a cert to revoke",
      serverCfg: "Server Config",
      cfgModeHint: "mutable=persist on save / ephemeral=memory only / immutable=read-only (greyed, server blocks edits). Changes apply via the <b>Save</b> button below (hot reload).",
      cfgMappings: "Mappings",
      cfgServices: "Services",
      cfgRoles: "Roles (declared; built-in \"any\" needs no declaration, service-only)",
      cfgHeaderM: "listen (:port[/path])",
      cfgHeaderS: "channels (multi)",
      cfgHeaderRoles: "roles (multi)",
      cfgNewRole: "New role",
      addRole: "+ Role",
      addMap: "+ Mapping",
      addSvc: "+ Service",
      save: "Save",
      cancel: "Cancel",
      cfgSaved: "Saved (hot reload active)",
      cfgChannelsPh: "— channels —",
      cfgRolesPh: "— roles —",
      errPrefix: "Error: ",
      ok: "OK",
      // server error localization
      errPwdNeeded: "Private key needs password: {cert} — enter the cert password and verify again",
      errNoCert: "No usable certificate: cert source empty or load failed",
      errExpired: "Certificate has expired — contact the admin for a reissue",
      errSvcNotFound: "Service not found on server: {s}",
      errCertNotFound: "Certificate not found: {s}",
      errImmutable: "Server config is immutable (read-only), cannot modify",
      errRevoked: "Certificate has been revoked",
      errAdminDenied: "Admin access denied: this cert is not an admin cert",
      errDenied: "Access denied (403): cert role has no access",
      logCfg: "Log config",
    },
  };

  // 支持的语言(可扩展: 加语言 = 加字典条目 + 这里加一行)
  const LANGS = [
    { code: "zh", label: "中文" },
    { code: "en", label: "English" },
  ];
  let lang = "zh";
  function detect() {
    try {
      const saved = localStorage.getItem("lang");
      for (const l of LANGS) if (l.code === saved) return l.code;
    } catch (e) { /* ignore */ }
    try {
      const nav = (navigator.language || "zh").toLowerCase();
      for (const l of LANGS) if (nav.startsWith(l.code)) return l.code;
      return LANGS[0].code;
    } catch (e) {
      return LANGS[0].code;
    }
  }
  function setLang(l) {
    lang = l;
    try { localStorage.setItem("lang", l); } catch (e) { /* ignore */ }
  }
  // t(key, vars): 取值 + 替换 {var}
  function t(key, vars) {
    let s = (L[lang] && L[lang][key]) || (L.zh && L.zh[key]) || key;
    if (vars) {
      for (const k in vars) s = s.replace(new RegExp("\\{" + k + "\\}", "g"), vars[k]);
    }
    return s;
  }
  function currentLang() { return lang; }
  function langOptions() { return LANGS.slice(); }
  function currentLangLabel() {
    for (const l of LANGS) if (l.code === lang) return l.label;
    return lang;
  }

  // 全局暴露 (Node 单测: module.exports)
  if (typeof module !== "undefined" && module.exports) {
    module.exports = { L, LANGS };
  } else {
    window.I18N = { t, setLang, currentLang, detect, langOptions, currentLangLabel };
  }
})();
