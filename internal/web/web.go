// Package web is the operator SPA. It must not import internal/app.
package web

import (
	"net/http"
)

const cookieHint = "labsso_session"

func Handler(uiEnabled func() bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if uiEnabled != nil && !uiEnabled() {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(indexHTML))
	})
}

func Script() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(appJS))
	})
}

const indexHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>LabSSO operator</title>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&amp;family=IBM+Plex+Mono:wght@400;500&amp;display=swap"/>
<style>
:root {
  --bg: #0b0c0e;
  --elev: #121317;
  --panel: #181a1f;
  --fg: #ecece8;
  --muted: #9a9b97;
  --subtle: #6d6e6a;
  --line: color-mix(in oklab, #ecece8 12%, transparent);
  --accent: #7c8cff;
  --danger: #c45c5c;
  --ok: #7c8cff;
  --mono: "IBM Plex Mono", ui-monospace, monospace;
  --sans: "IBM Plex Sans", system-ui, sans-serif;
}
*{box-sizing:border-box}
html,body{height:100%;margin:0;background:var(--bg);color:var(--fg);font-family:var(--sans)}
#shell{display:grid;grid-template-rows:56px 1fr;height:100%}
.mast{display:flex;align-items:center;gap:12px;padding:0 16px;background:var(--elev);border-bottom:1px solid var(--line)}
.mark{display:flex;align-items:center;gap:8px;font-weight:600}
.dot{width:8px;height:8px;border-radius:50%;background:var(--accent)}
.issuer{font-family:var(--mono);font-size:12px;color:var(--muted);padding:4px 8px;border:1px solid var(--line);border-radius:999px}
.mast .grow{flex:1}
.chip{font-size:12px;padding:3px 8px;border-radius:999px;background:color-mix(in oklab, var(--accent) 18%, transparent);color:var(--accent)}
.chip.off{background:var(--panel);color:var(--muted)}
.actor{font-size:13px;color:var(--muted)}
button{font-family:var(--sans);cursor:pointer}
.ghost{background:transparent;color:var(--fg);border:1px solid var(--line);border-radius:8px;padding:6px 10px}
.danger{background:transparent;color:var(--danger);border:1px solid color-mix(in oklab, var(--danger) 35%, transparent);border-radius:8px;padding:6px 10px}
.primary{background:var(--accent);color:#0b0c0e;border:0;border-radius:8px;padding:6px 12px;font-weight:500}
.body{display:grid;grid-template-columns:196px 1fr;min-height:0}
nav{background:var(--elev);border-right:1px solid var(--line);padding:16px 10px;overflow:auto}
.sec{font-size:11px;letter-spacing:.08em;color:var(--subtle);margin:12px 8px 6px}
nav a{display:flex;align-items:center;justify-content:space-between;color:var(--fg);text-decoration:none;padding:8px 10px;border-radius:8px}
nav a:hover{background:var(--panel)}
nav a.active{background:color-mix(in oklab, var(--accent) 14%, var(--panel));box-shadow:inset 2px 0 0 var(--accent)}
.badge{min-width:18px;height:18px;border-radius:999px;background:var(--accent);color:#0b0c0e;font-size:11px;display:inline-flex;align-items:center;justify-content:center;padding:0 5px}
#workspace{min-width:0;overflow:auto;padding:0}
.err{color:var(--danger);margin:0;padding:0 16px;min-height:0;font-size:13px}
.workspace{display:grid;grid-template-columns:340px 1fr;min-height:100%}
.workspace.users{grid-template-columns:280px 1fr}
.list,.insp{min-width:0}
.list{border-right:1px solid var(--line);background:var(--elev);display:flex;flex-direction:column}
.list h2,.insp-head h2{margin:0;font-size:13px;letter-spacing:.08em;font-weight:600}
.list-head,.insp-head{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:16px}
.filter{margin:0 16px 12px;padding:8px 10px;border-radius:8px;border:1px solid var(--line);background:var(--panel);color:var(--fg);font-family:var(--sans);width:calc(100% - 32px)}
.row{display:block;width:100%;text-align:left;background:transparent;border:0;border-top:1px solid var(--line);padding:12px 16px;color:var(--fg)}
.row:hover{background:var(--panel)}
.row.sel{background:color-mix(in oklab, var(--accent) 16%, var(--elev))}
.row .k{font-weight:500}
.row .t{float:right;color:var(--muted);font-family:var(--mono);font-size:12px}
.row .s{display:block;color:var(--muted);font-size:12px;margin-top:4px}
.note{padding:16px;color:var(--subtle);font-size:12px;font-family:var(--mono)}
.insp{padding:20px 24px}
.insp-head{padding:0 0 16px}
.insp h1{margin:0;font-size:28px}
.sub{color:var(--muted);font-family:var(--mono);font-size:12px;margin-top:4px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px;margin:14px 0}
.panel h3{margin:0 0 10px;font-size:12px;letter-spacing:.08em;color:var(--muted)}
.kv{display:grid;grid-template-columns:140px 1fr;gap:8px 12px;font-size:13px}
.kv dt{color:var(--muted)}
.kv dd{margin:0;font-family:var(--mono);word-break:break-all}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;background:color-mix(in oklab, var(--accent) 18%, transparent);color:var(--accent);font-size:12px}
.overlay{background:color-mix(in oklab, var(--accent) 10%, var(--panel));border:1px solid color-mix(in oklab, var(--accent) 35%, var(--line))}
.overlay pre{margin:8px 0;white-space:pre-wrap;word-break:break-all;font-family:var(--mono);font-size:12px;color:var(--fg)}
.actions{display:flex;gap:8px;align-items:center}
label{display:block;font-size:11px;letter-spacing:.06em;color:var(--muted);margin-bottom:4px}
input,select{background:var(--bg);color:var(--fg);border:1px solid var(--line);border-radius:8px;padding:8px 10px;font-family:var(--sans)}
.mfa-row{display:flex;gap:8px;align-items:end;flex-wrap:wrap}
.leftover{padding:20px}
.leftover pre{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px;overflow:auto;font-family:var(--mono);font-size:12px}
</style>
</head>
<body>
<div id="shell">
  <header class="mast">
    <div class="mark"><span class="dot"></span>LabSSO</div>
    <div class="issuer" id="issuer"></div>
    <div class="grow"></div>
    <span class="chip off" id="ready">not ready</span>
    <span class="actor" id="who"></span>
    <span class="chip off" id="mfa-chip">mfa never</span>
    <button type="button" class="ghost" id="logout">Sign out</button>
  </header>
  <div class="body">
    <nav>
      <div class="sec">IDENTITY</div>
      <a href="#sessions" data-view="sessions">Sessions <span class="badge" id="sess-badge" hidden>0</span></a>
      <a href="#users" data-view="users">Users</a>
      <a href="#groups" data-view="groups">Groups</a>
      <a href="#clients" data-view="clients">Clients</a>
      <div class="sec">LAB</div>
      <a href="#status" data-view="status">Status</a>
      <a href="#audit" data-view="audit">Audit</a>
    </nav>
    <div>
      <p class="err" id="err"></p>
      <div id="workspace"><div id="out">Loading…</div></div>
    </div>
  </div>
</div>
<script src="/app.js"></script>
</body>
</html>
`

// appJS is operator UI. Tokens stay in cookies + memory CSRF only.
const appJS = `
(function(){
  var csrf = "";
  var lastEnroll = null;
  var mintedOnce = false;
  var issuer = "";
  var rev = "";
  var mfaMode = "never";
  var ready = false;
  var sessionItems = [];
  var selectedSession = "";
  var sessionFilter = "";
  var userItems = [];
  var selectedUser = "";
  var userFilter = "";
  function $(id){ return document.getElementById(id); }
  function showErr(err){ $("err").textContent = err || ""; }
  function esc(s){
    return String(s == null ? "" : s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/\"/g,"&quot;");
  }
  function api(method, path, body){
    var h = {"Accept":"application/json"};
    if (method !== "GET" && csrf) h["X-LabSSO-CSRF"] = csrf;
    if (body) h["Content-Type"] = "application/json";
    return fetch(path, {method:method, headers:h, credentials:"same-origin", body: body ? JSON.stringify(body) : undefined})
      .then(function(r){ return r.text().then(function(t){ return {ok:r.ok, status:r.status, text:t}; }); });
  }
  function paintChrome(){
    $("issuer").textContent = issuer || "";
    var readyEl = $("ready");
    readyEl.textContent = ready ? "ready" : "not ready";
    readyEl.className = ready ? "chip" : "chip off";
    $("who").textContent = (($("who").dataset.actorId)||"") + " · " + (($("who").dataset.actorClass)||"");
    $("mfa-chip").textContent = "mfa " + mfaMode;
    $("mfa-chip").className = mfaMode === "never" ? "chip off" : "chip";
    var badge = $("sess-badge");
    if (sessionItems.length) { badge.hidden = false; badge.textContent = String(sessionItems.length); }
    else { badge.hidden = true; }
    var links = document.querySelectorAll("nav a[data-view]");
    for (var i = 0; i < links.length; i++) {
      links[i].className = links[i].getAttribute("data-view") === currentView ? "active" : "";
    }
  }
  function refreshWho(){
    return api("GET","/v1/session").then(function(r){
      if (!r.ok) {
        $("who").dataset.actorId = "";
        $("who").dataset.actorClass = "";
        csrf = "";
        return r;
      }
      var s = JSON.parse(r.text);
      csrf = s.csrf || "";
      $("who").dataset.actorId = s.actorId || "";
      $("who").dataset.actorClass = s.actorClass || "";
      return r;
    });
  }
  function mintOnce(){
    if (mintedOnce || csrf) return Promise.resolve();
    mintedOnce = true;
    return api("POST","/v1/session", {}).then(function(r){
      if (!r.ok) return;
      var s = JSON.parse(r.text);
      csrf = s.csrf || "";
      $("who").dataset.actorId = s.actorId || "";
      $("who").dataset.actorClass = s.actorClass || "";
    });
  }
  function refreshMeta(){
    return Promise.all([api("GET","/v1/status"), api("GET","/v1/state"), api("GET","/v1/health/ready")]).then(function(rs){
      if (rs[0].ok) {
        var st = JSON.parse(rs[0].text);
        issuer = st.issuer || "";
        rev = st.runtimeRevision || "";
      }
      if (rs[1].ok) {
        var state = JSON.parse(rs[1].text);
        var mode = (((state.canonical || {}).spec || {}).auth || {}).mfa || {};
        mfaMode = mode.mode || "never";
      }
      ready = false;
      if (rs[2].ok) {
        try { ready = (JSON.parse(rs[2].text).status === "ready"); } catch (e) { ready = false; }
      }
      paintChrome();
    });
  }
  function fmtExpires(s){
    if (!s) return "";
    var d = new Date(s);
    if (isNaN(d.getTime())) return String(s);
    var hh = ("0"+d.getUTCHours()).slice(-2);
    var mm = ("0"+d.getUTCMinutes()).slice(-2);
    return hh + ":" + mm + "Z";
  }
  function matchSession(it, q){
    if (!q) return true;
    q = q.toLowerCase();
    return String(it.Username||"").toLowerCase().indexOf(q) >= 0 ||
      String(it.ID||"").toLowerCase().indexOf(q) >= 0 ||
      String(it.UserID||"").toLowerCase().indexOf(q) >= 0;
  }
  function matchUser(it, q){
    if (!q) return true;
    q = q.toLowerCase();
    return String(it.username||"").toLowerCase().indexOf(q) >= 0 ||
      String(it.id||"").toLowerCase().indexOf(q) >= 0;
  }
  function renderSessions(){
    var keep = document.activeElement && document.activeElement.id === "sess-filter";
    var pos = keep && typeof document.activeElement.selectionStart === "number" ? document.activeElement.selectionStart : sessionFilter.length;
    var rows = "";
    var shown = [];
    for (var i = 0; i < sessionItems.length; i++) {
      var it = sessionItems[i];
      if (!matchSession(it, sessionFilter)) continue;
      shown.push(it);
      var sel = it.ID === selectedSession ? " sel" : "";
      var mfa = it.MFACompleted ? "MFACompleted" : "MFA incomplete";
      rows += "<button type=\"button\" class=\"row" + sel + "\" data-sid=\"" + esc(it.ID) + "\"><span class=\"k\">" +
        esc(it.Username) + "</span><span class=\"t\">" + esc(fmtExpires(it.Expires)) + "</span><span class=\"s\">userId " +
        esc(it.UserID) + " · " + mfa + "</span></button>";
    }
    if (!selectedSession && shown.length) selectedSession = shown[0].ID;
    var cur = null;
    for (var j = 0; j < sessionItems.length; j++) {
      if (sessionItems[j].ID === selectedSession) { cur = sessionItems[j]; break; }
    }
    var insp = "<div class=\"insp\"><p class=\"note\">Select a login session.</p></div>";
    if (cur) {
      insp = "<div class=\"insp\"><div class=\"insp-head\"><div><h1>" + esc(cur.Username) + "</h1><div class=\"sub\">" +
        esc(cur.ID) + "</div></div><button type=\"button\" class=\"danger\" data-expire=\"" + esc(cur.ID) +
        "\">Expire session</button></div><div class=\"panel\"><h3>LOGINSESSION</h3><dl class=\"kv\">" +
        "<dt>Username</dt><dd>" + esc(cur.Username) + "</dd>" +
        "<dt>UserID</dt><dd>" + esc(cur.UserID) + "</dd>" +
        "<dt>ID</dt><dd>" + esc(cur.ID) + "</dd>" +
        "<dt>Expires</dt><dd>" + esc(cur.Expires) + "</dd>" +
        "<dt>MFACompleted</dt><dd><span class=\"pill\">" + (cur.MFACompleted ? "true" : "false") + "</span></dd>" +
        "</dl><p class=\"note\">LoginSession only. Data-plane cookie is not labsso_session.</p></div></div>";
    }
    $("out").innerHTML =
      "<div class=\"workspace\"><div class=\"list\"><div class=\"list-head\"><h2>LOGIN SESSIONS</h2>" +
      "<button type=\"button\" class=\"danger\" id=\"expire-all\">Expire all</button></div>" +
      "<input class=\"filter\" id=\"sess-filter\" placeholder=\"Filter Username or ID\" value=\"" + esc(sessionFilter) + "\"/>" +
      rows + "<p class=\"note\">GET /v1/sessions items[] · LoginSession fields only.</p></div>" + insp + "</div>";
    var f = $("sess-filter");
    if (f) {
      f.oninput = function(){ sessionFilter = f.value; renderSessions(); };
      if (keep) { f.focus(); try { f.setSelectionRange(pos, pos); } catch (e) {} }
    }
  }
  function loadSessions(){
    return api("GET","/v1/sessions").then(function(r){
      if (!r.ok) { showErr(r.status + " " + r.text); return; }
      showErr("");
      var body = JSON.parse(r.text);
      sessionItems = body.items || [];
      paintChrome();
      renderSessions();
    });
  }
  function expireAll(){
    api("POST","/v1/sessions:expire-all", {}).then(function(r){
      if (!r.ok) { showErr(r.status + " " + r.text); return; }
      selectedSession = "";
      loadSessions();
    });
  }
  function expireOne(id){
    api("POST","/v1/sessions/"+encodeURIComponent(id)+":expire", {}).then(function(r){
      if (!r.ok) { showErr(r.status + " " + r.text); return; }
      if (selectedSession === id) selectedSession = "";
      loadSessions();
    });
  }
  function renderUsers(){
    var keepU = document.activeElement && document.activeElement.id === "user-filter";
    var posU = keepU && typeof document.activeElement.selectionStart === "number" ? document.activeElement.selectionStart : userFilter.length;
    var rows = "";
    var shown = [];
    for (var i = 0; i < userItems.length; i++) {
      var u = userItems[i];
      if (!matchUser(u, userFilter)) continue;
      shown.push(u);
      var totp = u.totp || {};
      var sel = u.id === selectedUser ? " sel" : "";
      rows += "<button type=\"button\" class=\"row" + sel + "\" data-uid=\"" + esc(u.id) + "\"><span class=\"k\">" +
        esc(u.username) + "</span><span class=\"s\">" + esc(u.id) + " · " + esc(totp.source || (totp.configured ? "totp" : "no totp")) +
        " <span class=\"pill\">" + esc(mfaMode) + "</span></span></button>";
    }
    if (!selectedUser && shown.length) selectedUser = shown[0].id;
    var cur = null;
    for (var j = 0; j < userItems.length; j++) {
      if (userItems[j].id === selectedUser) { cur = userItems[j]; break; }
    }
    var insp = "<div class=\"insp\"><p class=\"note\">Select a user.</p></div>";
    if (cur) {
      var totp2 = cur.totp || {};
      var overlay = "";
      if (lastEnroll && lastEnroll.userId === cur.id) {
        overlay = "<div class=\"panel overlay\"><h3>TOTP SEED Overlay (shown once)</h3>" +
          "<p class=\"note\">Held in page memory only. Not browser storage or the URL.</p>" +
          "<pre>secret " + esc(lastEnroll.secret) + "</pre><pre>" + esc(lastEnroll.otpauth) + "</pre>" +
          "<button type=\"button\" class=\"ghost\" id=\"dismiss-enroll\">Dismiss</button></div>";
      }
      insp = "<div class=\"insp\"><div class=\"insp-head\"><div><h1>" + esc(cur.username) + "</h1><div class=\"sub\">" +
        esc(cur.id) + "</div></div><div class=\"actions\">" +
        "<button type=\"button\" class=\"ghost\" data-enroll=\"" + esc(cur.id) + "\">Enroll / Rotate</button> " +
        "<button type=\"button\" class=\"danger\" data-clear=\"" + esc(cur.id) + "\">Clear overlay</button></div></div>" +
        overlay +
        "<div class=\"panel\"><h3>USERVIEW</h3><dl class=\"kv\">" +
        "<dt>id</dt><dd>" + esc(cur.id) + "</dd>" +
        "<dt>username</dt><dd>" + esc(cur.username) + "</dd>" +
        "<dt>totp.configured</dt><dd>" + (totp2.configured ? "true" : "false") + "</dd>" +
        "<dt>totp.source</dt><dd><span class=\"pill\">" + esc(totp2.source || "") + "</span></dd>" +
        "<dt>totpSecretRef</dt><dd>" + esc(cur.totpSecretRef || "") + "</dd>" +
        "<dt>passwordRef</dt><dd>" + esc(cur.passwordRef || "") + "</dd>" +
        "<dt>groupIds</dt><dd>" + esc(JSON.stringify(cur.groupIds || [])) + "</dd>" +
        "</dl><p class=\"note\">Do not copy totp into changes:apply. Seed is not totpSecretRef.</p></div>" +
        "<div class=\"panel\"><h3>SPEC.AUTH.MFA</h3><form id=\"mfa-form\" class=\"mfa-row\">" +
        "<div><label>mode</label><select id=\"mfa-mode\">" +
        "<option value=\"never\">never</option><option value=\"always\">always</option><option value=\"force-fail\">force-fail</option>" +
        "</select></div><div><label>reason</label><input id=\"mfa-reason\" placeholder=\"reason\" value=\"spa mfa\"/></div>" +
        "<button type=\"submit\" class=\"primary\">Save</button></form>" +
        "<p class=\"note\">POST /v1/auth/mfa needs expectedRevision from GET /v1/status.</p></div></div>";
    }
    $("out").innerHTML =
      "<div class=\"workspace users\"><div class=\"list\"><div class=\"list-head\"><h2>USERS</h2></div>" +
      "<input class=\"filter\" id=\"user-filter\" placeholder=\"Filter username or id\" value=\"" + esc(userFilter) + "\"/>" +
      rows + "</div>" + insp + "</div>";
    var uf = $("user-filter");
    if (uf) {
      uf.oninput = function(){ userFilter = uf.value; renderUsers(); };
      if (keepU) { uf.focus(); try { uf.setSelectionRange(posU, posU); } catch (e) {} }
    }
    var sel = $("mfa-mode");
    if (sel) sel.value = mfaMode;
    var form = $("mfa-form");
    if (form) form.onsubmit = function(ev){
      ev.preventDefault();
      api("POST","/v1/auth/mfa",{mode:$("mfa-mode").value, expectedRevision:rev, reason:$("mfa-reason").value || "spa mfa"}).then(function(r){
        if (!r.ok) { showErr(r.status + " " + r.text); return; }
        refreshMeta().then(loadUsers);
      });
    };
  }
  function loadUsers(){
    return refreshMeta().then(function(){ return api("GET","/v1/users"); }).then(function(r){
      if (!r.ok) { showErr(r.status + " " + r.text); return; }
      showErr("");
      var users = JSON.parse(r.text);
      userItems = users.items || [];
      renderUsers();
    });
  }
  function enrollUser(id){
    api("POST","/v1/users/"+encodeURIComponent(id)+"/totp:enroll",{reason:"spa enroll"}).then(function(r){
      if (!r.ok) { showErr(r.status + " " + r.text); return; }
      var out = JSON.parse(r.text);
      lastEnroll = {userId:id, secret: out.secret||"", otpauth: out.otpauth||""};
      selectedUser = id;
      loadUsers();
    });
  }
  function clearUser(id){
    api("POST","/v1/users/"+encodeURIComponent(id)+"/totp:clear",{reason:"spa clear"}).then(function(r){
      if (!r.ok) { showErr(r.status + " " + r.text); return; }
      if (lastEnroll && lastEnroll.userId === id) lastEnroll = null;
      loadUsers();
    });
  }
  var leftover = {status:"/v1/status", clients:"/v1/clients", groups:"/v1/groups", audit:"/v1/audit"};
  function loadLeftover(view){
    var path = leftover[view] || "/v1/status";
    api("GET", path).then(function(r){
      if (!r.ok) { showErr(r.status + " " + r.text); $("out").textContent = ""; return; }
      showErr("");
      $("out").innerHTML = "<div class=\"leftover\"><pre>" + esc(r.text) + "</pre></div>";
    });
  }
  var currentView = "sessions";
  function load(view){
    currentView = view || "sessions";
    paintChrome();
    if (currentView === "users") { loadUsers(); return; }
    if (currentView === "sessions") { loadSessions(); return; }
    loadLeftover(currentView);
  }
  document.querySelector("nav").addEventListener("click", function(e){
    var a = e.target.closest("a[data-view]");
    if (!a) return;
    e.preventDefault();
    var v = a.getAttribute("data-view");
    if (location.hash !== "#" + v) location.hash = v;
    else load(v);
  });
  $("workspace").onclick = function(ev){
    var t = ev.target;
    if (!t) return;
    if (t.id === "expire-all") { expireAll(); return; }
    if (t.id === "dismiss-enroll") { lastEnroll = null; renderUsers(); return; }
    var sid = t.getAttribute && t.getAttribute("data-sid");
    if (!sid && t.closest) {
      var row = t.closest("[data-sid]");
      if (row) sid = row.getAttribute("data-sid");
    }
    if (sid && !t.getAttribute("data-expire")) { selectedSession = sid; renderSessions(); return; }
    var exp = t.getAttribute && t.getAttribute("data-expire");
    if (exp) { expireOne(exp); return; }
    var uid = t.getAttribute && t.getAttribute("data-uid");
    if (!uid && t.closest) {
      var urow = t.closest("[data-uid]");
      if (urow) uid = urow.getAttribute("data-uid");
    }
    if (uid && !t.getAttribute("data-enroll") && !t.getAttribute("data-clear")) { selectedUser = uid; renderUsers(); return; }
    var enroll = t.getAttribute && t.getAttribute("data-enroll");
    if (enroll) { enrollUser(enroll); return; }
    var clear = t.getAttribute && t.getAttribute("data-clear");
    if (clear) { clearUser(clear); }
  };
  $("logout").onclick = function(){
    api("DELETE","/v1/session").then(function(){
      csrf = "";
      refreshWho().then(paintChrome);
      showErr("");
    });
  };
  window.addEventListener("hashchange", function(){
    var v = (location.hash || "#sessions").replace(/^#/, "") || "sessions";
    load(v);
  });
  refreshWho().then(function(){ return mintOnce(); }).then(function(){ return refreshWho(); }).then(function(){
    return refreshMeta();
  }).then(function(){
    var v = (location.hash || "#sessions").replace(/^#/, "") || "sessions";
    load(v);
  });
})();
`

var _ = cookieHint
