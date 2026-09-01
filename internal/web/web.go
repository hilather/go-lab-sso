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
<title>LabSSO</title>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<style>
body{font-family:system-ui,sans-serif;margin:1.5rem;max-width:960px}
nav a{margin-right:1rem}
pre{background:#f4f4f4;padding:1rem;overflow:auto}
.err{color:#a00}
</style>
</head>
<body>
<h1>LabSSO operator</h1>
<p id="who"></p>
<nav>
<a href="#status" data-view="status">Status</a>
<a href="#clients" data-view="clients">Clients</a>
<a href="#users" data-view="users">Users</a>
<a href="#groups" data-view="groups">Groups</a>
<a href="#sessions" data-view="sessions">Sessions</a>
<a href="#audit" data-view="audit">Audit</a>
<button type="button" id="login">Create session</button>
<button type="button" id="logout">Sign out</button>
</nav>
<p class="err" id="err"></p>
<div id="out">Loading…</div>
<script src="/app.js"></script>
</body>
</html>
`

// appJS is operator UI. Tokens stay in cookies + memory CSRF only.
const appJS = `
(function(){
  var csrf = "";
  var lastEnroll = "";
  function $(id){ return document.getElementById(id); }
  function show(err, data){
    $("err").textContent = err || "";
    $("out").textContent = data || "";
  }
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
  function refreshWho(){
    return api("GET","/v1/session").then(function(r){
      if (!r.ok) { $("who").textContent = "no session"; csrf = ""; return; }
      var s = JSON.parse(r.text);
      csrf = s.csrf || "";
      $("who").textContent = "actor " + (s.actorId||"") + " (" + (s.actorClass||"") + ")";
    });
  }
  function loadUsers(){
    Promise.all([api("GET","/v1/users"), api("GET","/v1/state"), api("GET","/v1/status")]).then(function(rs){
      for (var i = 0; i < rs.length; i++) {
        if (!rs[i].ok) { show(rs[i].status + " " + rs[i].text, ""); return; }
      }
      var users = JSON.parse(rs[0].text);
      var state = JSON.parse(rs[1].text);
      var status = JSON.parse(rs[2].text);
      var mode = (((state.canonical || {}).spec || {}).auth || {}).mfa || {};
      mode = mode.mode || "never";
      var rev = status.runtimeRevision || "";
      var items = users.items || [];
      var rows = "";
      for (var j = 0; j < items.length; j++) {
        var u = items[j];
        var totp = u.totp || {};
        rows += "<tr><td>" + esc(u.id) + "</td><td>" + esc(u.username) + "</td><td>" +
          (totp.configured ? "yes (" + esc(totp.source || "") + ")" : "no") +
          "</td><td><button type=\"button\" data-enroll=\"" + esc(u.id) + "\">Enroll / Rotate</button> " +
          "<button type=\"button\" data-clear=\"" + esc(u.id) + "\">Clear overlay</button></td></tr>";
      }
      $("err").textContent = "";
      $("out").innerHTML =
        "<h2>MFA</h2><p>mode: " + esc(mode) + "</p>" +
        "<form id=\"mfa-form\"><label>Set mode</label> " +
        "<select id=\"mfa-mode\"><option value=\"never\">never</option><option value=\"always\">always</option><option value=\"force-fail\">force-fail</option></select> " +
        "<input id=\"mfa-reason\" placeholder=\"reason\"/> " +
        "<button type=\"submit\">Save</button></form>" +
        "<p id=\"enroll-once\"></p>" +
        "<table><thead><tr><th>id</th><th>username</th><th>totp</th><th></th></tr></thead><tbody>" +
        rows + "</tbody></table>";
      var once = $("enroll-once");
      if (once && lastEnroll) once.textContent = lastEnroll;
      var sel = $("mfa-mode");
      if (sel) sel.value = mode;
      var form = $("mfa-form");
      if (form) form.onsubmit = function(ev){
        ev.preventDefault();
        api("POST","/v1/auth/mfa",{mode:$("mfa-mode").value, expectedRevision:rev, reason:$("mfa-reason").value || "spa mfa"}).then(function(r){
          if (!r.ok) { show(r.status + " " + r.text, ""); return; }
          loadUsers();
        });
      };
      $("out").onclick = function(ev){
        var enroll = ev.target.getAttribute && ev.target.getAttribute("data-enroll");
        var clear = ev.target.getAttribute && ev.target.getAttribute("data-clear");
        if (enroll) {
          api("POST","/v1/users/"+enroll+"/totp:enroll",{reason:"spa enroll"}).then(function(r){
            if (!r.ok) { show(r.status + " " + r.text, ""); return; }
            var out = JSON.parse(r.text);
            lastEnroll = "secret " + (out.secret||"") + " otpauth " + (out.otpauth||"");
            loadUsers();
          });
          return;
        }
        if (clear) {
          api("POST","/v1/users/"+clear+"/totp:clear",{reason:"spa clear"}).then(function(r){
            if (!r.ok) { show(r.status + " " + r.text, ""); return; }
            loadUsers();
          });
        }
      };
    });
  }
  function load(view){
    if (view === "users") { loadUsers(); return; }
    var path = ({status:"/v1/status", clients:"/v1/clients", groups:"/v1/groups", sessions:"/v1/sessions", audit:"/v1/audit"})[view] || "/v1/status";
    api("GET", path).then(function(r){
      if (!r.ok) { show(r.status + " " + r.text, ""); return; }
      show("", r.text);
    });
  }
  document.querySelector("nav").addEventListener("click", function(e){
    var a = e.target.closest("a[data-view]");
    if (!a) return;
    e.preventDefault();
    load(a.getAttribute("data-view"));
  });
  $("login").onclick = function(){
    api("POST","/v1/session", {}).then(function(r){
      if (!r.ok) { show("login failed "+r.text, ""); return; }
      var s = JSON.parse(r.text);
      csrf = s.csrf || "";
      refreshWho().then(function(){ load("status"); });
    });
  };
  $("logout").onclick = function(){
    api("DELETE","/v1/session").then(function(){ csrf = ""; refreshWho(); show("", "signed out"); });
  };
  refreshWho().then(function(){ load("status"); });
})();
`

var _ = cookieHint
