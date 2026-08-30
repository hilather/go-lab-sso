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
<pre id="out">Loading…</pre>
<script src="/app.js"></script>
</body>
</html>
`

// appJS is operator UI. Tokens stay in cookies + memory CSRF only.
const appJS = `
(function(){
  var csrf = "";
  function $(id){ return document.getElementById(id); }
  function show(err, data){
    $("err").textContent = err || "";
    $("out").textContent = data || "";
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
  function load(view){
    var path = ({status:"/v1/status", clients:"/v1/clients", users:"/v1/users", groups:"/v1/groups", sessions:"/v1/sessions", audit:"/v1/audit"})[view] || "/v1/status";
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
