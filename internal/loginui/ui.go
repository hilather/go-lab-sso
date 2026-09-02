package loginui

import (
	"fmt"
	"html"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/hilather/go-lab-sso/internal/model"
	"github.com/hilather/go-lab-sso/internal/oidc"
	"github.com/hilather/go-lab-sso/internal/saml"
	"github.com/hilather/go-lab-sso/internal/snapshot"
	"github.com/hilather/go-lab-sso/internal/totp"
	"github.com/hilather/go-lab-sso/internal/wsfed"
)

type UI struct {
	store   *snapshot.Store
	oidc    *oidc.Provider
	saml    *saml.Provider
	wsfed   *wsfed.Provider
	baseDir string
	limit   *limiter
}

func New(store *snapshot.Store, p *oidc.Provider, s *saml.Provider, w *wsfed.Provider, baseDir string) *UI {
	return &UI{store: store, oidc: p, saml: s, wsfed: w, baseDir: baseDir, limit: newLimiter(10, time.Minute)}
}

func (u *UI) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /login", u.getLogin)
	mux.HandleFunc("POST /login", u.postLogin)
	mux.HandleFunc("GET /consent", u.getConsent)
	mux.HandleFunc("POST /consent", u.postConsent)
}

func (u *UI) getLogin(w http.ResponseWriter, r *http.Request) {
	pending := r.URL.Query().Get("pending")
	writeHTML(w, loginPage(u.store.Load(), pending, "", false))
}

func (u *UI) postLogin(w http.ResponseWriter, r *http.Request) {
	if !u.limit.allow(clientIP(r)) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if u.oidc.Runtime().ForceFail() {
		writeHTML(w, loginPage(u.store.Load(), r.FormValue("pending"), "access denied", false))
		return
	}
	pending := r.FormValue("pending")
	user := r.FormValue("username")
	pass := r.FormValue("password")
	mfa := r.FormValue("mfa")
	snap := u.store.Load()
	if snap == nil {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	rec, ok := findUser(snap, user)
	if !ok {
		writeHTML(w, loginPage(snap, pending, "invalid credentials", false))
		return
	}
	if err := u.checkPassword(rec, []byte(pass)); err != nil {
		writeHTML(w, loginPage(snap, pending, "invalid credentials", false))
		return
	}
	mode := snap.Canonical.Spec.Auth.MFA.Mode
	if mode == "" {
		mode = "never"
	}
	if mode == "force-fail" {
		writeHTML(w, loginPage(snap, pending, "MFA failed", true))
		return
	}
	mfaOK := false
	if mode == "always" {
		if mfa == "" {
			writeHTML(w, loginPage(snap, pending, "", true))
			return
		}
		secret, ok := u.totpSecret(rec)
		if !ok || !u.oidc.Runtime().VerifyAndRecordTOTP(rec.ID, secret, mfa, time.Now()) {
			writeHTML(w, loginPage(snap, pending, "MFA failed", true))
			return
		}
		mfaOK = true
	}
	ttl := time.Hour
	if snap.Canonical.Spec.Auth.SessionTTL > 0 {
		ttl = snap.Canonical.Spec.Auth.SessionTTL.Duration()
	}
	sess := u.oidc.Runtime().PutSession(oidc.LoginSession{
		UserID: rec.ID, Username: rec.Username, Expires: time.Now().Add(ttl), MFACompleted: mfaOK,
	})
	secure := r.TLS != nil
	http.SetCookie(w, &http.Cookie{
		Name: oidc.CookieName(snap), Value: sess.ID, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Secure: secure,
	})
	cl := snap.ClientsByClientID[pendingClient(u, pending)]
	if cl.PreConsent && !u.oidc.Runtime().ForceConsent() {
		u.finish(w, r, pending, rec.ID, rec.Username, mfaOK)
		return
	}
	http.Redirect(w, r, "/consent?pending="+pending, http.StatusFound)
}

func (u *UI) getConsent(w http.ResponseWriter, r *http.Request) {
	writeHTML(w, consentPage(u.store.Load(), r.URL.Query().Get("pending")))
}

func (u *UI) postConsent(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	pending := r.FormValue("pending")
	if r.FormValue("approve") != "1" {
		u.deny(w, r, pending)
		return
	}
	c, err := r.Cookie(oidc.CookieName(u.store.Load()))
	if err != nil {
		http.Redirect(w, r, "/login?pending="+pending, http.StatusFound)
		return
	}
	sess, ok := u.oidc.Runtime().GetSession(c.Value)
	if !ok {
		http.Redirect(w, r, "/login?pending="+pending, http.StatusFound)
		return
	}
	mode := ""
	if snap := u.store.Load(); snap != nil && snap.Canonical != nil {
		mode = snap.Canonical.Spec.Auth.MFA.Mode
	}
	if !oidc.SessionUsable(sess, mode) {
		http.Redirect(w, r, "/login?pending="+pending, http.StatusFound)
		return
	}
	u.finish(w, r, pending, sess.UserID, sess.Username, sess.MFACompleted)
}

func (u *UI) finish(w http.ResponseWriter, r *http.Request, pending, userID, username string, mfa bool) {
	if pend, ok := u.oidc.Runtime().GetPending(pending); ok && pend.Protocol == wsfed.Protocol && u.wsfed != nil {
		body, err := u.wsfed.Complete(pending, userID, username, mfa)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeHTML(w, body)
		return
	}
	if pend, ok := u.oidc.Runtime().GetPending(pending); ok && pend.Protocol == oidc.ProtocolSAML && u.saml != nil {
		body, err := u.saml.Complete(pending, userID, username, mfa)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeHTML(w, body)
		return
	}
	loc, err := u.oidc.CompleteLogin(pending, userID, username, mfa)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, loc, http.StatusFound)
}

func (u *UI) deny(w http.ResponseWriter, r *http.Request, pending string) {
	if pend, ok := u.oidc.Runtime().GetPending(pending); ok && pend.Protocol == wsfed.Protocol && u.wsfed != nil {
		body, err := u.wsfed.Deny(pending)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeHTML(w, body)
		return
	}
	if pend, ok := u.oidc.Runtime().GetPending(pending); ok && pend.Protocol == oidc.ProtocolSAML && u.saml != nil {
		body, err := u.saml.Deny(pending)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeHTML(w, body)
		return
	}
	loc, err := u.oidc.DenyConsent(pending)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, loc, http.StatusFound)
}

func (u *UI) checkPassword(user model.User, provided []byte) error {
	ref := user.PasswordHashRef
	if ref == "" {
		ref = user.PasswordRef
	}
	if ref == "" {
		return fmt.Errorf("no password ref")
	}
	p := ref
	if !filepath.IsAbs(p) && u.baseDir != "" {
		p = filepath.Join(u.baseDir, p)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	return verifyPassword(b, provided)
}

func (u *UI) totpSecret(user model.User) ([]byte, bool) {
	if sec, ok := u.oidc.Runtime().GetTOTPOverlay(user.ID); ok {
		return sec, true
	}
	ref := user.TOTPSecretRef
	if ref == "" {
		return nil, false
	}
	p := ref
	if !filepath.IsAbs(p) && u.baseDir != "" {
		p = filepath.Join(u.baseDir, p)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, false
	}
	sec, err := totp.ParseSecret(b)
	if err != nil {
		return nil, false
	}
	return sec, true
}

func pendingClient(u *UI, pendingID string) string {
	p, ok := u.oidc.Runtime().GetPending(pendingID)
	if !ok {
		return ""
	}
	return p.ClientID
}

func findUser(snap *snapshot.Snapshot, username string) (model.User, bool) {
	if snap == nil || snap.Canonical == nil {
		return model.User{}, false
	}
	for _, u := range snap.Canonical.Spec.Users {
		if u.Username == username && model.BoolVal(u.Enabled, true) {
			return u, true
		}
	}
	return model.User{}, false
}

func familyHead(title string) string {
	return `<!doctype html><html lang="en"><head><meta charset="utf-8"/><title>` + html.EscapeString(title) + `</title>
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
body{display:flex;align-items:center;justify-content:center}
.card{width:380px;background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:22px 22px 18px}
.brand{display:flex;align-items:center;gap:8px;font-weight:600}
.dot{width:8px;height:8px;border-radius:50%;background:var(--accent)}
.sub{color:var(--muted);font-size:13px;margin:6px 0 14px;font-family:var(--mono)}
.step{color:var(--accent);font-size:13px;border-top:2px solid var(--accent);padding-top:10px;margin:0 0 16px}
h1{margin:0 0 16px;font-size:28px}
label{display:block;font-size:11px;letter-spacing:.08em;color:var(--muted);margin:12px 0 4px}
input{width:100%;background:var(--bg);color:var(--fg);border:1px solid var(--line);border-radius:8px;padding:10px;font-family:var(--mono)}
button{font-family:var(--sans);cursor:pointer}
.continue{width:100%;margin-top:18px;background:var(--fg);color:#0b0c0e;border:0;border-radius:10px;padding:12px;font-weight:600}
.row{display:flex;gap:10px;margin-top:16px}
.row button{flex:1;border-radius:10px;padding:12px;border:1px solid var(--line);background:var(--elev);color:var(--fg)}
.row button[value="1"]{background:var(--fg);color:#0b0c0e;border:0;font-weight:600}
.err{color:var(--danger);font-size:13px}
.foot{margin-top:16px;color:var(--subtle);font-size:11px;font-family:var(--mono)}
</style></head>`
}

func loginClothes(snap *snapshot.Snapshot) (title, heading, issuer, vendor, mode string) {
	title, heading, issuer, vendor, mode = "LabSSO login", "Sign in", "", "generic", "never"
	if snap == nil {
		return title, heading, issuer, vendor, mode
	}
	issuer = snap.Issuer
	if snap.Clothes.HTMLTitle != "" {
		title = snap.Clothes.HTMLTitle
	}
	if snap.Clothes.HTMLHeading != "" {
		heading = snap.Clothes.HTMLHeading
	}
	if snap.Clothes.Vendor != "" {
		vendor = snap.Clothes.Vendor
	}
	if snap.Canonical != nil && snap.Canonical.Spec.Auth.MFA.Mode != "" {
		mode = snap.Canonical.Spec.Auth.MFA.Mode
	}
	return title, heading, issuer, vendor, mode
}

func loginPage(snap *snapshot.Snapshot, pending, errMsg string, mfa bool) string {
	title, heading, issuer, vendor, mode := loginClothes(snap)
	extra := ""
	if mfa {
		extra = `<label>TOTP</label><input name="mfa" autocomplete="one-time-code" placeholder="6-digit code"/>`
	}
	msg := ""
	if errMsg != "" {
		msg = `<p class="err">` + html.EscapeString(errMsg) + `</p>`
	}
	step := ""
	if mfa || mode == "always" || mode == "force-fail" {
		step = `<p class="step">TOTP · spec.auth.mfa.mode ` + html.EscapeString(mode) + `</p>`
	}
	foot := `Data-plane login. Not the operator SPA. Cookie is the clothes name, not labsso_session.`
	if mfa {
		foot = `Data-plane login. Password already accepted; TOTP is required because mode is ` + html.EscapeString(mode) + `.`
	}
	return familyHead(title) + `<body><div class="card">
<div class="brand"><span class="dot"></span>LabSSO</div>
<div class="sub">` + html.EscapeString(issuer) + ` · ` + html.EscapeString(vendor) + `</div>
` + step + `
<h1>` + html.EscapeString(heading) + `</h1>` + msg + `
<form method="post" action="/login">
<input type="hidden" name="pending" value="` + html.EscapeString(pending) + `"/>
<label>Username</label><input name="username" autocomplete="username"/>
<label>Password</label><input name="password" type="password" autocomplete="current-password"/>
` + extra + `
<button class="continue" type="submit">Continue</button>
</form>
<p class="foot">` + foot + `</p>
</div></body></html>`
}

func consentPage(snap *snapshot.Snapshot, pending string) string {
	title := "LabSSO consent"
	issuer, vendor := "", "generic"
	if snap != nil {
		issuer = snap.Issuer
		if snap.Clothes.ConsentTitle != "" {
			title = snap.Clothes.ConsentTitle
		}
		if snap.Clothes.Vendor != "" {
			vendor = snap.Clothes.Vendor
		}
	}
	return familyHead(title) + `<body><div class="card">
<div class="brand"><span class="dot"></span>LabSSO</div>
<div class="sub">` + html.EscapeString(issuer) + ` · ` + html.EscapeString(vendor) + `</div>
<h1>Consent</h1>
<form method="post" action="/consent">
<input type="hidden" name="pending" value="` + html.EscapeString(pending) + `"/>
<div class="row">
<button type="submit" name="approve" value="1">Allow</button>
<button type="submit" name="approve" value="0">Deny</button>
</div>
</form>
<p class="foot">Data-plane consent. Not the operator SPA.</p>
</div></body></html>`
}

func writeHTML(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(body))
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

type limiter struct {
	mu     sync.Mutex
	n      int
	window time.Duration
	hits   map[string][]time.Time
}

func newLimiter(n int, window time.Duration) *limiter {
	return &limiter{n: n, window: window, hits: map[string][]time.Time{}}
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	cut := now.Add(-l.window)
	cur := l.hits[key]
	kept := cur[:0]
	for _, t := range cur {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.n {
		l.hits[key] = kept
		return false
	}
	l.hits[key] = append(kept, now)
	return true
}
