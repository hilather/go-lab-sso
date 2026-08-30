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
	"github.com/hilather/go-lab-sso/internal/snapshot"
)

const totpStub = "lab-totp"

type UI struct {
	store   *snapshot.Store
	oidc    *oidc.Provider
	baseDir string
	limit   *limiter
}

func New(store *snapshot.Store, p *oidc.Provider, baseDir string) *UI {
	return &UI{store: store, oidc: p, baseDir: baseDir, limit: newLimiter(10, time.Minute)}
}

func (u *UI) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /login", u.getLogin)
	mux.HandleFunc("POST /login", u.postLogin)
	mux.HandleFunc("GET /consent", u.getConsent)
	mux.HandleFunc("POST /consent", u.postConsent)
}

func (u *UI) getLogin(w http.ResponseWriter, r *http.Request) {
	pending := r.URL.Query().Get("pending")
	writeHTML(w, loginPage(pending, "", false))
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
		writeHTML(w, loginPage(r.FormValue("pending"), "access denied", false))
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
		writeHTML(w, loginPage(pending, "invalid credentials", false))
		return
	}
	if err := u.checkPassword(rec, []byte(pass)); err != nil {
		writeHTML(w, loginPage(pending, "invalid credentials", false))
		return
	}
	mode := snap.Canonical.Spec.Auth.MFA.Mode
	if mode == "" {
		mode = "never"
	}
	if mode == "force-fail" {
		writeHTML(w, loginPage(pending, "MFA failed", true))
		return
	}
	if mode == "always" && mfa != totpStub {
		writeHTML(w, loginPage(pending, "", true))
		return
	}
	ttl := time.Hour
	if snap.Canonical.Spec.Auth.SessionTTL > 0 {
		ttl = snap.Canonical.Spec.Auth.SessionTTL.Duration()
	}
	sess := u.oidc.Runtime().PutSession(oidc.LoginSession{
		UserID: rec.ID, Username: rec.Username, Expires: time.Now().Add(ttl),
	})
	secure := r.TLS != nil
	http.SetCookie(w, &http.Cookie{
		Name: oidc.CookieLogin, Value: sess.ID, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Secure: secure,
	})
	cl, _ := snap.ClientsByClientID[pendingClient(u, pending)]
	if cl.PreConsent {
		loc, err := u.oidc.CompleteLogin(pending, rec.ID, rec.Username)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, loc, http.StatusFound)
		return
	}
	http.Redirect(w, r, "/consent?pending="+pending, http.StatusFound)
}

func (u *UI) getConsent(w http.ResponseWriter, r *http.Request) {
	writeHTML(w, consentPage(r.URL.Query().Get("pending")))
}

func (u *UI) postConsent(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	pending := r.FormValue("pending")
	if r.FormValue("approve") != "1" {
		loc, err := u.oidc.DenyConsent(pending)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, loc, http.StatusFound)
		return
	}
	c, err := r.Cookie(oidc.CookieLogin)
	if err != nil {
		http.Redirect(w, r, "/login?pending="+pending, http.StatusFound)
		return
	}
	sess, ok := u.oidc.Runtime().GetSession(c.Value)
	if !ok {
		http.Redirect(w, r, "/login?pending="+pending, http.StatusFound)
		return
	}
	loc, err := u.oidc.CompleteLogin(pending, sess.UserID, sess.Username)
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

func loginPage(pending, errMsg string, mfa bool) string {
	extra := ""
	if mfa {
		extra = `<label>TOTP (lab stub: lab-totp)</label><input name="mfa" autocomplete="one-time-code"/>`
	}
	msg := ""
	if errMsg != "" {
		msg = `<p class="err">` + html.EscapeString(errMsg) + `</p>`
	}
	return `<!doctype html><html><head><title>LabSSO login</title></head><body>
<h1>Sign in</h1>` + msg + `
<form method="post" action="/login">
<input type="hidden" name="pending" value="` + html.EscapeString(pending) + `"/>
<label>Username</label><input name="username" autocomplete="username"/>
<label>Password</label><input name="password" type="password" autocomplete="current-password"/>
` + extra + `
<button type="submit">Continue</button>
</form></body></html>`
}

func consentPage(pending string) string {
	return `<!doctype html><html><head><title>LabSSO consent</title></head><body>
<h1>Consent</h1>
<form method="post" action="/consent">
<input type="hidden" name="pending" value="` + html.EscapeString(pending) + `"/>
<button type="submit" name="approve" value="1">Allow</button>
<button type="submit" name="approve" value="0">Deny</button>
</form></body></html>`
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
