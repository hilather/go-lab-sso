package oidc

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hilather/go-lab-sso/internal/model"
	"github.com/hilather/go-lab-sso/internal/snapshot"
)

const CookieLogin = "labsso_login"

type Provider struct {
	store *snapshot.Store
	rt    *Runtime
	limit *limiter
}

func New(store *snapshot.Store) *Provider {
	return &Provider{store: store, rt: NewRuntime(), limit: newLimiter(60, time.Minute)}
}

func (p *Provider) Runtime() *Runtime { return p.rt }

func (p *Provider) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /oauth2/authorize", p.authorize)
	mux.HandleFunc("POST /oauth2/token", p.token)
	mux.HandleFunc("GET /oauth2/jwks", p.jwks)
	mux.HandleFunc("GET /oauth2/userinfo", p.userinfo)
	mux.HandleFunc("GET /oauth2/logout", p.logout)
	return mux
}

func (p *Provider) snapOIDC(w http.ResponseWriter) *snapshot.Snapshot {
	snap := p.store.Load()
	if snap == nil {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return nil
	}
	if snap.Canonical != nil && !snap.Canonical.Spec.Protocols.OIDC.IsEnabled(true) {
		http.Error(w, "not found", http.StatusNotFound)
		return nil
	}
	return snap
}

func (p *Provider) discovery(w http.ResponseWriter, r *http.Request) {
	snap := p.snapOIDC(w)
	if snap == nil {
		return
	}
	iss := strings.TrimRight(snap.Issuer, "/")
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                iss,
		"authorization_endpoint":                iss + "/oauth2/authorize",
		"token_endpoint":                        iss + "/oauth2/token",
		"jwks_uri":                              iss + "/oauth2/jwks",
		"userinfo_endpoint":                     iss + "/oauth2/userinfo",
		"end_session_endpoint":                  iss + "/oauth2/logout",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "groups", "offline_access"},
		"subject_types_supported":               []string{"public"},
	})
}

func (p *Provider) jwks(w http.ResponseWriter, r *http.Request) {
	snap := p.snapOIDC(w)
	if snap == nil {
		return
	}
	sig, err := newSigner(snap.SigningKey)
	if err != nil {
		http.Error(w, "signing key", http.StatusInternalServerError)
		return
	}
	set := sig.publicJWKS()
	for _, k := range set.Keys {
		if !k.IsPublic() {
			http.Error(w, "jwks leaked private key", http.StatusInternalServerError)
			return
		}
	}
	writeJSON(w, http.StatusOK, set)
}

func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	snap := p.snapOIDC(w)
	if snap == nil {
		return
	}
	if !p.limit.allow(clientIP(r)) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirect := q.Get("redirect_uri")
	if clientID == "" || redirect == "" {
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}
	cl, ok := snap.ClientsByClientID[clientID]
	if !ok {
		http.Error(w, "invalid_client", http.StatusBadRequest)
		return
	}
	if !exactRedirect(cl.RedirectURIs, redirect) {
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}
	if inj := p.rt.TakeInject(); inj != "" {
		oauthErrorRedirect(w, r, redirect, q.Get("state"), inj, "injected")
		return
	}
	method := q.Get("code_challenge_method")
	challenge := q.Get("code_challenge")
	if method == "plain" || method != "S256" || challenge == "" {
		desc := "PKCE S256 required"
		if method == "plain" {
			desc = "PKCE plain is rejected"
		}
		oauthErrorRedirect(w, r, redirect, q.Get("state"), "invalid_request", desc)
		return
	}
	if q.Get("response_type") != "code" {
		oauthErrorRedirect(w, r, redirect, q.Get("state"), "unsupported_response_type", "only code")
		return
	}
	mfa := ""
	if snap.Canonical != nil {
		mfa = snap.Canonical.Spec.Auth.MFA.Mode
	}
	if p.rt.ForceFail() || mfa == "force-fail" {
		oauthErrorRedirect(w, r, redirect, q.Get("state"), "access_denied", "force-fail")
		return
	}
	iss := strings.TrimRight(snap.Issuer, "/")
	if sid, err := r.Cookie(CookieLogin); err == nil && sid.Value != "" {
		if sess, ok := p.rt.GetSession(sid.Value); ok {
			if cl.PreConsent {
				code := randomID()
				p.rt.PutCode(AuthCode{
					Code: code, ClientID: clientID, RedirectURI: redirect,
					UserID: sess.UserID, Username: sess.Username, Scope: q.Get("scope"),
					Nonce: q.Get("nonce"), Challenge: challenge, Expires: time.Now().Add(5 * time.Minute),
				})
				u, err := url.Parse(redirect)
				if err != nil {
					http.Error(w, "invalid_request", http.StatusBadRequest)
					return
				}
				qq := u.Query()
				qq.Set("code", code)
				if st := q.Get("state"); st != "" {
					qq.Set("state", st)
				}
				u.RawQuery = qq.Encode()
				http.Redirect(w, r, u.String(), http.StatusFound)
				return
			}
			pend := p.rt.PutPending(Pending{
				ClientID: clientID, RedirectURI: redirect, Scope: q.Get("scope"),
				State: q.Get("state"), Nonce: q.Get("nonce"), Challenge: challenge, Method: method,
			})
			http.Redirect(w, r, iss+"/consent?pending="+url.QueryEscape(pend.ID), http.StatusFound)
			return
		}
	}
	pend := p.rt.PutPending(Pending{
		ClientID: clientID, RedirectURI: redirect, Scope: q.Get("scope"),
		State: q.Get("state"), Nonce: q.Get("nonce"), Challenge: challenge, Method: method,
	})
	http.Redirect(w, r, iss+"/login?pending="+url.QueryEscape(pend.ID), http.StatusFound)
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	snap := p.snapOIDC(w)
	if snap == nil {
		return
	}
	if !p.limit.allow(clientIP(r)) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "temporarily_unavailable", "error_description": "rate limited"})
		return
	}
	if p.rt.Paused() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "temporarily_unavailable", "error_description": "token endpoint paused"})
		return
	}
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	if inj := p.rt.TakeInject(); inj != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": inj, "error_description": "injected"})
		return
	}
	grant := r.FormValue("grant_type")
	switch grant {
	case "authorization_code":
		p.tokenCode(w, r, snap)
	case "refresh_token":
		p.tokenRefresh(w, r, snap)
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
	}
}

func (p *Provider) tokenCode(w http.ResponseWriter, r *http.Request, snap *snapshot.Snapshot) {
	_, clientID, err := p.clientFromRequest(r, snap)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	code := r.FormValue("code")
	verifier := r.FormValue("code_verifier")
	redirect := r.FormValue("redirect_uri")
	c, ok := p.rt.TakeCode(code)
	if !ok || time.Now().After(c.Expires) || c.RedirectURI != redirect || c.ClientID != clientID {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	if !verifyPKCE(c.Challenge, "S256", verifier) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "PKCE verifier mismatch"})
		return
	}
	p.writeTokens(w, snap, c.ClientID, c.UserID, c.Username, c.Scope, c.Nonce)
}

func (p *Provider) tokenRefresh(w http.ResponseWriter, r *http.Request, snap *snapshot.Snapshot) {
	_, clientID, err := p.clientFromRequest(r, snap)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	tok := r.FormValue("refresh_token")
	ref, ok := p.rt.TakeRefresh(tok)
	if !ok || time.Now().After(ref.Expires) || ref.ClientID != clientID {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	p.writeTokens(w, snap, ref.ClientID, ref.UserID, ref.Username, ref.Scope, "")
}

func (p *Provider) clientFromRequest(r *http.Request, snap *snapshot.Snapshot) (model.Client, string, error) {
	id, secret, ok := r.BasicAuth()
	if !ok || id == "" {
		id = r.FormValue("client_id")
		secret = r.FormValue("client_secret")
	}
	if id == "" {
		return model.Client{}, "", fmt.Errorf("invalid_client")
	}
	cl, found := snap.ClientsByClientID[id]
	if !found {
		return model.Client{}, "", fmt.Errorf("invalid_client")
	}
	if cl.Public {
		if secret != "" {
			return model.Client{}, "", fmt.Errorf("invalid_client")
		}
		return cl, id, nil
	}
	want := snap.ClientSecrets[id]
	if len(want) == 0 || subtle.ConstantTimeCompare(want, []byte(secret)) != 1 {
		return model.Client{}, "", fmt.Errorf("invalid_client")
	}
	return cl, id, nil
}

func (p *Provider) writeTokens(w http.ResponseWriter, snap *snapshot.Snapshot, clientID, userID, username, scope, nonce string) {
	sig, err := newSigner(snap.SigningKey)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	extra := map[string]any{}
	if username != "" {
		extra["preferred_username"] = username
	}
	if user, ok := snap.UsersByID[userID]; ok {
		if hasScope(scope, "email") && user.Email != "" {
			extra["email"] = user.Email
		}
		if hasScope(scope, "groups") {
			extra["groups"] = groupNames(snap, user)
		}
	}
	idTok, err := sig.mint(snap.Issuer, userID, clientID, nonce, time.Hour, extra)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	access, err := sig.mint(snap.Issuer, userID, clientID, "", time.Hour, map[string]any{"token_use": "access", "scope": scope})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	ref := randomID()
	p.rt.PutRefresh(Refresh{Token: ref, ClientID: clientID, UserID: userID, Username: username, Scope: scope, Expires: time.Now().Add(24 * time.Hour)})
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  access,
		"id_token":      idTok,
		"refresh_token": ref,
		"token_type":    "Bearer",
		"expires_in":    3600,
	})
}

func (p *Provider) userinfo(w http.ResponseWriter, r *http.Request) {
	snap := p.snapOIDC(w)
	if snap == nil {
		return
	}
	raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if raw == "" {
		http.Error(w, "invalid_token", http.StatusUnauthorized)
		return
	}
	sig, err := newSigner(snap.SigningKey)
	if err != nil {
		http.Error(w, "server_error", http.StatusInternalServerError)
		return
	}
	c, extra, err := parseAndVerifyExtra(raw, sig.jwk, snap.Issuer, true)
	if err != nil {
		http.Error(w, "invalid_token", http.StatusUnauthorized)
		return
	}
	out := map[string]any{"sub": c.Subject, "iss": c.Issuer}
	scope, _ := extra["scope"].(string)
	if user, ok := snap.UsersByID[c.Subject]; ok {
		if username := user.Username; username != "" {
			out["preferred_username"] = username
		}
		if hasScope(scope, "email") && user.Email != "" {
			out["email"] = user.Email
		}
		if hasScope(scope, "groups") {
			out["groups"] = groupNames(snap, user)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (p *Provider) CompleteLogin(pendingID, userID, username string) (string, error) {
	if p.rt.ForceFail() {
		return "", fmt.Errorf("access_denied")
	}
	if snap := p.store.Load(); snap != nil && snap.Canonical != nil && snap.Canonical.Spec.Auth.MFA.Mode == "force-fail" {
		return "", fmt.Errorf("access_denied")
	}
	pend, ok := p.rt.TakePending(pendingID)
	if !ok {
		return "", fmt.Errorf("pending request not found")
	}
	code := randomID()
	p.rt.PutCode(AuthCode{
		Code: code, ClientID: pend.ClientID, RedirectURI: pend.RedirectURI,
		UserID: userID, Username: username, Scope: pend.Scope,
		Nonce: pend.Nonce, Challenge: pend.Challenge, Expires: time.Now().Add(5 * time.Minute),
	})
	u, err := url.Parse(pend.RedirectURI)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("code", code)
	if pend.State != "" {
		q.Set("state", pend.State)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (p *Provider) DenyConsent(pendingID string) (string, error) {
	pend, ok := p.rt.TakePending(pendingID)
	if !ok {
		return "", fmt.Errorf("pending request not found")
	}
	return oauthErrorLocation(pend.RedirectURI, pend.State, "access_denied", "user denied")
}

func (p *Provider) logout(w http.ResponseWriter, r *http.Request) {
	if p.snapOIDC(w) == nil {
		return
	}
	if c, err := r.Cookie(CookieLogin); err == nil && c.Value != "" {
		p.rt.ExpireSession(c.Value)
	}
	secure := r.TLS != nil
	http.SetCookie(w, &http.Cookie{
		Name: CookieLogin, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: secure,
	})
	post := r.URL.Query().Get("post_logout_redirect_uri")
	if post != "" {
		snap := p.store.Load()
		if snap == nil || !logoutRedirectOK(snap, post) {
			http.Error(w, "invalid_request", http.StatusBadRequest)
			return
		}
		u, err := url.Parse(post)
		if err != nil {
			http.Error(w, "invalid_request", http.StatusBadRequest)
			return
		}
		if st := r.URL.Query().Get("state"); st != "" {
			q := u.Query()
			q.Set("state", st)
			u.RawQuery = q.Encode()
		}
		http.Redirect(w, r, u.String(), http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("<!doctype html><html><body><p>Logged out</p></body></html>"))
}

func logoutRedirectOK(snap *snapshot.Snapshot, uri string) bool {
	for _, c := range snap.ClientsByID {
		if exactRedirect(c.RedirectURIs, uri) {
			return true
		}
	}
	return false
}

func groupNames(snap *snapshot.Snapshot, user model.User) []string {
	names := make([]string, 0, len(user.GroupIDs))
	for _, gid := range user.GroupIDs {
		if g, ok := snap.GroupsByID[gid]; ok && g.Name != "" {
			names = append(names, g.Name)
		} else {
			names = append(names, gid)
		}
	}
	return names
}

func exactRedirect(uris []string, got string) bool {
	for _, u := range uris {
		if u == got {
			return true
		}
	}
	return false
}

func oauthErrorLocation(redirect, state, code, desc string) (string, error) {
	if redirect == "" {
		return "", fmt.Errorf("%s", code)
	}
	u, err := url.Parse(redirect)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("error", code)
	if desc != "" {
		q.Set("error_description", desc)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func oauthErrorRedirect(w http.ResponseWriter, r *http.Request, redirect, state, code, desc string) {
	loc, err := oauthErrorLocation(redirect, state, code, desc)
	if err != nil {
		http.Error(w, code, http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, loc, http.StatusFound)
}

func hasScope(scope, want string) bool {
	for _, s := range strings.Fields(scope) {
		if s == want {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
