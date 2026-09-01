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
	"github.com/hilather/go-lab-sso/internal/totp"
	"github.com/hilather/go-lab-sso/internal/vendor"
)

const CookieLogin = "labsso_login"

type Provider struct {
	store *snapshot.Store
	rt    *Runtime
	limit *limiter
	warn  func(string)
}

func New(store *snapshot.Store) *Provider {
	return &Provider{store: store, rt: NewRuntime(), limit: newLimiter(60, time.Minute)}
}

func (p *Provider) Runtime() *Runtime { return p.rt }

func (p *Provider) SetWarn(fn func(string)) { p.warn = fn }

func (p *Provider) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /{a}/{b}/.well-known/openid-configuration", p.twoSegmentDiscovery)
	mux.HandleFunc("GET /affwebservices/CASSO/oidc/{name}/.well-known/openid-configuration", p.siteminderDiscovery)
	for _, path := range []string{
		"/oauth2/authorize", "/oauth2/v2.0/authorize", "/oauth2/default/v1/authorize",
		"/as/authorization.oauth2", "/adfs/oauth2/authorize", "/o/oauth2/v2/auth",
		"/realms/{realm}/protocol/openid-connect/auth", "/authorize",
		"/oidc/{name}/authorize", "/affwebservices/CASSO/oidc/{name}/authorize",
		"/idp/profile/oidc/authorize",
	} {
		mux.HandleFunc("GET "+path, p.requirePath(func(c snapshot.Clothes) string { return c.AuthorizePath }, p.authorize))
	}
	for _, path := range []string{
		"/oauth2/token", "/oauth2/v2.0/token", "/oauth2/default/v1/token",
		"/as/token.oauth2", "/adfs/oauth2/token", "/token",
		"/realms/{realm}/protocol/openid-connect/token",
		"/oidc/{name}/token", "/affwebservices/CASSO/oidc/{name}/token",
		"/idp/profile/oidc/token",
	} {
		mux.HandleFunc("POST "+path, p.requirePath(func(c snapshot.Clothes) string { return c.TokenPath }, p.token))
	}
	for _, path := range []string{
		"/oauth2/jwks", "/oauth2/v2.0/jwks", "/oauth2/default/v1/jwks",
		"/pf/JWKS", "/adfs/discovery/keys", "/oauth2/v3/certs",
		"/realms/{realm}/protocol/openid-connect/certs", "/jwks",
		"/oidc/{name}/jwks", "/affwebservices/CASSO/oidc/{name}/jwks",
		"/idp/profile/oidc/keyset",
	} {
		mux.HandleFunc("GET "+path, p.requirePath(func(c snapshot.Clothes) string { return c.JWKSPath }, p.jwks))
	}
	for _, path := range []string{
		"/oauth2/userinfo", "/oauth2/v2.0/userinfo", "/oauth2/default/v1/userinfo",
		"/idp/userinfo.openid", "/adfs/userinfo", "/oauth2/v3/userinfo",
		"/realms/{realm}/protocol/openid-connect/userinfo", "/userinfo",
		"/oidc/{name}/userinfo", "/affwebservices/CASSO/oidc/{name}/userinfo",
		"/idp/profile/oidc/userinfo",
	} {
		mux.HandleFunc("GET "+path, p.requirePath(func(c snapshot.Clothes) string { return c.UserInfoPath }, p.userinfo))
	}
	for _, path := range []string{
		"/oauth2/logout", "/oauth2/v2.0/logout", "/oauth2/default/v1/logout",
		"/idp/startSLO.ping", "/adfs/oauth2/logout", "/logout",
		"/realms/{realm}/protocol/openid-connect/logout",
		"/oidc/{name}/logout", "/affwebservices/CASSO/oidc/{name}/logout",
		"/idp/profile/oidc/logout",
	} {
		mux.HandleFunc("GET "+path, p.requirePath(func(c snapshot.Clothes) string { return c.LogoutPath }, p.logout))
	}
	mux.HandleFunc("POST /v1.0/users/{oid}/getMemberGroups", p.graphMemberGroups)
	return mux
}

func (p *Provider) requirePath(sel func(snapshot.Clothes) string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		snap := p.snapOIDC(w)
		if snap == nil {
			return
		}
		want := sel(clothesOf(snap))
		if want == "" || r.URL.Path != want {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		next(w, r)
	}
}

func clothesOf(snap *snapshot.Snapshot) snapshot.Clothes {
	if snap == nil {
		return snapshot.Clothes{}
	}
	if snap.Clothes.AuthorizePath != "" {
		return snap.Clothes
	}
	vendorName, tid := "", ""
	if snap.Canonical != nil {
		vendorName = snap.Canonical.Spec.Profile.Vendor
		tid = snap.Canonical.Spec.Profile.TenantID
	}
	realm := ""
	if snap.Canonical != nil {
		realm = snap.Canonical.Metadata.Name
	}
	c, err := vendor.Resolve(vendorName, tid, realm)
	if err != nil {
		return snap.Clothes
	}
	return c
}

func CookieName(snap *snapshot.Snapshot) string {
	if c := clothesOf(snap); c.CookieName != "" {
		return c.CookieName
	}
	return CookieLogin
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
	p.writeDiscovery(w, snap)
}

func (p *Provider) twoSegmentDiscovery(w http.ResponseWriter, r *http.Request) {
	snap := p.snapOIDC(w)
	if snap == nil {
		return
	}
	c := clothesOf(snap)
	a, b := r.PathValue("a"), r.PathValue("b")
	ok := (c.Vendor == "entra" && a == c.TenantID && b == "v2.0") ||
		(c.Vendor == "duo" && a == "oidc" && b == c.Realm)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	p.writeDiscovery(w, snap)
}

func (p *Provider) siteminderDiscovery(w http.ResponseWriter, r *http.Request) {
	snap := p.snapOIDC(w)
	if snap == nil {
		return
	}
	c := clothesOf(snap)
	if c.Vendor != "siteminder" || r.PathValue("name") != c.Realm {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	p.writeDiscovery(w, snap)
}

func (p *Provider) writeDiscovery(w http.ResponseWriter, snap *snapshot.Snapshot) {
	iss := strings.TrimRight(snap.Issuer, "/")
	c := clothesOf(snap)
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                iss,
		"authorization_endpoint":                iss + c.AuthorizePath,
		"token_endpoint":                        iss + c.TokenPath,
		"jwks_uri":                              iss + c.JWKSPath,
		"userinfo_endpoint":                     iss + c.UserInfoPath,
		"end_session_endpoint":                  iss + c.LogoutPath,
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
	if sid, err := r.Cookie(CookieName(snap)); err == nil && sid.Value != "" {
		if sess, ok := p.rt.GetSession(sid.Value); ok && SessionUsable(sess, mfa) {
			if cl.PreConsent && !p.rt.ForceConsent() {
				code := randomID()
				p.rt.PutCode(AuthCode{
					Code: code, ClientID: clientID, RedirectURI: redirect,
					UserID: sess.UserID, Username: sess.Username, Scope: q.Get("scope"),
					Nonce: q.Get("nonce"), Challenge: challenge, Expires: time.Now().Add(5 * time.Minute),
					MFACompleted: sess.MFACompleted,
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
				Protocol: ProtocolOIDC,
				ClientID: clientID, RedirectURI: redirect, Scope: q.Get("scope"),
				State: q.Get("state"), Nonce: q.Get("nonce"), Challenge: challenge, Method: method,
			})
			http.Redirect(w, r, iss+"/consent?pending="+url.QueryEscape(pend.ID), http.StatusFound)
			return
		}
	}
	pend := p.rt.PutPending(Pending{
		Protocol: ProtocolOIDC,
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
		writeTokenError(w, snap, http.StatusTooManyRequests, "temporarily_unavailable", "rate limited")
		return
	}
	if p.rt.Paused() {
		writeTokenError(w, snap, http.StatusServiceUnavailable, "temporarily_unavailable", "token endpoint paused")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, snap, http.StatusBadRequest, "invalid_request", "")
		return
	}
	if inj := p.rt.TakeInject(); inj != "" {
		writeTokenError(w, snap, http.StatusBadRequest, inj, "injected")
		return
	}
	grant := r.FormValue("grant_type")
	switch grant {
	case "authorization_code":
		p.tokenCode(w, r, snap)
	case "refresh_token":
		p.tokenRefresh(w, r, snap)
	default:
		writeTokenError(w, snap, http.StatusBadRequest, "unsupported_grant_type", "")
	}
}

func (p *Provider) tokenCode(w http.ResponseWriter, r *http.Request, snap *snapshot.Snapshot) {
	_, clientID, err := p.clientFromRequest(r, snap)
	if err != nil {
		writeTokenError(w, snap, http.StatusUnauthorized, "invalid_client", "")
		return
	}
	code := r.FormValue("code")
	verifier := r.FormValue("code_verifier")
	redirect := r.FormValue("redirect_uri")
	c, ok := p.rt.TakeCode(code)
	if !ok || time.Now().After(c.Expires) || c.RedirectURI != redirect || c.ClientID != clientID {
		writeTokenError(w, snap, http.StatusBadRequest, "invalid_grant", "")
		return
	}
	if !verifyPKCE(c.Challenge, "S256", verifier) {
		writeTokenError(w, snap, http.StatusBadRequest, "invalid_grant", "PKCE verifier mismatch")
		return
	}
	p.writeTokens(w, snap, c.ClientID, c.UserID, c.Username, c.Scope, c.Nonce, c.MFACompleted)
}

func (p *Provider) tokenRefresh(w http.ResponseWriter, r *http.Request, snap *snapshot.Snapshot) {
	_, clientID, err := p.clientFromRequest(r, snap)
	if err != nil {
		writeTokenError(w, snap, http.StatusUnauthorized, "invalid_client", "")
		return
	}
	tok := r.FormValue("refresh_token")
	ref, ok := p.rt.TakeRefresh(tok)
	if !ok || time.Now().After(ref.Expires) || ref.ClientID != clientID {
		writeTokenError(w, snap, http.StatusBadRequest, "invalid_grant", "")
		return
	}
	p.writeTokens(w, snap, ref.ClientID, ref.UserID, ref.Username, ref.Scope, "", ref.MFACompleted)
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

func (p *Provider) writeTokens(w http.ResponseWriter, snap *snapshot.Snapshot, clientID, userID, username, scope, nonce string, mfa bool) {
	sig, err := newSigner(snap.SigningKey)
	if err != nil {
		writeTokenError(w, snap, http.StatusInternalServerError, "server_error", "")
		return
	}
	extra := map[string]any{}
	if username != "" {
		extra["preferred_username"] = username
	}
	accessExtra := map[string]any{"token_use": "access", "scope": scope}
	if user, ok := snap.UsersByID[userID]; ok {
		if hasScope(scope, "email") && user.Email != "" {
			extra["email"] = user.Email
		}
		if hasScope(scope, "groups") {
			gc, gerr := groupClaims(snap, user, p.warn)
			if gerr != nil {
				writeTokenError(w, snap, http.StatusBadRequest, "invalid_grant", gerr.Error())
				return
			}
			for k, v := range gc {
				extra[k] = v
				accessExtra[k] = v
			}
		}
	}
	if mfa {
		extra["amr"] = []string{"pwd", "otp"}
		extra["acr"] = totp.ACR
		accessExtra["amr"] = []string{"pwd", "otp"}
		accessExtra["acr"] = totp.ACR
	}
	applyClothesClaims(extra, snap, userID)
	idTok, err := sig.mint(snap.Issuer, userID, clientID, nonce, time.Hour, extra)
	if err != nil {
		writeTokenError(w, snap, http.StatusInternalServerError, "server_error", "")
		return
	}
	access, err := sig.mint(snap.Issuer, userID, clientID, "", time.Hour, accessExtra)
	if err != nil {
		writeTokenError(w, snap, http.StatusInternalServerError, "server_error", "")
		return
	}
	ref := randomID()
	p.rt.PutRefresh(Refresh{Token: ref, ClientID: clientID, UserID: userID, Username: username, Scope: scope, Expires: time.Now().Add(24 * time.Hour), MFACompleted: mfa})
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
			gc, gerr := groupClaims(snap, user, nil)
			if gerr == nil {
				for k, v := range gc {
					out[k] = v
				}
			}
		}
	}
	applyClothesClaims(out, snap, c.Subject)
	writeJSON(w, http.StatusOK, out)
}

func (p *Provider) CompleteLogin(pendingID, userID, username string, mfa bool) (string, error) {
	if p.rt.ForceFail() {
		return "", fmt.Errorf("access_denied")
	}
	if snap := p.store.Load(); snap != nil && snap.Canonical != nil && snap.Canonical.Spec.Auth.MFA.Mode == "force-fail" {
		return "", fmt.Errorf("access_denied")
	}
	pend, ok := p.rt.GetPending(pendingID)
	if !ok || (pend.Protocol != "" && pend.Protocol != ProtocolOIDC) {
		return "", fmt.Errorf("pending request not found")
	}
	if _, ok := p.rt.TakePending(pendingID); !ok {
		return "", fmt.Errorf("pending request not found")
	}
	code := randomID()
	p.rt.PutCode(AuthCode{
		Code: code, ClientID: pend.ClientID, RedirectURI: pend.RedirectURI,
		UserID: userID, Username: username, Scope: pend.Scope,
		Nonce: pend.Nonce, Challenge: pend.Challenge, Expires: time.Now().Add(5 * time.Minute),
		MFACompleted: mfa,
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
	pend, ok := p.rt.GetPending(pendingID)
	if !ok || (pend.Protocol != "" && pend.Protocol != ProtocolOIDC) {
		return "", fmt.Errorf("pending request not found")
	}
	if _, ok := p.rt.TakePending(pendingID); !ok {
		return "", fmt.Errorf("pending request not found")
	}
	return oauthErrorLocation(pend.RedirectURI, pend.State, "access_denied", "user denied")
}

func (p *Provider) logout(w http.ResponseWriter, r *http.Request) {
	snap := p.snapOIDC(w)
	if snap == nil {
		return
	}
	name := CookieName(snap)
	if c, err := r.Cookie(name); err == nil && c.Value != "" {
		p.rt.ExpireSession(c.Value)
	}
	secure := r.TLS != nil
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: "/", MaxAge: -1,
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

func (p *Provider) graphMemberGroups(w http.ResponseWriter, r *http.Request) {
	snap := p.snapOIDC(w)
	if snap == nil {
		return
	}
	if snap.Clothes.Vendor != "entra" || snap.Canonical == nil || !snap.Canonical.Spec.GroupOverage.EntraGraphStub {
		http.NotFound(w, r)
		return
	}
	oid := r.PathValue("oid")
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
	c, _, err := parseAndVerifyExtra(raw, sig.jwk, snap.Issuer, true)
	if err != nil || c.Subject != oid {
		http.Error(w, "invalid_token", http.StatusUnauthorized)
		return
	}
	user, ok := snap.UsersByID[oid]
	if !ok {
		http.Error(w, "invalid_token", http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": groupNames(snap, user)})
}

func (p *Provider) Mint(clientID, userID, username, scope string) (access, idToken string, err error) {
	snap := p.store.Load()
	if snap == nil || snap.Canonical == nil || !snap.Canonical.Spec.Protocols.OIDC.IsEnabled(false) {
		return "", "", fmt.Errorf("oidc disabled")
	}
	sig, err := newSigner(snap.SigningKey)
	if err != nil {
		return "", "", err
	}
	extra := map[string]any{}
	if username != "" {
		extra["preferred_username"] = username
	}
	accessExtra := map[string]any{"token_use": "access", "scope": scope}
	if user, ok := snap.UsersByID[userID]; ok {
		if hasScope(scope, "email") && user.Email != "" {
			extra["email"] = user.Email
		}
		if hasScope(scope, "groups") {
			gc, gerr := groupClaims(snap, user, p.warn)
			if gerr != nil {
				return "", "", gerr
			}
			for k, v := range gc {
				extra[k] = v
				accessExtra[k] = v
			}
		}
	}
	applyClothesClaims(extra, snap, userID)
	idToken, err = sig.mint(snap.Issuer, userID, clientID, "", time.Hour, extra)
	if err != nil {
		return "", "", err
	}
	access, err = sig.mint(snap.Issuer, userID, clientID, "", time.Hour, accessExtra)
	return access, idToken, err
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

func applyClothesClaims(extra map[string]any, snap *snapshot.Snapshot, userID string) {
	if snap == nil || snap.Clothes.Vendor != "entra" {
		return
	}
	extra["oid"] = userID
	extra["tid"] = snap.Clothes.TenantID
	extra["ver"] = "2.0"
}

func writeTokenError(w http.ResponseWriter, snap *snapshot.Snapshot, status int, code, desc string) {
	body := map[string]any{"error": code}
	if desc != "" {
		body["error_description"] = desc
	}
	if snap != nil && snap.Clothes.Vendor == "entra" {
		body["error_codes"] = []int{entraTokenErrorCode(code)}
		body["trace_id"] = randomID()
	}
	writeJSON(w, status, body)
}

func entraTokenErrorCode(code string) int {
	switch code {
	case "invalid_client":
		return 700016
	case "invalid_grant":
		return 70008
	case "invalid_request":
		return 90014
	case "temporarily_unavailable":
		return 50058
	case "unsupported_grant_type":
		return 90014
	case "server_error":
		return 50000
	default:
		return 0
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
