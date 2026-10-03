package oidc

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"html/template"
	"net/http"
)

// logoutCSRF binds confirmation to the live session and the complete logout
// request without exposing the session cookie or allocating pending state.
func logoutCSRF(sessionID, path, redirect, state string) string {
	mac := hmac.New(sha256.New, []byte(sessionID))
	_, _ = mac.Write([]byte("labsso/logout/v1\x00" + path + "\x00" + redirect + "\x00" + state))
	return hex.EncodeToString(mac.Sum(nil))
}

var logoutConfirmation = template.Must(template.New("logout").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Sign out of LabSSO</title></head>
<body><main><h1>Sign out of LabSSO?</h1><p>Confirm to end your sign-in session.</p>
<form method="post" action="{{.Path}}">
<input type="hidden" name="post_logout_redirect_uri" value="{{.Redirect}}">
<input type="hidden" name="logout_state" value="{{.State}}">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<button type="submit">Sign out</button></form></main></body></html>`))

func writeLogoutConfirmation(w http.ResponseWriter, path, redirect, state, csrf string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	// Encode opaque state so HTML parsing and form line-ending normalization
	// cannot change the RP's value or invalidate the confirmation token.
	state = base64.RawURLEncoding.EncodeToString([]byte(state))
	_ = logoutConfirmation.Execute(w, struct{ Path, Redirect, State, CSRF string }{path, redirect, state, csrf})
}
