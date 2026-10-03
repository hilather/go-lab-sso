package oidc_test

import (
	"encoding/base64"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-sso/internal/app"
	"github.com/hilather/go-lab-sso/internal/auth"
	"github.com/hilather/go-lab-sso/internal/model"
	"github.com/hilather/go-lab-sso/internal/oidc"
)

func logoutForm(t *testing.T, h http.Handler, target string, cookie *http.Cookie) url.Values {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.AddCookie(cookie)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("Set-Cookie") != "" {
		t.Fatalf("logout confirmation = %d, cookies %q, body %s", rec.Code, rec.Header().Get("Set-Cookie"), rec.Body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Frame-Options") != "DENY" || !strings.Contains(rec.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatalf("unprotected logout confirmation headers: %v", rec.Header())
	}
	if strings.Contains(rec.Body.String(), cookie.Value) {
		t.Fatal("logout confirmation exposes the session cookie")
	}
	form := url.Values{}
	for _, field := range regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`).FindAllStringSubmatch(rec.Body.String(), -1) {
		form.Set(field[1], html.UnescapeString(field[2]))
	}
	if form.Get("csrf") == "" || !strings.Contains(rec.Body.String(), `method="post"`) {
		t.Fatalf("missing logout confirmation form: %s", rec.Body)
	}
	return form
}

func TestLogoutGETAndHEADDoNotChangeSession(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		for _, site := range []string{"", "cross-site", "same-site", "same-origin", "none"} {
			t.Run(method+"/"+site, func(t *testing.T) {
				a, h := bootOIDC(t)
				sess := a.OIDC().Runtime().PutSession(oidc.LoginSession{UserID: "u1", Expires: time.Now().Add(time.Hour)})
				req := httptest.NewRequest(method, "https://lab.example.net/oauth2/logout", nil)
				req.AddCookie(&http.Cookie{Name: oidc.CookieLogin, Value: sess.ID})
				if site != "" {
					req.Header.Set("Sec-Fetch-Site", site)
				}
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				if rec.Code != http.StatusOK || rec.Header().Get("Set-Cookie") != "" {
					t.Fatalf("GET/HEAD logout = %d, cookies %q", rec.Code, rec.Header().Get("Set-Cookie"))
				}
				if _, ok := a.OIDC().Runtime().GetSession(sess.ID); !ok {
					t.Fatal("GET/HEAD logout expired session before confirmation")
				}
			})
		}
	}
}

func TestLogoutInvalidRedirectPreservesSession(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			a, h := bootOIDC(t)
			sess := a.OIDC().Runtime().PutSession(oidc.LoginSession{UserID: "u1", Expires: time.Now().Add(time.Hour)})
			cookie := &http.Cookie{Name: oidc.CookieLogin, Value: sess.ID}
			params := url.Values{"post_logout_redirect_uri": {"https://evil.example/cb"}}
			target := "https://lab.example.net/oauth2/logout"
			req := httptest.NewRequest(method, target+"?"+params.Encode(), nil)
			if method == http.MethodPost {
				params = logoutForm(t, h, target, cookie)
				params.Set("post_logout_redirect_uri", "https://evil.example/cb")
				req = httptest.NewRequest(method, target, strings.NewReader(params.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			req.AddCookie(cookie)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest || rec.Header().Get("Set-Cookie") != "" {
				t.Fatalf("invalid logout redirect = %d, cookies %q", rec.Code, rec.Header().Get("Set-Cookie"))
			}
			if _, ok := a.OIDC().Runtime().GetSession(sess.ID); !ok {
				t.Fatal("invalid logout redirect expired session")
			}
		})
	}
}

func TestLogoutConfirmationCSRF(t *testing.T) {
	for _, tc := range []struct {
		name, origin, fetchSite string
		change                  func(url.Values)
		otherSession            bool
	}{
		{name: "missing token", change: func(v url.Values) { v.Del("csrf") }},
		{name: "forged token", change: func(v url.Values) { v.Set("csrf", "forged") }},
		{name: "different session", otherSession: true},
		{name: "changed state", change: func(v url.Values) { v.Set("logout_state", base64.RawURLEncoding.EncodeToString([]byte("changed"))) }},
		{name: "changed redirect", change: func(v url.Values) { v.Set("post_logout_redirect_uri", "https://sut.example.net/cb") }},
		{name: "cross-site origin", origin: "https://evil.example"},
		{name: "cross-site fetch", fetchSite: "cross-site"},
		{name: "same-site fetch", fetchSite: "same-site"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, h := bootOIDC(t)
			sess := a.OIDC().Runtime().PutSession(oidc.LoginSession{UserID: "u1", Expires: time.Now().Add(time.Hour)})
			cookie := &http.Cookie{Name: oidc.CookieLogin, Value: sess.ID}
			target := "https://lab.example.net/oauth2/logout"
			form := logoutForm(t, h, target, cookie)
			if tc.change != nil {
				tc.change(form)
			}
			if tc.otherSession {
				other := a.OIDC().Runtime().PutSession(oidc.LoginSession{UserID: "u2", Expires: time.Now().Add(time.Hour)})
				cookie.Value = other.ID
			}
			req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.fetchSite != "" {
				req.Header.Set("Sec-Fetch-Site", tc.fetchSite)
			}
			req.AddCookie(cookie)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden || rec.Header().Get("Set-Cookie") != "" {
				t.Fatalf("CSRF logout = %d, cookies %q", rec.Code, rec.Header().Get("Set-Cookie"))
			}
			for _, id := range []string{sess.ID, cookie.Value} {
				if _, ok := a.OIDC().Runtime().GetSession(id); !ok {
					t.Fatal("CSRF logout expired session")
				}
			}
		})
	}
}

func TestLogoutConfirmationAcrossVendorClothes(t *testing.T) {
	for _, vendor := range []string{"generic", "entra", "okta", "ping", "adfs", "google", "keycloak", "iam-identity-center", "duo", "siteminder", "shibboleth"} {
		t.Run(vendor, func(t *testing.T) {
			a, h := bootOIDC(t)
			swapVendor(t, a, vendor)
			snap := a.Store().Load()
			sess := a.OIDC().Runtime().PutSession(oidc.LoginSession{UserID: "u1", Expires: time.Now().Add(time.Hour)})
			cookie := &http.Cookie{Name: oidc.CookieName(snap), Value: sess.ID}
			target := snap.Issuer + snap.Clothes.LogoutPath
			state := `bye<&"'`
			params := url.Values{"post_logout_redirect_uri": {"https://sut.example.net/cb"}, "state": {state}}
			form := logoutForm(t, h, target+"?"+params.Encode(), cookie)
			if form.Get("post_logout_redirect_uri") != params.Get("post_logout_redirect_uri") {
				t.Fatalf("confirmation lost redirect: %v", form)
			}
			req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Origin", snap.Issuer)
			req.AddCookie(cookie)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			want := params.Get("post_logout_redirect_uri") + "?" + url.Values{"state": {state}}.Encode()
			if rec.Code != http.StatusFound || rec.Header().Get("Location") != want {
				t.Fatalf("confirmed logout = %d, redirect %q", rec.Code, rec.Header().Get("Location"))
			}
			if _, ok := a.OIDC().Runtime().GetSession(sess.ID); ok {
				t.Fatal("confirmed logout preserved session")
			}
			cookies := rec.Result().Cookies()
			if len(cookies) != 1 || cookies[0].Name != cookie.Name || cookies[0].MaxAge != -1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode {
				t.Fatalf("logout did not clear active cookie securely: %v", cookies)
			}
			replay := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
			replay.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			replay.AddCookie(cookie)
			rec = httptest.NewRecorder()
			h.ServeHTTP(rec, replay)
			if rec.Code != http.StatusForbidden || rec.Header().Get("Set-Cookie") != "" {
				t.Fatalf("logout replay = %d, cookies %q", rec.Code, rec.Header().Get("Set-Cookie"))
			}
			if vendor != "generic" {
				rec = httptest.NewRecorder()
				h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "https://lab.example.net/oauth2/logout", nil))
				if rec.Code != http.StatusNotFound {
					t.Fatalf("inactive logout POST = %d", rec.Code)
				}
			}
		})
	}
}

func TestLogoutMalformedConfirmationPreservesSession(t *testing.T) {
	for _, tc := range []struct {
		name, method, query, body string
	}{
		{name: "malformed query", method: http.MethodGet, query: "?state=%zz"},
		{name: "malformed body", method: http.MethodPost, body: "state=%zz"},
		{name: "malformed encoded state", method: http.MethodPost, body: "logout_state=!"},
		{name: "oversized query state", method: http.MethodGet, query: "?state=" + strings.Repeat("a", 4097)},
		{name: "oversized body", method: http.MethodPost, body: "state=" + strings.Repeat("a", 64<<10)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, h := bootOIDC(t)
			sess := a.OIDC().Runtime().PutSession(oidc.LoginSession{UserID: "u1", Expires: time.Now().Add(time.Hour)})
			req := httptest.NewRequest(tc.method, "https://lab.example.net/oauth2/logout"+tc.query, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(&http.Cookie{Name: oidc.CookieLogin, Value: sess.ID})
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest || rec.Header().Get("Set-Cookie") != "" {
				t.Fatalf("malformed logout = %d, cookies %q", rec.Code, rec.Header().Get("Set-Cookie"))
			}
			if _, ok := a.OIDC().Runtime().GetSession(sess.ID); !ok {
				t.Fatal("malformed logout expired session")
			}
		})
	}
}

func TestLogoutConfirmationPreservesOpaqueState(t *testing.T) {
	a, h := bootOIDC(t)
	sess := a.OIDC().Runtime().PutSession(oidc.LoginSession{UserID: "u1", Expires: time.Now().Add(time.Hour)})
	cookie := &http.Cookie{Name: oidc.CookieLogin, Value: sess.ID}
	target := "https://lab.example.net/oauth2/logout"
	state := "opaque\rreturn\nline\r\nending\x00value"
	params := url.Values{"post_logout_redirect_uri": {"https://sut.example.net/cb"}, "state": {state}}
	form := logoutForm(t, h, target+"?"+params.Encode(), cookie)
	// A browser normalizes CR/LF and NUL when parsing HTML and submitting a form.
	// State must survive that round trip byte-for-byte to match the RP request.
	for key, values := range form {
		for i, value := range values {
			value = strings.ReplaceAll(value, "\r\n", "\n")
			value = strings.ReplaceAll(value, "\r", "\n")
			value = strings.ReplaceAll(value, "\n", "\r\n")
			form[key][i] = strings.ReplaceAll(value, "\x00", "\uFFFD")
		}
	}
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("opaque state logout = %d, body %s", rec.Code, rec.Body)
	}
	redirect, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || redirect.Query().Get("state") != state {
		t.Fatalf("logout changed opaque state: %q, error %v", rec.Header().Get("Location"), err)
	}
}

func TestLogoutConfirmationProtocolDisabled(t *testing.T) {
	a, h := bootOIDC(t)
	val, _ := json.Marshal(model.Protocols{OIDC: model.ProtocolToggle{Enabled: model.Ptr(false)}})
	if _, err := a.Apply(auth.AdminActor(), app.ChangeIn{
		ExpectedRevision: a.Status().RuntimeRevision, Reason: "disable OIDC",
		Operations: []model.Operation{{Op: model.OpUpdate, Target: model.Target{Kind: model.TargetProtocols}, Value: val}},
	}); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "https://lab.example.net/oauth2/logout", nil))
	if rec.Code != http.StatusNotFound || rec.Header().Get("Set-Cookie") != "" {
		t.Fatalf("disabled logout POST = %d, cookies %q", rec.Code, rec.Header().Get("Set-Cookie"))
	}
}
