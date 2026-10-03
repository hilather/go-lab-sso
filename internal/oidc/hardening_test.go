package oidc_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hilather/go-lab-sso/internal/app"
	"github.com/hilather/go-lab-sso/internal/auth"
	"github.com/hilather/go-lab-sso/internal/compiler"
	"github.com/hilather/go-lab-sso/internal/model"
	"github.com/hilather/go-lab-sso/internal/oidc"
	"github.com/hilather/go-lab-sso/internal/snapshot"
)

func reviewApply(t *testing.T, a *app.App, op model.Operation) {
	t.Helper()
	_, err := a.Apply(auth.AdminActor(), app.ChangeIn{ExpectedRevision: a.Status().RuntimeRevision, Reason: "review", Operations: []model.Operation{op}})
	if err != nil {
		t.Fatal(err)
	}
}
func reviewUser(t *testing.T, a *app.App, hashRef string) {
	u := model.User{ID: "u1", Username: "alice", PasswordRef: "testdata/secrets/users/alice.password"}
	if hashRef != "" {
		u.PasswordRef = ""
		u.PasswordHashRef = hashRef
	}
	b, _ := json.Marshal(u)
	reviewApply(t, a, model.Operation{Op: model.OpAdd, Target: model.Target{Kind: model.TargetUser, ID: "u1"}, Value: b})
}
func reviewPost(h http.Handler, path string, form url.Values, origin string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		req.Header.Set("Origin", origin)
		req.Header.Set("Sec-Fetch-Site", "cross-site")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}
func TestHardeningLoginCrossSiteAndMissingPending(t *testing.T) {
	a, h := bootOIDC(t)
	reviewUser(t, a, "")
	rec := reviewPost(h, "/login", url.Values{"username": {"alice"}, "password": {"alice-password"}}, "https://evil.example")
	if rec.Header().Get("Set-Cookie") != "" {
		t.Fatalf("cross-site login without pending accepted and set cookie: %d %s", rec.Code, rec.Header().Get("Location"))
	}
}
func TestHardeningDisabledDeletedUserRefresh(t *testing.T) {
	for _, remove := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "deleted"}[remove], func(t *testing.T) {
			a, h := bootOIDC(t)
			reviewUser(t, a, "")
			rt := a.OIDC().Runtime()
			rt.PutRefresh(oidc.Refresh{Token: "refresh", ClientID: "app-1", UserID: "u1", Username: "alice", Scope: "openid", Expires: time.Now().Add(time.Hour)})
			if remove {
				reviewApply(t, a, model.Operation{Op: model.OpRemove, Target: model.Target{Kind: model.TargetUser, ID: "u1"}})
			} else {
				f := false
				b, _ := json.Marshal(model.User{ID: "u1", Username: "alice", PasswordRef: "testdata/secrets/users/alice.password", Enabled: &f})
				reviewApply(t, a, model.Operation{Op: model.OpUpdate, Target: model.Target{Kind: model.TargetUser, ID: "u1"}, Value: b})
			}
			rec := reviewPost(h, "/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"app-1"}, "refresh_token": {"refresh"}}, "")
			if rec.Code == 200 {
				t.Fatal("issued new tokens for disabled/deleted user")
			}
		})
	}
}
func TestHardeningForbiddenClientScope(t *testing.T) {
	a, h := bootOIDC(t)
	b, _ := json.Marshal(model.Client{ID: "app-1", ClientID: "app-1", Public: true, Scopes: []string{"openid"}, RedirectURIs: []string{"https://sut.example.net/cb"}})
	reviewApply(t, a, model.Operation{Op: model.OpUpdate, Target: model.Target{Kind: model.TargetClient, ID: "app-1"}, Value: b})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/oauth2/authorize?response_type=code&client_id=app-1&redirect_uri=https%3A%2F%2Fsut.example.net%2Fcb&scope=openid+email+groups&code_challenge=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&code_challenge_method=S256", nil))
	if !strings.Contains(rec.Header().Get("Location"), "error=invalid_scope") {
		t.Fatalf("accepted client-disallowed scopes: %s", rec.Header().Get("Location"))
	}
}
func TestHardeningECDiscovery(t *testing.T) {
	a, h := bootOIDC(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	doc := *a.Store().Load().Canonical
	doc.Spec.Signing.KeyRef = path
	// No signing mutation target; compile through store is a public API used by bootstrap.
	old := a.Store().Load()
	next := *old
	next.SigningKey = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	a.Store().Swap(&next)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/.well-known/openid-configuration", nil))
	if !strings.Contains(rec.Body.String(), "ES256") {
		t.Fatal("ECDSA snapshot still advertises only RS256")
	}
}
func TestHardeningTokenNotCacheable(t *testing.T) {
	a, h := bootOIDC(t)
	reviewUser(t, a, "")
	a.OIDC().Runtime().PutRefresh(oidc.Refresh{Token: "refresh", ClientID: "app-1", UserID: "u1", Scope: "openid", Expires: time.Now().Add(time.Hour)})
	rec := reviewPost(h, "/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"app-1"}, "refresh_token": {"refresh"}}, "")
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("token response cache control is %q", rec.Header().Get("Cache-Control"))
	}
}

func TestHardeningPasswordStableInSnapshot(t *testing.T) {
	a, h := bootOIDC(t)
	path := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(path, []byte("first-password"), 0600); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(model.User{ID: "u1", Username: "alice", PasswordRef: path})
	reviewApply(t, a, model.Operation{Op: model.OpAdd, Target: model.Target{Kind: model.TargetUser, ID: "u1"}, Value: b})
	if err := os.WriteFile(path, []byte("changed-password"), 0600); err != nil {
		t.Fatal(err)
	}
	a.OIDC().Runtime().PutPending(oidc.Pending{ID: "p", ClientID: "app-1", RedirectURI: "https://sut.example.net/cb"})
	rec := reviewPost(h, "/login", url.Values{"pending": {"p"}, "username": {"alice"}, "password": {"changed-password"}}, "")
	if rec.Header().Get("Set-Cookie") != "" {
		t.Fatal("external file edit changed active login credentials without compile/apply")
	}
}
func TestHardeningStaleRedirectOnCode(t *testing.T) {
	a, h := bootOIDC(t)
	reviewUser(t, a, "")
	verifier := "a-valid-verifier-abcdefghijklmnopqrstuvwxyz-0123456789"
	rt := a.OIDC().Runtime()
	rt.PutCode(oidc.AuthCode{Code: "code", ClientID: "app-1", RedirectURI: "https://sut.example.net/cb", UserID: "u1", Username: "alice", Challenge: s256(verifier), Scope: "openid", Expires: time.Now().Add(time.Hour)})
	b, _ := json.Marshal(model.Client{ID: "app-1", ClientID: "app-1", Public: true, RedirectURIs: []string{"https://safe.example/cb"}})
	reviewApply(t, a, model.Operation{Op: model.OpUpdate, Target: model.Target{Kind: model.TargetClient, ID: "app-1"}, Value: b})
	rec := reviewPost(h, "/oauth2/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {"app-1"}, "code": {"code"}, "code_verifier": {verifier}, "redirect_uri": {"https://sut.example.net/cb"}}, "")
	if rec.Code == 200 {
		t.Fatal("redeemed code for removed redirect URI")
	}
}
func TestHardeningWeakPKCE(t *testing.T) {
	a, h := bootOIDC(t)
	reviewUser(t, a, "")
	rt := a.OIDC().Runtime()
	rt.PutCode(oidc.AuthCode{Code: "code", ClientID: "app-1", RedirectURI: "https://sut.example.net/cb", UserID: "u1", Challenge: s256("a"), Scope: "openid", Expires: time.Now().Add(time.Hour)})
	rec := reviewPost(h, "/oauth2/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {"app-1"}, "code": {"code"}, "code_verifier": {"a"}, "redirect_uri": {"https://sut.example.net/cb"}}, "")
	if rec.Code == 200 {
		t.Fatal("one-character PKCE verifier accepted")
	}
}

func TestHardeningUnsupportedECCurveAccepted(t *testing.T) {
	a, _ := bootOIDC(t)
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	doc := *a.Store().Load().Canonical
	doc.Spec.Signing.KeyRef = path
	snap, err := compiler.Compile(doc, compiler.Options{BaseDir: repoRoot(t)})
	if err != nil {
		t.Fatal(err)
	}
	a.Store().Swap(snap)
	if _, _, err := a.OIDC().Mint("app-1", "u1", "alice", "openid"); err != nil {
		t.Fatalf("compile accepted key unusable by OIDC: %v", err)
	}
}

func TestHardeningRefreshScopeNarrowing(t *testing.T) {
	for _, tc := range []struct {
		name, requested, retry, want string
	}{
		{name: "narrow", requested: "openid", want: "openid"},
		{name: "widen then default", requested: "openid email groups", want: "openid email"},
		{name: "widen then original", requested: "openid email groups", retry: "openid email", want: "openid email"},
		{name: "widen then narrow", requested: "openid email groups", retry: "openid", want: "openid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, h := bootOIDC(t)
			reviewUser(t, a, "")
			a.OIDC().Runtime().PutRefresh(oidc.Refresh{Token: "refresh", ClientID: "app-1", UserID: "u1", Scope: "openid email", Expires: time.Now().Add(time.Hour)})
			rec := reviewPost(h, "/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"app-1"}, "refresh_token": {"refresh"}, "scope": {tc.requested}}, "")
			if tc.requested != "openid" {
				if rec.Code != 400 || !strings.Contains(rec.Body.String(), `"error":"invalid_scope"`) {
					t.Fatal("scope widening accepted")
				}
				form := url.Values{"grant_type": {"refresh_token"}, "client_id": {"app-1"}, "refresh_token": {"refresh"}}
				if tc.retry != "" {
					form.Set("scope", tc.retry)
				}
				rec = reviewPost(h, "/oauth2/token", form, "")
			}
			if rec.Code != 200 {
				t.Fatal(rec.Body.String())
			}
			var tokens map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &tokens); err != nil {
				t.Fatal(err)
			}
			parts := strings.Split(tokens["access_token"].(string), ".")
			payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
			var claims map[string]any
			if err := json.Unmarshal(payload, &claims); err != nil {
				t.Fatal(err)
			}
			if claims["scope"] != tc.want {
				t.Fatalf("scope = %v, want %q", claims["scope"], tc.want)
			}
			if tokens["refresh_token"] == "refresh" || tokens["refresh_token"] == "" || tokens["refresh_token"] == nil {
				t.Fatal("refresh token was not rotated")
			}
			replay := reviewPost(h, "/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"app-1"}, "refresh_token": {"refresh"}}, "")
			if replay.Code != 400 || !strings.Contains(replay.Body.String(), `"error":"invalid_grant"`) {
				t.Fatal("consumed refresh token accepted")
			}
		})
	}
}

func TestHardeningRefreshConcurrentRedemption(t *testing.T) {
	a, h := bootOIDC(t)
	reviewUser(t, a, "")
	a.OIDC().Runtime().PutRefresh(oidc.Refresh{Token: "refresh", ClientID: "app-1", UserID: "u1", Scope: "openid email", Expires: time.Now().Add(time.Hour)})
	const requests = 8
	results := make(chan *httptest.ResponseRecorder, requests)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range requests {
		wg.Go(func() {
			<-start
			results <- reviewPost(h, "/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"app-1"}, "refresh_token": {"refresh"}, "scope": {"openid"}}, "")
		})
	}
	close(start)
	wg.Wait()
	close(results)
	succeeded := 0
	for rec := range results {
		if rec.Code == http.StatusOK {
			succeeded++
		} else if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"error":"invalid_grant"`) {
			t.Fatalf("unexpected refresh response: %d %s", rec.Code, rec.Body.String())
		}
	}
	if succeeded != 1 {
		t.Fatalf("successful concurrent redemptions = %d, want 1", succeeded)
	}
}
func TestHardeningPendingRequiredBeforeLogin(t *testing.T) {
	a, h := bootOIDC(t)
	reviewUser(t, a, "")
	for _, pending := range []string{"", "random", "expired"} {
		a.OIDC().Runtime().PutPending(oidc.Pending{ID: "expired", ClientID: "app-1", RedirectURI: "https://sut.example.net/cb", Created: time.Now().Add(-time.Hour)})
		rec := reviewPost(h, "/login", url.Values{"pending": {pending}, "username": {"alice"}, "password": {"alice-password"}}, "")
		if rec.Code != 400 || rec.Header().Get("Set-Cookie") != "" || len(a.OIDC().Runtime().ListSessions()) != 0 {
			t.Fatal("invalid pending authenticated")
		}
	}
}
func TestHardeningCrossOriginConsentAndAudit(t *testing.T) {
	a, h := bootOIDC(t)
	reviewUser(t, a, "")
	var reasons []string
	a.OIDC().Runtime().SetReject(func(reason string) { reasons = append(reasons, reason) })
	for _, path := range []string{"/login", "/consent"} {
		rec := reviewPost(h, path, url.Values{"password": {"do-not-audit"}, "mfa": {"654321"}}, "https://evil.example")
		if rec.Code != 403 {
			t.Fatalf("%s cross-origin accepted", path)
		}
	}
	if len(reasons) != 2 {
		t.Fatal("missing cross-origin audit events")
	}
}

func TestHardeningRejectCallbackRedactsCredentials(t *testing.T) {
	a, h := bootOIDC(t)
	reviewUser(t, a, "")
	var reasons []string
	a.OIDC().Runtime().SetReject(func(reason string) { reasons = append(reasons, reason) })
	a.OIDC().Runtime().PutPending(oidc.Pending{ID: "secret-pending", ClientID: "app-1", RedirectURI: "https://sut.example.net/cb"})
	reviewPost(h, "/login", url.Values{"pending": {"secret-pending"}, "username": {"secret-user"}, "password": {"secret-password"}, "mfa": {"654321"}}, "")
	if len(reasons) == 0 {
		t.Fatal("missing rejection event")
	}
	for _, reason := range reasons {
		for _, secret := range []string{"secret-pending", "secret-user", "secret-password", "654321"} {
			if strings.Contains(reason, secret) {
				t.Fatal("audit leaked credential")
			}
		}
	}
}

// swapSnapshot installs an edited copy of the active snapshot without the
// Apply-path purge and returns the original so the test can restore it.
func swapSnapshot(a *app.App, edit func(*snapshot.Snapshot)) *snapshot.Snapshot {
	old := a.Store().Load()
	next := *old
	doc := *old.Canonical
	next.Canonical = &doc
	next.UsersByID = maps.Clone(old.UsersByID)
	next.ClientsByClientID = maps.Clone(old.ClientsByClientID)
	edit(&next)
	a.Store().Swap(&next)
	return old
}

func refreshWith(h http.Handler, path, token, scope string) *httptest.ResponseRecorder {
	form := url.Values{"grant_type": {"refresh_token"}, "client_id": {"app-1"}, "refresh_token": {token}}
	if scope != "" {
		form.Set("scope", scope)
	}
	return reviewPost(h, path, form, "")
}

func TestHardeningRefreshSurvivesIssueFailure(t *testing.T) {
	for _, tc := range []struct {
		name, vendor, path, scope, wantError string
		groups, wantCode                     int
		fail, recover                        func(*testing.T, *app.App)
	}{
		{
			name: "force-fail tunable", path: "/oauth2/token", scope: "openid", wantCode: http.StatusBadRequest, wantError: `"error":"invalid_grant","error_description":"force-fail"`,
			fail:    func(_ *testing.T, a *app.App) { a.OIDC().Runtime().SetForceFail(true) },
			recover: func(_ *testing.T, a *app.App) { a.OIDC().Runtime().SetForceFail(false) },
		},
		{
			name: "okta overage", vendor: "okta", path: "/oauth2/default/v1/token", scope: "openid groups", groups: 100, wantCode: http.StatusBadRequest, wantError: `"error":"invalid_grant","error_description":"okta overage"`,
			fail: func(*testing.T, *app.App) {},
			recover: func(t *testing.T, a *app.App) {
				failAt := 200
				if _, err := a.SetOverage(auth.AdminActor(), app.SetOverageIn{OktaFailAt: &failAt, ExpectedRevision: a.Status().RuntimeRevision, Reason: "raise okta limit"}); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			// Overage settings do not purge grants, so the stored row survives
			// the tunable change and the failed refresh.
			name: "entra stub off", vendor: "entra", path: "/oauth2/v2.0/token", scope: "openid groups", groups: 3, wantCode: http.StatusBadRequest, wantError: `"error":"invalid_grant","error_codes":[70008],"error_description":"entra stub disabled"`,
			fail: func(t *testing.T, a *app.App) {
				off, limit := false, 2
				if _, err := a.SetOverage(auth.AdminActor(), app.SetOverageIn{EntraGraphStub: &off, GenericCap: &limit, ExpectedRevision: a.Status().RuntimeRevision, Reason: "stub off"}); err != nil {
					t.Fatal(err)
				}
			},
			recover: func(t *testing.T, a *app.App) {
				on := true
				if _, err := a.SetOverage(auth.AdminActor(), app.SetOverageIn{EntraGraphStub: &on, ExpectedRevision: a.Status().RuntimeRevision, Reason: "stub on"}); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			// token:pause is the transient-failure simulation: 503 before any
			// grant handling.
			name: "token paused", path: "/oauth2/token", scope: "openid", wantCode: http.StatusServiceUnavailable, wantError: `"error":"temporarily_unavailable"`,
			fail: func(t *testing.T, a *app.App) {
				if err := a.PauseToken(auth.AdminActor(), "pause"); err != nil {
					t.Fatal(err)
				}
			},
			recover: func(t *testing.T, a *app.App) {
				if err := a.ResumeToken(auth.AdminActor(), "resume"); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			// Signing-key changes purge grants through Apply; the swap only
			// exercises the signer error path after validation.
			name: "signer error", path: "/oauth2/token", scope: "openid", wantCode: http.StatusInternalServerError, wantError: `"error":"server_error"`,
			fail: func(_ *testing.T, a *app.App) {
				swapSnapshot(a, func(s *snapshot.Snapshot) { s.SigningKey = []byte("not a key") })
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, h := bootOIDC(t)
			if tc.vendor != "" {
				swapVendor(t, a, tc.vendor)
			}
			if tc.groups > 0 {
				seedGroups(t, a, tc.groups)
			} else {
				reviewUser(t, a, "")
			}
			good := a.Store().Load()
			a.OIDC().Runtime().PutRefresh(oidc.Refresh{Generation: good.Generation, Token: "refresh", ClientID: "app-1", UserID: "u1", Username: "alice", Scope: tc.scope, Expires: time.Now().Add(time.Hour)})
			tc.fail(t, a)
			if rec := refreshWith(h, tc.path, "refresh", ""); rec.Code != tc.wantCode || !strings.Contains(rec.Body.String(), tc.wantError) {
				t.Fatalf("failing refresh = %d %s", rec.Code, rec.Body)
			}
			if tc.recover != nil {
				tc.recover(t, a)
			} else {
				a.Store().Swap(good)
			}
			rec := refreshWith(h, tc.path, "refresh", "")
			if rec.Code != http.StatusOK {
				t.Fatalf("refresh after transient failure = %d %s", rec.Code, rec.Body)
			}
			if replay := refreshWith(h, tc.path, "refresh", ""); replay.Code != http.StatusBadRequest || !strings.Contains(replay.Body.String(), `"error":"invalid_grant"`) {
				t.Fatalf("rotated refresh token replayed: %d %s", replay.Code, replay.Body)
			}
		})
	}
}

// TestHardeningCodeForceFailDescription covers both force-fail sources on the
// code grant: the runtime tunable and the YAML MFA mode. Changing auth purges
// refresh grants, so the MFA mode is exercised through a code planted after
// the change.
func TestHardeningCodeForceFailDescription(t *testing.T) {
	verifier := "a-valid-verifier-abcdefghijklmnopqrstuvwxyz-0123456789"
	for _, tc := range []struct {
		name string
		fail func(*testing.T, *app.App)
	}{
		{name: "tunable", fail: func(_ *testing.T, a *app.App) { a.OIDC().Runtime().SetForceFail(true) }},
		{name: "yaml mfa mode", fail: func(t *testing.T, a *app.App) {
			val, _ := json.Marshal(model.Auth{MFA: model.MFA{Mode: "force-fail"}})
			reviewApply(t, a, model.Operation{Op: model.OpUpdate, Target: model.Target{Kind: model.TargetAuth}, Value: val})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, h := bootOIDC(t)
			reviewUser(t, a, "")
			tc.fail(t, a)
			a.OIDC().Runtime().PutCode(oidc.AuthCode{Generation: a.Store().Load().Generation, Code: "code", ClientID: "app-1", RedirectURI: "https://sut.example.net/cb", UserID: "u1", Username: "alice", Challenge: s256(verifier), Scope: "openid", Expires: time.Now().Add(time.Hour)})
			rec := reviewPost(h, "/oauth2/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {"app-1"}, "code": {"code"}, "code_verifier": {verifier}, "redirect_uri": {"https://sut.example.net/cb"}}, "")
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"error":"invalid_grant","error_description":"force-fail"`) {
				t.Fatalf("force-fail code exchange = %d %s", rec.Code, rec.Body)
			}
		})
	}
}

// TestHardeningRefreshRevokedUnderForceFail checks that revocation wins over
// force-fail: the grant is consumed and the error does not claim force-fail.
func TestHardeningRefreshRevokedUnderForceFail(t *testing.T) {
	a, h := bootOIDC(t)
	reviewUser(t, a, "")
	a.OIDC().Runtime().PutRefresh(oidc.Refresh{Generation: a.Store().Load().Generation, Token: "refresh", ClientID: "app-1", UserID: "u1", Username: "alice", Scope: "openid", Expires: time.Now().Add(time.Hour)})
	old := swapSnapshot(a, func(s *snapshot.Snapshot) {
		u := s.UsersByID["u1"]
		u.Enabled = model.Ptr(false)
		s.UsersByID["u1"] = u
	})
	a.OIDC().Runtime().SetForceFail(true)
	if rec := refreshWith(h, "/oauth2/token", "refresh", ""); rec.Code != http.StatusBadRequest || rec.Body.String() != `{"error":"invalid_grant"}`+"\n" {
		t.Fatalf("revoked refresh under force-fail = %d %q", rec.Code, rec.Body)
	}
	a.Store().Swap(old)
	a.OIDC().Runtime().SetForceFail(false)
	if rec := refreshWith(h, "/oauth2/token", "refresh", ""); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"error":"invalid_grant"`) {
		t.Fatalf("revoked grant survived force-fail: %d %s", rec.Code, rec.Body)
	}
}

func TestHardeningRefreshRevokedLosesGrant(t *testing.T) {
	for _, tc := range []struct {
		name   string
		revoke func(*testing.T, *app.App) (restore func())
	}{
		{name: "user disabled without purge", revoke: func(_ *testing.T, a *app.App) func() {
			old := swapSnapshot(a, func(s *snapshot.Snapshot) {
				u := s.UsersByID["u1"]
				u.Enabled = model.Ptr(false)
				s.UsersByID["u1"] = u
			})
			return func() { a.Store().Swap(old) }
		}},
		{name: "client scope withdrawn without purge", revoke: func(_ *testing.T, a *app.App) func() {
			old := swapSnapshot(a, func(s *snapshot.Snapshot) {
				cl := s.ClientsByClientID["app-1"]
				cl.Scopes = []string{"profile"}
				s.ClientsByClientID["app-1"] = cl
			})
			return func() { a.Store().Swap(old) }
		}},
		// The Apply cases are end-to-end regressions: Apply purges every refresh
		// row before the request reaches writeTokens.
		{name: "user disabled by apply", revoke: func(t *testing.T, a *app.App) func() {
			b, _ := json.Marshal(model.User{ID: "u1", Username: "alice", PasswordRef: "testdata/secrets/users/alice.password", Enabled: model.Ptr(false)})
			reviewApply(t, a, model.Operation{Op: model.OpUpdate, Target: model.Target{Kind: model.TargetUser, ID: "u1"}, Value: b})
			return func() {
				b, _ := json.Marshal(model.User{ID: "u1", Username: "alice", PasswordRef: "testdata/secrets/users/alice.password"})
				reviewApply(t, a, model.Operation{Op: model.OpUpdate, Target: model.Target{Kind: model.TargetUser, ID: "u1"}, Value: b})
			}
		}},
		{name: "client removed by apply", revoke: func(t *testing.T, a *app.App) func() {
			reviewApply(t, a, model.Operation{Op: model.OpRemove, Target: model.Target{Kind: model.TargetClient, ID: "app-1"}})
			return func() {
				b, _ := json.Marshal(model.Client{ID: "app-1", ClientID: "app-1", Public: true, RedirectURIs: []string{"https://sut.example.net/cb"}})
				reviewApply(t, a, model.Operation{Op: model.OpAdd, Target: model.Target{Kind: model.TargetClient, ID: "app-1"}, Value: b})
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, h := bootOIDC(t)
			reviewUser(t, a, "")
			a.OIDC().Runtime().PutRefresh(oidc.Refresh{Generation: a.Store().Load().Generation, Token: "refresh", ClientID: "app-1", UserID: "u1", Username: "alice", Scope: "openid", Expires: time.Now().Add(time.Hour)})
			restore := tc.revoke(t, a)
			if rec := refreshWith(h, "/oauth2/token", "refresh", ""); rec.Code == http.StatusOK {
				t.Fatal("refresh issued tokens after revocation")
			}
			restore()
			if rec := refreshWith(h, "/oauth2/token", "refresh", ""); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"error":"invalid_grant"`) {
				t.Fatalf("revoked refresh grant survived: %d %s", rec.Code, rec.Body)
			}
		})
	}
}

func TestHardeningRefreshStaleSnapshotKeepsNewerGrant(t *testing.T) {
	a, h := bootOIDC(t)
	reviewUser(t, a, "")
	stale := a.Store().Load().Generation
	swapSnapshot(a, func(s *snapshot.Snapshot) {
		u := s.UsersByID["u1"]
		u.Enabled = model.Ptr(false)
		s.UsersByID["u1"] = u
	})
	// A newer generation re-enabled the user and issued this grant; a request
	// still holding the older revoked snapshot must not consume it.
	rt := a.OIDC().Runtime()
	rt.InvalidateBefore(stale + 1)
	rt.PutRefresh(oidc.Refresh{Generation: stale + 1, Token: "refresh", ClientID: "app-1", UserID: "u1", Username: "alice", Scope: "openid", Expires: time.Now().Add(time.Hour)})
	if rec := refreshWith(h, "/oauth2/token", "refresh", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("stale snapshot refresh = %d %s", rec.Code, rec.Body)
	}
	if _, ok := rt.GetRefresh("refresh"); !ok {
		t.Fatal("stale snapshot consumed a newer grant")
	}
}
