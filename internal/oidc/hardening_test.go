package oidc_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-sso/internal/app"
	"github.com/hilather/go-lab-sso/internal/auth"
	"github.com/hilather/go-lab-sso/internal/compiler"
	"github.com/hilather/go-lab-sso/internal/model"
	"github.com/hilather/go-lab-sso/internal/oidc"
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
	for _, scope := range []string{"openid", "openid email groups"} {
		t.Run(scope, func(t *testing.T) {
			a, h := bootOIDC(t)
			reviewUser(t, a, "")
			a.OIDC().Runtime().PutRefresh(oidc.Refresh{Token: "refresh", ClientID: "app-1", UserID: "u1", Scope: "openid email", Expires: time.Now().Add(time.Hour)})
			rec := reviewPost(h, "/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"app-1"}, "refresh_token": {"refresh"}, "scope": {scope}}, "")
			if scope != "openid" {
				if rec.Code != 400 {
					t.Fatal("scope widening accepted")
				}
				return
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
			if claims["scope"] != "openid" {
				t.Fatal("scope not narrowed")
			}
		})
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
