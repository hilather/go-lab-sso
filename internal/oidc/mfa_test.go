package oidc_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-sso/internal/app"
	"github.com/hilather/go-lab-sso/internal/auth"
	"github.com/hilather/go-lab-sso/internal/model"
	"github.com/hilather/go-lab-sso/internal/oidc"
	"github.com/hilather/go-lab-sso/internal/totp"
)

func TestMintOmitsMFAClaims(t *testing.T) {
	a, _ := bootOIDC(t)
	uval, _ := json.Marshal(model.User{ID: "u1", Username: "alice", PasswordRef: "testdata/secrets/users/alice.password"})
	if _, err := a.Apply(auth.AdminActor(), app.ChangeIn{
		ExpectedRevision: a.Status().RuntimeRevision, Reason: "u",
		Operations: []model.Operation{{Op: model.OpAdd, Target: model.Target{Kind: model.TargetUser, ID: "u1"}, Value: uval}},
	}); err != nil {
		t.Fatal(err)
	}
	out, err := a.MintToken(auth.AdminActor(), app.MintTokenIn{UserID: "u1", ClientID: "app-1", Scope: "openid"})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(out.IDToken, ".")
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(b, &claims); err != nil {
		t.Fatal(err)
	}
	if _, ok := claims["amr"]; ok || claims["acr"] != nil {
		t.Fatalf("mint must omit MFA claims %v", claims)
	}
}

func TestIncompleteSessionIgnoredWhenAlways(t *testing.T) {
	a, h := bootOIDC(t)
	uval, _ := json.Marshal(model.User{ID: "u1", Username: "alice", PasswordRef: "testdata/secrets/users/alice.password"})
	if _, err := a.Apply(auth.AdminActor(), app.ChangeIn{
		ExpectedRevision: a.Status().RuntimeRevision, Reason: "u",
		Operations: []model.Operation{{Op: model.OpAdd, Target: model.Target{Kind: model.TargetUser, ID: "u1"}, Value: uval}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.SetMFA(auth.AdminActor(), app.SetMFAIn{
		Mode: "always", ExpectedRevision: a.Status().RuntimeRevision, Reason: "on",
	}); err != nil {
		t.Fatal(err)
	}
	sess := a.OIDC().Runtime().PutSession(oidc.LoginSession{
		UserID: "u1", Username: "alice", MFACompleted: false, Expires: time.Now().Add(time.Hour),
	})
	ch := s256("verifier-value-1234567890")
	req := httptest.NewRequest("GET", "/oauth2/authorize?response_type=code&client_id=app-1&redirect_uri="+url.QueryEscape("https://sut.example.net/cb")+"&code_challenge="+ch+"&code_challenge_method=S256", nil)
	req.AddCookie(&http.Cookie{Name: oidc.CookieLogin, Value: sess.ID})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 302 || !strings.Contains(rec.Header().Get("Location"), "/login") {
		t.Fatalf("incomplete cookie must not mint %d %s", rec.Code, rec.Header().Get("Location"))
	}
}

func TestMFACompletedCookieReuseClaims(t *testing.T) {
	a, h := bootOIDC(t)
	uval, _ := json.Marshal(model.User{ID: "u1", Username: "alice", PasswordRef: "testdata/secrets/users/alice.password"})
	cval, _ := json.Marshal(model.Client{
		ID: "app-1", ClientID: "app-1", Public: true, PreConsent: true,
		RedirectURIs: []string{"https://sut.example.net/cb"},
	})
	if _, err := a.Apply(auth.AdminActor(), app.ChangeIn{
		ExpectedRevision: a.Status().RuntimeRevision, Reason: "pre",
		Operations: []model.Operation{{Op: model.OpUpdate, Target: model.Target{Kind: model.TargetClient, ID: "app-1"}, Value: cval}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Apply(auth.AdminActor(), app.ChangeIn{
		ExpectedRevision: a.Status().RuntimeRevision, Reason: "u",
		Operations: []model.Operation{{Op: model.OpAdd, Target: model.Target{Kind: model.TargetUser, ID: "u1"}, Value: uval}},
	}); err != nil {
		t.Fatal(err)
	}
	sess := a.OIDC().Runtime().PutSession(oidc.LoginSession{
		UserID: "u1", Username: "alice", MFACompleted: true, Expires: time.Now().Add(time.Hour),
	})
	ch := s256("verifier-value-1234567890")
	req := httptest.NewRequest("GET", "/oauth2/authorize?response_type=code&client_id=app-1&redirect_uri="+url.QueryEscape("https://sut.example.net/cb")+"&code_challenge="+ch+"&code_challenge_method=S256&scope=openid", nil)
	req.AddCookie(&http.Cookie{Name: oidc.CookieLogin, Value: sess.ID})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("%d %s", rec.Code, rec.Header().Get("Location"))
	}
	tokForm := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://sut.example.net/cb"}, "code_verifier": {"verifier-value-1234567890"}, "client_id": {"app-1"}}
	req = httptest.NewRequest("POST", "/oauth2/token", strings.NewReader(tokForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var tok map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &tok); err != nil {
		t.Fatal(rec.Body.String())
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.Split(tok["id_token"].(string), ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(b, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["acr"] != totp.ACR {
		t.Fatalf("cookie-reuse acr %v", claims)
	}
}
