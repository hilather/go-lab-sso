package oidc_test

import (
	"encoding/base64"
	"encoding/json"
	"github.com/hilather/go-lab-sso/internal/oidc"
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
	"github.com/hilather/go-lab-sso/internal/model"
)

func TestIntegrationReviewGraphRejectsRevokedGeneration(t *testing.T) {
	a, h := bootOIDC(t)
	reviewUser(t, a, "")
	_, err := a.SwapVendor(auth.AdminActor(), app.SwapVendorIn{Vendor: "entra", ExpectedRevision: a.Status().RuntimeRevision, Reason: "review"})
	if err != nil {
		t.Fatal(err)
	}
	on := true
	_, err = a.SetOverage(auth.AdminActor(), app.SetOverageIn{EntraGraphStub: &on, ExpectedRevision: a.Status().RuntimeRevision, Reason: "review"})
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := a.OIDC().Mint("app-1", "u1", "alice", "openid groups")
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.SetMFA(auth.AdminActor(), app.SetMFAIn{Mode: "always", ExpectedRevision: a.Status().RuntimeRevision, Reason: "review"})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/oauth2/v2.0/userinfo", "/v1.0/users/u1/getMemberGroups"} {
		method := "GET"
		if strings.Contains(path, "getMemberGroups") {
			method = "POST"
		}
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 401 {
			t.Errorf("%s accepted revoked access token: status%d body%s", path, rec.Code, rec.Body.String())
		}
	}
}

func TestIntegrationReviewSAMLRelayStateBound(t *testing.T) {
	a, h := bootOIDC(t)
	cl := model.Client{ID: "app-1", ClientID: "app-1", Public: true, RedirectURIs: []string{"https://sut.example.net/cb"}, SAML: model.ClientSAML{EntityID: "https://sut.example.net/sp"}}
	b, _ := json.Marshal(cl)
	reviewApply(t, a, model.Operation{Op: model.OpUpdate, Target: model.Target{Kind: model.TargetClient, ID: "app-1"}, Value: b})
	p := a.Store().Load().Canonical.Spec.Protocols
	on := true
	p.SAML.Enabled = &on
	b, _ = json.Marshal(p)
	reviewApply(t, a, model.Operation{Op: model.OpUpdate, Target: model.Target{Kind: model.TargetProtocols}, Value: b})
	xml := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_review"><saml:Issuer>https://sut.example.net/sp</saml:Issuer></samlp:AuthnRequest>`
	rec := reviewPost(h, "/saml/sso", url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString([]byte(xml))}, "RelayState": {strings.Repeat("x", 1<<20)}}, "")
	if rec.Code == 302 {
		loc, _ := url.Parse(rec.Header().Get("Location"))
		pend, ok := a.OIDC().Runtime().GetPending(loc.Query().Get("pending"))
		t.Fatalf("accepted oversized unauthenticated SAML relay payload, retained=%v bytes=%d", ok, len(pend.RelayState))
	}
}

func TestOIDCRejectsOversizedContextBeforeCookieReuse(t *testing.T) {
	a, h := bootOIDC(t)
	reviewUser(t, a, "")
	cl := a.Store().Load().ClientsByClientID["app-1"]
	cl.PreConsent = true
	value, _ := json.Marshal(cl)
	reviewApply(t, a, model.Operation{Op: model.OpUpdate, Target: model.Target{Kind: model.TargetClient, ID: "app-1"}, Value: value})
	sess := a.OIDC().Runtime().PutSession(oidc.LoginSession{UserID: "u1", Username: "alice", Expires: time.Now().Add(time.Hour)})
	for _, field := range []string{"state", "nonce"} {
		query := url.Values{"response_type": {"code"}, "client_id": {"app-1"}, "redirect_uri": {"https://sut.example.net/cb"}, "code_challenge": {strings.Repeat("A", 43)}, "code_challenge_method": {"S256"}, field: {strings.Repeat("x", 4097)}}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/oauth2/authorize?"+query.Encode(), nil)
		req.AddCookie(&http.Cookie{Name: oidc.CookieLogin, Value: sess.ID})
		h.ServeHTTP(rec, req)
		if rec.Code != 400 {
			t.Fatal("oversized OIDC context accepted")
		}
	}
}

func TestIntegrationReviewOAuthBasicEncodedCredentials(t *testing.T) {
	a, h := bootOIDC(t)
	reviewUser(t, a, "")
	file := filepath.Join(t.TempDir(), "secret")
	secret := "p+a:ss%word"
	if err := os.WriteFile(file, []byte(secret), 0600); err != nil {
		t.Fatal(err)
	}
	cl := model.Client{ID: "app-1", ClientID: "app-1", SecretRef: file, RedirectURIs: []string{"https://sut.example.net/cb"}}
	b, _ := json.Marshal(cl)
	reviewApply(t, a, model.Operation{Op: model.OpUpdate, Target: model.Target{Kind: model.TargetClient, ID: "app-1"}, Value: b})
	a.OIDC().Runtime().PutRefresh(oidc.Refresh{Generation: a.Store().Load().Generation, Token: "refresh", ClientID: "app-1", UserID: "u1", Scope: "openid", Expires: time.Now().Add(time.Hour)})
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"refresh"}}
	req := httptest.NewRequest("POST", "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape("app-1"), url.QueryEscape(secret))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("RFC6749 encoded Basic credentials rejected: %d %s", rec.Code, rec.Body.String())
	}
}
