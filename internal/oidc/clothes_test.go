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
	"github.com/hilather/go-lab-sso/internal/vendor"
)

func swapVendor(t *testing.T, a *app.App, vendorName string) {
	t.Helper()
	if _, err := a.SwapVendor(auth.AdminActor(), app.SwapVendorIn{
		Vendor: vendorName, ExpectedRevision: a.Status().RuntimeRevision, Reason: "clothes",
	}); err != nil {
		t.Fatal(err)
	}
}

func discoveryDoc(t *testing.T, h http.Handler, path string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	var doc map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &doc)
	return rec.Code, doc
}

func assertNoVendorHosts(t *testing.T, blob string) {
	t.Helper()
	for _, host := range vendor.ForbiddenHosts {
		if strings.Contains(blob, host) {
			t.Fatalf("discovery/token JSON contains hostname %s", host)
		}
	}
}

func TestClothesDiscoveryISSStable(t *testing.T) {
	a, h := bootOIDC(t)
	wantISS := "https://lab.example.net"
	for _, v := range []string{"generic", "entra", "okta"} {
		if v != "generic" {
			swapVendor(t, a, v)
		}
		code, doc := discoveryDoc(t, h, "/.well-known/openid-configuration")
		if code != 200 {
			t.Fatalf("%s discovery %d", v, code)
		}
		if doc["issuer"] != wantISS {
			t.Fatalf("%s iss %v", v, doc["issuer"])
		}
		b, _ := json.Marshal(doc)
		assertNoVendorHosts(t, string(b))
		prefix := map[string]string{
			"generic": "/oauth2",
			"entra":   "/oauth2/v2.0",
			"okta":    "/oauth2/default/v1",
		}[v]
		want := map[string]string{
			"authorization_endpoint": wantISS + prefix + "/authorize",
			"token_endpoint":         wantISS + prefix + "/token",
			"jwks_uri":               wantISS + prefix + "/jwks",
			"userinfo_endpoint":      wantISS + prefix + "/userinfo",
			"end_session_endpoint":   wantISS + prefix + "/logout",
		}
		for k, exp := range want {
			if doc[k] != exp {
				t.Fatalf("%s %s=%v want %s", v, k, doc[k], exp)
			}
		}
	}
}

func TestClothesInactivePaths404(t *testing.T) {
	a, h := bootOIDC(t)
	swapVendor(t, a, "entra")
	for _, path := range []string{"/oauth2/authorize", "/oauth2/token", "/oauth2/jwks", "/oauth2/userinfo", "/oauth2/logout",
		"/oauth2/default/v1/authorize", "/oauth2/default/v1/jwks"} {
		rec := httptest.NewRecorder()
		method := "GET"
		if strings.HasSuffix(path, "/token") {
			method = "POST"
		}
		h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
		if rec.Code != 404 {
			t.Fatalf("%s want 404 got %d %s", path, rec.Code, rec.Body)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/oauth2/v2.0/jwks", nil))
	if rec.Code != 200 {
		t.Fatalf("entra jwks %d %s", rec.Code, rec.Body)
	}
	code, doc := discoveryDoc(t, h, "/00000000-0000-0000-0000-000000000001/v2.0/.well-known/openid-configuration")
	if code != 200 || doc["issuer"] != "https://lab.example.net" {
		t.Fatalf("entra alias %d %v", code, doc)
	}
	code, _ = discoveryDoc(t, h, "/wrong-tid/v2.0/.well-known/openid-configuration")
	if code != 404 {
		t.Fatalf("wrong tid want 404 got %d", code)
	}
	custom := "11111111-1111-1111-1111-111111111111"
	if _, err := a.SwapVendor(auth.AdminActor(), app.SwapVendorIn{
		Vendor: "entra", TenantID: &custom, ExpectedRevision: a.Status().RuntimeRevision, Reason: "tid",
	}); err != nil {
		t.Fatal(err)
	}
	code, doc = discoveryDoc(t, h, "/"+custom+"/v2.0/.well-known/openid-configuration")
	if code != 200 || doc["issuer"] != "https://lab.example.net" {
		t.Fatalf("custom tid alias %d %v", code, doc)
	}
	code, _ = discoveryDoc(t, h, "/00000000-0000-0000-0000-000000000001/v2.0/.well-known/openid-configuration")
	if code != 404 {
		t.Fatalf("default tid after custom want 404 got %d", code)
	}
}

func TestClothesEntraClaimsAndTokenError(t *testing.T) {
	a, h := bootOIDC(t)
	swapVendor(t, a, "entra")
	a.OIDC().Runtime().PutCode(oidc.AuthCode{
		Code: "entra-code", ClientID: "app-1", RedirectURI: "https://sut.example.net/cb",
		UserID: "u1", Username: "alice", Scope: "openid groups", Challenge: s256("verifier-value-1234567890"),
		Expires: time.Now().Add(time.Minute),
	})
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {"entra-code"},
		"redirect_uri": {"https://sut.example.net/cb"}, "code_verifier": {"verifier-value-1234567890"},
		"client_id": {"app-1"},
	}
	req := httptest.NewRequest("POST", "/oauth2/v2.0/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	assertNoVendorHosts(t, rec.Body.String())
	var tok map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &tok)
	parts := strings.Split(tok["id_token"].(string), ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	_ = json.Unmarshal(payload, &claims)
	if claims["iss"] != "https://lab.example.net" || claims["oid"] != "u1" || claims["tid"] != vendor.DefaultTenantID || claims["ver"] != "2.0" {
		t.Fatalf("id_token claims %v", claims)
	}
	req = httptest.NewRequest("GET", "/oauth2/v2.0/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tok["access_token"].(string))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"oid":"u1"`) || !strings.Contains(rec.Body.String(), `"ver":"2.0"`) {
		t.Fatalf("userinfo %d %s", rec.Code, rec.Body)
	}
	req = httptest.NewRequest("POST", "/oauth2/v2.0/token", strings.NewReader(url.Values{"grant_type": {"authorization_code"}, "code": {"gone"}, "redirect_uri": {"https://sut.example.net/cb"}, "client_id": {"app-1"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "error_codes") || !strings.Contains(rec.Body.String(), "trace_id") {
		t.Fatalf("entra token error %d %s", rec.Code, rec.Body)
	}
}

func TestClothesOktaAuthorizeAndLogout(t *testing.T) {
	a, h := bootOIDC(t)
	swapVendor(t, a, "okta")
	sess := a.OIDC().Runtime().PutSession(oidc.LoginSession{UserID: "u1", Username: "alice", Expires: time.Now().Add(time.Hour)})
	u := "/oauth2/default/v1/authorize?response_type=code&client_id=app-1&redirect_uri=" + url.QueryEscape("https://sut.example.net/cb") + "&code_challenge=abc&code_challenge_method=S256"
	req := httptest.NewRequest("GET", u, nil)
	req.AddCookie(&http.Cookie{Name: "labsso_okta", Value: sess.ID})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 302 || !strings.Contains(rec.Header().Get("Location"), "/consent?pending=") {
		t.Fatalf("okta authorize %d %s", rec.Code, rec.Header().Get("Location"))
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/oauth2/default/v1/logout", nil))
	if rec.Code != 200 || !strings.Contains(rec.Header().Get("Set-Cookie"), "labsso_okta") {
		t.Fatalf("okta logout %d %s", rec.Code, rec.Header().Get("Set-Cookie"))
	}
}

func TestClothesSwapPurgesCodesKeepsPause(t *testing.T) {
	a, h := bootOIDC(t)
	swapVendor(t, a, "entra")
	if err := a.PauseToken(auth.AdminActor()); err != nil {
		t.Fatal(err)
	}
	a.OIDC().Runtime().PutCode(oidc.AuthCode{
		Code: "planted", ClientID: "app-1", RedirectURI: "https://sut.example.net/cb",
		UserID: "u1", Username: "alice", Scope: "openid", Challenge: s256("v"),
		Expires: time.Now().Add(time.Minute),
	})
	swapVendor(t, a, "generic")
	if !a.OIDC().Runtime().Paused() {
		t.Fatal("pause overlay must survive clothes swap")
	}
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {"planted"},
		"redirect_uri": {"https://sut.example.net/cb"}, "code_verifier": {"v"}, "client_id": {"app-1"},
	}
	req := httptest.NewRequest("POST", "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 503 {
		t.Fatalf("paused token want 503 got %d %s", rec.Code, rec.Body)
	}
	if err := a.ResumeToken(auth.AdminActor()); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest("POST", "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "invalid_grant") {
		t.Fatalf("purged code want invalid_grant, got %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "error_codes") {
		t.Fatal("generic token error must stay RFC 6749")
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/login", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "LabSSO login") || strings.Contains(rec.Body.String(), "Entra") {
		t.Fatalf("cookie/chrome after swap-to-generic %s", rec.Body)
	}
}

func TestClothesApplyAlsoPurges(t *testing.T) {
	a, h := bootOIDC(t)
	swapVendor(t, a, "entra")
	if err := a.PauseToken(auth.AdminActor()); err != nil {
		t.Fatal(err)
	}
	a.OIDC().Runtime().PutCode(oidc.AuthCode{
		Code: "apply-planted", ClientID: "app-1", RedirectURI: "https://sut.example.net/cb",
		UserID: "u1", Username: "alice", Scope: "openid", Challenge: s256("v"),
		Expires: time.Now().Add(time.Minute),
	})
	val, _ := json.Marshal(model.Profile{Vendor: "generic"})
	if _, err := a.Apply(auth.AdminActor(), app.ChangeIn{
		ExpectedRevision: a.Status().RuntimeRevision, Reason: "apply clothes",
		Operations: []model.Operation{{Op: model.OpUpdate, Target: model.Target{Kind: model.TargetProfile}, Value: val}},
	}); err != nil {
		t.Fatal(err)
	}
	if !a.OIDC().Runtime().Paused() {
		t.Fatal("apply vendor change must not Reset overlays")
	}
	if err := a.ResumeToken(auth.AdminActor()); err != nil {
		t.Fatal(err)
	}
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {"apply-planted"},
		"redirect_uri": {"https://sut.example.net/cb"}, "code_verifier": {"v"}, "client_id": {"app-1"},
	}
	req := httptest.NewRequest("POST", "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "invalid_grant") {
		t.Fatalf("apply purge want invalid_grant, got %d %s", rec.Code, rec.Body)
	}
}

func TestClothesApplyPingRejected(t *testing.T) {
	a, _ := bootOIDC(t)
	_, err := a.SwapVendor(auth.AdminActor(), app.SwapVendorIn{
		Vendor: "ping", ExpectedRevision: a.Status().RuntimeRevision, Reason: "nope",
	})
	if err == nil || !strings.Contains(err.Error(), "clothes not implemented") {
		t.Fatalf("want compile reject, got %v", err)
	}
}
