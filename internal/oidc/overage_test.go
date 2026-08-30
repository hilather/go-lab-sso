package oidc_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
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

func seedGroups(t *testing.T, a *app.App, n int) {
	t.Helper()
	ops := make([]model.Operation, 0, n+1)
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("g-%03d", i)
		ids = append(ids, id)
		val, _ := json.Marshal(model.Group{ID: id, Name: "n-" + id})
		ops = append(ops, model.Operation{Op: model.OpAdd, Target: model.Target{Kind: model.TargetGroup, ID: id}, Value: val})
	}
	uval, _ := json.Marshal(model.User{
		ID: "u1", Username: "alice", Email: "alice@lab.example.net",
		PasswordRef: "testdata/secrets/users/alice.password", GroupIDs: ids,
	})
	ops = append(ops, model.Operation{Op: model.OpAdd, Target: model.Target{Kind: model.TargetUser, ID: "u1"}, Value: uval})
	if _, err := a.Apply(auth.AdminActor(), app.ChangeIn{
		ExpectedRevision: a.Status().RuntimeRevision, Reason: "groups", Operations: ops,
	}); err != nil {
		t.Fatal(err)
	}
}

func exchangeCode(t *testing.T, h http.Handler, path, code string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {"https://sut.example.net/cb"}, "code_verifier": {"verifier-value-1234567890"},
		"client_id": {"app-1"},
	}
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func plantCode(a *app.App, code, scope string) {
	a.OIDC().Runtime().PutCode(oidc.AuthCode{
		Code: code, ClientID: "app-1", RedirectURI: "https://sut.example.net/cb",
		UserID: "u1", Username: "alice", Scope: scope, Challenge: s256("verifier-value-1234567890"),
		Expires: time.Now().Add(time.Minute),
	})
}

func jwtMap(t *testing.T, tok string) map[string]any {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) < 2 {
		t.Fatalf("not a jwt: %s", tok)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

func groupSlice(v any) []string {
	arr, _ := v.([]any)
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func TestGenericOverageEmbedAndCap(t *testing.T) {
	a, h := bootOIDC(t)
	seedGroups(t, a, 200)
	plantCode(a, "g200", "openid groups")
	rec := exchangeCode(t, h, "/oauth2/token", "g200")
	if rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	var tok map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &tok)
	idc := jwtMap(t, tok["id_token"].(string))
	acc := jwtMap(t, tok["access_token"].(string))
	if len(groupSlice(idc["groups"])) != 200 || len(groupSlice(acc["groups"])) != 200 {
		t.Fatalf("want 200 groups id=%d access=%d", len(groupSlice(idc["groups"])), len(groupSlice(acc["groups"])))
	}

	a2, h2 := bootOIDC(t)
	seedGroups(t, a2, 201)
	plantCode(a2, "g201", "openid groups")
	rec = exchangeCode(t, h2, "/oauth2/token", "g201")
	if rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &tok)
	idc = jwtMap(t, tok["id_token"].(string))
	acc = jwtMap(t, tok["access_token"].(string))
	if len(groupSlice(idc["groups"])) != 200 || len(groupSlice(acc["groups"])) != 200 {
		t.Fatalf("cap omit want 200 got id=%d access=%d", len(groupSlice(idc["groups"])), len(groupSlice(acc["groups"])))
	}
	warned := false
	for _, e := range a2.Audit().Recent() {
		if e.Capability == "sso.oidc.overage" && strings.Contains(e.Reason, "generic overage") {
			warned = true
		}
	}
	if !warned {
		t.Fatal("expected generic overage audit warning")
	}
	req := httptest.NewRequest("GET", "/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tok["access_token"].(string))
	rec = httptest.NewRecorder()
	h2.ServeHTTP(rec, req)
	var ui map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &ui)
	if len(groupSlice(ui["groups"])) != 200 {
		t.Fatalf("userinfo groups %d", len(groupSlice(ui["groups"])))
	}
}

func TestEntraOverageClaimNamesOnAllTokens(t *testing.T) {
	a, h := bootOIDC(t)
	swapVendor(t, a, "entra")
	seedGroups(t, a, 201)
	plantCode(a, "e201", "openid groups")
	rec := exchangeCode(t, h, "/oauth2/v2.0/token", "e201")
	if rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	assertNoVendorHosts(t, rec.Body.String())
	var tok map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &tok)
	for _, name := range []string{"id_token", "access_token"} {
		c := jwtMap(t, tok[name].(string))
		if c["groups"] != nil {
			t.Fatalf("%s still has groups %v", name, c["groups"])
		}
		names, _ := c["_claim_names"].(map[string]any)
		if names["groups"] != "src1" {
			t.Fatalf("%s _claim_names %v", name, c["_claim_names"])
		}
		src, _ := c["_claim_sources"].(map[string]any)
		src1, _ := src["src1"].(map[string]any)
		ep, _ := src1["endpoint"].(string)
		want := "https://lab.example.net/v1.0/users/u1/getMemberGroups"
		if ep != want {
			t.Fatalf("%s endpoint %q", name, ep)
		}
		if strings.Contains(ep, "graph.microsoft.com") {
			t.Fatal("graph host leaked")
		}
	}
	req := httptest.NewRequest("GET", "/oauth2/v2.0/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tok["access_token"].(string))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assertNoVendorHosts(t, rec.Body.String())
	if !strings.Contains(rec.Body.String(), "_claim_names") || strings.Contains(rec.Body.String(), `"groups":[`) {
		t.Fatalf("userinfo %s", rec.Body)
	}

	a2, h2 := bootOIDC(t)
	swapVendor(t, a2, "entra")
	seedGroups(t, a2, 200)
	plantCode(a2, "e200", "openid groups")
	rec = exchangeCode(t, h2, "/oauth2/v2.0/token", "e200")
	if rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &tok)
	idc := jwtMap(t, tok["id_token"].(string))
	acc := jwtMap(t, tok["access_token"].(string))
	if len(groupSlice(idc["groups"])) != 200 || len(groupSlice(acc["groups"])) != 200 {
		t.Fatalf("entra embed id=%d access=%d", len(groupSlice(idc["groups"])), len(groupSlice(acc["groups"])))
	}
	if idc["oid"] != "u1" || idc["tid"] != vendor.DefaultTenantID {
		t.Fatalf("clothes claims %v", idc)
	}
}

func TestOktaOverageFailsToken(t *testing.T) {
	a, h := bootOIDC(t)
	swapVendor(t, a, "okta")
	seedGroups(t, a, 99)
	plantCode(a, "o99", "openid groups")
	rec := exchangeCode(t, h, "/oauth2/default/v1/token", "o99")
	if rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	var tok map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &tok)
	if len(groupSlice(jwtMap(t, tok["access_token"].(string))["groups"])) != 99 {
		t.Fatal("okta 99 should embed")
	}

	a2, h2 := bootOIDC(t)
	swapVendor(t, a2, "okta")
	seedGroups(t, a2, 100)
	plantCode(a2, "o100", "openid groups")
	rec = exchangeCode(t, h2, "/oauth2/default/v1/token", "o100")
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "invalid_grant") {
		t.Fatalf("okta 100 want token fail, got %d %s", rec.Code, rec.Body)
	}
	if err := a2.PauseToken(auth.AdminActor()); err != nil {
		t.Fatal(err)
	}
	if !a2.OIDC().Runtime().Paused() {
		t.Fatal("pause overlay must stay independent of overage fail")
	}
}

func TestEntraGraphStubAuth(t *testing.T) {
	a, h := bootOIDC(t)
	swapVendor(t, a, "entra")
	seedGroups(t, a, 3)
	plantCode(a, "stub", "openid groups")
	rec := exchangeCode(t, h, "/oauth2/v2.0/token", "stub")
	if rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	var tok map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &tok)
	access := tok["access_token"].(string)

	req := httptest.NewRequest("POST", "/v1.0/users/u1/getMemberGroups", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("stub %d %s", rec.Code, rec.Body)
	}
	assertNoVendorHosts(t, rec.Body.String())
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if len(groupSlice(body["value"])) != 3 {
		t.Fatalf("stub value %v", body)
	}

	req = httptest.NewRequest("POST", "/v1.0/users/other/getMemberGroups", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("oid mismatch want 401 got %d", rec.Code)
	}
	req = httptest.NewRequest("POST", "/v1.0/users/u1/getMemberGroups", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("no bearer want 401 got %d", rec.Code)
	}

	swapVendor(t, a, "generic")
	req = httptest.NewRequest("POST", "/v1.0/users/u1/getMemberGroups", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 404 {
		t.Fatalf("inactive clothes stub want 404 got %d", rec.Code)
	}
}

func TestEntraStubOffFailsOverage(t *testing.T) {
	a, h := bootOIDC(t)
	swapVendor(t, a, "entra")
	off := false
	if _, err := a.SetOverage(auth.AdminActor(), app.SetOverageIn{
		EntraGraphStub: &off, ExpectedRevision: a.Status().RuntimeRevision, Reason: "stub off",
	}); err != nil {
		t.Fatal(err)
	}
	if a.Store().Load().Canonical.Spec.GroupOverage.EntraGraphStub {
		t.Fatal("stub still on")
	}
	seedGroups(t, a, 201)
	plantCode(a, "nostub", "openid groups")
	rec := exchangeCode(t, h, "/oauth2/v2.0/token", "nostub")
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "invalid_grant") || !strings.Contains(rec.Body.String(), "error_codes") {
		t.Fatalf("stub-off overage want clothed fail, got %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "_claim_names") || strings.Contains(rec.Body.String(), "graph.microsoft.com") {
		t.Fatal(rec.Body.String())
	}
}

func TestOverageRefreshMatchesWriteTokens(t *testing.T) {
	a, h := bootOIDC(t)
	seedGroups(t, a, 2)
	plantCode(a, "ref", "openid groups")
	rec := exchangeCode(t, h, "/oauth2/token", "ref")
	if rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	var tok map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &tok)
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)}, "client_id": {"app-1"}}
	req := httptest.NewRequest("POST", "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &tok)
	if len(groupSlice(jwtMap(t, tok["access_token"].(string))["groups"])) != 2 {
		t.Fatal("refresh missing groups on access token")
	}
}

func TestOverageScopeGated(t *testing.T) {
	a, h := bootOIDC(t)
	seedGroups(t, a, 3)
	plantCode(a, "noscope", "openid")
	rec := exchangeCode(t, h, "/oauth2/token", "noscope")
	if rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	var tok map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &tok)
	if jwtMap(t, tok["access_token"].(string))["groups"] != nil {
		t.Fatal("groups without scope")
	}
}

func TestGenericCapMatrix(t *testing.T) {
	a, h := bootOIDC(t)
	cap := 2
	if _, err := a.SetOverage(auth.AdminActor(), app.SetOverageIn{
		GenericCap: &cap, ExpectedRevision: a.Status().RuntimeRevision, Reason: "cap",
	}); err != nil {
		t.Fatal(err)
	}
	if a.Store().Load().Canonical.Spec.GroupOverage.GenericCap != 2 {
		t.Fatal("genericCap not set")
	}
	seedGroups(t, a, 3)
	plantCode(a, "cap2", "openid groups")
	rec := exchangeCode(t, h, "/oauth2/token", "cap2")
	if rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	var tok map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &tok)
	if n := len(groupSlice(jwtMap(t, tok["access_token"].(string))["groups"])); n != 2 {
		t.Fatalf("cap 2 want 2 groups got %d", n)
	}
}
