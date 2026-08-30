package oidc_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/hilather/go-lab-sso/internal/app"
	"github.com/hilather/go-lab-sso/internal/auth"
	"github.com/hilather/go-lab-sso/internal/compiler"
	"github.com/hilather/go-lab-sso/internal/config"
	"github.com/hilather/go-lab-sso/internal/model"
	"github.com/hilather/go-lab-sso/internal/oidc"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

func bootOIDC(t *testing.T) (*app.App, http.Handler) {
	t.Helper()
	root := repoRoot(t)
	dir := t.TempDir()
	boot := filepath.Join(dir, "config.yaml")
	src, err := os.ReadFile(filepath.Join(root, "testdata/config/valid/minimal.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(boot, src, 0o644); err != nil {
		t.Fatal(err)
	}
	a := app.New(app.Options{BootstrapPath: boot, BaseDir: root})
	if _, err := a.InstallBootstrapFile(); err != nil {
		t.Fatal(err)
	}
	val, _ := json.Marshal(model.Client{
		ID: "app-1", ClientID: "app-1", Public: true,
		RedirectURIs: []string{"https://sut.example.net/cb"},
	})
	if _, err := a.Apply(auth.AdminActor(), app.ChangeIn{
		ExpectedRevision: a.Status().RuntimeRevision,
		Reason:           "client",
		Operations: []model.Operation{{
			Op: model.OpAdd, Target: model.Target{Kind: model.TargetClient, ID: "app-1"}, Value: val,
		}},
	}); err != nil {
		t.Fatal(err)
	}
	return a, a.HTTPSHandler()
}

func TestDiscoveryISS(t *testing.T) {
	_, h := bootOIDC(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/.well-known/openid-configuration", nil))
	if rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	var doc map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &doc)
	if doc["issuer"] != "https://lab.example.net" {
		t.Fatalf("iss %v", doc["issuer"])
	}
}

func TestJWKSPublicOnly(t *testing.T) {
	_, h := bootOIDC(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/oauth2/jwks", nil))
	if rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"d"`) {
		t.Fatal("JWKS leaked private exponent")
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 1 || !set.Keys[0].IsPublic() {
		t.Fatal("expected one public JWK")
	}
}

func TestPKCEPlainRejected(t *testing.T) {
	_, h := bootOIDC(t)
	u := "/oauth2/authorize?response_type=code&client_id=app-1&redirect_uri=" + url.QueryEscape("https://sut.example.net/cb") + "&code_challenge=abc&code_challenge_method=plain"
	req := httptest.NewRequest("GET", u, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 302 {
		t.Fatalf("code %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "error=invalid_request") || !strings.Contains(strings.ToLower(loc), "plain") {
		t.Fatal(loc)
	}
}

func TestAuthorizeWithoutSessionRedirectsLogin(t *testing.T) {
	a, h := bootOIDC(t)
	u := "/oauth2/authorize?response_type=code&client_id=app-1&redirect_uri=" + url.QueryEscape("https://sut.example.net/cb") + "&code_challenge=abc&code_challenge_method=S256&state=st"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", u, nil))
	if rec.Code != 302 {
		t.Fatalf("code %d body=%s", rec.Code, rec.Body)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://lab.example.net/login?pending=") {
		t.Fatal(loc)
	}
	id := strings.TrimPrefix(loc, "https://lab.example.net/login?pending=")
	if _, ok := a.OIDC().Runtime().GetPending(id); !ok {
		t.Fatal("pending not persisted")
	}
}

func TestMissingSigningKeyDoesNotListen(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "testdata/config/valid/minimal.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	s := strings.Replace(string(raw), "testdata/secrets/oidc/signing.pem", "testdata/secrets/oidc/missing.pem", 1)
	_, err = config.Load([]byte(s), config.Options{BaseDir: root})
	if err == nil {
		t.Fatal("load should fail on missing signing key")
	}
	doc, err := config.LoadFile(filepath.Join(root, "testdata/config/valid/minimal.yaml"), config.Options{BaseDir: root})
	if err != nil {
		t.Fatal(err)
	}
	doc.Spec.Signing.KeyRef = "testdata/secrets/oidc/missing.pem"
	if _, err := compiler.Compile(doc, compiler.Options{BaseDir: root}); err == nil {
		t.Fatal("compile must fail closed without signing key")
	}
}

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestRefreshGrant(t *testing.T) {
	a, h := bootOIDC(t)
	verifier := "verifier-value-1234567890"
	a.OIDC().Runtime().PutCode(oidc.AuthCode{
		Code: "code1", ClientID: "app-1", RedirectURI: "https://sut.example.net/cb",
		UserID: "u1", Username: "alice", Scope: "openid", Challenge: s256(verifier),
		Expires: time.Now().Add(time.Minute),
	})
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"code1"},
		"redirect_uri":  {"https://sut.example.net/cb"},
		"code_verifier": {verifier},
		"client_id":     {"app-1"},
	}
	req := httptest.NewRequest("POST", "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	var tok map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &tok)
	idTok, _ := tok["id_token"].(string)
	if idTok == "" {
		t.Fatal("missing id_token")
	}
	parts := strings.Split(idTok, ".")
	if len(parts) != 3 {
		t.Fatal("not a JWS")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	_ = json.Unmarshal(payload, &claims)
	if claims["iss"] != "https://lab.example.net" {
		t.Fatalf("iss %v", claims["iss"])
	}
	parsed, err := jwt.ParseSigned(idTok, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	jwksRec := httptest.NewRecorder()
	h.ServeHTTP(jwksRec, httptest.NewRequest("GET", "/oauth2/jwks", nil))
	var set jose.JSONWebKeySet
	_ = json.Unmarshal(jwksRec.Body.Bytes(), &set)
	var out jwt.Claims
	if err := parsed.Claims(set.Keys[0].Key, &out); err != nil {
		t.Fatal(err)
	}
	if out.Issuer != "https://lab.example.net" {
		t.Fatal(out.Issuer)
	}
	ref, _ := tok["refresh_token"].(string)
	form2 := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {ref}, "client_id": {"app-1"}}
	req2 := httptest.NewRequest("POST", "/oauth2/token", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != 200 {
		t.Fatal(rec2.Body.String())
	}
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, req2)
	if rec3.Code == 200 {
		t.Fatal("spent refresh token must not be reusable")
	}
}

func TestAuthorizeSnapshotRace(t *testing.T) {
	a, h := bootOIDC(t)
	u := "/oauth2/authorize?response_type=code&client_id=app-1&redirect_uri=" + url.QueryEscape("https://sut.example.net/cb") + "&code_challenge=abc&code_challenge_method=S256"
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest("GET", u, nil))
			if rec.Code != 302 && rec.Code != 400 {
				t.Errorf("unexpected %d", rec.Code)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			_, _ = a.Reset(auth.AdminActor(), app.ResetIn{Reason: "race"})
		}
	}()
	wg.Wait()
}

func TestPauseTokenLeavesDiscoveryUp(t *testing.T) {
	a, h := bootOIDC(t)
	if err := a.PauseToken(auth.AdminActor()); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/.well-known/openid-configuration", nil))
	if rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	req := httptest.NewRequest("POST", "/oauth2/token", strings.NewReader("grant_type=authorization_code"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	if rec2.Code != 503 {
		t.Fatalf("paused token want 503 got %d", rec2.Code)
	}
	_ = io.Discard
}

func TestPKCEPlainUnregisteredRedirectIs400(t *testing.T) {
	_, h := bootOIDC(t)
	u := "/oauth2/authorize?response_type=code&client_id=app-1&redirect_uri=" + url.QueryEscape("https://evil.example/cb") + "&code_challenge=abc&code_challenge_method=plain"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", u, nil))
	if rec.Code != 400 {
		t.Fatalf("unregistered redirect must not 302, got %d loc=%s", rec.Code, rec.Header().Get("Location"))
	}
}

func TestTokenBindsClientID(t *testing.T) {
	a, h := bootOIDC(t)
	val, _ := json.Marshal(model.Client{ID: "app-2", ClientID: "app-2", Public: true, RedirectURIs: []string{"https://other.example/cb"}})
	if _, err := a.Apply(auth.AdminActor(), app.ChangeIn{
		ExpectedRevision: a.Status().RuntimeRevision, Reason: "c2",
		Operations: []model.Operation{{Op: model.OpAdd, Target: model.Target{Kind: model.TargetClient, ID: "app-2"}, Value: val}},
	}); err != nil {
		t.Fatal(err)
	}
	verifier := "verifier-value-1234567890"
	a.OIDC().Runtime().PutCode(oidc.AuthCode{
		Code: "code2", ClientID: "app-1", RedirectURI: "https://sut.example.net/cb",
		UserID: "u1", Username: "alice", Scope: "openid", Challenge: s256(verifier),
		Expires: time.Now().Add(time.Minute),
	})
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {"code2"},
		"redirect_uri": {"https://sut.example.net/cb"}, "code_verifier": {verifier},
		"client_id": {"app-2"},
	}
	req := httptest.NewRequest("POST", "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == 200 {
		t.Fatal("code must not redeem as a different client")
	}
}

func TestUserInfoRejectsIDToken(t *testing.T) {
	a, h := bootOIDC(t)
	verifier := "verifier-value-1234567890"
	a.OIDC().Runtime().PutCode(oidc.AuthCode{
		Code: "code3", ClientID: "app-1", RedirectURI: "https://sut.example.net/cb",
		UserID: "u1", Username: "alice", Scope: "openid", Challenge: s256(verifier),
		Expires: time.Now().Add(time.Minute),
	})
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {"code3"},
		"redirect_uri": {"https://sut.example.net/cb"}, "code_verifier": {verifier},
		"client_id": {"app-1"},
	}
	req := httptest.NewRequest("POST", "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	var tok map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &tok)
	req = httptest.NewRequest("GET", "/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tok["id_token"].(string))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("id_token at userinfo want 401 got %d", rec.Code)
	}
	req = httptest.NewRequest("GET", "/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tok["access_token"].(string))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("access token userinfo %d %s", rec.Code, rec.Body)
	}
}

func TestInjectErrorHitsAuthorize(t *testing.T) {
	a, h := bootOIDC(t)
	if err := a.InjectError(auth.AdminActor(), "temporarily_unavailable"); err != nil {
		t.Fatal(err)
	}
	u := "/oauth2/authorize?response_type=code&client_id=app-1&redirect_uri=" + url.QueryEscape("https://sut.example.net/cb") + "&code_challenge=abc&code_challenge_method=S256"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", u, nil))
	if rec.Code != 302 || !strings.Contains(rec.Header().Get("Location"), "temporarily_unavailable") {
		t.Fatalf("inject missed authorize: %d %s", rec.Code, rec.Header().Get("Location"))
	}
}

func TestExpireSessionKillsCodes(t *testing.T) {
	a, _ := bootOIDC(t)
	sess := a.OIDC().Runtime().PutSession(oidc.LoginSession{UserID: "u1", Username: "alice", Expires: time.Now().Add(time.Hour)})
	a.OIDC().Runtime().PutCode(oidc.AuthCode{
		Code: "killme", ClientID: "app-1", UserID: "u1", Expires: time.Now().Add(time.Minute),
	})
	if err := a.ExpireSession(auth.AdminActor(), sess.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.OIDC().Runtime().TakeCode("killme"); ok {
		t.Fatal("expire session must drop associated codes")
	}
}

func TestOIDCDisabled404(t *testing.T) {
	a, h := bootOIDC(t)
	val, _ := json.Marshal(model.Protocols{OIDC: model.ProtocolToggle{Enabled: model.Ptr(false)}, SAML: model.ProtocolToggle{Enabled: model.Ptr(false)}, WSFed: model.ProtocolToggle{Enabled: model.Ptr(false)}})
	if _, err := a.Apply(auth.AdminActor(), app.ChangeIn{
		ExpectedRevision: a.Status().RuntimeRevision, Reason: "off",
		Operations: []model.Operation{{Op: model.OpUpdate, Target: model.Target{Kind: model.TargetProtocols}, Value: val}},
	}); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/.well-known/openid-configuration", nil))
	if rec.Code != 404 {
		t.Fatalf("disabled oidc want 404 got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/oauth2/logout", nil))
	if rec.Code != 404 {
		t.Fatalf("disabled logout want 404 got %d", rec.Code)
	}
}

func TestLogoutPostRedirect(t *testing.T) {
	_, h := bootOIDC(t)
	u := "/oauth2/logout?post_logout_redirect_uri=" + url.QueryEscape("https://sut.example.net/cb") + "&state=bye"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", u, nil))
	if rec.Code != 302 || !strings.Contains(rec.Header().Get("Location"), "https://sut.example.net/cb") || !strings.Contains(rec.Header().Get("Location"), "state=bye") {
		t.Fatalf("logout %d %s", rec.Code, rec.Header().Get("Location"))
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/oauth2/logout?post_logout_redirect_uri="+url.QueryEscape("https://evil.example/cb"), nil))
	if rec.Code != 400 {
		t.Fatalf("unregistered logout redirect want 400 got %d", rec.Code)
	}
}

func TestYAMLMFAForceFailBlocksAuthorize(t *testing.T) {
	a, h := bootOIDC(t)
	val, _ := json.Marshal(model.Auth{MFA: model.MFA{Mode: "force-fail"}})
	if _, err := a.Apply(auth.AdminActor(), app.ChangeIn{
		ExpectedRevision: a.Status().RuntimeRevision, Reason: "mfa",
		Operations: []model.Operation{{Op: model.OpUpdate, Target: model.Target{Kind: model.TargetAuth}, Value: val}},
	}); err != nil {
		t.Fatal(err)
	}
	sess := a.OIDC().Runtime().PutSession(oidc.LoginSession{UserID: "u1", Username: "alice", Expires: time.Now().Add(time.Hour)})
	u := "/oauth2/authorize?response_type=code&client_id=app-1&redirect_uri=" + url.QueryEscape("https://sut.example.net/cb") + "&code_challenge=abc&code_challenge_method=S256"
	req := httptest.NewRequest("GET", u, nil)
	req.AddCookie(&http.Cookie{Name: oidc.CookieLogin, Value: sess.ID})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 302 || !strings.Contains(rec.Header().Get("Location"), "access_denied") {
		t.Fatalf("yaml force-fail want deny, got %d %s", rec.Code, rec.Header().Get("Location"))
	}
}

func TestUserInfoEmitsScopedClaims(t *testing.T) {
	a, h := bootOIDC(t)
	gval, _ := json.Marshal(model.Group{ID: "g1", Name: "lab"})
	if _, err := a.Apply(auth.AdminActor(), app.ChangeIn{
		ExpectedRevision: a.Status().RuntimeRevision, Reason: "g",
		Operations: []model.Operation{{Op: model.OpAdd, Target: model.Target{Kind: model.TargetGroup, ID: "g1"}, Value: gval}},
	}); err != nil {
		t.Fatal(err)
	}
	uval, _ := json.Marshal(model.User{ID: "u1", Username: "alice", Email: "alice@lab.example.net", PasswordRef: "testdata/secrets/users/alice.password", GroupIDs: []string{"g1"}})
	if _, err := a.Apply(auth.AdminActor(), app.ChangeIn{
		ExpectedRevision: a.Status().RuntimeRevision, Reason: "u",
		Operations: []model.Operation{{Op: model.OpAdd, Target: model.Target{Kind: model.TargetUser, ID: "u1"}, Value: uval}},
	}); err != nil {
		t.Fatal(err)
	}
	verifier := "verifier-value-1234567890"
	a.OIDC().Runtime().PutCode(oidc.AuthCode{
		Code: "code-claims", ClientID: "app-1", RedirectURI: "https://sut.example.net/cb",
		UserID: "u1", Username: "alice", Scope: "openid email groups", Challenge: s256(verifier),
		Expires: time.Now().Add(time.Minute),
	})
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {"code-claims"},
		"redirect_uri": {"https://sut.example.net/cb"}, "code_verifier": {verifier},
		"client_id": {"app-1"},
	}
	req := httptest.NewRequest("POST", "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	var tok map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &tok)
	parts := strings.Split(tok["id_token"].(string), ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	_ = json.Unmarshal(payload, &claims)
	if claims["email"] != "alice@lab.example.net" {
		t.Fatalf("id_token email %v", claims["email"])
	}
	req = httptest.NewRequest("GET", "/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tok["access_token"].(string))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "alice@lab.example.net") || !strings.Contains(rec.Body.String(), "lab") {
		t.Fatalf("userinfo %d %s", rec.Code, rec.Body)
	}
}

func TestLoggedInAuthorizeWithoutPreConsentGoesToConsent(t *testing.T) {
	a, h := bootOIDC(t)
	sess := a.OIDC().Runtime().PutSession(oidc.LoginSession{UserID: "u1", Username: "alice", Expires: time.Now().Add(time.Hour)})
	u := "/oauth2/authorize?response_type=code&client_id=app-1&redirect_uri=" + url.QueryEscape("https://sut.example.net/cb") + "&code_challenge=abc&code_challenge_method=S256"
	req := httptest.NewRequest("GET", u, nil)
	req.AddCookie(&http.Cookie{Name: oidc.CookieLogin, Value: sess.ID})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 302 || !strings.Contains(rec.Header().Get("Location"), "/consent?pending=") {
		t.Fatalf("want consent, got %d %s", rec.Code, rec.Header().Get("Location"))
	}
}
