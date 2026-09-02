package loginui_test

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
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
	"github.com/hilather/go-lab-sso/internal/loginui"
	"github.com/hilather/go-lab-sso/internal/model"
	"github.com/hilather/go-lab-sso/internal/oidc"
	"github.com/hilather/go-lab-sso/internal/totp"
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

func bootLogin(t *testing.T, preConsent bool) *app.App {
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
	ops := []model.Operation{
		{
			Op: model.OpAdd, Target: model.Target{Kind: model.TargetClient, ID: "app-1"},
			Value: mustJSON(model.Client{ID: "app-1", ClientID: "app-1", Public: true, PreConsent: preConsent, RedirectURIs: []string{"https://sut.example.net/cb"}}),
		},
		{
			Op: model.OpAdd, Target: model.Target{Kind: model.TargetUser, ID: "u1"},
			Value: mustJSON(model.User{ID: "u1", Username: "alice", PasswordRef: "testdata/secrets/users/alice.password"}),
		},
	}
	if _, err := a.Apply(auth.AdminActor(), app.ChangeIn{ExpectedRevision: a.Status().RuntimeRevision, Reason: "dir", Operations: ops}); err != nil {
		t.Fatal(err)
	}
	return a
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func TestAuthorizeLoginConsentToken(t *testing.T) {
	a := bootLogin(t, true)
	h := a.HTTPSHandler()
	verifier := "pkce-verifier-value-1234567890"
	ch := pkceS256(verifier)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/oauth2/authorize?response_type=code&client_id=app-1&redirect_uri="+url.QueryEscape("https://sut.example.net/cb")+"&code_challenge="+ch+"&code_challenge_method=S256&state=st&scope=openid", nil))
	if rec.Code != 302 || !strings.Contains(rec.Header().Get("Location"), "/login?pending=") {
		t.Fatalf("authorize %d %s", rec.Code, rec.Header().Get("Location"))
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	pending := loc.Query().Get("pending")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/login?pending="+pending, nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Sign in") {
		t.Fatal(rec.Body.String())
	}
	crec := httptest.NewRecorder()
	h.ServeHTTP(crec, httptest.NewRequest("GET", "/consent?pending="+pending, nil))
	if !strings.Contains(crec.Body.String(), `name="approve" value="0"`) {
		t.Fatal("consent page must include Deny")
	}
	form := url.Values{"pending": {pending}, "username": {"alice"}, "password": {"alice-password"}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 302 {
		t.Fatalf("login %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Header().Get("Set-Cookie"), oidc.CookieLogin) {
		t.Fatal(rec.Header().Get("Set-Cookie"))
	}
	redir, _ := url.Parse(rec.Header().Get("Location"))
	code := redir.Query().Get("code")
	if code == "" {
		t.Fatal(rec.Header().Get("Location"))
	}
	tokForm := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://sut.example.net/cb"}, "code_verifier": {verifier}, "client_id": {"app-1"}}
	req = httptest.NewRequest("POST", "/oauth2/token", strings.NewReader(tokForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "id_token") {
		t.Fatal(rec.Body.String())
	}
	var tok map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &tok); err != nil {
		t.Fatal(err)
	}
	claims := jwtClaims(t, tok["id_token"].(string))
	if _, ok := claims["amr"]; ok {
		t.Fatalf("password-only must omit amr: %v", claims)
	}
	if _, ok := claims["acr"]; ok {
		t.Fatalf("password-only must omit acr: %v", claims)
	}
}

func TestForceConsentIgnoresPreConsent(t *testing.T) {
	a := bootLogin(t, true)
	if err := a.ForceConsent(auth.AdminActor(), true); err != nil {
		t.Fatal(err)
	}
	h := a.HTTPSHandler()
	ch := pkceS256("v")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/oauth2/authorize?response_type=code&client_id=app-1&redirect_uri="+url.QueryEscape("https://sut.example.net/cb")+"&code_challenge="+ch+"&code_challenge_method=S256", nil))
	pending, _ := url.Parse(rec.Header().Get("Location"))
	form := url.Values{"pending": {pending.Query().Get("pending")}, "username": {"alice"}, "password": {"alice-password"}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 302 || !strings.Contains(rec.Header().Get("Location"), "/consent") {
		t.Fatalf("force-consent must ignore PreConsent, got %s", rec.Header().Get("Location"))
	}
	sess := a.OIDC().Runtime().PutSession(oidc.LoginSession{UserID: "u1", Username: "alice"})
	req = httptest.NewRequest("GET", "/oauth2/authorize?response_type=code&client_id=app-1&redirect_uri="+url.QueryEscape("https://sut.example.net/cb")+"&code_challenge="+ch+"&code_challenge_method=S256", nil)
	req.AddCookie(&http.Cookie{Name: oidc.CookieLogin, Value: sess.ID})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 302 || !strings.Contains(rec.Header().Get("Location"), "/consent") {
		t.Fatalf("force-consent must ignore PreConsent on authorize shortcut, got %s", rec.Header().Get("Location"))
	}
}

func TestConsentWhenNotPreConsented(t *testing.T) {
	a := bootLogin(t, false)
	h := a.HTTPSHandler()
	ch := pkceS256("v")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/oauth2/authorize?response_type=code&client_id=app-1&redirect_uri="+url.QueryEscape("https://sut.example.net/cb")+"&code_challenge="+ch+"&code_challenge_method=S256", nil))
	pending, _ := url.Parse(rec.Header().Get("Location"))
	form := url.Values{"pending": {pending.Query().Get("pending")}, "username": {"alice"}, "password": {"alice-password"}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 302 || !strings.Contains(rec.Header().Get("Location"), "/consent") {
		t.Fatalf("want consent, got %s", rec.Header().Get("Location"))
	}
	cform := url.Values{"pending": {pending.Query().Get("pending")}, "approve": {"1"}}
	req = httptest.NewRequest("POST", "/consent", strings.NewReader(cform.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", rec.Header().Get("Set-Cookie"))
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	if rec2.Code != 302 || !strings.Contains(rec2.Header().Get("Location"), "code=") {
		t.Fatalf("consent %d %s", rec2.Code, rec2.Header().Get("Location"))
	}
}

func TestConsentDenyRedirectsClient(t *testing.T) {
	a := bootLogin(t, false)
	h := a.HTTPSHandler()
	ch := pkceS256("v")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/oauth2/authorize?response_type=code&client_id=app-1&redirect_uri="+url.QueryEscape("https://sut.example.net/cb")+"&code_challenge="+ch+"&code_challenge_method=S256&state=st", nil))
	pending, _ := url.Parse(rec.Header().Get("Location"))
	form := url.Values{"pending": {pending.Query().Get("pending")}, "username": {"alice"}, "password": {"alice-password"}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	dform := url.Values{"pending": {pending.Query().Get("pending")}, "approve": {"0"}}
	req = httptest.NewRequest("POST", "/consent", strings.NewReader(dform.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", rec.Header().Get("Set-Cookie"))
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	loc := rec2.Header().Get("Location")
	if rec2.Code != 302 || !strings.Contains(loc, "error=access_denied") || !strings.Contains(loc, "state=st") {
		t.Fatalf("deny %d %s", rec2.Code, loc)
	}
}

func clothedLoginToken(t *testing.T, vendorName, authorizePath, tokenPath, cookie string) {
	t.Helper()
	a := bootLogin(t, true)
	if _, err := a.SwapVendor(auth.AdminActor(), app.SwapVendorIn{
		Vendor: vendorName, ExpectedRevision: a.Status().RuntimeRevision, Reason: "clothes",
	}); err != nil {
		t.Fatal(err)
	}
	h := a.HTTPSHandler()
	verifier := "pkce-verifier-value-1234567890"
	ch := pkceS256(verifier)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", authorizePath+"?response_type=code&client_id=app-1&redirect_uri="+url.QueryEscape("https://sut.example.net/cb")+"&code_challenge="+ch+"&code_challenge_method=S256&state=st&scope=openid", nil))
	if rec.Code != 302 || !strings.Contains(rec.Header().Get("Location"), "/login?pending=") {
		t.Fatalf("%s authorize %d %s", vendorName, rec.Code, rec.Header().Get("Location"))
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	pending := loc.Query().Get("pending")
	form := url.Values{"pending": {pending}, "username": {"alice"}, "password": {"alice-password"}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 302 {
		t.Fatalf("%s login %d %s", vendorName, rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Header().Get("Set-Cookie"), cookie) {
		t.Fatalf("%s cookie %s", vendorName, rec.Header().Get("Set-Cookie"))
	}
	redir, _ := url.Parse(rec.Header().Get("Location"))
	code := redir.Query().Get("code")
	if code == "" {
		t.Fatal(rec.Header().Get("Location"))
	}
	tokForm := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://sut.example.net/cb"}, "code_verifier": {verifier}, "client_id": {"app-1"}}
	req = httptest.NewRequest("POST", tokenPath, strings.NewReader(tokForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "id_token") {
		t.Fatalf("%s token %d %s", vendorName, rec.Code, rec.Body)
	}
}

func TestEntraAuthorizeLoginToken(t *testing.T) {
	clothedLoginToken(t, "entra", "/oauth2/v2.0/authorize", "/oauth2/v2.0/token", "labsso_entra")
}

func TestOktaAuthorizeLoginToken(t *testing.T) {
	clothedLoginToken(t, "okta", "/oauth2/default/v1/authorize", "/oauth2/default/v1/token", "labsso_okta")
}

func TestDuoAuthorizeLoginToken(t *testing.T) {
	clothedLoginToken(t, "duo", "/oidc/lab/authorize", "/oidc/lab/token", "labsso_duo")
}

func TestSiteMinderAuthorizeLoginToken(t *testing.T) {
	clothedLoginToken(t, "siteminder", "/affwebservices/CASSO/oidc/lab/authorize", "/affwebservices/CASSO/oidc/lab/token", "labsso_siteminder")
}

func TestShibbolethAuthorizeLoginToken(t *testing.T) {
	clothedLoginToken(t, "shibboleth", "/idp/profile/oidc/authorize", "/idp/profile/oidc/token", "labsso_shibboleth")
}

func TestEntraConsentUsesClothesCookie(t *testing.T) {
	a := bootLogin(t, false)
	if _, err := a.SwapVendor(auth.AdminActor(), app.SwapVendorIn{
		Vendor: "entra", ExpectedRevision: a.Status().RuntimeRevision, Reason: "clothes",
	}); err != nil {
		t.Fatal(err)
	}
	h := a.HTTPSHandler()
	ch := pkceS256("v")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/oauth2/v2.0/authorize?response_type=code&client_id=app-1&redirect_uri="+url.QueryEscape("https://sut.example.net/cb")+"&code_challenge="+ch+"&code_challenge_method=S256", nil))
	pending, _ := url.Parse(rec.Header().Get("Location"))
	form := url.Values{"pending": {pending.Query().Get("pending")}, "username": {"alice"}, "password": {"alice-password"}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 302 || !strings.Contains(rec.Header().Get("Location"), "/consent") {
		t.Fatalf("want consent, got %s", rec.Header().Get("Location"))
	}
	if !strings.Contains(rec.Header().Get("Set-Cookie"), "labsso_entra") {
		t.Fatalf("cookie %s", rec.Header().Get("Set-Cookie"))
	}
	cform := url.Values{"pending": {pending.Query().Get("pending")}, "approve": {"1"}}
	req = httptest.NewRequest("POST", "/consent", strings.NewReader(cform.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", rec.Header().Get("Set-Cookie"))
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	if rec2.Code != 302 || !strings.Contains(rec2.Header().Get("Location"), "code=") {
		t.Fatalf("entra consent %d %s", rec2.Code, rec2.Header().Get("Location"))
	}
}

func TestEntraLoginChromeAndUIDisabled(t *testing.T) {
	a := bootLogin(t, true)
	if _, err := a.SwapVendor(auth.AdminActor(), app.SwapVendorIn{
		Vendor: "entra", ExpectedRevision: a.Status().RuntimeRevision, Reason: "clothes",
	}); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	a.HTTPSHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/login", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "LabSSO Entra login") || !strings.Contains(rec.Body.String(), "Sign in") {
		t.Fatalf("entra chrome %d %s", rec.Code, rec.Body)
	}
	val, _ := json.Marshal(model.UI{Enabled: model.Ptr(false)})
	if _, err := a.Apply(auth.AdminActor(), app.ChangeIn{
		ExpectedRevision: a.Status().RuntimeRevision, Reason: "ui off",
		Operations: []model.Operation{{Op: model.OpUpdate, Target: model.Target{Kind: model.TargetUI}, Value: val}},
	}); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	a.HTTPSHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/login", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "LabSSO Entra login") {
		t.Fatalf("ui disabled login %d %s", rec.Code, rec.Body)
	}
	form := url.Values{"pending": {"x"}, "username": {"alice"}, "password": {"alice-password"}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	a.HTTPSHandler().ServeHTTP(rec, req)
	if !strings.Contains(rec.Header().Get("Set-Cookie"), "labsso_entra") {
		t.Fatalf("cookie %s", rec.Header().Get("Set-Cookie"))
	}
}

func TestUIDisabledStillServesLogin(t *testing.T) {
	a := bootLogin(t, true)
	val, _ := json.Marshal(model.UI{Enabled: model.Ptr(false)})
	if _, err := a.Apply(auth.AdminActor(), app.ChangeIn{
		ExpectedRevision: a.Status().RuntimeRevision,
		Reason:           "ui off",
		Operations:       []model.Operation{{Op: model.OpUpdate, Target: model.Target{Kind: model.TargetUI}, Value: val}},
	}); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	a.HTTPSHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/login", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Sign in") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestLoginChromeIsLabIdPNotOperatorRail(t *testing.T) {
	a := bootLogin(t, true)
	rec := httptest.NewRecorder()
	a.HTTPSHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/login", nil))
	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(body, "Sign in") || !strings.Contains(body, "--bg: #0b0c0e") {
		t.Fatalf("login chrome %d %s", rec.Code, body)
	}
	if strings.Contains(body, `name="mfa"`) {
		t.Fatal("GET /login must not include TOTP input")
	}
	for _, bad := range []string{"data-view", "IDENTITY", "Expire all", "Entra"} {
		if strings.Contains(body, bad) {
			t.Fatalf("login must not contain %q", bad)
		}
	}
	crec := httptest.NewRecorder()
	a.HTTPSHandler().ServeHTTP(crec, httptest.NewRequest("GET", "/consent?pending=p", nil))
	cbody := crec.Body.String()
	if !strings.Contains(cbody, `name="approve" value="1"`) || !strings.Contains(cbody, `name="approve" value="0"`) {
		t.Fatal(cbody)
	}
	if strings.Contains(cbody, "IDENTITY") || strings.Contains(cbody, "data-view") {
		t.Fatal("consent must not be the operator rail")
	}
}

func TestMFAForceFail(t *testing.T) {
	a := bootLogin(t, true)
	val, _ := json.Marshal(model.Auth{MFA: model.MFA{Mode: "force-fail"}})
	if _, err := a.Apply(auth.AdminActor(), app.ChangeIn{
		ExpectedRevision: a.Status().RuntimeRevision, Reason: "mfa",
		Operations: []model.Operation{{Op: model.OpUpdate, Target: model.Target{Kind: model.TargetAuth}, Value: val}},
	}); err != nil {
		t.Fatal(err)
	}
	form := url.Values{"pending": {"x"}, "username": {"alice"}, "password": {"alice-password"}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	a.HTTPSHandler().ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "MFA failed") {
		t.Fatal(rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `name="mfa"`) {
		t.Fatal("force-fail must not solicit a TOTP field")
	}
}

func TestPHCArgon2id(t *testing.T) {
	root := repoRoot(t)
	dir := t.TempDir()
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	hash := loginui.EncodePHCForTest([]byte("secret"), salt)
	hf := filepath.Join(dir, "hash")
	if err := os.WriteFile(hf, []byte(hash), 0o644); err != nil {
		t.Fatal(err)
	}
	boot := filepath.Join(dir, "config.yaml")
	src, _ := os.ReadFile(filepath.Join(root, "testdata/config/valid/minimal.yaml"))
	_ = os.WriteFile(boot, src, 0o644)
	a := app.New(app.Options{BootstrapPath: boot, BaseDir: root})
	if _, err := a.InstallBootstrapFile(); err != nil {
		t.Fatal(err)
	}
	ops := []model.Operation{{
		Op: model.OpAdd, Target: model.Target{Kind: model.TargetUser, ID: "u2"},
		Value: mustJSON(model.User{ID: "u2", Username: "bob", PasswordHashRef: hf}),
	}}
	if _, err := a.Apply(auth.AdminActor(), app.ChangeIn{ExpectedRevision: a.Status().RuntimeRevision, Reason: "u", Operations: ops}); err != nil {
		t.Fatal(err)
	}
	form := url.Values{"pending": {"x"}, "username": {"bob"}, "password": {"secret"}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	a.HTTPSHandler().ServeHTTP(rec, req)
	if strings.Contains(rec.Body.String(), "invalid credentials") {
		t.Fatal("PHC should accept")
	}
}

func TestRefreshDroppedOnRestart(t *testing.T) {
	a := bootLogin(t, true)
	a.OIDC().Runtime().PutRefresh(oidc.Refresh{Token: "r1", ClientID: "app-1", UserID: "u1", Username: "alice", Scope: "openid"})
	b := bootLogin(t, true)
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"r1"}}
	req := httptest.NewRequest("POST", "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	b.HTTPSHandler().ServeHTTP(rec, req)
	if rec.Code == 200 {
		t.Fatal("refresh must not survive new process")
	}
	_ = io.Discard
}

func TestPauseLeavesLoginUp(t *testing.T) {
	a := bootLogin(t, true)
	if err := a.PauseToken(auth.AdminActor()); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	a.HTTPSHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/login", nil))
	if rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	rec = httptest.NewRecorder()
	a.HTTPSHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/.well-known/openid-configuration", nil))
	if rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
}

func pkceS256(verifier string) string {
	return loginui.S256ForTest(verifier)
}

func enableAlways(t *testing.T, a *app.App) {
	t.Helper()
	if _, err := a.SetMFA(auth.AdminActor(), app.SetMFAIn{
		Mode: "always", ExpectedRevision: a.Status().RuntimeRevision, Reason: "mfa",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestMFATwoSubmitAndLabTOTPRejected(t *testing.T) {
	a := bootLogin(t, true)
	enableAlways(t, a)
	h := a.HTTPSHandler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/login?pending=p1", nil))
	if strings.Contains(rec.Body.String(), `name="mfa"`) || strings.Contains(rec.Body.String(), "lab-totp") {
		t.Fatal(rec.Body.String())
	}
	form := url.Values{"pending": {"p1"}, "username": {"alice"}, "password": {"alice-password"}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `name="mfa"`) {
		t.Fatalf("want TOTP field %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "Password already accepted") {
		t.Fatal("footer must not claim password persist; second POST still needs username and password")
	}
	if !strings.Contains(rec.Body.String(), `value="alice"`) {
		t.Fatal("MFA step should keep the username")
	}
	totpOnly := url.Values{"pending": {"p1"}, "mfa": {"123456"}}
	req = httptest.NewRequest("POST", "/login", strings.NewReader(totpOnly.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "invalid credentials") {
		t.Fatal("TOTP-only second POST must not skip username/password")
	}
	if strings.Contains(rec.Header().Get("Set-Cookie"), oidc.CookieLogin) {
		t.Fatal("cookie before MFA")
	}
	if strings.Contains(rec.Body.String(), "lab-totp") {
		t.Fatal("label must not mention lab-totp")
	}
	form.Set("mfa", "lab-totp")
	req = httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "MFA failed") {
		t.Fatal(rec.Body.String())
	}
	if strings.Contains(rec.Header().Get("Set-Cookie"), oidc.CookieLogin) {
		t.Fatal("cookie on fail")
	}
}

func TestMFAFileRefLogin(t *testing.T) {
	a := bootLogin(t, true)
	uval, _ := json.Marshal(model.User{
		ID: "u1", Username: "alice", PasswordRef: "testdata/secrets/users/alice.password",
		TOTPSecretRef: "testdata/secrets/users/alice.totp",
	})
	if _, err := a.Apply(auth.AdminActor(), app.ChangeIn{
		ExpectedRevision: a.Status().RuntimeRevision, Reason: "ref",
		Operations: []model.Operation{{Op: model.OpUpdate, Target: model.Target{Kind: model.TargetUser, ID: "u1"}, Value: uval}},
	}); err != nil {
		t.Fatal(err)
	}
	enableAlways(t, a)
	code := totp.Code([]byte("12345678901234567890"), time.Now())
	form := url.Values{"pending": {"x"}, "username": {"alice"}, "password": {"alice-password"}, "mfa": {code}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	a.HTTPSHandler().ServeHTTP(rec, req)
	if !strings.Contains(rec.Header().Get("Set-Cookie"), oidc.CookieLogin) {
		t.Fatalf("want cookie %d %s", rec.Code, rec.Body)
	}
}

func TestMFAOverlayRotateSameWindow(t *testing.T) {
	a := bootLogin(t, true)
	enableAlways(t, a)
	first, err := a.EnrollTOTP(auth.AdminActor(), "u1", "e1")
	if err != nil {
		t.Fatal(err)
	}
	sec, err := totp.ParseSecret([]byte(first.Secret))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	code1 := totp.Code(sec, now)
	form := url.Values{"pending": {"x"}, "username": {"alice"}, "password": {"alice-password"}, "mfa": {code1}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	a.HTTPSHandler().ServeHTTP(rec, req)
	if !strings.Contains(rec.Header().Get("Set-Cookie"), oidc.CookieLogin) {
		t.Fatalf("first login %d %s", rec.Code, rec.Body)
	}
	second, err := a.EnrollTOTP(auth.AdminActor(), "u1", "e2")
	if err != nil {
		t.Fatal(err)
	}
	sec2, err := totp.ParseSecret([]byte(second.Secret))
	if err != nil {
		t.Fatal(err)
	}
	code2 := totp.Code(sec2, now)
	form.Set("mfa", code2)
	req = httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	a.HTTPSHandler().ServeHTTP(rec, req)
	if !strings.Contains(rec.Header().Get("Set-Cookie"), oidc.CookieLogin) {
		t.Fatalf("rotate same window %d %s", rec.Code, rec.Body)
	}
}

func TestMFAConsentPathClaims(t *testing.T) {
	a := bootLogin(t, false)
	enableAlways(t, a)
	en, err := a.EnrollTOTP(auth.AdminActor(), "u1", "e")
	if err != nil {
		t.Fatal(err)
	}
	sec, _ := totp.ParseSecret([]byte(en.Secret))
	h := a.HTTPSHandler()
	verifier := "pkce-verifier-value-1234567890"
	ch := pkceS256(verifier)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/oauth2/authorize?response_type=code&client_id=app-1&redirect_uri="+url.QueryEscape("https://sut.example.net/cb")+"&code_challenge="+ch+"&code_challenge_method=S256&scope=openid", nil))
	pending, _ := url.Parse(rec.Header().Get("Location"))
	pid := pending.Query().Get("pending")
	form := url.Values{"pending": {pid}, "username": {"alice"}, "password": {"alice-password"}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	form.Set("mfa", totp.Code(sec, time.Now()))
	req = httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 302 || !strings.Contains(rec.Header().Get("Location"), "/consent") {
		t.Fatalf("want consent %s", rec.Header().Get("Location"))
	}
	cookie := rec.Result().Cookies()
	req = httptest.NewRequest("POST", "/consent", strings.NewReader(url.Values{"pending": {pid}, "approve": {"1"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookie {
		req.AddCookie(c)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("consent %d %s", rec.Code, rec.Header().Get("Location"))
	}
	tokForm := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://sut.example.net/cb"}, "code_verifier": {verifier}, "client_id": {"app-1"}}
	req = httptest.NewRequest("POST", "/oauth2/token", strings.NewReader(tokForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var tok map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &tok); err != nil {
		t.Fatal(err)
	}
	claims := jwtClaims(t, tok["id_token"].(string))
	if claims["acr"] != totp.ACR {
		t.Fatalf("acr %v", claims["acr"])
	}
	amr, _ := claims["amr"].([]any)
	if len(amr) != 2 {
		t.Fatalf("amr %v", claims["amr"])
	}
	ref := tok["refresh_token"].(string)
	refForm := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {ref}, "client_id": {"app-1"}}
	req = httptest.NewRequest("POST", "/oauth2/token", strings.NewReader(refForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if err := json.Unmarshal(rec.Body.Bytes(), &tok); err != nil {
		t.Fatal(rec.Body.String())
	}
	again := jwtClaims(t, tok["id_token"].(string))
	if again["acr"] != totp.ACR {
		t.Fatalf("refresh acr %v", again["acr"])
	}
}

func jwtClaims(t *testing.T, tok string) map[string]any {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) < 2 {
		t.Fatal(tok)
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
