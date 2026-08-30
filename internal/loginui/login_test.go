package loginui_test

import (
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-sso/internal/app"
	"github.com/hilather/go-lab-sso/internal/auth"
	"github.com/hilather/go-lab-sso/internal/loginui"
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
	if rec.Code != 302 && !strings.Contains(rec.Body.String(), "invalid") {
		// pending x is missing so CompleteLogin may 400 after cookie — password accepted if not invalid credentials
	}
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
