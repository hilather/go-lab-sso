package rest_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-sso/internal/app"
	"github.com/hilather/go-lab-sso/internal/auth"
	"github.com/hilather/go-lab-sso/internal/control/rest"
	"github.com/hilather/go-lab-sso/internal/model"
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

func boot(t *testing.T) (*app.App, http.Handler) {
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
	return a, rest.New(a, "/v1").Handler()
}

func do(t *testing.T, h http.Handler, method, path, remote, authz string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.RemoteAddr = remote
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHealthLiveUnauth(t *testing.T) {
	_, h := boot(t)
	rec := do(t, h, "GET", "/v1/health/live", "10.1.2.3:9", "", nil)
	if rec.Code != 200 {
		t.Fatalf("code %d %s", rec.Code, rec.Body)
	}
}

func TestReadyAfterBootstrap(t *testing.T) {
	_, h := boot(t)
	rec := do(t, h, "GET", "/v1/health/ready", "10.1.2.3:9", "", nil)
	if rec.Code != 200 {
		t.Fatalf("code %d %s", rec.Code, rec.Body)
	}
}

func TestRemoteRequiresBearer(t *testing.T) {
	_, h := boot(t)
	rec := do(t, h, "GET", "/v1/status", "10.1.2.3:9", "", nil)
	if rec.Code != 401 {
		t.Fatalf("code %d %s", rec.Code, rec.Body)
	}
}

func TestXForwardedForUntrusted(t *testing.T) {
	_, h := boot(t)
	req := httptest.NewRequest("GET", "/v1/status", nil)
	req.RemoteAddr = "10.1.2.3:9"
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("XFF must not grant loopback, code %d", rec.Code)
	}
}

func TestLoopbackPlanApplyExport(t *testing.T) {
	a, h := boot(t)
	st := a.Status()
	body, _ := json.Marshal(map[string]any{
		"expectedRevision": st.RuntimeRevision,
		"reason":           "add client",
		"operations": []map[string]any{
			{
				"op":     "add",
				"target": map[string]any{"kind": "client", "id": "app-1"},
				"value":  map[string]any{"id": "app-1", "clientId": "app-1", "public": true, "redirectURIs": []string{"https://sut.example.net/cb"}},
			},
		},
	})
	rec := do(t, h, "POST", "/v1/changes:apply", "127.0.0.1:9", "", body)
	if rec.Code != 200 {
		t.Fatalf("apply %d %s", rec.Code, rec.Body)
	}
	rec = do(t, h, "GET", "/v1/state:export", "127.0.0.1:9", "", nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "app-1") {
		t.Fatalf("export %d %s", rec.Code, rec.Body)
	}
	rec = do(t, h, "GET", "/v1/clients/app-1", "127.0.0.1:9", "", nil)
	if rec.Code != 200 {
		t.Fatalf("get client %d %s", rec.Code, rec.Body)
	}
}

func TestRemoteBearer(t *testing.T) {
	_, h := boot(t)
	rec := do(t, h, "GET", "/v1/status", "10.1.2.3:9", "Bearer lab-dev-token-not-for-production", nil)
	if rec.Code != 200 {
		t.Fatalf("code %d %s", rec.Code, rec.Body)
	}
}

func TestRevisionConflictHTTP(t *testing.T) {
	_, h := boot(t)
	body := []byte(`{"expectedRevision":"sha256:dead","reason":"x","operations":[]}`)
	rec := do(t, h, "POST", "/v1/changes:apply", "127.0.0.1:9", "", body)
	if rec.Code != 409 {
		t.Fatalf("code %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "revision_conflict") {
		t.Fatal(rec.Body.String())
	}
}

func TestResetInvalidJSONDoesNotReset(t *testing.T) {
	a, h := boot(t)
	rev := a.Status().RuntimeRevision
	rec := do(t, h, "POST", "/v1/state:reset", "127.0.0.1:9", "", []byte("{"))
	if rec.Code != 400 {
		t.Fatalf("code %d %s", rec.Code, rec.Body)
	}
	if a.Status().RuntimeRevision != rev {
		t.Fatal("invalid JSON must not reset")
	}
}

func TestApplyMissingPasswordIs400(t *testing.T) {
	a, h := boot(t)
	body, _ := json.Marshal(map[string]any{
		"expectedRevision": a.Status().RuntimeRevision,
		"reason":           "user",
		"operations": []map[string]any{
			{"op": "add", "target": map[string]any{"kind": "user", "id": "u1"}, "value": map[string]any{"id": "u1", "username": "alice"}},
		},
	})
	rec := do(t, h, "POST", "/v1/changes:apply", "127.0.0.1:9", "", body)
	if rec.Code != 400 {
		t.Fatalf("compile validation want 400 got %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "validation_failed") {
		t.Fatal(rec.Body.String())
	}
}

func TestLoopbackEvilHostRejected(t *testing.T) {
	_, h := boot(t)
	req := httptest.NewRequest("POST", "/v1/state:reset", strings.NewReader(`{"reason":"x"}`))
	req.RemoteAddr = "127.0.0.1:9"
	req.Host = "evil.example"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("evil Host on loopback want 403 got %d %s", rec.Code, rec.Body)
	}
}

func TestSessionExpireRequiresSuffix(t *testing.T) {
	_, h := boot(t)
	rec := do(t, h, "POST", "/v1/sessions/abc", "127.0.0.1:9", "", nil)
	if rec.Code != 400 {
		t.Fatalf("want 400 without :expire, got %d %s", rec.Code, rec.Body)
	}
}

func TestApplyUnknownTargetIs400(t *testing.T) {
	a, h := boot(t)
	body, _ := json.Marshal(map[string]any{
		"expectedRevision": a.Status().RuntimeRevision,
		"reason":           "bad",
		"operations": []map[string]any{
			{"op": "add", "target": map[string]any{"kind": "nope", "id": "x"}, "value": map[string]any{}},
		},
	})
	rec := do(t, h, "POST", "/v1/changes:apply", "127.0.0.1:9", "", body)
	if rec.Code != 400 {
		t.Fatalf("wrapped validation want 400 got %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "validation_failed") {
		t.Fatal(rec.Body.String())
	}
}

func cookieCSRF(t *testing.T, rec *httptest.ResponseRecorder) (string, string) {
	t.Helper()
	var sess string
	for _, c := range rec.Result().Cookies() {
		if c.Name == "labsso_session" {
			sess = c.Value
		}
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	csrf, _ := body["csrf"].(string)
	if sess == "" || csrf == "" {
		t.Fatalf("session cookies %v body %s", rec.Result().Cookies(), rec.Body)
	}
	return sess, csrf
}

func TestCookieCSRFAndSPA(t *testing.T) {
	a, h := boot(t)
	rec := do(t, h, "POST", "/v1/session", "127.0.0.1:9", "", []byte(`{}`))
	if rec.Code != 200 {
		t.Fatalf("create session %d %s", rec.Code, rec.Body)
	}
	sess, csrf := cookieCSRF(t, rec)
	req := httptest.NewRequest("GET", "/v1/status", nil)
	req.RemoteAddr = "10.1.2.3:9"
	req.AddCookie(&http.Cookie{Name: "labsso_session", Value: sess})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("cookie GET %d %s", rec.Code, rec.Body)
	}
	req = httptest.NewRequest("POST", "/v1/tunables/token:pause", strings.NewReader(`{}`))
	req.RemoteAddr = "10.1.2.3:9"
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "labsso_session", Value: sess})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("cookie POST without CSRF want 403 got %d %s", rec.Code, rec.Body)
	}
	req = httptest.NewRequest("POST", "/v1/tunables/token:pause", strings.NewReader(`{}`))
	req.RemoteAddr = "10.1.2.3:9"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-LabSSO-CSRF", csrf)
	req.AddCookie(&http.Cookie{Name: "labsso_session", Value: sess})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("cookie POST with CSRF %d %s", rec.Code, rec.Body)
	}
	req = httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:9"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "LabSSO operator") {
		t.Fatalf("SPA %d %s", rec.Code, rec.Body)
	}
	off := false
	val, _ := json.Marshal(map[string]any{"enabled": off})
	if _, err := a.Apply(adminREST(), app.ChangeIn{
		ExpectedRevision: a.Status().RuntimeRevision, Reason: "ui off",
		Operations: []model.Operation{{Op: model.OpUpdate, Target: model.Target{Kind: model.TargetUI}, Value: val}},
	}); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:9"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 404 {
		t.Fatalf("ui.enabled false want 404 got %d", rec.Code)
	}
	rec = do(t, h, "GET", "/v1/audit", "127.0.0.1:9", "", nil)
	if rec.Code != 200 {
		t.Fatalf("audit %d %s", rec.Code, rec.Body)
	}
}

func TestStaleSessionCookieFallsThrough(t *testing.T) {
	_, h := boot(t)
	rec := do(t, h, "POST", "/v1/session", "127.0.0.1:9", "", []byte(`{}`))
	if rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	sess, _ := cookieCSRF(t, rec)
	if strings.Contains(rec.Body.String(), sess) {
		t.Fatalf("cookie secret leaked in JSON: %s", rec.Body)
	}
	req := httptest.NewRequest("GET", "/v1/status", nil)
	req.RemoteAddr = "127.0.0.1:9"
	req.AddCookie(&http.Cookie{Name: "labsso_session", Value: "dead-session"})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("stale cookie must fall through to loopback, got %d %s", rec.Code, rec.Body)
	}
	cleared := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == "labsso_session" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("stale cookie should be cleared on lookup miss")
	}
	req = httptest.NewRequest("GET", "/v1/session", nil)
	req.RemoteAddr = "127.0.0.1:9"
	req.AddCookie(&http.Cookie{Name: "labsso_session", Value: sess})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), sess) {
		t.Fatalf("GET session leaked cookie: %s", rec.Body)
	}
}

func TestBearerWinsOverCookieCSRF(t *testing.T) {
	_, h := boot(t)
	rec := do(t, h, "POST", "/v1/session", "127.0.0.1:9", "", []byte(`{}`))
	sess, _ := cookieCSRF(t, rec)
	req := httptest.NewRequest("POST", "/v1/tunables/token:pause", strings.NewReader(`{}`))
	req.RemoteAddr = "10.1.2.3:9"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer lab-dev-token-not-for-production")
	req.AddCookie(&http.Cookie{Name: "labsso_session", Value: sess})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("bearer should skip CSRF, got %d %s", rec.Code, rec.Body)
	}
}

func adminREST() auth.Actor { return auth.AdminActor() }

func TestLoopbackEnrollAndRemote401(t *testing.T) {
	a, h := boot(t)
	body, _ := json.Marshal(map[string]any{
		"expectedRevision": a.Status().RuntimeRevision,
		"reason":           "user",
		"operations": []map[string]any{
			{"op": "add", "target": map[string]any{"kind": "user", "id": "u1"}, "value": map[string]any{"id": "u1", "username": "alice", "passwordRef": "testdata/secrets/users/alice.password"}},
		},
	})
	rec := do(t, h, "POST", "/v1/changes:apply", "127.0.0.1:9", "", body)
	if rec.Code != 200 {
		t.Fatalf("apply %d %s", rec.Code, rec.Body)
	}
	rec = do(t, h, "POST", "/v1/users/u1/totp:enroll", "127.0.0.1:9", "", []byte(`{"reason":"lab"}`))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"source":"overlay"`) {
		t.Fatalf("loopback enroll %d %s", rec.Code, rec.Body)
	}
	rec = do(t, h, "POST", "/v1/users/u1/totp:enroll", "10.1.2.3:9", "", []byte(`{"reason":"lab"}`))
	if rec.Code != 401 {
		t.Fatalf("remote enroll without bearer want 401 got %d %s", rec.Code, rec.Body)
	}
}

func TestCookieCSRFOnTOTPEnroll(t *testing.T) {
	a, h := boot(t)
	body, _ := json.Marshal(map[string]any{
		"expectedRevision": a.Status().RuntimeRevision,
		"reason":           "user",
		"operations": []map[string]any{
			{"op": "add", "target": map[string]any{"kind": "user", "id": "u1"}, "value": map[string]any{"id": "u1", "username": "alice", "passwordRef": "testdata/secrets/users/alice.password"}},
		},
	})
	if rec := do(t, h, "POST", "/v1/changes:apply", "127.0.0.1:9", "", body); rec.Code != 200 {
		t.Fatalf("apply %d %s", rec.Code, rec.Body)
	}
	rec := do(t, h, "POST", "/v1/session", "127.0.0.1:9", "", []byte(`{}`))
	sess, csrf := cookieCSRF(t, rec)
	req := httptest.NewRequest("POST", "/v1/users/u1/totp:enroll", strings.NewReader(`{"reason":"spa"}`))
	req.RemoteAddr = "10.1.2.3:9"
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: auth.CookieSession, Value: sess})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("enroll without CSRF want 403 got %d %s", rec.Code, rec.Body)
	}
	req = httptest.NewRequest("POST", "/v1/users/u1/totp:enroll", strings.NewReader(`{"reason":"spa"}`))
	req.RemoteAddr = "10.1.2.3:9"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-LabSSO-CSRF", csrf)
	req.AddCookie(&http.Cookie{Name: auth.CookieSession, Value: sess})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("enroll with CSRF %d %s", rec.Code, rec.Body)
	}
}

func TestCrossSitePOSTRejected(t *testing.T) {
	_, h := boot(t)
	req := httptest.NewRequest("POST", "/v1/state:reset", strings.NewReader(`{"reason":"x"}`))
	req.RemoteAddr = "127.0.0.1:9"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-site POST want 403 got %d %s", rec.Code, rec.Body)
	}
}
