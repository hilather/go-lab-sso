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
	"github.com/hilather/go-lab-sso/internal/control/rest"
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
