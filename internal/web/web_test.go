package web_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hilather/go-lab-sso/internal/web"
)

func TestSPA404WhenDisabled(t *testing.T) {
	h := web.Handler(func() bool { return false })
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 404 {
		t.Fatalf("code %d", rec.Code)
	}
}

func TestSPANoTokenStorage(t *testing.T) {
	h := web.Handler(func() bool { return true })
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "LabSSO operator") {
		t.Fatal(rec.Body.String())
	}
	js := httptest.NewRecorder()
	web.Script().ServeHTTP(js, httptest.NewRequest("GET", "/app.js", nil))
	blob := js.Body.String() + rec.Body.String()
	for _, bad := range []string{"localStorage", "sessionStorage", "indexedDB", "IndexedDB"} {
		if strings.Contains(blob, bad) {
			t.Fatalf("SPA must not use %s", bad)
		}
	}
	if !strings.Contains(blob, "X-LabSSO-CSRF") || !strings.Contains(blob, "credentials") {
		t.Fatal("SPA must send CSRF and cookies")
	}
	if !strings.Contains(blob, "/v1/users/") || !strings.Contains(blob, "totp:enroll") || !strings.Contains(blob, "/v1/auth/mfa") {
		t.Fatal("Users view must bind MFA enroll/set")
	}
	if !strings.Contains(blob, "/v1/sessions:expire-all") {
		t.Fatal("Sessions view must bind expire-all")
	}
	if !strings.Contains(blob, `"/v1/sessions/"+encodeURIComponent(id)+":expire"`) {
		t.Fatal("Sessions view must bind POST /v1/sessions/{id}:expire")
	}
	if !strings.Contains(blob, "MFACompleted") || !strings.Contains(blob, "UserID") {
		t.Fatal("Sessions inspector must paint LoginSession fields")
	}
}

func TestScriptNoStore(t *testing.T) {
	rec := httptest.NewRecorder()
	web.Script().ServeHTTP(rec, httptest.NewRequest("GET", "/app.js", nil))
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(rec.Header().Get("Cache-Control"))
	}
	if rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
}
