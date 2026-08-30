package wsfed_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-sso/internal/app"
	"github.com/hilather/go-lab-sso/internal/auth"
	"github.com/hilather/go-lab-sso/internal/model"
	"github.com/hilather/go-lab-sso/internal/vendor"
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

func bootWSFed(t *testing.T, vendorName string) (*app.App, http.Handler) {
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
	on := true
	pval, _ := json.Marshal(model.Protocols{
		OIDC:  model.ProtocolToggle{Enabled: model.Ptr(true)},
		SAML:  model.ProtocolToggle{Enabled: model.Ptr(false)},
		WSFed: model.ProtocolToggle{Enabled: &on},
	})
	cval, _ := json.Marshal(model.Client{
		ID: "rp-1", ClientID: "rp-1", Public: true, PreConsent: true,
		RedirectURIs: []string{"https://rp.example.net/wreply"},
		SAML:         model.ClientSAML{EntityID: "https://rp.example.net", ACSURLs: []string{"https://rp.example.net/wreply"}},
	})
	uval, _ := json.Marshal(model.User{ID: "u1", Username: "alice", Email: "alice@lab.example.net", PasswordRef: "testdata/secrets/users/alice.password"})
	ops := []model.Operation{
		{Op: model.OpUpdate, Target: model.Target{Kind: model.TargetProtocols}, Value: pval},
		{Op: model.OpAdd, Target: model.Target{Kind: model.TargetClient, ID: "rp-1"}, Value: cval},
		{Op: model.OpAdd, Target: model.Target{Kind: model.TargetUser, ID: "u1"}, Value: uval},
	}
	if vendorName != "" && vendorName != "generic" {
		vval, _ := json.Marshal(model.Profile{Vendor: vendorName})
		ops = append(ops, model.Operation{Op: model.OpUpdate, Target: model.Target{Kind: model.TargetProfile}, Value: vval})
	}
	if _, err := a.Apply(auth.AdminActor(), app.ChangeIn{
		ExpectedRevision: a.Status().RuntimeRevision, Reason: "wsfed", Operations: ops,
	}); err != nil {
		t.Fatal(err)
	}
	return a, a.HTTPSHandler()
}

func assertNoVendorHosts(t *testing.T, blob string) {
	t.Helper()
	for _, host := range vendor.ForbiddenHosts {
		if strings.Contains(blob, host) {
			t.Fatalf("contains hostname %s", host)
		}
	}
}

func TestWSFedDisabled404(t *testing.T) {
	root := repoRoot(t)
	dir := t.TempDir()
	boot := filepath.Join(dir, "config.yaml")
	src, _ := os.ReadFile(filepath.Join(root, "testdata/config/valid/minimal.yaml"))
	_ = os.WriteFile(boot, src, 0o644)
	a := app.New(app.Options{BootstrapPath: boot, BaseDir: root})
	if _, err := a.InstallBootstrapFile(); err != nil {
		t.Fatal(err)
	}
	h := a.HTTPSHandler()
	for _, path := range []string{"/wsfed/metadata", "/wsfed/passive", "/FederationMetadata/2007-06/FederationMetadata.xml", "/adfs/ls/"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 404 {
			t.Fatalf("%s want 404 got %d", path, rec.Code)
		}
	}
}

func TestWSFedMetadataEntityID(t *testing.T) {
	_, h := bootWSFed(t, "generic")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/wsfed/metadata", nil))
	if rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `entityID="https://lab.example.net"`) {
		t.Fatalf("entityID: %s", body)
	}
	if !strings.Contains(body, "https://lab.example.net/wsfed/passive") {
		t.Fatalf("passive endpoint: %s", body)
	}
	assertNoVendorHosts(t, body)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/FederationMetadata/2007-06/FederationMetadata.xml", nil))
	if rec.Code != 404 {
		t.Fatalf("adfs metadata under generic want 404 got %d", rec.Code)
	}
}

func TestWSFedPassiveLoginWreply(t *testing.T) {
	_, h := bootWSFed(t, "generic")
	u := "/wsfed/passive?wa=wsignin1.0&wtrealm=" + url.QueryEscape("https://rp.example.net") +
		"&wreply=" + url.QueryEscape("https://rp.example.net/wreply") + "&wctx=ctx1"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", u, nil))
	if rec.Code != 302 || !strings.Contains(rec.Header().Get("Location"), "/login?pending=") {
		t.Fatalf("passive %d %s", rec.Code, rec.Header().Get("Location"))
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	pending := loc.Query().Get("pending")
	form := url.Values{"pending": {pending}, "username": {"alice"}, "password": {"alice-password"}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(body, `name="wa" value="wsignin1.0"`) || !strings.Contains(body, `name="wresult"`) {
		t.Fatalf("complete %d %s", rec.Code, body)
	}
	if !strings.Contains(body, `action="https://rp.example.net/wreply"`) {
		t.Fatalf("wreply form %s", body)
	}
	if !strings.Contains(body, `name="wctx" value="ctx1"`) {
		t.Fatal("wctx missing")
	}
	assertNoVendorHosts(t, body)
}

func TestWSFedInvalidWreply(t *testing.T) {
	_, h := bootWSFed(t, "generic")
	u := "/wsfed/passive?wa=wsignin1.0&wtrealm=https://rp.example.net&wreply=" + url.QueryEscape("https://evil.example/cb")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", u, nil))
	if rec.Code != 400 {
		t.Fatalf("want 400 got %d %s", rec.Code, rec.Body)
	}
}

func TestWSFedADFSClothes(t *testing.T) {
	_, h := bootWSFed(t, "adfs")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/FederationMetadata/2007-06/FederationMetadata.xml", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `entityID="https://lab.example.net"`) {
		t.Fatalf("adfs metadata %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "/adfs/ls/") {
		t.Fatalf("adfs passive path %s", rec.Body)
	}
	assertNoVendorHosts(t, rec.Body.String())
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/wsfed/metadata", nil))
	if rec.Code != 404 {
		t.Fatalf("generic metadata under adfs want 404 got %d", rec.Code)
	}
	u := "/adfs/ls/?wa=wsignin1.0&wtrealm=rp-1&wreply=" + url.QueryEscape("https://rp.example.net/wreply")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", u, nil))
	if rec.Code != 302 || !strings.Contains(rec.Header().Get("Location"), "/login?pending=") {
		t.Fatalf("adfs passive %d %s", rec.Code, rec.Header().Get("Location"))
	}
}
