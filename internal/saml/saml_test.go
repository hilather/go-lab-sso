package saml_test

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
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

func bootSAML(t *testing.T, acs []string) (*app.App, http.Handler) {
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
		SAML:  model.ProtocolToggle{Enabled: &on},
		WSFed: model.ProtocolToggle{Enabled: model.Ptr(false)},
	})
	cval, _ := json.Marshal(model.Client{
		ID: "sp-1", ClientID: "sp-1", Public: true, PreConsent: true,
		RedirectURIs: []string{"https://sp.example.net/acs"},
		SAML:         model.ClientSAML{EntityID: "https://sp.example.net", ACSURLs: acs},
	})
	uval, _ := json.Marshal(model.User{ID: "u1", Username: "alice", Email: "alice@lab.example.net", PasswordRef: "testdata/secrets/users/alice.password"})
	if _, err := a.Apply(auth.AdminActor(), app.ChangeIn{
		ExpectedRevision: a.Status().RuntimeRevision, Reason: "saml",
		Operations: []model.Operation{
			{Op: model.OpUpdate, Target: model.Target{Kind: model.TargetProtocols}, Value: pval},
			{Op: model.OpAdd, Target: model.Target{Kind: model.TargetClient, ID: "sp-1"}, Value: cval},
			{Op: model.OpAdd, Target: model.Target{Kind: model.TargetUser, ID: "u1"}, Value: uval},
		},
	}); err != nil {
		t.Fatal(err)
	}
	return a, a.HTTPSHandler()
}

func encodeRedirect(t *testing.T, xmlBody string) string {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(xmlBody)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func authnXML(id, issuer, acs string) string {
	return `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="` + id + `" Version="2.0" IssueInstant="2026-08-30T00:00:00Z" AssertionConsumerServiceURL="` + acs + `"><saml:Issuer>` + issuer + `</saml:Issuer></samlp:AuthnRequest>`
}

func TestSAMLDisabled404(t *testing.T) {
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
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/saml/metadata", nil))
	if rec.Code != 404 {
		t.Fatalf("disabled metadata want 404 got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/saml/sso?SAMLRequest=x", nil))
	if rec.Code != 404 {
		t.Fatalf("disabled sso want 404 got %d", rec.Code)
	}
}

func TestSAMLMetadataEntityID(t *testing.T) {
	_, h := bootSAML(t, []string{"https://sp.example.net/acs"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/saml/metadata", nil))
	if rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `entityID="https://lab.example.net"`) {
		t.Fatalf("entityID: %s", body)
	}
	if strings.Contains(body, "graph.microsoft.com") || strings.Contains(body, "login.microsoftonline.com") {
		t.Fatal("vendor host in metadata")
	}
	if !strings.Contains(body, "BEGIN") && !strings.Contains(body, "X509Certificate") {
		t.Fatal("expected signing cert in metadata")
	}
}

func TestSAMLAuthnRequestLoginACS(t *testing.T) {
	a, h := bootSAML(t, []string{"https://sp.example.net/acs"})
	reqXML := authnXML("id-1", "https://sp.example.net", "https://sp.example.net/acs")
	u := "/saml/sso?SAMLRequest=" + url.QueryEscape(encodeRedirect(t, reqXML)) + "&RelayState=rs1"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", u, nil))
	if rec.Code != 302 || !strings.Contains(rec.Header().Get("Location"), "/login?pending=") {
		t.Fatalf("sso %d %s", rec.Code, rec.Header().Get("Location"))
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	pending := loc.Query().Get("pending")
	form := url.Values{"pending": {pending}, "username": {"alice"}, "password": {"alice-password"}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "SAMLResponse") {
		t.Fatalf("login complete %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `action="https://sp.example.net/acs"`) {
		t.Fatalf("ACS form %s", rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `name="RelayState" value="rs1"`) {
		t.Fatal("relay state missing")
	}
	raw := extractHidden(rec.Body.String(), "SAMLResponse")
	xmlBytes, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		t.Fatal(err)
	}
	s := string(xmlBytes)
	if !strings.Contains(s, `Destination="https://sp.example.net/acs"`) || !strings.Contains(s, "alice") || !strings.Contains(s, "Signature") {
		t.Fatalf("assertion %s", s)
	}
	if !strings.Contains(s, `Name="uid"`) || !strings.Contains(s, `Name="mail"`) {
		t.Fatalf("attrs %s", s)
	}
	_ = a
}

func TestSAMLInvalidACSRejected(t *testing.T) {
	_, h := bootSAML(t, []string{"https://sp.example.net/acs"})
	reqXML := authnXML("id-evil", "https://sp.example.net", "https://evil.example/cb")
	u := "/saml/sso?SAMLRequest=" + url.QueryEscape(encodeRedirect(t, reqXML))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", u, nil))
	if rec.Code != 400 {
		t.Fatalf("evil ACS want 400 got %d %s", rec.Code, rec.Body)
	}
}

func TestSAMLEmptyACSUsesRedirectURIs(t *testing.T) {
	_, h := bootSAML(t, nil)
	reqXML := authnXML("id-2", "https://sp.example.net", "https://sp.example.net/acs")
	u := "/saml/sso?SAMLRequest=" + url.QueryEscape(encodeRedirect(t, reqXML))
	sess := httptest.NewRequest("GET", u, nil)
	// plant session so we can complete without login if we set preconsent + session
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, sess)
	if rec.Code != 302 || !strings.Contains(rec.Header().Get("Location"), "/login") {
		t.Fatalf("%d %s", rec.Code, rec.Header().Get("Location"))
	}
}

func TestSAMLXXERejected(t *testing.T) {
	_, h := bootSAML(t, []string{"https://sp.example.net/acs"})
	xxe := `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="x" Version="2.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://sp.example.net</saml:Issuer></samlp:AuthnRequest>`
	u := "/saml/sso?SAMLRequest=" + url.QueryEscape(encodeRedirect(t, xxe))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", u, nil))
	if rec.Code != 400 || !strings.Contains(strings.ToLower(rec.Body.String()), "entit") && !strings.Contains(strings.ToLower(rec.Body.String()), "dtd") && !strings.Contains(rec.Body.String(), "rejected") {
		t.Fatalf("xxe want 400, got %d %s", rec.Code, rec.Body)
	}
}

func TestSAMLLoggedInPreConsentPostsACS(t *testing.T) {
	a, h := bootSAML(t, []string{"https://sp.example.net/acs"})
	sess := a.OIDC().Runtime().PutSession(oidc.LoginSession{UserID: "u1", Username: "alice"})
	reqXML := authnXML("id-3", "https://sp.example.net", "https://sp.example.net/acs")
	u := "/saml/sso?SAMLRequest=" + url.QueryEscape(encodeRedirect(t, reqXML))
	req := httptest.NewRequest("GET", u, nil)
	req.AddCookie(&http.Cookie{Name: oidc.CookieLogin, Value: sess.ID})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "SAMLResponse") {
		t.Fatalf("session complete %d %s", rec.Code, rec.Body)
	}
}

func extractHidden(page, name string) string {
	marker := `name="` + name + `" value="`
	i := strings.Index(page, marker)
	if i < 0 {
		return ""
	}
	rest := page[i+len(marker):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return ""
	}
	return rest[:j]
}

func TestSAMLRequestXMLShape(t *testing.T) {
	var req struct {
		XMLName xml.Name
		ID      string `xml:"ID,attr"`
	}
	if err := xml.Unmarshal([]byte(authnXML("a", "b", "c")), &req); err != nil {
		t.Fatal(err)
	}
	if req.ID != "a" {
		t.Fatal(req.ID)
	}
}
