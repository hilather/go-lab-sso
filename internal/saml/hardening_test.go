package saml_test

import (
	"encoding/base64"
	"encoding/json"
	"github.com/hilather/go-lab-sso/internal/app"
	"github.com/hilather/go-lab-sso/internal/auth"
	"github.com/hilather/go-lab-sso/internal/model"
	"github.com/hilather/go-lab-sso/internal/oidc"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestHardeningSAMLAuthnRequestShape(t *testing.T) {
	_, h := bootSAML(t, nil)
	for _, x := range []string{`<NOT_SAML ID="x"><Issuer>https://sp.example.net</Issuer></NOT_SAML>`, strings.Replace(authnXML("x", "https://sp.example.net", ""), `Version="2.0"`, `Version="9.9"`, 1), strings.Replace(authnXML("x", "https://sp.example.net", ""), `ID="x"`, `ID="x" Destination="https://other-idp.example/sso"`, 1)} {
		f := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString([]byte(x))}}
		r := httptest.NewRequest("POST", "/saml/sso", strings.NewReader(f.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code == http.StatusFound {
			t.Errorf("malformed SAML accepted: %s", x)
		}
	}
}
func TestHardeningSAMLRevocation(t *testing.T) {
	for _, change := range []string{"protocol", "remove_client", "remove_user", "disable_user", "replace_acs", "force_mfa_fail"} {
		t.Run(change, func(t *testing.T) {
			a, h := bootSAML(t, nil)
			rt := a.OIDC().Runtime()
			sess := rt.PutSession(oidc.LoginSession{UserID: "u1", Username: "alice", Expires: time.Now().Add(time.Hour)})
			pend := rt.PutPending(oidc.Pending{Protocol: oidc.ProtocolSAML, ClientID: "sp-1", SPEntityID: "https://sp.example.net", ACSURL: "https://sp.example.net/acs", RequestID: "x"})
			op := model.Operation{Op: model.OpUpdate}
			var v any
			switch change {
			case "protocol":
				op.Target.Kind = model.TargetProtocols
				v = model.Protocols{OIDC: model.ProtocolToggle{Enabled: model.Ptr(true)}, SAML: model.ProtocolToggle{Enabled: model.Ptr(false)}}
			case "remove_client":
				op.Op = model.OpRemove
				op.Target = model.Target{Kind: model.TargetClient, ID: "sp-1"}
			case "remove_user":
				op.Op = model.OpRemove
				op.Target = model.Target{Kind: model.TargetUser, ID: "u1"}
			case "disable_user":
				op.Target = model.Target{Kind: model.TargetUser, ID: "u1"}
				v = model.User{ID: "u1", Username: "alice", PasswordRef: "testdata/secrets/users/alice.password", Enabled: model.Ptr(false)}
			case "replace_acs":
				op.Target = model.Target{Kind: model.TargetClient, ID: "sp-1"}
				v = model.Client{ID: "sp-1", ClientID: "sp-1", Public: true, SAML: model.ClientSAML{EntityID: "https://sp.example.net", ACSURLs: []string{"https://different.example/acs"}}}
			case "force_mfa_fail":
				op.Target.Kind = model.TargetAuth
				v = model.Auth{MFA: model.MFA{Mode: "force-fail"}}
			}
			if v != nil {
				op.Value, _ = json.Marshal(v)
			}
			if _, e := a.Apply(auth.AdminActor(), app.ChangeIn{ExpectedRevision: a.Status().RuntimeRevision, Reason: "revoke", Operations: []model.Operation{op}}); e != nil {
				t.Fatal(e)
			}
			f := url.Values{"pending": {pend.ID}, "approve": {"1"}}
			r := httptest.NewRequest("POST", "/consent", strings.NewReader(f.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.AddCookie(&http.Cookie{Name: "labsso_login", Value: sess.ID})
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if strings.Contains(w.Body.String(), `name="SAMLResponse"`) {
				t.Fatal("issued SAML response after revocation")
			}
		})
	}
}

func TestSAMLBodyAndContextLimits(t *testing.T) {
	_, h := bootSAML(t, nil)
	for _, f := range []url.Values{
		{"SAMLRequest": {base64.StdEncoding.EncodeToString([]byte(authnXML("x", "https://sp.example.net", "")))}, "RelayState": {strings.Repeat("x", 4097)}},
		{"SAMLRequest": {base64.StdEncoding.EncodeToString([]byte(authnXML("x", "https://sp.example.net", "")))}, "unused": {strings.Repeat("x", 512<<10)}},
	} {
		req := httptest.NewRequest("POST", "/saml/sso", strings.NewReader(f.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 400 {
			t.Fatal("oversized SAML form/context accepted")
		}
	}
}
