package wsfed_test

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
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

func TestHardeningWSFedRevocation(t *testing.T) {
	for _, change := range []string{"protocol", "remove_client", "remove_user", "disable_user", "replace_acs", "force_mfa_fail"} {
		t.Run(change, func(t *testing.T) {
			a, h := bootWSFed(t, "generic")
			rt := a.OIDC().Runtime()
			sess := rt.PutSession(oidc.LoginSession{UserID: "u1", Username: "alice", Expires: time.Now().Add(time.Hour)})
			pend := rt.PutPending(oidc.Pending{Protocol: "wsfed", ClientID: "rp-1", SPEntityID: "https://rp.example.net", ACSURL: "https://rp.example.net/wreply", RequestID: "x"})
			op := model.Operation{Op: model.OpUpdate}
			var v any
			switch change {
			case "protocol":
				op.Target.Kind = model.TargetProtocols
				v = model.Protocols{OIDC: model.ProtocolToggle{Enabled: model.Ptr(true)}, WSFed: model.ProtocolToggle{Enabled: model.Ptr(false)}}
			case "remove_client":
				op.Op = model.OpRemove
				op.Target = model.Target{Kind: model.TargetClient, ID: "rp-1"}
			case "remove_user":
				op.Op = model.OpRemove
				op.Target = model.Target{Kind: model.TargetUser, ID: "u1"}
			case "disable_user":
				op.Target = model.Target{Kind: model.TargetUser, ID: "u1"}
				v = model.User{ID: "u1", Username: "alice", PasswordRef: "testdata/secrets/users/alice.password", Enabled: model.Ptr(false)}
			case "replace_acs":
				op.Target = model.Target{Kind: model.TargetClient, ID: "rp-1"}
				v = model.Client{ID: "rp-1", ClientID: "rp-1", Public: true, SAML: model.ClientSAML{EntityID: "https://rp.example.net", ACSURLs: []string{"https://different.example/acs"}}}
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
			if strings.Contains(w.Body.String(), `name="wresult"`) {
				t.Fatal("issued SAML response after revocation")
			}
		})
	}
}

func TestHardeningWSFedForceFailureAndMetadataTrust(t *testing.T) {
	a, h := bootWSFed(t, "generic")
	rt := a.OIDC().Runtime()
	sess := rt.PutSession(oidc.LoginSession{UserID: "u1", Username: "alice", Expires: time.Now().Add(time.Hour)})
	pending := rt.PutPending(oidc.Pending{Protocol: "wsfed", ClientID: "rp-1", SPEntityID: "https://rp.example.net", ACSURL: "https://rp.example.net/wreply"})
	rt.SetForceFail(true)
	form := url.Values{"pending": {pending.ID}, "approve": {"1"}}
	req := httptest.NewRequest("POST", "/consent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: oidc.CookieLogin, Value: sess.ID})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if strings.Contains(rec.Body.String(), `name="wresult"`) {
		t.Fatal("force-fail assertion")
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/wsfed/metadata", nil))
	cert := a.Store().Load().SigningCert
	if len(cert) == 0 {
		cert = a.Store().Load().TLSCert
	}
	block, _ := pem.Decode(cert)
	if block == nil {
		t.Fatal("cert fixture")
	}
	if !strings.Contains(rec.Body.String(), base64.StdEncoding.EncodeToString(block.Bytes)) || !strings.Contains(rec.Body.String(), `protocolSupportEnumeration="http://docs.oasis-open.org/wsfed/federation/200706"`) {
		t.Fatal("metadata omits signing trust/protocol")
	}
}

func TestWSFedRejectsOversizedContext(t *testing.T) {
	_, h := bootWSFed(t, "generic")
	q := url.Values{"wa": {"wsignin1.0"}, "wtrealm": {"https://rp.example.net"}, "wctx": {strings.Repeat("x", 4097)}}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/wsfed/passive?"+q.Encode(), nil))
	if rec.Code != 400 {
		t.Fatal("oversized wctx accepted")
	}
}
