package saml

import (
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hilather/go-lab-sso/internal/model"
	"github.com/hilather/go-lab-sso/internal/oidc"
	"github.com/hilather/go-lab-sso/internal/snapshot"
)

type Provider struct {
	store *snapshot.Store
	rt    *oidc.Runtime
}

func New(store *snapshot.Store, rt *oidc.Runtime) *Provider {
	return &Provider{store: store, rt: rt}
}

func (p *Provider) Mount(mux *http.ServeMux) {
	for _, path := range []string{
		"/saml/metadata",
		"/saml2/sp/{name}/metadata",
		"/affwebservices/public/saml2meta",
		"/idp/shibboleth",
	} {
		mux.HandleFunc("GET "+path, p.requireMeta(p.metadata))
	}
	for _, path := range []string{
		"/saml/sso",
		"/saml2/sp/{name}/sso",
		"/affwebservices/public/saml2sso",
		"/idp/profile/SAML2/Redirect/SSO",
	} {
		mux.HandleFunc("GET "+path, p.requireSSO(http.MethodGet, p.sso))
	}
	for _, path := range []string{
		"/saml/sso",
		"/saml2/sp/{name}/sso",
		"/affwebservices/public/saml2sso",
		"/idp/profile/SAML2/POST/SSO",
	} {
		mux.HandleFunc("POST "+path, p.requireSSO(http.MethodPost, p.sso))
	}
}

func (p *Provider) requireMeta(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		snap := p.snapSAML(w)
		if snap == nil {
			return
		}
		want := snap.Clothes.SAMLMetadataPath
		if want == "" || r.URL.Path != want {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		next(w, r)
	}
}

func (p *Provider) requireSSO(method string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		snap := p.snapSAML(w)
		if snap == nil {
			return
		}
		want := snap.Clothes.SAMLSSOPath
		if method == http.MethodPost {
			want = snap.Clothes.SAMLSSOPOSTPath
		}
		if want == "" || r.URL.Path != want {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		next(w, r)
	}
}

func (p *Provider) snapSAML(w http.ResponseWriter) *snapshot.Snapshot {
	snap := p.store.Load()
	if snap == nil {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return nil
	}
	if snap.Canonical == nil || !snap.Canonical.Spec.Protocols.SAML.IsEnabled(false) {
		http.Error(w, "not found", http.StatusNotFound)
		return nil
	}
	return snap
}

func (p *Provider) metadata(w http.ResponseWriter, r *http.Request) {
	snap := p.snapSAML(w)
	if snap == nil {
		return
	}
	iss := strings.TrimRight(snap.Issuer, "/")
	cert := certB64(snap)
	redir := iss + snap.Clothes.SAMLSSOPath
	post := iss + snap.Clothes.SAMLSSOPOSTPath
	body := `<?xml version="1.0" encoding="UTF-8"?>` +
		`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + html.EscapeString(iss) + `">` +
		`<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
		`<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>` + cert + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>` +
		`<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="` + html.EscapeString(redir) + `"/>` +
		`<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="` + html.EscapeString(post) + `"/>` +
		`</md:IDPSSODescriptor></md:EntityDescriptor>`
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	_, _ = w.Write([]byte(body))
}

func (p *Provider) sso(w http.ResponseWriter, r *http.Request) {
	snap := p.snapSAML(w)
	if snap == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}
	raw := r.FormValue("SAMLRequest")
	deflated := r.Method == http.MethodGet
	req, err := decodeSAMLRequest(raw, deflated)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cl, ok := snap.ClientsBySAMLEntity[req.Issuer]
	if !ok {
		http.Error(w, "unknown SP entityID", http.StatusBadRequest)
		return
	}
	acs := req.AssertionConsumerServiceURL
	allowed := acsURLs(cl)
	if acs == "" {
		if len(allowed) == 0 {
			http.Error(w, "no ACS", http.StatusBadRequest)
			return
		}
		acs = allowed[0]
	} else if !contains(allowed, acs) {
		http.Error(w, "invalid ACS", http.StatusBadRequest)
		return
	}
	mfa := ""
	if snap.Canonical != nil {
		mfa = snap.Canonical.Spec.Auth.MFA.Mode
	}
	if p.rt.ForceFail() || mfa == "force-fail" {
		htmlForm, err := p.responseHTML(snap, model.User{}, acs, req.ID, req.Issuer, r.FormValue("RelayState"), false)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeHTML(w, htmlForm)
		return
	}
	pend := p.rt.PutPending(oidc.Pending{
		Protocol:    oidc.ProtocolSAML,
		ClientID:    clientKey(cl),
		ACSURL:      acs,
		RequestID:   req.ID,
		SPEntityID:  req.Issuer,
		RelayState:  r.FormValue("RelayState"),
		RedirectURI: acs,
	})
	iss := strings.TrimRight(snap.Issuer, "/")
	if sid, err := r.Cookie(oidc.CookieName(snap)); err == nil && sid.Value != "" {
		if sess, ok := p.rt.GetSession(sid.Value); ok {
			if cl.PreConsent && !p.rt.ForceConsent() {
				htmlForm, err := p.completeUser(pend.ID, sess.UserID, sess.Username)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				writeHTML(w, htmlForm)
				return
			}
			http.Redirect(w, r, iss+"/consent?pending="+url.QueryEscape(pend.ID), http.StatusFound)
			return
		}
	}
	http.Redirect(w, r, iss+"/login?pending="+url.QueryEscape(pend.ID), http.StatusFound)
}

func (p *Provider) Complete(pendingID, userID, username string) (string, error) {
	return p.completeUser(pendingID, userID, username)
}

func (p *Provider) Deny(pendingID string) (string, error) {
	return p.finishPending(pendingID, "", "", false)
}

func (p *Provider) completeUser(pendingID, userID, username string) (string, error) {
	if p.rt.ForceFail() {
		return "", fmt.Errorf("access_denied")
	}
	return p.finishPending(pendingID, userID, username, true)
}

func (p *Provider) finishPending(pendingID, userID, username string, success bool) (string, error) {
	pend, ok := p.rt.GetPending(pendingID)
	if !ok || pend.Protocol != oidc.ProtocolSAML {
		return "", fmt.Errorf("pending request not found")
	}
	snap := p.store.Load()
	if snap == nil {
		return "", fmt.Errorf("not ready")
	}
	user, ok := snap.UsersByID[userID]
	if !ok {
		user = model.User{ID: userID, Username: username}
	}
	htmlForm, err := p.responseHTML(snap, user, pend.ACSURL, pend.RequestID, pend.SPEntityID, pend.RelayState, success)
	if err != nil {
		return "", err
	}
	if _, ok := p.rt.TakePending(pendingID); !ok {
		return "", fmt.Errorf("pending request not found")
	}
	return htmlForm, nil
}

func (p *Provider) responseHTML(snap *snapshot.Snapshot, user model.User, acs, inResponseTo, audience, relay string, success bool) (string, error) {
	return AutoPost(snap, user, acs, inResponseTo, audience, relay, success)
}

func AutoPost(snap *snapshot.Snapshot, user model.User, acs, inResponseTo, audience, relay string, success bool) (string, error) {
	b64, err := SignedResponseB64(snap, user, acs, inResponseTo, audience, success)
	if err != nil {
		return "", err
	}
	return autoPostForm(acs, b64, relay), nil
}

func SignedResponseB64(snap *snapshot.Snapshot, user model.User, acs, inResponseTo, audience string, success bool) (string, error) {
	return buildResponse(snap, user, acs, inResponseTo, audience, time.Now(), success)
}

func autoPostForm(acs, samlResponse, relay string) string {
	extra := ""
	if relay != "" {
		extra = `<input type="hidden" name="RelayState" value="` + html.EscapeString(relay) + `"/>`
	}
	return `<!doctype html><html><body onload="document.forms[0].submit()">
<form method="post" action="` + html.EscapeString(acs) + `">
<input type="hidden" name="SAMLResponse" value="` + html.EscapeString(samlResponse) + `"/>
` + extra + `
<button type="submit">Continue</button>
</form></body></html>`
}

func acsURLs(c model.Client) []string {
	if len(c.SAML.ACSURLs) > 0 {
		return c.SAML.ACSURLs
	}
	return c.RedirectURIs
}

func contains(list []string, got string) bool {
	for _, u := range list {
		if u == got {
			return true
		}
	}
	return false
}

func clientKey(c model.Client) string {
	if c.ClientID != "" {
		return c.ClientID
	}
	return c.ID
}

func writeHTML(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(body))
}
