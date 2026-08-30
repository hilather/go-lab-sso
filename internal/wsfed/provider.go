package wsfed

import (
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"

	"github.com/hilather/go-lab-sso/internal/model"
	"github.com/hilather/go-lab-sso/internal/oidc"
	"github.com/hilather/go-lab-sso/internal/saml"
	"github.com/hilather/go-lab-sso/internal/snapshot"
)

const Protocol = "wsfed"

type Provider struct {
	store *snapshot.Store
	rt    *oidc.Runtime
}

func New(store *snapshot.Store, rt *oidc.Runtime) *Provider {
	return &Provider{store: store, rt: rt}
}

func (p *Provider) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /wsfed/metadata", p.require(func(c snapshot.Clothes) string { return c.WSFedMetadataPath }, p.metadata))
	mux.HandleFunc("GET /FederationMetadata/2007-06/FederationMetadata.xml", p.require(func(c snapshot.Clothes) string { return c.WSFedMetadataPath }, p.metadata))
	mux.HandleFunc("GET /wsfed/passive", p.require(func(c snapshot.Clothes) string { return c.WSFedPassivePath }, p.passive))
	mux.HandleFunc("GET /adfs/ls/", p.require(func(c snapshot.Clothes) string { return c.WSFedPassivePath }, p.passive))
}

func (p *Provider) require(sel func(snapshot.Clothes) string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		snap := p.snap(w)
		if snap == nil {
			return
		}
		want := sel(snap.Clothes)
		if want == "" || r.URL.Path != want {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		next(w, r)
	}
}

func (p *Provider) snap(w http.ResponseWriter) *snapshot.Snapshot {
	snap := p.store.Load()
	if snap == nil {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return nil
	}
	if snap.Canonical == nil || !snap.Canonical.Spec.Protocols.WSFed.IsEnabled(false) {
		http.Error(w, "not found", http.StatusNotFound)
		return nil
	}
	return snap
}

func (p *Provider) metadata(w http.ResponseWriter, r *http.Request) {
	snap := p.snap(w)
	if snap == nil {
		return
	}
	iss := strings.TrimRight(snap.Issuer, "/")
	body := `<?xml version="1.0"?>` +
		`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + html.EscapeString(iss) + `">` +
		`<RoleDescriptor xsi:type="fed:SecurityTokenServiceType" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:fed="http://docs.oasis-open.org/wsfed/federation/200706">` +
		`<fed:PassiveRequestorEndpoint><EndpointReference xmlns="http://www.w3.org/2005/08/addressing"><Address>` +
		html.EscapeString(iss+snap.Clothes.WSFedPassivePath) + `</Address></EndpointReference></fed:PassiveRequestorEndpoint>` +
		`</RoleDescriptor></EntityDescriptor>`
	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write([]byte(body))
}

func (p *Provider) passive(w http.ResponseWriter, r *http.Request) {
	snap := p.snap(w)
	if snap == nil {
		return
	}
	if r.URL.Query().Get("wa") != "wsignin1.0" {
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}
	if p.rt.ForceFail() || (snap.Canonical != nil && snap.Canonical.Spec.Auth.MFA.Mode == "force-fail") {
		http.Error(w, "access_denied", http.StatusForbidden)
		return
	}
	realm := r.URL.Query().Get("wtrealm")
	reply := r.URL.Query().Get("wreply")
	cl, ok := snap.ClientsBySAMLEntity[realm]
	if !ok {
		cl, ok = snap.ClientsByClientID[realm]
	}
	if !ok {
		http.Error(w, "unknown realm", http.StatusBadRequest)
		return
	}
	allowed := cl.SAML.ACSURLs
	if len(allowed) == 0 {
		allowed = cl.RedirectURIs
	}
	if reply == "" && len(allowed) > 0 {
		reply = allowed[0]
	}
	if reply == "" || !contains(allowed, reply) {
		http.Error(w, "invalid wreply", http.StatusBadRequest)
		return
	}
	pend := p.rt.PutPending(oidc.Pending{
		Protocol: Protocol, ClientID: clientKey(cl), ACSURL: reply,
		SPEntityID: realm, RelayState: r.URL.Query().Get("wctx"), RedirectURI: reply,
	})
	iss := strings.TrimRight(snap.Issuer, "/")
	if sid, err := r.Cookie(oidc.CookieName(snap)); err == nil && sid.Value != "" {
		if sess, ok := p.rt.GetSession(sid.Value); ok {
			if cl.PreConsent && !p.rt.ForceConsent() {
				htmlForm, err := p.Complete(pend.ID, sess.UserID, sess.Username)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = w.Write([]byte(htmlForm))
				return
			}
			http.Redirect(w, r, iss+"/consent?pending="+url.QueryEscape(pend.ID), http.StatusFound)
			return
		}
	}
	http.Redirect(w, r, iss+"/login?pending="+url.QueryEscape(pend.ID), http.StatusFound)
}

func (p *Provider) Complete(pendingID, userID, username string) (string, error) {
	return p.finish(pendingID, userID, username, true)
}

func (p *Provider) Deny(pendingID string) (string, error) {
	return p.finish(pendingID, "", "", false)
}

func (p *Provider) finish(pendingID, userID, username string, success bool) (string, error) {
	pend, ok := p.rt.GetPending(pendingID)
	if !ok || pend.Protocol != Protocol {
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
	b64, err := saml.SignedResponseB64(snap, user, pend.ACSURL, pend.RequestID, pend.SPEntityID, success)
	if err != nil {
		return "", err
	}
	if _, ok := p.rt.TakePending(pendingID); !ok {
		return "", fmt.Errorf("pending request not found")
	}
	return autoPost(pend.ACSURL, b64, pend.RelayState), nil
}

func clientKey(c model.Client) string {
	if c.ClientID != "" {
		return c.ClientID
	}
	return c.ID
}

func autoPost(wreply, wresult, wctx string) string {
	extra := ""
	if wctx != "" {
		extra = `<input type="hidden" name="wctx" value="` + html.EscapeString(wctx) + `"/>`
	}
	return `<!doctype html><html><body onload="document.forms[0].submit()">
<form method="post" action="` + html.EscapeString(wreply) + `">
<input type="hidden" name="wa" value="wsignin1.0"/>
<input type="hidden" name="wresult" value="` + html.EscapeString(wresult) + `"/>
` + extra + `
<button type="submit">Continue</button>
</form></body></html>`
}

func contains(list []string, got string) bool {
	for _, u := range list {
		if u == got {
			return true
		}
	}
	return false
}
