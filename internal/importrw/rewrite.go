package importrw

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hilather/go-lab-sso/internal/model"
	"github.com/hilather/go-lab-sso/internal/saml"
)

const (
	KindEntraManifest = "entra-manifest"
	KindOktaApp       = "okta-app"
	KindSAMLMetadata  = "saml-metadata"
	KindOIDCClient    = "oidc-client"
)

type Result struct {
	Client   model.Client
	Unmapped map[string]any
	Warnings []string
	Kind     string
}

func ValidKind(k string) bool {
	switch k {
	case KindEntraManifest, KindOktaApp, KindSAMLMetadata, KindOIDCClient:
		return true
	default:
		return false
	}
}

func Rewrite(kind, raw string) (Result, error) {
	if !ValidKind(kind) {
		return Result{}, fmt.Errorf("unknown import kind %q", kind)
	}
	var res Result
	var err error
	switch kind {
	case KindEntraManifest:
		res, err = rewriteEntra(raw)
	case KindOktaApp:
		res, err = rewriteOkta(raw)
	case KindSAMLMetadata:
		res, err = rewriteSAML(raw)
	default:
		res, err = rewriteOIDC(raw)
	}
	if err != nil {
		return Result{}, err
	}
	return finish(res)
}

func finish(res Result) (Result, error) {
	blob := res.Client.ClientID + res.Client.ID + strings.Join(res.Client.RedirectURIs, "") + res.Client.SAML.EntityID + strings.Join(res.Client.SAML.ACSURLs, "")
	if strings.Contains(strings.ToUpper(blob), "-----BEGIN ") {
		return Result{}, fmt.Errorf("inline PEM rejected; use file refs")
	}
	res.Unmapped, res.Warnings = scrubSecrets(res.Unmapped, res.Warnings)
	return res, nil
}

func scrubSecrets(unmapped map[string]any, warn []string) (map[string]any, []string) {
	if unmapped == nil {
		return unmapped, warn
	}
	cleaned, extra := scrubValue("", unmapped)
	m, _ := cleaned.(map[string]any)
	if m == nil {
		m = map[string]any{}
	}
	return m, append(warn, extra...)
}

func scrubValue(path string, v any) (any, []string) {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		var warn []string
		for k, child := range t {
			p := k
			if path != "" {
				p = path + "." + k
			}
			if secretKey(k) || pemString(child) {
				warn = append(warn, "dropped secret-like field "+p+"; use file refs")
				continue
			}
			kept, extra := scrubValue(p, child)
			warn = append(warn, extra...)
			if kept != nil {
				out[k] = kept
			}
		}
		return out, warn
	case []any:
		var out []any
		var warn []string
		for i, child := range t {
			p := path + "[]"
			if pemString(child) {
				warn = append(warn, "dropped secret-like field "+p+"; use file refs")
				continue
			}
			_ = i
			kept, extra := scrubValue(p, child)
			warn = append(warn, extra...)
			if kept != nil {
				out = append(out, kept)
			}
		}
		return out, warn
	default:
		if pemString(t) {
			return nil, []string{"dropped secret-like field " + path + "; use file refs"}
		}
		return t, nil
	}
}

func pemString(v any) bool {
	s, ok := v.(string)
	return ok && strings.Contains(strings.ToUpper(s), "-----BEGIN ")
}

func secretKey(k string) bool {
	switch strings.ToLower(k) {
	case "client_secret", "clientsecret", "password", "private_key", "privatekey", "pem", "jwks":
		return true
	default:
		return false
	}
}

func rewriteEntra(raw string) (Result, error) {
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return Result{}, fmt.Errorf("entra-manifest JSON: %w", err)
	}
	unmapped := copyMap(m)
	cl := model.Client{Public: true}
	if v, ok := str(m, "appId"); ok {
		cl.ClientID = v
		delete(unmapped, "appId")
	}
	if cl.ClientID == "" {
		if v, ok := str(m, "id"); ok {
			cl.ClientID = v
			delete(unmapped, "id")
		}
	} else {
		delete(unmapped, "id")
	}
	cl.ID = "imported-" + sanitize(cl.ClientID)
	uris := redirectList(m, "replyUrlsWithType", "redirectUris", "replyUrls")
	delete(unmapped, "replyUrlsWithType")
	delete(unmapped, "redirectUris")
	delete(unmapped, "replyUrls")
	https, warn := onlyHTTPS(uris)
	cl.RedirectURIs = https
	if implicitOn(m) {
		warn = append(warn, "implicit flow is not enabled; LabSSO stays authorization-code")
	}
	if gm, ok := m["groupMembershipClaims"]; ok && gm != nil && fmt.Sprint(gm) != "None" {
		cl.Scopes = []string{"openid", "groups"}
		delete(unmapped, "groupMembershipClaims")
	}
	if cl.ClientID == "" || len(cl.RedirectURIs) == 0 {
		return Result{}, fmt.Errorf("import produced no clientId/redirectURIs")
	}
	return Result{Client: cl, Unmapped: unmapped, Warnings: warn, Kind: KindEntraManifest}, nil
}

func rewriteOkta(raw string) (Result, error) {
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return Result{}, fmt.Errorf("okta-app JSON: %w", err)
	}
	unmapped := copyMap(m)
	cl := model.Client{Public: true}
	if v, ok := str(m, "client_id"); ok {
		cl.ClientID = v
		delete(unmapped, "client_id")
	}
	uris := stringSlice(m["redirect_uris"])
	if len(uris) == 0 {
		if settings, ok := m["settings"].(map[string]any); ok {
			if oc, ok := settings["oauthClient"].(map[string]any); ok {
				uris = stringSlice(oc["redirect_uris"])
			}
		}
	}
	delete(unmapped, "redirect_uris")
	https, warn := onlyHTTPS(uris)
	cl.RedirectURIs = https
	if v, ok := str(m, "label"); ok {
		unmapped["label"] = v
	}
	if sign, ok := str(m, "signOnMode"); ok && strings.EqualFold(sign, "SAML_2_0") {
		warn = append(warn, "sign-on mode SAML is not silently enabling saml.enabled")
	}
	cl.ID = "imported-" + sanitize(cl.ClientID)
	if cl.ClientID == "" || len(cl.RedirectURIs) == 0 {
		return Result{}, fmt.Errorf("import produced no clientId/redirectURIs")
	}
	return Result{Client: cl, Unmapped: unmapped, Warnings: warn, Kind: KindOktaApp}, nil
}

func rewriteOIDC(raw string) (Result, error) {
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return Result{}, fmt.Errorf("oidc-client JSON: %w", err)
	}
	unmapped := copyMap(m)
	cl := model.Client{}
	if v, ok := str(m, "client_id"); ok {
		cl.ClientID = v
		delete(unmapped, "client_id")
	}
	uris, warn := onlyHTTPS(stringSlice(m["redirect_uris"]))
	cl.RedirectURIs = uris
	delete(unmapped, "redirect_uris")
	method, _ := str(m, "token_endpoint_auth_method")
	delete(unmapped, "token_endpoint_auth_method")
	if method == "" || method == "none" {
		cl.Public = true
	} else {
		cl.Public = false
		warn = append(warn, "confidential client requires secretRef before apply")
	}
	cl.ID = "imported-" + sanitize(cl.ClientID)
	if cl.ClientID == "" || len(cl.RedirectURIs) == 0 {
		return Result{}, fmt.Errorf("import produced no clientId/redirectURIs")
	}
	return Result{Client: cl, Unmapped: unmapped, Warnings: warn, Kind: KindOIDCClient}, nil
}

func rewriteSAML(raw string) (Result, error) {
	entity, acs, err := saml.ParseSPSSO(raw)
	if err != nil {
		return Result{}, err
	}
	if entity == "" {
		return Result{}, fmt.Errorf("import produced no SAML entityID")
	}
	https, warn := onlyHTTPS(acs)
	if len(https) == 0 {
		return Result{}, fmt.Errorf("import produced no ACS / redirectURIs")
	}
	cl := model.Client{
		ID: "imported-" + sanitize(entity), ClientID: entity, Public: true,
		RedirectURIs: https,
		SAML:         model.ClientSAML{EntityID: entity, ACSURLs: https},
	}
	return Result{Client: cl, Unmapped: map[string]any{}, Warnings: warn, Kind: KindSAMLMetadata}, nil
}

func onlyHTTPS(in []string) ([]string, []string) {
	var out, warn []string
	for _, u := range in {
		if strings.HasPrefix(u, "https://") {
			out = append(out, u)
			continue
		}
		warn = append(warn, "dropped non-https redirect "+u)
	}
	return out, warn
}

func implicitOn(m map[string]any) bool {
	for _, k := range []string{"oauth2AllowIdTokenImplicitFlow", "oauth2AllowImplicitFlow"} {
		if b, ok := m[k].(bool); ok && b {
			return true
		}
	}
	return false
}

func redirectList(m map[string]any, keys ...string) []string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if sl := stringSlice(v); len(sl) > 0 {
				return sl
			}
			if arr, ok := v.([]any); ok {
				var out []string
				for _, item := range arr {
					if obj, ok := item.(map[string]any); ok {
						if u, ok := str(obj, "url"); ok {
							out = append(out, u)
						}
					}
				}
				if len(out) > 0 {
					return out
				}
			}
		}
	}
	return nil
}

func stringSlice(v any) []string {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return t
	default:
		return nil
	}
}

func str(m map[string]any, k string) (string, bool) {
	v, ok := m[k]
	if !ok || v == nil {
		return "", false
	}
	s, ok := v.(string)
	return s, ok && s != ""
}

func copyMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func sanitize(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 40 {
		out = out[:40]
	}
	if out == "" {
		out = "client"
	}
	return out
}
