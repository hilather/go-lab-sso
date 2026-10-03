package importrw_test

import (
	"encoding/json"
	"github.com/hilather/go-lab-sso/internal/importrw"
	"strings"
	"testing"
)

func TestReviewEntraSecrets(t *testing.T) {
	r, e := importrw.Rewrite(importrw.KindEntraManifest, `{"appId":"x","redirectUris":["https://sut.example/cb"],"passwordCredentials":[{"secretText":"DO-NOT-EXPOSE"}]}`)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "DO-NOT-EXPOSE") {
		t.Fatalf("credential exposed: %s", b)
	}
}
func TestReviewMixedMetadata(t *testing.T) {
	r, e := importrw.Rewrite(importrw.KindSAMLMetadata, `<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"><EntityDescriptor entityID="https://first.example"><SPSSODescriptor><AssertionConsumerService Location="https://first.example/acs" /></SPSSODescriptor></EntityDescriptor><EntityDescriptor entityID="https://second.example"><SPSSODescriptor><AssertionConsumerService Location="https://second.example/acs" /></SPSSODescriptor></EntityDescriptor></EntitiesDescriptor>`)
	if e == nil {
		t.Fatalf("mixed entities: %+v", r.Client.SAML)
	}
}
func TestReviewRejectMalformedHTTPS(t *testing.T) {
	r, e := importrw.Rewrite(importrw.KindOIDCClient, `{"client_id":"x","redirect_uris":["https://","https:///path","https://sut.example/cb#fragment"]}`)
	if e == nil {
		t.Fatalf("accepts invalid redirects: %+v", r.Client.RedirectURIs)
	}
}

func TestNestedCredentialScrubAcrossFormats(t *testing.T) {
	for _, kind := range []string{importrw.KindOIDCClient, importrw.KindEntraManifest, importrw.KindOktaApp} {
		t.Run(kind, func(t *testing.T) {
			raw := `{"client_id":"x","appId":"x","redirectUris":["https://sut.example/cb"],"redirect_uris":["https://sut.example/cb"],"nested":[{"secretText":"DO-NOT-EXPOSE","access_token":"DO-NOT-EXPOSE","refreshToken":"DO-NOT-EXPOSE","keyCredentials":[{"value":"DO-NOT-EXPOSE"}]}]}`
			r, err := importrw.Rewrite(kind, raw)
			if err != nil {
				t.Fatal(err)
			}
			b, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(b), "DO-NOT-EXPOSE") || len(r.Warnings) == 0 {
				t.Fatal(string(b))
			}
		})
	}
}

func TestDroppedRedirectWarningContainsNoURISecrets(t *testing.T) {
	r, err := importrw.Rewrite(importrw.KindOIDCClient, `{"client_id":"x","redirect_uris":["https://sut.example/cb","http://u:DO-NOT-EXPOSE@sut.example/cb?token=DO-NOT-EXPOSE"]}`)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "DO-NOT-EXPOSE") {
		t.Fatal(string(b))
	}
}
