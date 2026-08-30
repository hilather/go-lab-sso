package importrw_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-sso/internal/importrw"
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
		dir = filepath.Dir(dir)
	}
}

func TestGoldens(t *testing.T) {
	root := repoRoot(t)
	cases := []struct {
		kind, file, clientID string
		warnImplicit         bool
	}{
		{importrw.KindEntraManifest, "testdata/import/entra-manifest.json", "11111111-2222-3333-4444-555555555555", true},
		{importrw.KindOktaApp, "testdata/import/okta-app.json", "0oa1example", false},
		{importrw.KindOIDCClient, "testdata/import/oidc-client.json", "oidc-app", false},
		{importrw.KindSAMLMetadata, "testdata/import/saml-metadata.xml", "https://sp.example.net", false},
	}
	for _, tc := range cases {
		raw, err := os.ReadFile(filepath.Join(root, tc.file))
		if err != nil {
			t.Fatal(err)
		}
		res, err := importrw.Rewrite(tc.kind, string(raw))
		if err != nil {
			t.Fatalf("%s: %v", tc.kind, err)
		}
		if res.Client.ClientID != tc.clientID {
			t.Fatalf("%s clientId %s", tc.kind, res.Client.ClientID)
		}
		if len(res.Client.RedirectURIs) == 0 && len(res.Client.SAML.ACSURLs) == 0 {
			t.Fatalf("%s no redirects", tc.kind)
		}
		if tc.kind == importrw.KindSAMLMetadata {
			if len(res.Client.SAML.ACSURLs) == 0 || res.Client.SAML.EntityID != tc.clientID {
				t.Fatalf("SAML ACS/entity not mapped: %+v", res.Client.SAML)
			}
		}
		if tc.warnImplicit {
			found := false
			for _, w := range res.Warnings {
				if strings.Contains(w, "implicit") {
					found = true
				}
			}
			if !found {
				t.Fatalf("%s missing implicit warning", tc.kind)
			}
		}
		if tc.kind == importrw.KindEntraManifest {
			if _, ok := res.Unmapped["displayName"]; !ok {
				t.Fatal("unmapped displayName parked")
			}
			if res.Client.ID == "displayName" {
				t.Fatal("unmapped leaked into spec id")
			}
		}
	}
}

func TestXXERejected(t *testing.T) {
	xxe := `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><EntityDescriptor entityID="https://sp.example.net"></EntityDescriptor>`
	_, err := importrw.Rewrite(importrw.KindSAMLMetadata, xxe)
	if err == nil {
		t.Fatal("expected XXE reject")
	}
	low := strings.ToLower(err.Error())
	if !strings.Contains(low, "dtd") && !strings.Contains(low, "entit") {
		t.Fatalf("XXE error should name DTD/entities, got %v", err)
	}
}

func TestSAMLMetadataWithCertOK(t *testing.T) {
	raw := `<EntityDescriptor entityID="https://sp.example.net" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor><KeyName>-----BEGIN CERTIFICATE----- MIIB -----END CERTIFICATE-----</KeyName></KeyDescriptor>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.net/acs" index="0"/>
  </SPSSODescriptor>
</EntityDescriptor>`
	res, err := importrw.Rewrite(importrw.KindSAMLMetadata, raw)
	if err != nil {
		t.Fatal(err)
	}
	if res.Client.SAML.EntityID != "https://sp.example.net" || len(res.Client.SAML.ACSURLs) != 1 {
		t.Fatalf("%+v", res.Client.SAML)
	}
	if strings.Contains(strings.ToUpper(res.Client.SAML.EntityID+strings.Join(res.Client.SAML.ACSURLs, "")), "BEGIN ") {
		t.Fatal("PEM leaked into fragment")
	}
}

func TestInlinePEMNotCopied(t *testing.T) {
	res, err := importrw.Rewrite(importrw.KindOIDCClient, `{"client_id":"x","redirect_uris":["https://s.example/cb"],"pem":"-----BEGIN CERTIFICATE-----\nYQ==\n-----END CERTIFICATE-----","client_secret":"s3cret","jwks":{"keys":[]}}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"pem", "client_secret", "jwks"} {
		if _, ok := res.Unmapped[k]; ok {
			t.Fatalf("%s must not be parked in unmapped", k)
		}
	}
	dropped := 0
	for _, w := range res.Warnings {
		if strings.Contains(w, "dropped secret-like") {
			dropped++
		}
	}
	if dropped < 3 {
		t.Fatalf("want drop warnings, got %v", res.Warnings)
	}
	if strings.Contains(strings.ToUpper(res.Client.ClientID), "BEGIN") {
		t.Fatal("PEM leaked into client")
	}
	nested, err := importrw.Rewrite(importrw.KindOktaApp, `{"client_id":"0oa1","redirect_uris":["https://s.example/cb"],"credentials":{"oauthClient":{"client_secret":"real-secret","jwks":{"keys":[]}}}}`)
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := json.Marshal(nested.Unmapped)
	if strings.Contains(string(blob), "real-secret") || strings.Contains(string(blob), "jwks") {
		t.Fatalf("nested secret parked: %s", blob)
	}
}

func TestUnknownKind(t *testing.T) {
	if _, err := importrw.Rewrite("nope", `{}`); err == nil {
		t.Fatal("expected unknown kind")
	}
}
