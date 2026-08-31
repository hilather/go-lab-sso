package vendor_test

import (
	"strings"
	"testing"

	"github.com/hilather/go-lab-sso/internal/model"
	"github.com/hilather/go-lab-sso/internal/vendor"
)

func TestResolveImplemented(t *testing.T) {
	for _, v := range []string{"generic", "entra", "okta", "ping", "adfs", "google", "keycloak", "iam-identity-center", "duo", "siteminder", "shibboleth"} {
		c, err := vendor.Resolve(v, "", "")
		if err != nil {
			t.Fatalf("%s: %v", v, err)
		}
		if c.Vendor != v {
			t.Fatalf("vendor %s", c.Vendor)
		}
		if c.TenantID != vendor.DefaultTenantID {
			t.Fatalf("%s tenant %s", v, c.TenantID)
		}
		if c.AuthorizePath == "" || c.CookieName == "" {
			t.Fatalf("%s missing paths/cookie", v)
		}
		if c.SAMLMetadataPath == "" || c.SAMLSSOPath == "" || c.SAMLSSOPOSTPath == "" {
			t.Fatalf("%s missing SAML paths %+v", v, c)
		}
		switch v {
		case "duo", "siteminder", "shibboleth":
		default:
			if c.SAMLMetadataPath != "/saml/metadata" || c.SAMLSSOPath != "/saml/sso" || c.SAMLSSOPOSTPath != "/saml/sso" {
				t.Fatalf("%s SAML defaults %+v", v, c)
			}
		}
		blob := c.AuthorizePath + c.TokenPath + c.JWKSPath + c.UserInfoPath + c.LogoutPath + c.HTMLTitle + c.WSFedMetadataPath + c.WSFedPassivePath + c.SAMLMetadataPath + c.SAMLSSOPath + c.SAMLSSOPOSTPath
		for _, h := range vendor.ForbiddenHosts {
			if strings.Contains(blob, h) {
				t.Fatalf("%s clothes contain hostname %s", v, h)
			}
		}
	}
}

func TestValidVendorImplementedLockstep(t *testing.T) {
	for _, v := range []string{"generic", "entra", "okta", "ping", "adfs", "google", "keycloak", "iam-identity-center", "duo", "siteminder", "shibboleth"} {
		if !model.ValidVendor(v) {
			t.Fatalf("ValidVendor missing %s", v)
		}
		if !vendor.Implemented(v) {
			t.Fatalf("Implemented missing %s", v)
		}
	}
	if model.ValidVendor("forgerock") || vendor.Implemented("forgerock") {
		t.Fatal("unknown vendor must stay out of both lists")
	}
}

func TestResolveUnknownRejected(t *testing.T) {
	if _, err := vendor.Resolve("forgerock", "", ""); err == nil {
		t.Fatal("expected clothes not implemented")
	}
}

func TestResolveVEN003Paths(t *testing.T) {
	duo, err := vendor.Resolve("duo", "", "lab")
	if err != nil {
		t.Fatal(err)
	}
	if duo.AuthorizePath != "/oidc/lab/authorize" || duo.SAMLMetadataPath != "/saml2/sp/lab/metadata" || duo.SAMLSSOPath != "/saml2/sp/lab/sso" || duo.SAMLSSOPOSTPath != "/saml2/sp/lab/sso" {
		t.Fatalf("duo %+v", duo)
	}
	sm, err := vendor.Resolve("siteminder", "", "lab")
	if err != nil {
		t.Fatal(err)
	}
	if sm.AuthorizePath != "/affwebservices/CASSO/oidc/lab/authorize" || sm.SAMLMetadataPath != "/affwebservices/public/saml2meta" || sm.SAMLSSOPath != "/affwebservices/public/saml2sso" || sm.SAMLSSOPOSTPath != "/affwebservices/public/saml2sso" {
		t.Fatalf("siteminder %+v", sm)
	}
	sh, err := vendor.Resolve("shibboleth", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if sh.JWKSPath != "/idp/profile/oidc/keyset" || sh.SAMLSSOPath != "/idp/profile/SAML2/Redirect/SSO" || sh.SAMLSSOPOSTPath != "/idp/profile/SAML2/POST/SSO" {
		t.Fatalf("shibboleth %+v", sh)
	}
}

func TestResolveTenantOverride(t *testing.T) {
	c, err := vendor.Resolve("entra", "11111111-1111-1111-1111-111111111111", "")
	if err != nil {
		t.Fatal(err)
	}
	if c.TenantID != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("tid %s", c.TenantID)
	}
	if c.CookieName != "labsso_entra" {
		t.Fatalf("cookie %s", c.CookieName)
	}
}

func TestEmptyVendorIsGeneric(t *testing.T) {
	c, err := vendor.Resolve("", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if c.Vendor != "generic" || c.CookieName != "labsso_login" {
		t.Fatalf("%+v", c)
	}
}

func TestKeycloakRealmFromName(t *testing.T) {
	c, err := vendor.Resolve("keycloak", "", "realm-a")
	if err != nil {
		t.Fatal(err)
	}
	if c.Realm != "realm-a" {
		t.Fatalf("realm %s", c.Realm)
	}
	want := "/realms/realm-a/protocol/openid-connect/auth"
	if c.AuthorizePath != want {
		t.Fatalf("auth %s", c.AuthorizePath)
	}
}

func TestADFSWSFedPaths(t *testing.T) {
	c, err := vendor.Resolve("adfs", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if c.WSFedMetadataPath != "/FederationMetadata/2007-06/FederationMetadata.xml" {
		t.Fatalf("meta %s", c.WSFedMetadataPath)
	}
	if c.WSFedPassivePath != "/adfs/ls/" {
		t.Fatalf("passive %s", c.WSFedPassivePath)
	}
}
