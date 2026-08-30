package vendor_test

import (
	"strings"
	"testing"

	"github.com/hilather/go-lab-sso/internal/vendor"
)

func TestResolveImplemented(t *testing.T) {
	for _, v := range []string{"generic", "entra", "okta", "ping", "adfs", "google", "keycloak", "iam-identity-center"} {
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
		blob := c.AuthorizePath + c.TokenPath + c.JWKSPath + c.UserInfoPath + c.LogoutPath + c.HTMLTitle + c.WSFedMetadataPath + c.WSFedPassivePath
		for _, h := range vendor.ForbiddenHosts {
			if strings.Contains(blob, h) {
				t.Fatalf("%s clothes contain hostname %s", v, h)
			}
		}
	}
}

func TestResolveUnknownRejected(t *testing.T) {
	if _, err := vendor.Resolve("duo", "", ""); err == nil {
		t.Fatal("expected clothes not implemented")
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
