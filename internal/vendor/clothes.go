package vendor

import (
	"fmt"

	"github.com/hilather/go-lab-sso/internal/snapshot"
)

const DefaultTenantID = "00000000-0000-0000-0000-000000000001"

// ForbiddenHosts must never appear in discovery or token JSON.
var ForbiddenHosts = []string{
	"login.microsoftonline.com",
	"login.microsoft.com",
	"okta.com",
	"oktapreview.com",
	"accounts.google.com",
	"pingidentity.com",
	"sso.amazonaws.com",
}

func Implemented(vendor string) bool {
	switch vendor {
	case "generic", "entra", "okta", "ping", "adfs", "google", "keycloak", "iam-identity-center":
		return true
	default:
		return false
	}
}

func Resolve(vendor, tenantID, realm string) (snapshot.Clothes, error) {
	if vendor == "" {
		vendor = "generic"
	}
	if !Implemented(vendor) {
		return snapshot.Clothes{}, fmt.Errorf("clothes not implemented")
	}
	if tenantID == "" {
		tenantID = DefaultTenantID
	}
	if realm == "" {
		realm = "lab"
	}
	base := snapshot.Clothes{Vendor: vendor, TenantID: tenantID, Realm: realm}
	switch vendor {
	case "entra":
		base.CookieName = "labsso_entra"
		base.AuthorizePath = "/oauth2/v2.0/authorize"
		base.TokenPath = "/oauth2/v2.0/token"
		base.JWKSPath = "/oauth2/v2.0/jwks"
		base.UserInfoPath = "/oauth2/v2.0/userinfo"
		base.LogoutPath = "/oauth2/v2.0/logout"
		base.HTMLTitle, base.HTMLHeading, base.ConsentTitle = "LabSSO Entra login", "Sign in", "LabSSO Entra consent"
	case "okta":
		base.CookieName = "labsso_okta"
		base.AuthorizePath = "/oauth2/default/v1/authorize"
		base.TokenPath = "/oauth2/default/v1/token"
		base.JWKSPath = "/oauth2/default/v1/jwks"
		base.UserInfoPath = "/oauth2/default/v1/userinfo"
		base.LogoutPath = "/oauth2/default/v1/logout"
		base.HTMLTitle, base.HTMLHeading, base.ConsentTitle = "LabSSO Okta login", "Sign in", "LabSSO Okta consent"
	case "ping":
		base.CookieName = "labsso_ping"
		base.AuthorizePath = "/as/authorization.oauth2"
		base.TokenPath = "/as/token.oauth2"
		base.JWKSPath = "/pf/JWKS"
		base.UserInfoPath = "/idp/userinfo.openid"
		base.LogoutPath = "/idp/startSLO.ping"
		base.HTMLTitle, base.HTMLHeading, base.ConsentTitle = "LabSSO Ping login", "Sign in", "LabSSO Ping consent"
	case "adfs":
		base.CookieName = "labsso_adfs"
		base.AuthorizePath = "/adfs/oauth2/authorize"
		base.TokenPath = "/adfs/oauth2/token"
		base.JWKSPath = "/adfs/discovery/keys"
		base.UserInfoPath = "/adfs/userinfo"
		base.LogoutPath = "/adfs/oauth2/logout"
		base.WSFedMetadataPath = "/FederationMetadata/2007-06/FederationMetadata.xml"
		base.WSFedPassivePath = "/adfs/ls/"
		base.HTMLTitle, base.HTMLHeading, base.ConsentTitle = "LabSSO ADFS login", "Sign in", "LabSSO ADFS consent"
	case "google":
		base.CookieName = "labsso_google"
		base.AuthorizePath = "/o/oauth2/v2/auth"
		base.TokenPath = "/token"
		base.JWKSPath = "/oauth2/v3/certs"
		base.UserInfoPath = "/oauth2/v3/userinfo"
		base.LogoutPath = "/logout"
		base.HTMLTitle, base.HTMLHeading, base.ConsentTitle = "LabSSO Google login", "Sign in", "LabSSO Google consent"
	case "keycloak":
		prefix := "/realms/" + realm + "/protocol/openid-connect"
		base.CookieName = "labsso_keycloak"
		base.AuthorizePath = prefix + "/auth"
		base.TokenPath = prefix + "/token"
		base.JWKSPath = prefix + "/certs"
		base.UserInfoPath = prefix + "/userinfo"
		base.LogoutPath = prefix + "/logout"
		base.HTMLTitle, base.HTMLHeading, base.ConsentTitle = "LabSSO Keycloak login", "Sign in", "LabSSO Keycloak consent"
	case "iam-identity-center":
		base.CookieName = "labsso_iamic"
		base.AuthorizePath = "/authorize"
		base.TokenPath = "/token"
		base.JWKSPath = "/jwks"
		base.UserInfoPath = "/userinfo"
		base.LogoutPath = "/logout"
		base.HTMLTitle, base.HTMLHeading, base.ConsentTitle = "LabSSO IAM IC login", "Sign in", "LabSSO IAM IC consent"
	default:
		base.Vendor = "generic"
		base.CookieName = "labsso_login"
		base.AuthorizePath = "/oauth2/authorize"
		base.TokenPath = "/oauth2/token"
		base.JWKSPath = "/oauth2/jwks"
		base.UserInfoPath = "/oauth2/userinfo"
		base.LogoutPath = "/oauth2/logout"
		base.WSFedMetadataPath = "/wsfed/metadata"
		base.WSFedPassivePath = "/wsfed/passive"
		base.HTMLTitle, base.HTMLHeading, base.ConsentTitle = "LabSSO login", "Sign in", "LabSSO consent"
	}
	if base.WSFedMetadataPath == "" {
		base.WSFedMetadataPath = "/wsfed/metadata"
		base.WSFedPassivePath = "/wsfed/passive"
	}
	return base, nil
}
