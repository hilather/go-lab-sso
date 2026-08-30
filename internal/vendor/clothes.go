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
}

func Implemented(vendor string) bool {
	switch vendor {
	case "generic", "entra", "okta":
		return true
	default:
		return false
	}
}

func Resolve(vendor, tenantID string) (snapshot.Clothes, error) {
	if vendor == "" {
		vendor = "generic"
	}
	if !Implemented(vendor) {
		return snapshot.Clothes{}, fmt.Errorf("clothes not implemented")
	}
	if tenantID == "" {
		tenantID = DefaultTenantID
	}
	switch vendor {
	case "entra":
		return snapshot.Clothes{
			Vendor:        "entra",
			TenantID:      tenantID,
			CookieName:    "labsso_entra",
			AuthorizePath: "/oauth2/v2.0/authorize",
			TokenPath:     "/oauth2/v2.0/token",
			JWKSPath:      "/oauth2/v2.0/jwks",
			UserInfoPath:  "/oauth2/v2.0/userinfo",
			LogoutPath:    "/oauth2/v2.0/logout",
			HTMLTitle:     "LabSSO Entra login",
			HTMLHeading:   "Sign in",
			ConsentTitle:  "LabSSO Entra consent",
		}, nil
	case "okta":
		return snapshot.Clothes{
			Vendor:        "okta",
			TenantID:      tenantID,
			CookieName:    "labsso_okta",
			AuthorizePath: "/oauth2/default/v1/authorize",
			TokenPath:     "/oauth2/default/v1/token",
			JWKSPath:      "/oauth2/default/v1/jwks",
			UserInfoPath:  "/oauth2/default/v1/userinfo",
			LogoutPath:    "/oauth2/default/v1/logout",
			HTMLTitle:     "LabSSO Okta login",
			HTMLHeading:   "Sign in",
			ConsentTitle:  "LabSSO Okta consent",
		}, nil
	default:
		return snapshot.Clothes{
			Vendor:        "generic",
			TenantID:      tenantID,
			CookieName:    "labsso_login",
			AuthorizePath: "/oauth2/authorize",
			TokenPath:     "/oauth2/token",
			JWKSPath:      "/oauth2/jwks",
			UserInfoPath:  "/oauth2/userinfo",
			LogoutPath:    "/oauth2/logout",
			HTMLTitle:     "LabSSO login",
			HTMLHeading:   "Sign in",
			ConsentTitle:  "LabSSO consent",
		}, nil
	}
}
