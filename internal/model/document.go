package model

import (
	"fmt"
	"time"
)

const (
	APIVersion = "labsso.dev/v1alpha1"
	Kind       = "LabSSO"
)

type Duration time.Duration

type Document struct {
	APIVersion string   `yaml:"apiVersion" json:"apiVersion"`
	Kind       string   `yaml:"kind" json:"kind"`
	Metadata   Metadata `yaml:"metadata" json:"metadata"`
	Spec       Spec     `yaml:"spec" json:"spec"`
}

type Metadata struct {
	Name string `yaml:"name" json:"name"`
}

type Spec struct {
	Listeners    Listeners    `yaml:"listeners" json:"listeners"`
	Issuer       string       `yaml:"issuer" json:"issuer"`
	Profile      Profile      `yaml:"profile" json:"profile"`
	Protocols    Protocols    `yaml:"protocols" json:"protocols"`
	Signing      Signing      `yaml:"signing" json:"signing"`
	Clients      []Client     `yaml:"clients" json:"clients"`
	Users        []User       `yaml:"users" json:"users"`
	Groups       []Group      `yaml:"groups" json:"groups"`
	Auth         Auth         `yaml:"auth" json:"auth"`
	GroupOverage GroupOverage `yaml:"groupOverage" json:"groupOverage"`
	UI           UI           `yaml:"ui" json:"ui"`
	Access       Access       `yaml:"access" json:"access"`
}

type Listeners struct {
	HTTPS      HTTPSListener      `yaml:"https" json:"https"`
	Management ManagementListener `yaml:"management" json:"management"`
}

type HTTPSListener struct {
	Address string `yaml:"address" json:"address"`
	CertRef string `yaml:"certRef" json:"certRef"`
	KeyRef  string `yaml:"keyRef" json:"keyRef"`
}

type ManagementListener struct {
	Address  string    `yaml:"address" json:"address"`
	RESTPath string    `yaml:"restPath" json:"restPath"`
	MCPPath  string    `yaml:"mcpPath" json:"mcpPath"`
	MCP      MCPConfig `yaml:"mcp" json:"mcp"`
}

type MCPConfig struct {
	AllowLegacyClients bool `yaml:"allowLegacyClients" json:"allowLegacyClients"`
}

type Profile struct {
	Vendor   string `yaml:"vendor" json:"vendor"`
	TenantID string `yaml:"tenantId,omitempty" json:"tenantId,omitempty"`
}

type Protocols struct {
	OIDC  ProtocolToggle `yaml:"oidc" json:"oidc"`
	SAML  ProtocolToggle `yaml:"saml" json:"saml"`
	WSFed ProtocolToggle `yaml:"wsfed" json:"wsfed"`
}

type ProtocolToggle struct {
	Enabled *bool `yaml:"enabled" json:"enabled"`
}

type Signing struct {
	KeyRef string `yaml:"keyRef" json:"keyRef"`
}

type Client struct {
	ID           string   `yaml:"id" json:"id"`
	ClientID     string   `yaml:"clientId" json:"clientId"`
	RedirectURIs []string `yaml:"redirectURIs" json:"redirectURIs"`
	Public       bool     `yaml:"public" json:"public"`
	SecretRef    string   `yaml:"secretRef,omitempty" json:"secretRef,omitempty"`
	Scopes       []string `yaml:"scopes,omitempty" json:"scopes,omitempty"`
	PreConsent   bool     `yaml:"preConsent,omitempty" json:"preConsent,omitempty"`
}

type User struct {
	ID              string   `yaml:"id" json:"id"`
	Username        string   `yaml:"username" json:"username"`
	Email           string   `yaml:"email,omitempty" json:"email,omitempty"`
	PasswordRef     string   `yaml:"passwordRef,omitempty" json:"passwordRef,omitempty"`
	PasswordHashRef string   `yaml:"passwordHashRef,omitempty" json:"passwordHashRef,omitempty"`
	GroupIDs        []string `yaml:"groupIds,omitempty" json:"groupIds,omitempty"`
	Enabled         *bool    `yaml:"enabled,omitempty" json:"enabled,omitempty"`
}

type Group struct {
	ID   string `yaml:"id" json:"id"`
	Name string `yaml:"name" json:"name"`
}

type Auth struct {
	SessionTTL Duration `yaml:"sessionTTL" json:"sessionTTL"`
	MFA        MFA      `yaml:"mfa" json:"mfa"`
}

type MFA struct {
	Mode string `yaml:"mode" json:"mode"`
}

type GroupOverage struct {
	EntraGraphStub bool `yaml:"entraGraphStub" json:"entraGraphStub"`
	OktaFailAt     int  `yaml:"oktaFailAt" json:"oktaFailAt"`
}

type UI struct {
	Enabled *bool `yaml:"enabled" json:"enabled"`
}

type Access struct {
	TokenRef string `yaml:"tokenRef" json:"tokenRef"`
}

func (d Duration) Duration() time.Duration { return time.Duration(d) }

func (d Duration) String() string { return time.Duration(d).String() }

func BoolVal(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

func (p ProtocolToggle) IsEnabled(def bool) bool {
	return BoolVal(p.Enabled, def)
}

var vendors = map[string]struct{}{
	"generic": {}, "entra": {}, "okta": {}, "ping": {}, "adfs": {},
	"google": {}, "keycloak": {}, "iam-identity-center": {},
}

func ValidVendor(v string) bool {
	_, ok := vendors[v]
	return ok
}

func ValidMFA(mode string) bool {
	switch mode {
	case "never", "always", "force-fail":
		return true
	default:
		return false
	}
}

func Ptr[T any](v T) *T { return &v }

func (c Client) Clone() Client {
	out := c
	if c.RedirectURIs != nil {
		out.RedirectURIs = append([]string(nil), c.RedirectURIs...)
	}
	if c.Scopes != nil {
		out.Scopes = append([]string(nil), c.Scopes...)
	}
	return out
}

func (u User) Clone() User {
	out := u
	if u.GroupIDs != nil {
		out.GroupIDs = append([]string(nil), u.GroupIDs...)
	}
	if u.Enabled != nil {
		v := *u.Enabled
		out.Enabled = &v
	}
	return out
}

func (d Document) ValidateIDs() error {
	if d.APIVersion != APIVersion {
		return fmt.Errorf("apiVersion must be %s", APIVersion)
	}
	if d.Kind != Kind {
		return fmt.Errorf("kind must be %s", Kind)
	}
	if d.Metadata.Name == "" {
		return fmt.Errorf("metadata.name is required")
	}
	groups := map[string]struct{}{}
	for i, g := range d.Spec.Groups {
		if g.ID == "" {
			return fmt.Errorf("spec.groups[%d].id is required", i)
		}
		if _, dup := groups[g.ID]; dup {
			return fmt.Errorf("spec.groups: duplicate id %q", g.ID)
		}
		groups[g.ID] = struct{}{}
	}
	users := map[string]struct{}{}
	usernames := map[string]struct{}{}
	for i, u := range d.Spec.Users {
		if u.ID == "" {
			return fmt.Errorf("spec.users[%d].id is required", i)
		}
		if _, dup := users[u.ID]; dup {
			return fmt.Errorf("spec.users: duplicate id %q", u.ID)
		}
		users[u.ID] = struct{}{}
		if u.Username == "" {
			return fmt.Errorf("spec.users[%d].username is required", i)
		}
		if _, dup := usernames[u.Username]; dup {
			return fmt.Errorf("spec.users: duplicate username %q", u.Username)
		}
		usernames[u.Username] = struct{}{}
		if u.PasswordRef == "" && u.PasswordHashRef == "" {
			return fmt.Errorf("spec.users[%d]: passwordRef or passwordHashRef is required", i)
		}
		for _, gid := range u.GroupIDs {
			if _, ok := groups[gid]; !ok {
				return fmt.Errorf("spec.users[%d].groupIds: dangling %q", i, gid)
			}
		}
	}
	clients := map[string]struct{}{}
	clientIDs := map[string]struct{}{}
	for i, c := range d.Spec.Clients {
		if c.ID == "" {
			return fmt.Errorf("spec.clients[%d].id is required", i)
		}
		if _, dup := clients[c.ID]; dup {
			return fmt.Errorf("spec.clients: duplicate id %q", c.ID)
		}
		clients[c.ID] = struct{}{}
		cid := c.ClientID
		if cid == "" {
			cid = c.ID
		}
		if _, dup := clientIDs[cid]; dup {
			return fmt.Errorf("spec.clients: duplicate clientId %q", cid)
		}
		clientIDs[cid] = struct{}{}
		if !c.Public && c.SecretRef == "" {
			return fmt.Errorf("spec.clients[%d]: confidential client requires secretRef", i)
		}
	}
	if d.Spec.Profile.Vendor != "" && !ValidVendor(d.Spec.Profile.Vendor) {
		return fmt.Errorf("spec.profile.vendor %q is not a known vendor", d.Spec.Profile.Vendor)
	}
	if d.Spec.Auth.MFA.Mode != "" && !ValidMFA(d.Spec.Auth.MFA.Mode) {
		return fmt.Errorf("spec.auth.mfa.mode %q is invalid", d.Spec.Auth.MFA.Mode)
	}
	return nil
}
