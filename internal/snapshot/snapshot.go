package snapshot

import (
	"bytes"
	"github.com/hilather/go-lab-sso/internal/password"
	"maps"
	"time"

	"github.com/hilather/go-lab-sso/internal/model"
)

type Clothes struct {
	Vendor            string
	TenantID          string
	CookieName        string
	AuthorizePath     string
	TokenPath         string
	JWKSPath          string
	UserInfoPath      string
	LogoutPath        string
	HTMLTitle         string
	HTMLHeading       string
	ConsentTitle      string
	Realm             string
	WSFedMetadataPath string
	WSFedPassivePath  string
	SAMLMetadataPath  string
	SAMLSSOPath       string
	SAMLSSOPOSTPath   string
}

type Snapshot struct {
	passwords           map[string]password.Credential
	totpSeeds           map[string]string
	Canonical           *model.Document
	Revision            string
	BootstrapRevision   string
	Generation          int
	CompiledAt          time.Time
	Issuer              string
	TLSCert             []byte
	TLSKey              []byte
	SigningKey          []byte
	SigningCert         []byte
	AccessToken         []byte
	ClientSecrets       map[string][]byte
	ClientsByID         map[string]model.Client
	ClientsByClientID   map[string]model.Client
	ClientsBySAMLEntity map[string]model.Client
	UsersByID           map[string]model.User
	GroupsByID          map[string]model.Group
	Clothes             Clothes
}

func (s *Snapshot) Drifted() bool {
	if s == nil {
		return false
	}
	return s.Revision != s.BootstrapRevision
}

func (s *Snapshot) SetUserSecrets(credentials map[string]password.Credential, seeds map[string][]byte) {
	s.passwords = make(map[string]password.Credential, len(credentials))
	for k, v := range credentials {
		s.passwords[k] = v
	}
	s.totpSeeds = make(map[string]string, len(seeds))
	for k, v := range seeds {
		s.totpSeeds[k] = string(v)
	}
}
func (s *Snapshot) Password(id string) (password.Credential, bool) {
	if s == nil {
		return password.Credential{}, false
	}
	c, ok := s.passwords[id]
	return c, ok
}
func (s *Snapshot) TOTP(id string) ([]byte, bool) {
	if s == nil {
		return nil, false
	}
	v, ok := s.totpSeeds[id]
	return []byte(v), ok
}

// SecurityEqual compares compiled credentials without exporting secret values.
func (s *Snapshot) SecurityEqual(other *Snapshot) bool {
	if s == nil || other == nil {
		return s == other
	}
	if !maps.Equal(s.passwords, other.passwords) || !maps.Equal(s.totpSeeds, other.totpSeeds) || !bytes.Equal(s.SigningKey, other.SigningKey) || !bytes.Equal(s.AccessToken, other.AccessToken) || len(s.ClientSecrets) != len(other.ClientSecrets) {
		return false
	}
	for id, secret := range s.ClientSecrets {
		if !bytes.Equal(secret, other.ClientSecrets[id]) {
			return false
		}
	}
	return true
}
