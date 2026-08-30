package snapshot

import (
	"time"

	"github.com/hilather/go-lab-sso/internal/model"
)

type Clothes struct {
	Vendor        string
	TenantID      string
	CookieName    string
	AuthorizePath string
	TokenPath     string
	JWKSPath      string
	UserInfoPath  string
	LogoutPath    string
	HTMLTitle          string
	HTMLHeading        string
	ConsentTitle       string
	Realm              string
	WSFedMetadataPath  string
	WSFedPassivePath   string
}

type Snapshot struct {
	Canonical         *model.Document
	Revision          string
	BootstrapRevision string
	Generation        int
	CompiledAt        time.Time
	Issuer            string
	TLSCert           []byte
	TLSKey            []byte
	SigningKey         []byte
	SigningCert        []byte
	AccessToken        []byte
	ClientSecrets      map[string][]byte
	ClientsByID        map[string]model.Client
	ClientsByClientID  map[string]model.Client
	ClientsBySAMLEntity map[string]model.Client
	UsersByID          map[string]model.User
	GroupsByID         map[string]model.Group
	Clothes            Clothes
}

func (s *Snapshot) Drifted() bool {
	if s == nil {
		return false
	}
	return s.Revision != s.BootstrapRevision
}
