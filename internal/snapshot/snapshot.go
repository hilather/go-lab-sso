package snapshot

import (
	"time"

	"github.com/hilather/go-lab-sso/internal/model"
)

type Snapshot struct {
	Canonical         *model.Document
	Revision          string
	BootstrapRevision string
	Generation        int
	CompiledAt        time.Time
	Issuer            string
	TLSCert           []byte
	TLSKey            []byte
	SigningKey        []byte
	AccessToken       []byte
	ClientSecrets     map[string][]byte
	ClientsByID       map[string]model.Client
	ClientsByClientID map[string]model.Client
	UsersByID         map[string]model.User
	GroupsByID        map[string]model.Group
}

func (s *Snapshot) Drifted() bool {
	if s == nil {
		return false
	}
	return s.Revision != s.BootstrapRevision
}
