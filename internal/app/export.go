package app

import (
	"strings"

	"github.com/hilather/go-lab-sso/internal/auth"
	"github.com/hilather/go-lab-sso/internal/config"
	"github.com/hilather/go-lab-sso/internal/domainerr"
)

func (a *App) Export(actor auth.Actor) (*Export, error) {
	if err := a.authorize(actor, "sso.state.export"); err != nil {
		return nil, err
	}
	snap := a.store.Load()
	if snap == nil || snap.Canonical == nil {
		return nil, domainerr.Validation("no active snapshot")
	}
	b, err := config.CanonicalYAML(*snap.Canonical)
	if err != nil {
		return nil, err
	}
	if strings.Contains(string(b), "-----BEGIN ") {
		return nil, domainerr.Validation("export leaked inline PEM")
	}
	return &Export{Format: "yaml", YAML: b, Revision: snap.Revision}, nil
}
