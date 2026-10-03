package app

import (
	"encoding/json"
	"strings"

	"github.com/hilather/go-lab-sso/internal/auth"
	"github.com/hilather/go-lab-sso/internal/config"
	"github.com/hilather/go-lab-sso/internal/domainerr"
)

func (a *App) Export(actor auth.Actor, formats ...string) (*Export, error) {
	if err := a.authorize(actor, "sso.state.export"); err != nil {
		return nil, err
	}
	snap := a.store.Load()
	if snap == nil || snap.Canonical == nil {
		return nil, domainerr.Validation("no active snapshot")
	}
	format := "yaml"
	if len(formats) > 0 && formats[0] != "" {
		format = formats[0]
	}
	if format != "yaml" && format != "json" {
		return nil, domainerr.Validation("format must be yaml or json")
	}
	var b []byte
	var err error
	if format == "json" {
		b, err = json.MarshalIndent(snap.Canonical, "", "  ")
	} else {
		b, err = config.CanonicalYAML(*snap.Canonical)
	}
	if err != nil {
		return nil, err
	}
	if strings.Contains(string(b), "-----BEGIN ") {
		return nil, domainerr.Validation("export leaked inline PEM")
	}
	return &Export{Format: format, YAML: b, Data: b, Revision: snap.Revision}, nil
}
