package app

import (
	"os"

	"github.com/hilather/go-lab-sso/internal/auth"
	"github.com/hilather/go-lab-sso/internal/compiler"
	"github.com/hilather/go-lab-sso/internal/config"
	"github.com/hilather/go-lab-sso/internal/domainerr"
	"github.com/hilather/go-lab-sso/internal/snapshot"
)

func (a *App) Reset(actor auth.Actor, in ResetIn) (*ApplyResult, error) {
	if err := a.authorize(actor, "sso.state.reset"); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	prev := a.store.Load()
	gen := 1
	if prev != nil {
		gen = prev.Generation + 1
	}
	next, err := a.loadBootstrap(gen)
	if err != nil {
		return nil, err
	}
	a.store.Swap(next)
	a.store.SetBootstrap(next)
	a.idemp.clear()
	if a.oidc != nil {
		a.oidc.Runtime().Reset()
	}
	p := planFrom(prev, next, nil)
	prevRev := ""
	if prev != nil {
		prevRev = prev.Revision
	}
	id := a.audit.EmitOK(actor, "sso.state.reset", in.Reason, next.Revision, prevRev)
	return &ApplyResult{Plan: *p, Applied: true, Generation: next.Generation, AuditEventID: id}, nil
}

func (a *App) loadBootstrap(gen int) (*snapshot.Snapshot, error) {
	if a.bootstrapPath != "" {
		if _, err := os.Stat(a.bootstrapPath); err != nil {
			return nil, domainerr.Validation("bootstrap file unavailable; active snapshot unchanged")
		}
		doc, err := config.LoadFile(a.bootstrapPath, config.Options{BaseDir: a.baseDir})
		if err != nil {
			return nil, err
		}
		return compiler.Compile(doc, a.compileOpts(gen, ""))
	}
	boot := a.store.Bootstrap()
	if boot == nil || boot.Canonical == nil {
		return nil, domainerr.Validation("no bootstrap snapshot")
	}
	return compiler.Compile(*boot.Canonical, a.compileOpts(gen, boot.Revision))
}
