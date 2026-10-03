package app

import (
	"github.com/hilather/go-lab-sso/internal/audit"
	"os"
	"strings"

	"github.com/hilather/go-lab-sso/internal/auth"
	"github.com/hilather/go-lab-sso/internal/compiler"
	"github.com/hilather/go-lab-sso/internal/config"
	"github.com/hilather/go-lab-sso/internal/domainerr"
	"github.com/hilather/go-lab-sso/internal/snapshot"
)

func (a *App) Reset(actor auth.Actor, in ResetIn) (result *ApplyResult, retErr error) {
	defer func() {
		if retErr != nil && domainerr.CodeOf(retErr) != domainerr.CodeForbidden {
			a.audit.Emit(audit.Event{ActorID: actor.ID, ActorClass: actor.Class, Transport: actor.Transport, Capability: "sso.state.reset", Result: audit.ResultError, ErrorCode: domainerr.CodeOf(retErr)})
		}
	}()
	if err := a.authorize(actor, "sso.state.reset"); err != nil {
		return nil, err
	}
	if strings.TrimSpace(in.Reason) == "" {
		return nil, domainerr.Validation("reason is required")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	replay, fp, err := a.replayTyped(actor, "sso.state.reset", in.IdempotencyKey, in)
	if err != nil {
		return nil, err
	}
	if replay != nil {
		return replay, nil
	}
	if in.ExpectedRevision == "" {
		return nil, domainerr.Validation("expectedRevision is required")
	}
	prev := a.store.Load()
	if in.ExpectedRevision != "" && (prev == nil || in.ExpectedRevision != prev.Revision) {
		want := ""
		if prev != nil {
			want = prev.Revision
		}
		return nil, domainerr.RevisionConflict(want, in.ExpectedRevision)
	}
	gen := 1
	if prev != nil {
		gen = prev.Generation + 1
	}
	next, err := a.loadBootstrap(gen)
	if err != nil {
		return nil, err
	}
	if err := a.validateLiveListeners(prev, next); err != nil {
		return nil, err
	}
	p := planFrom(prev, next, nil)
	if in.DryRun {
		return &ApplyResult{Plan: *p, Applied: false, Generation: gen}, nil
	}
	if a.oidc != nil {
		a.oidc.Runtime().InvalidateBefore(next.Generation)
	}
	if a.oidc != nil {
		a.oidc.Runtime().Reset()
	}
	a.store.Swap(next)
	a.store.SetBootstrap(next)
	prevRev := ""
	if prev != nil {
		prevRev = prev.Revision
	}
	id := a.audit.EmitOK(actor, "sso.state.reset", in.Reason, next.Revision, prevRev)
	res := &ApplyResult{Plan: *p, Applied: true, Generation: next.Generation, AuditEventID: id}
	a.idemp.store(scopedKey(actor, "sso.state.reset", in.IdempotencyKey), fp, p, res)
	return res, nil
}

func (a *App) loadBootstrap(gen int) (*snapshot.Snapshot, error) {
	if a.bootstrapPath != "" {
		if _, err := os.Stat(a.bootstrapPath); err != nil {
			return nil, domainerr.Validation("bootstrap file unavailable; active snapshot unchanged")
		}
		doc, err := config.LoadFile(a.bootstrapPath, config.Options{BaseDir: a.baseDir})
		if err != nil {
			return nil, domainerr.Validation("invalid bootstrap configuration: " + err.Error())
		}
		return compiler.Compile(doc, a.compileOpts(gen, ""))
	}
	boot := a.store.Bootstrap()
	if boot == nil || boot.Canonical == nil {
		return nil, domainerr.Validation("no bootstrap snapshot")
	}
	return compiler.Compile(*boot.Canonical, a.compileOpts(gen, boot.Revision))
}
