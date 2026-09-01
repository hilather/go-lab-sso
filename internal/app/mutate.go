package app

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/hilather/go-lab-sso/internal/auth"
	"github.com/hilather/go-lab-sso/internal/compiler"
	"github.com/hilather/go-lab-sso/internal/config"
	"github.com/hilather/go-lab-sso/internal/domainerr"
	"github.com/hilather/go-lab-sso/internal/model"
	"github.com/hilather/go-lab-sso/internal/snapshot"
)

func (a *App) Plan(actor auth.Actor, in ChangeIn) (*Plan, error) {
	if err := a.authorize(actor, "sso.change.plan"); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.planLocked(in)
}

func (a *App) Apply(actor auth.Actor, in ChangeIn) (*ApplyResult, error) {
	if err := a.authorize(actor, "sso.change.apply"); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.applyLocked(actor, "sso.change.apply", in)
}

func (a *App) applyLocked(actor auth.Actor, capID string, in ChangeIn) (*ApplyResult, error) {
	fp, err := fingerprintChange(in)
	if err != nil {
		return nil, err
	}
	if hit, err := a.idemp.lookup(in.IdempotencyKey, fp); err != nil {
		return nil, err
	} else if hit != nil && hit.res != nil {
		out := *hit.res
		return &out, nil
	}
	p, err := a.planLocked(in)
	if err != nil {
		return nil, err
	}
	cand, err := a.buildCandidate(in, true)
	if err != nil {
		return nil, err
	}
	prev := a.store.Swap(cand)
	if vendorChanged(prev, cand) && a.oidc != nil {
		a.oidc.Runtime().PurgeProtocol()
	}
	if a.oidc != nil {
		a.syncTOTPOverlay(prev, cand)
	}
	res := &ApplyResult{Plan: *p, Applied: true, Generation: cand.Generation}
	prevRev := ""
	if prev != nil {
		prevRev = prev.Revision
	}
	res.AuditEventID = a.audit.EmitOK(actor, capID, in.Reason, cand.Revision, prevRev)
	a.idemp.store(in.IdempotencyKey, fp, p, res)
	return res, nil
}

func vendorChanged(prev, next *snapshot.Snapshot) bool {
	if prev == nil || next == nil || prev.Canonical == nil || next.Canonical == nil {
		return false
	}
	return prev.Canonical.Spec.Profile.Vendor != next.Canonical.Spec.Profile.Vendor
}

func (a *App) planLocked(in ChangeIn) (*Plan, error) {
	fp, err := fingerprintChange(in)
	if err != nil {
		return nil, err
	}
	if hit, err := a.idemp.lookup(in.IdempotencyKey, fp); err != nil {
		return nil, err
	} else if hit != nil && hit.plan != nil {
		live := a.store.Load()
		if live == nil || in.ExpectedRevision != live.Revision {
			want := ""
			if live != nil {
				want = live.Revision
			}
			return nil, domainerr.RevisionConflict(want, in.ExpectedRevision)
		}
		out := *hit.plan
		return &out, nil
	}
	cand, err := a.buildCandidate(in, true)
	if err != nil {
		return nil, err
	}
	prev := a.store.Load()
	p := planFrom(prev, cand, in.Operations)
	a.idemp.store(in.IdempotencyKey, fp, p, nil)
	return p, nil
}

func (a *App) Validate(actor auth.Actor, in ValidateIn) (*Plan, error) {
	if err := a.authorize(actor, "sso.state.validate"); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	var base model.Document
	prev := a.store.Load()
	if in.Document != nil {
		base = *compiler.CloneDocument(*in.Document)
	} else if prev != nil && prev.Canonical != nil {
		base = *compiler.CloneDocument(*prev.Canonical)
	} else {
		return nil, domainerr.Validation("no document to validate")
	}
	if err := applyOperations(&base, in.Operations); err != nil {
		return nil, err
	}
	boot := ""
	gen := 1
	if prev != nil {
		boot = prev.BootstrapRevision
		gen = prev.Generation
	}
	next, err := compiler.Compile(base, a.compileOpts(gen, boot))
	if err != nil {
		return nil, err
	}
	return planFrom(prev, next, in.Operations), nil
}

func (a *App) Canonicalize(doc model.Document) ([]byte, error) {
	config.Normalize(&doc)
	if err := doc.ValidateIDs(); err != nil {
		return nil, err
	}
	return config.CanonicalYAML(doc)
}

func (a *App) Status() Status {
	snap := a.store.Load()
	if snap == nil {
		return Status{}
	}
	return Status{
		BootstrapRevision: snap.BootstrapRevision,
		RuntimeRevision:   snap.Revision,
		Generation:        snap.Generation,
		Drifted:           snap.Drifted(),
		Issuer:            snap.Issuer,
	}
}

func (a *App) buildCandidate(in ChangeIn, requireRev bool) (*snapshot.Snapshot, error) {
	prev := a.store.Load()
	if prev == nil || prev.Canonical == nil {
		return nil, domainerr.Validation("no active snapshot")
	}
	if requireRev {
		if in.ExpectedRevision == "" {
			return nil, domainerr.Validation("expectedRevision is required")
		}
		if in.ExpectedRevision != prev.Revision {
			return nil, domainerr.RevisionConflict(prev.Revision, in.ExpectedRevision)
		}
	}
	cloned := compiler.CloneDocument(*prev.Canonical)
	base := *cloned
	if err := applyOperations(&base, in.Operations); err != nil {
		return nil, err
	}
	return compiler.Compile(base, a.compileOpts(prev.Generation+1, prev.BootstrapRevision))
}

func planFrom(prev, next *snapshot.Snapshot, ops []model.Operation) *Plan {
	p := &Plan{Operations: append([]model.Operation(nil), ops...)}
	if prev != nil {
		p.PreviousRevision = prev.Revision
	}
	if next != nil {
		p.CandidateRevision = next.Revision
		p.Drifted = next.Drifted()
	}
	before := ""
	after := ""
	if prev != nil && prev.Canonical != nil {
		if b, err := json.Marshal(prev.Canonical.Spec); err == nil {
			before = string(b)
		}
	}
	if next != nil && next.Canonical != nil {
		if b, err := json.Marshal(next.Canonical.Spec); err == nil {
			after = string(b)
		}
	}
	if before != after {
		p.Diff = []DiffEntry{{Path: "spec", Op: "update", Before: redact(before), After: redact(after)}}
	}
	if prev != nil && next != nil && prev.Canonical != nil && next.Canonical != nil {
		p.Impact = Impact{
			ClientsChanged: sliceChanged(prev.Canonical.Spec.Clients, next.Canonical.Spec.Clients),
			UsersChanged:   sliceChanged(prev.Canonical.Spec.Users, next.Canonical.Spec.Users),
			GroupsChanged:  sliceChanged(prev.Canonical.Spec.Groups, next.Canonical.Spec.Groups),
			IssuerChanged:  prev.Canonical.Spec.Issuer != next.Canonical.Spec.Issuer,
			VendorChanged:  prev.Canonical.Spec.Profile.Vendor != next.Canonical.Spec.Profile.Vendor,
			OverageChanged: prev.Canonical.Spec.GroupOverage != next.Canonical.Spec.GroupOverage,
		}
	}
	return p
}

func sliceChanged[T any](a, b []T) bool {
	ab, errA := json.Marshal(a)
	bb, errB := json.Marshal(b)
	if errA != nil || errB != nil {
		return true
	}
	return !bytes.Equal(ab, bb)
}

func redact(s string) string {
	if len(s) > 4096 {
		return s[:4096] + "…"
	}
	return s
}

func (a *App) InstallBootstrapFile() (*snapshot.Snapshot, error) {
	doc, err := config.LoadFile(a.bootstrapPath, config.Options{BaseDir: a.baseDir})
	if err != nil {
		return nil, err
	}
	snap, err := compiler.Compile(doc, a.compileOpts(1, ""))
	if err != nil {
		return nil, err
	}
	if a.store.InstallBootstrap(snap) == nil && snap == nil {
		return nil, fmt.Errorf("install bootstrap failed")
	}
	return snap, nil
}
