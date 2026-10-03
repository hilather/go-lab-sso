package app

import (
	"encoding/json"
	"github.com/hilather/go-lab-sso/internal/audit"

	"github.com/hilather/go-lab-sso/internal/auth"
	"github.com/hilather/go-lab-sso/internal/domainerr"
	"github.com/hilather/go-lab-sso/internal/importrw"
	"github.com/hilather/go-lab-sso/internal/model"
)

type ImportIn struct {
	Kind             string
	Document         string
	ExpectedRevision string
	IdempotencyKey   string
	Reason           string
}

type ImportOut struct {
	Plan     *Plan          `json:"plan,omitempty"`
	Client   model.Client   `json:"client"`
	Unmapped map[string]any `json:"imported,omitempty"`
	Blockers []string       `json:"blockers,omitempty"`
	Warnings []string       `json:"warnings,omitempty"`
	Applied  bool           `json:"applied,omitempty"`
}

func (a *App) ImportPlan(actor auth.Actor, in ImportIn) (result *ImportOut, retErr error) {
	defer func() {
		if retErr != nil && domainerr.CodeOf(retErr) != domainerr.CodeForbidden {
			a.recordRejected(actor, "sso.import.plan", retErr)
		}
	}()
	if err := a.authorize(actor, "sso.import.plan"); err != nil {
		return nil, err
	}
	res, err := importrw.Rewrite(in.Kind, in.Document)
	if err != nil {
		return nil, domainerr.Validation(err.Error())
	}
	ops, err := importOps(res.Client)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	snap := a.store.Load()
	if snap == nil {
		return nil, domainerr.Validation("no active snapshot")
	}
	p, err := a.planLocked(ChangeIn{ExpectedRevision: snap.Revision, Operations: ops})
	if err != nil {
		if domainerr.CodeOf(err) != domainerr.CodeValidation {
			return nil, err
		}
		return &ImportOut{Client: res.Client, Unmapped: map[string]any{"unmapped": res.Unmapped}, Warnings: res.Warnings, Blockers: []string{err.Error()}}, nil
	}
	return &ImportOut{Plan: p, Client: res.Client, Unmapped: map[string]any{"unmapped": res.Unmapped}, Warnings: res.Warnings}, nil
}

func (a *App) ImportApply(actor auth.Actor, in ImportIn) (result *ImportOut, retErr error) {
	applying := false
	defer func() {
		if retErr != nil && !applying && domainerr.CodeOf(retErr) != domainerr.CodeForbidden {
			a.recordRejected(actor, "sso.import.apply", retErr)
		}
	}()
	if err := a.authorize(actor, "sso.import.apply"); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	replay, fp, err := a.replayTyped(actor, "sso.import.apply", in.IdempotencyKey, in)
	if err != nil {
		return nil, err
	}
	if replay != nil {
		res, err := importrw.Rewrite(in.Kind, in.Document)
		if err != nil {
			return nil, domainerr.Validation(err.Error())
		}
		return &ImportOut{Plan: &replay.Plan, Client: res.Client, Unmapped: map[string]any{"unmapped": res.Unmapped}, Warnings: res.Warnings, Applied: replay.Applied}, nil
	}
	res, err := importrw.Rewrite(in.Kind, in.Document)
	if err != nil {
		return nil, domainerr.Validation(err.Error())
	}
	ops, err := importOps(res.Client)
	if err != nil {
		return nil, err
	}
	applying = true
	applied, err := a.applyLocked(actor, "sso.import.apply", ChangeIn{
		fingerprint:      fp,
		ExpectedRevision: in.ExpectedRevision,
		IdempotencyKey:   in.IdempotencyKey,
		Reason:           in.Reason,
		Operations:       ops,
	})
	if err != nil {
		return nil, err
	}
	return &ImportOut{Plan: &applied.Plan, Client: res.Client, Unmapped: map[string]any{"unmapped": res.Unmapped}, Warnings: res.Warnings, Applied: applied.Applied}, nil
}

func importOps(c model.Client) ([]model.Operation, error) {
	val, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	return []model.Operation{{Op: model.OpAdd, Target: model.Target{Kind: model.TargetClient, ID: c.ID}, Value: val}}, nil
}

type RewriteRedirectIn struct {
	ClientID         string
	RedirectURIs     []string
	ExpectedRevision string
	IdempotencyKey   string
	Reason           string
}

func (a *App) RewriteRedirect(actor auth.Actor, in RewriteRedirectIn) (*ApplyResult, error) {
	if err := a.authorize(actor, "sso.tunable.redirect.rewrite"); err != nil {
		return nil, err
	}
	if in.ClientID == "" {
		return nil, domainerr.Validation("clientId is required")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	replay, fp, err := a.replayTyped(actor, "sso.tunable.redirect.rewrite", in.IdempotencyKey, in)
	if err != nil {
		return nil, err
	}
	if replay != nil {
		return replay, nil
	}
	prev := a.store.Load()
	if prev == nil || prev.Canonical == nil {
		return nil, domainerr.Validation("no active snapshot")
	}
	cl, ok := prev.ClientsByClientID[in.ClientID]
	if !ok {
		cl, ok = prev.ClientsByID[in.ClientID]
	}
	if !ok {
		return nil, domainerr.NotFound("client " + in.ClientID)
	}
	cl.RedirectURIs = append([]string(nil), in.RedirectURIs...)
	val, err := json.Marshal(cl)
	if err != nil {
		return nil, err
	}
	return a.applyLocked(actor, "sso.tunable.redirect.rewrite", ChangeIn{
		fingerprint:      fp,
		ExpectedRevision: in.ExpectedRevision,
		IdempotencyKey:   in.IdempotencyKey,
		Reason:           in.Reason,
		Operations: []model.Operation{{
			Op: model.OpUpdate, Target: model.Target{Kind: model.TargetClient, ID: cl.ID}, Value: val,
		}},
	})
}

func (a *App) recordRejected(actor auth.Actor, capability string, err error) {
	code := domainerr.CodeOf(err)
	if code == "" {
		code = domainerr.CodeInternal
	}
	a.audit.Emit(audit.Event{ActorID: actor.ID, ActorClass: actor.Class, Transport: actor.Transport, Capability: capability, Result: audit.ResultError, ErrorCode: code})
}

// RejectInput records adapter decoding failures without retaining supplied bytes.
func (a *App) RejectInput(actor auth.Actor, err error) {
	a.recordRejected(actor, "sso.management.input.rejected", err)
}
