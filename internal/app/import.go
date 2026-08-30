package app

import (
	"encoding/json"

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
	Warnings []string       `json:"warnings,omitempty"`
	Applied  bool           `json:"applied,omitempty"`
}

func (a *App) ImportPlan(actor auth.Actor, in ImportIn) (*ImportOut, error) {
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
	p, err := a.planLocked(ChangeIn{ExpectedRevision: a.store.Load().Revision, Operations: ops})
	if err != nil {
		return nil, err
	}
	return &ImportOut{Plan: p, Client: res.Client, Unmapped: map[string]any{"unmapped": res.Unmapped}, Warnings: res.Warnings}, nil
}

func (a *App) ImportApply(actor auth.Actor, in ImportIn) (*ImportOut, error) {
	if err := a.authorize(actor, "sso.import.apply"); err != nil {
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
	applied, err := a.applyLocked(actor, "sso.import.apply", ChangeIn{
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
		ExpectedRevision: in.ExpectedRevision,
		IdempotencyKey:   in.IdempotencyKey,
		Reason:           in.Reason,
		Operations: []model.Operation{{
			Op: model.OpUpdate, Target: model.Target{Kind: model.TargetClient, ID: cl.ID}, Value: val,
		}},
	})
}
