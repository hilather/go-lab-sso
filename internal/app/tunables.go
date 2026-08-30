package app

import (
	"encoding/json"

	"github.com/hilather/go-lab-sso/internal/auth"
	"github.com/hilather/go-lab-sso/internal/domainerr"
	"github.com/hilather/go-lab-sso/internal/model"
	"github.com/hilather/go-lab-sso/internal/oidc"
)

type SwapVendorIn struct {
	Vendor           string
	TenantID         *string
	ExpectedRevision string
	IdempotencyKey   string
	Reason           string
}

func (a *App) ListSessions(actor auth.Actor) ([]oidc.LoginSession, error) {
	if err := a.authorize(actor, "sso.sessions.list"); err != nil {
		return nil, err
	}
	if a.oidc == nil {
		return nil, domainerr.Validation("oidc not started")
	}
	return a.oidc.Runtime().ListSessions(), nil
}

func (a *App) ExpireSession(actor auth.Actor, id string) error {
	if err := a.authorize(actor, "sso.session.expire"); err != nil {
		return err
	}
	if a.oidc == nil || !a.oidc.Runtime().ExpireSession(id) {
		return domainerr.NotFound("session " + id)
	}
	a.audit.EmitOK(actor, "sso.session.expire", "expire session", "", "")
	return nil
}

func (a *App) PauseToken(actor auth.Actor) error {
	if err := a.authorize(actor, "sso.tunable.token.pause"); err != nil {
		return err
	}
	a.oidc.Runtime().SetPaused(true)
	a.audit.EmitOK(actor, "sso.tunable.token.pause", "pause token", "", "")
	return nil
}

func (a *App) ResumeToken(actor auth.Actor) error {
	if err := a.authorize(actor, "sso.tunable.token.resume"); err != nil {
		return err
	}
	a.oidc.Runtime().SetPaused(false)
	a.audit.EmitOK(actor, "sso.tunable.token.resume", "resume token", "", "")
	return nil
}

func (a *App) ForceFail(actor auth.Actor, on bool) error {
	if err := a.authorize(actor, "sso.tunable.auth.force_fail"); err != nil {
		return err
	}
	a.oidc.Runtime().SetForceFail(on)
	a.audit.EmitOK(actor, "sso.tunable.auth.force_fail", "force-fail", "", "")
	return nil
}

func (a *App) InjectError(actor auth.Actor, code string) error {
	if err := a.authorize(actor, "sso.tunable.error.inject"); err != nil {
		return err
	}
	a.oidc.Runtime().SetInject(code)
	a.audit.EmitOK(actor, "sso.tunable.error.inject", code, "", "")
	return nil
}

func (a *App) SwapVendor(actor auth.Actor, in SwapVendorIn) (*ApplyResult, error) {
	if err := a.authorize(actor, "sso.tunable.vendor.swap"); err != nil {
		return nil, err
	}
	if in.Vendor == "" {
		return nil, domainerr.Validation("vendor is required")
	}
	if !model.ValidVendor(in.Vendor) {
		return nil, domainerr.Validation("spec.profile.vendor is not a known vendor")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	prev := a.store.Load()
	if prev == nil || prev.Canonical == nil {
		return nil, domainerr.Validation("no active snapshot")
	}
	profile := prev.Canonical.Spec.Profile
	profile.Vendor = in.Vendor
	if in.TenantID != nil {
		profile.TenantID = *in.TenantID
	}
	val, err := json.Marshal(profile)
	if err != nil {
		return nil, err
	}
	return a.applyLocked(actor, "sso.tunable.vendor.swap", ChangeIn{
		ExpectedRevision: in.ExpectedRevision,
		IdempotencyKey:   in.IdempotencyKey,
		Reason:           in.Reason,
		Operations: []model.Operation{{
			Op: model.OpUpdate, Target: model.Target{Kind: model.TargetProfile}, Value: val,
		}},
	})
}
