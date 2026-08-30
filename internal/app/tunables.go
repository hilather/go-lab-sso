package app

import (
	"github.com/hilather/go-lab-sso/internal/auth"
	"github.com/hilather/go-lab-sso/internal/domainerr"
	"github.com/hilather/go-lab-sso/internal/oidc"
)

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
