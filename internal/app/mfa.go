package app

import (
	"encoding/json"

	"github.com/hilather/go-lab-sso/internal/auth"
	"github.com/hilather/go-lab-sso/internal/domainerr"
	"github.com/hilather/go-lab-sso/internal/model"
	"github.com/hilather/go-lab-sso/internal/snapshot"
	"github.com/hilather/go-lab-sso/internal/totp"
)

type SetMFAIn struct {
	Mode             string
	ExpectedRevision string
	IdempotencyKey   string
	Reason           string
}

type EnrollTOTPOut struct {
	UserID   string `json:"userId"`
	Username string `json:"username"`
	Secret   string `json:"secret"`
	OTPAuth  string `json:"otpauth"`
	Source   string `json:"source"`
}

func (a *App) SetMFA(actor auth.Actor, in SetMFAIn) (*ApplyResult, error) {
	if err := a.authorize(actor, "sso.auth.mfa.set"); err != nil {
		return nil, err
	}
	if !model.ValidMFA(in.Mode) {
		return nil, domainerr.Validation("mfa.mode must be never, always, or force-fail")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	prev := a.store.Load()
	if prev == nil || prev.Canonical == nil {
		return nil, domainerr.Validation("no active snapshot")
	}
	authCfg := prev.Canonical.Spec.Auth
	authCfg.MFA.Mode = in.Mode
	val, err := json.Marshal(authCfg)
	if err != nil {
		return nil, err
	}
	return a.applyLocked(actor, "sso.auth.mfa.set", ChangeIn{
		ExpectedRevision: in.ExpectedRevision,
		IdempotencyKey:   in.IdempotencyKey,
		Reason:           in.Reason,
		Operations: []model.Operation{{
			Op: model.OpUpdate, Target: model.Target{Kind: model.TargetAuth}, Value: val,
		}},
	})
}

func (a *App) EnrollTOTP(actor auth.Actor, id, reason string) (*EnrollTOTPOut, error) {
	if err := a.authorize(actor, "sso.user.totp.enroll"); err != nil {
		return nil, err
	}
	if a.oidc == nil {
		return nil, domainerr.Validation("oidc not started")
	}
	snap := a.store.Load()
	if snap == nil {
		return nil, domainerr.Validation("no active snapshot")
	}
	u, ok := snap.UsersByID[id]
	if !ok {
		return nil, domainerr.NotFound("user " + id)
	}
	secret, err := totp.Generate()
	if err != nil {
		return nil, err
	}
	a.oidc.Runtime().SetTOTPOverlay(id, secret)
	b32 := totp.EncodeSecret(secret)
	auditReason := "enroll " + id
	if reason != "" {
		auditReason = "enroll " + id + ": " + reason
	}
	a.audit.EmitOK(actor, "sso.user.totp.enroll", auditReason, "", "")
	return &EnrollTOTPOut{
		UserID:   u.ID,
		Username: u.Username,
		Secret:   b32,
		OTPAuth:  totp.OTPAuth(u.Username, b32),
		Source:   "overlay",
	}, nil
}

func (a *App) ClearTOTP(actor auth.Actor, id, reason string) error {
	if err := a.authorize(actor, "sso.user.totp.clear"); err != nil {
		return err
	}
	if a.oidc == nil {
		return domainerr.Validation("oidc not started")
	}
	snap := a.store.Load()
	if snap == nil {
		return domainerr.Validation("no active snapshot")
	}
	if _, ok := snap.UsersByID[id]; !ok {
		return domainerr.NotFound("user " + id)
	}
	a.oidc.Runtime().ClearTOTPOverlay(id)
	auditReason := "clear " + id
	if reason != "" {
		auditReason = "clear " + id + ": " + reason
	}
	a.audit.EmitOK(actor, "sso.user.totp.clear", auditReason, "", "")
	return nil
}

func (a *App) syncTOTPOverlay(prev, cand *snapshot.Snapshot) {
	if a.oidc == nil {
		return
	}
	rt := a.oidc.Runtime()
	prevMode := ""
	nextMode := ""
	if prev != nil && prev.Canonical != nil {
		prevMode = prev.Canonical.Spec.Auth.MFA.Mode
	}
	if cand != nil && cand.Canonical != nil {
		nextMode = cand.Canonical.Spec.Auth.MFA.Mode
	}
	if nextMode == "always" && prevMode != "always" {
		rt.ExpireIncompleteMFA()
	}
	prevRefs := map[string]string{}
	if prev != nil && prev.Canonical != nil {
		for _, u := range prev.Canonical.Spec.Users {
			prevRefs[u.ID] = u.TOTPSecretRef
		}
	}
	nextRefs := map[string]string{}
	if cand != nil && cand.Canonical != nil {
		for _, u := range cand.Canonical.Spec.Users {
			nextRefs[u.ID] = u.TOTPSecretRef
		}
	}
	for id, ref := range prevRefs {
		nextRef, still := nextRefs[id]
		if !still || nextRef != ref {
			rt.ClearTOTPOverlay(id)
		}
	}
}
