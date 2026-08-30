package app

import (
	"github.com/hilather/go-lab-sso/internal/auth"
	"github.com/hilather/go-lab-sso/internal/buildinfo"
	"github.com/hilather/go-lab-sso/internal/capabilities"
	"github.com/hilather/go-lab-sso/internal/compiler"
	"github.com/hilather/go-lab-sso/internal/domainerr"
	"github.com/hilather/go-lab-sso/internal/model"
)

func (a *App) HealthLive() map[string]string {
	return map[string]string{"status": "ok"}
}

func (a *App) HealthReady() (map[string]string, bool) {
	if a.store.Load() == nil {
		return map[string]string{"status": "not_ready", "reason": "no snapshot"}, false
	}
	if a.requireHTTPS && !a.httpsBound {
		return map[string]string{"status": "not_ready", "reason": "https unbound"}, false
	}
	return map[string]string{"status": "ready"}, true
}

func (a *App) SetRequireHTTPS(v bool) { a.requireHTTPS = v }
func (a *App) SetHTTPSBound(v bool)   { a.httpsBound = v }

func (a *App) Version(actor auth.Actor) (buildinfo.Info, error) {
	if err := a.authorize(actor, "sso.version.get"); err != nil {
		return buildinfo.Info{}, err
	}
	return buildinfo.Get(), nil
}

func (a *App) GetStatus(actor auth.Actor) (Status, error) {
	if err := a.authorize(actor, "sso.status.get"); err != nil {
		return Status{}, err
	}
	return a.Status(), nil
}

func (a *App) Capabilities(actor auth.Actor) ([]capabilities.Capability, error) {
	if err := a.authorize(actor, "sso.capabilities.get"); err != nil {
		return nil, err
	}
	return capabilities.Catalog(), nil
}

func (a *App) SchemaConfig(actor auth.Actor) (map[string]any, error) {
	if err := a.authorize(actor, "sso.schema.config.get"); err != nil {
		return nil, err
	}
	return map[string]any{
		"apiVersion": model.APIVersion,
		"kind":       model.Kind,
		"generated":  false,
		"note":       "hand-described labsso.dev/v1alpha1 surface; not a generated OpenAPI document",
		"membership": "user.groupIds",
		"profile": map[string]any{
			"vendor":   "generic|entra|okta|ping|adfs|google|keycloak|iam-identity-center implemented; unknown-to-Implemented compile-reject",
			"tenantId": "optional; compile default 00000000-0000-0000-0000-000000000001 (not written into Canonical)",
		},
	}, nil
}

type StateView struct {
	BootstrapRevision string          `json:"bootstrapRevision"`
	RuntimeRevision   string          `json:"runtimeRevision"`
	Generation        int             `json:"generation"`
	Drifted           bool            `json:"drifted"`
	Canonical         *model.Document `json:"canonical"`
}

func (a *App) GetState(actor auth.Actor) (*StateView, error) {
	if err := a.authorize(actor, "sso.state.get"); err != nil {
		return nil, err
	}
	snap := a.store.Load()
	if snap == nil || snap.Canonical == nil {
		return nil, domainerr.Validation("no active snapshot")
	}
	return &StateView{
		BootstrapRevision: snap.BootstrapRevision,
		RuntimeRevision:   snap.Revision,
		Generation:        snap.Generation,
		Drifted:           snap.Drifted(),
		Canonical:         compiler.CloneDocument(*snap.Canonical),
	}, nil
}

func (a *App) ListClients(actor auth.Actor) ([]model.Client, error) {
	if err := a.authorize(actor, "sso.clients.list"); err != nil {
		return nil, err
	}
	snap := a.store.Load()
	if snap == nil || snap.Canonical == nil {
		return nil, domainerr.Validation("no active snapshot")
	}
	out := make([]model.Client, len(snap.Canonical.Spec.Clients))
	for i, c := range snap.Canonical.Spec.Clients {
		out[i] = c.Clone()
	}
	return out, nil
}

func (a *App) GetClient(actor auth.Actor, id string) (model.Client, error) {
	if err := a.authorize(actor, "sso.client.get"); err != nil {
		return model.Client{}, err
	}
	snap := a.store.Load()
	if snap == nil {
		return model.Client{}, domainerr.Validation("no active snapshot")
	}
	c, ok := snap.ClientsByID[id]
	if !ok {
		return model.Client{}, domainerr.NotFound("client " + id)
	}
	return c.Clone(), nil
}

func (a *App) ListUsers(actor auth.Actor) ([]model.User, error) {
	if err := a.authorize(actor, "sso.users.list"); err != nil {
		return nil, err
	}
	snap := a.store.Load()
	if snap == nil || snap.Canonical == nil {
		return nil, domainerr.Validation("no active snapshot")
	}
	out := make([]model.User, len(snap.Canonical.Spec.Users))
	for i, u := range snap.Canonical.Spec.Users {
		out[i] = u.Clone()
	}
	return out, nil
}

func (a *App) GetUser(actor auth.Actor, id string) (model.User, error) {
	if err := a.authorize(actor, "sso.user.get"); err != nil {
		return model.User{}, err
	}
	snap := a.store.Load()
	if snap == nil {
		return model.User{}, domainerr.Validation("no active snapshot")
	}
	u, ok := snap.UsersByID[id]
	if !ok {
		return model.User{}, domainerr.NotFound("user " + id)
	}
	return u.Clone(), nil
}

func (a *App) ListGroups(actor auth.Actor) ([]model.Group, error) {
	if err := a.authorize(actor, "sso.groups.list"); err != nil {
		return nil, err
	}
	snap := a.store.Load()
	if snap == nil || snap.Canonical == nil {
		return nil, domainerr.Validation("no active snapshot")
	}
	return append([]model.Group(nil), snap.Canonical.Spec.Groups...), nil
}

func (a *App) GetGroup(actor auth.Actor, id string) (model.Group, error) {
	if err := a.authorize(actor, "sso.group.get"); err != nil {
		return model.Group{}, err
	}
	snap := a.store.Load()
	if snap == nil {
		return model.Group{}, domainerr.Validation("no active snapshot")
	}
	g, ok := snap.GroupsByID[id]
	if !ok {
		return model.Group{}, domainerr.NotFound("group " + id)
	}
	return g, nil
}

func (a *App) authorize(actor auth.Actor, id string) error {
	cap, ok := capabilities.ByID(id)
	if !ok {
		return domainerr.NotFound("capability " + id)
	}
	if err := auth.Authorize(actor, cap); err != nil {
		a.audit.EmitDenied(actor, id, err)
		return err
	}
	return nil
}
