package app

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/hilather/go-lab-sso/internal/audit"
	"github.com/hilather/go-lab-sso/internal/auth"
	"github.com/hilather/go-lab-sso/internal/domainerr"
)

type OperatorSession struct {
	ID      string
	CSRF    string
	Actor   auth.Actor
	Expires time.Time
}

type SessionOut struct {
	ActorID    string    `json:"actorId"`
	ActorClass string    `json:"actorClass"`
	CSRF       string    `json:"csrf"`
	Expires    time.Time `json:"expires,omitempty"`
}

func (a *App) CreateOperatorSession(actor auth.Actor) (OperatorSession, error) {
	if err := a.authorize(actor, "sso.session.create"); err != nil {
		return OperatorSession{}, err
	}
	s := OperatorSession{
		ID:      randomHex(16),
		CSRF:    randomHex(16),
		Actor:   auth.Actor{ID: actor.ID, Class: auth.ClassCookie, Scopes: append([]string(nil), actor.Scopes...)},
		Expires: time.Now().Add(8 * time.Hour),
	}
	a.opsess.Put(s)
	a.audit.EmitOK(actor, "sso.session.create", "operator session", "", "")
	return s, nil
}

func (a *App) GetOperatorSession(actor auth.Actor) (SessionOut, error) {
	if err := a.authorize(actor, "sso.session.get"); err != nil {
		return SessionOut{}, err
	}
	return SessionOut{ActorID: actor.ID, ActorClass: actor.Class}, nil
}

func (a *App) DeleteOperatorSession(actor auth.Actor, id string) error {
	if err := a.authorize(actor, "sso.session.delete"); err != nil {
		return err
	}
	a.opsess.Delete(id)
	a.audit.EmitOK(actor, "sso.session.delete", "operator logout", "", "")
	return nil
}

func (a *App) LookupOperatorSession(id string) (OperatorSession, bool) {
	return a.opsess.Get(id)
}

func (a *App) ExpireAllSessions(actor auth.Actor) (int, error) {
	if err := a.authorize(actor, "sso.sessions.expire_all"); err != nil {
		return 0, err
	}
	n := 0
	if a.oidc != nil {
		n = a.oidc.Runtime().ExpireAll()
	}
	a.audit.EmitOK(actor, "sso.sessions.expire_all", "expire all", "", "")
	return n, nil
}

func (a *App) ListAudit(actor auth.Actor) ([]audit.Event, error) {
	if err := a.authorize(actor, "sso.audit.list"); err != nil {
		return nil, err
	}
	return a.audit.Recent(), nil
}

func (a *App) GetAudit(actor auth.Actor, id string) (audit.Event, error) {
	if err := a.authorize(actor, "sso.audit.get"); err != nil {
		return audit.Event{}, err
	}
	e, ok := a.audit.Get(id)
	if !ok {
		return audit.Event{}, domainerr.NotFound("audit " + id)
	}
	return e, nil
}

func (a *App) UIEnabled() bool {
	snap := a.store.Load()
	if snap == nil || snap.Canonical == nil {
		return true
	}
	return snap.Canonical.Spec.UI.IsEnabled(true)
}

type opStore struct {
	mu   sync.Mutex
	byID map[string]OperatorSession
}

func (s *opStore) Put(sess OperatorSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byID == nil {
		s.byID = map[string]OperatorSession{}
	}
	s.byID[sess.ID] = sess
}

func (s *opStore) Get(id string) (OperatorSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byID[id]
	if !ok {
		return OperatorSession{}, false
	}
	if !sess.Expires.IsZero() && time.Now().After(sess.Expires) {
		delete(s.byID, id)
		return OperatorSession{}, false
	}
	return sess, true
}

func (s *opStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byID, id)
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
