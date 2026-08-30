package oidc

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/hilather/go-lab-sso/internal/snapshot"
)

type Pending struct {
	ID          string
	ClientID    string
	RedirectURI string
	Scope       string
	State       string
	Nonce       string
	Challenge   string
	Method      string
	Created     time.Time
}

type AuthCode struct {
	Code        string
	ClientID    string
	RedirectURI string
	UserID      string
	Username    string
	Scope       string
	Nonce       string
	Challenge   string
	Expires     time.Time
}

type Refresh struct {
	Token    string
	ClientID string
	UserID   string
	Username string
	Scope    string
	Expires  time.Time
}

type LoginSession struct {
	ID       string
	UserID   string
	Username string
	Expires  time.Time
}

type Runtime struct {
	mu        sync.Mutex
	pending   map[string]Pending
	codes     map[string]AuthCode
	refresh   map[string]Refresh
	sessions  map[string]LoginSession
	paused    bool
	forceFail bool
	inject    string
}

func NewRuntime() *Runtime {
	return &Runtime{
		pending:  map[string]Pending{},
		codes:    map[string]AuthCode{},
		refresh:  map[string]Refresh{},
		sessions: map[string]LoginSession{},
	}
}

func (r *Runtime) PutPending(p Pending) Pending {
	r.mu.Lock()
	defer r.mu.Unlock()
	if p.ID == "" {
		p.ID = randomID()
	}
	if p.Created.IsZero() {
		p.Created = time.Now()
	}
	r.pending[p.ID] = p
	return p
}

const pendingTTL = 10 * time.Minute

func (r *Runtime) livePendingLocked(id string) (Pending, bool) {
	p, ok := r.pending[id]
	if !ok {
		return Pending{}, false
	}
	if !p.Created.IsZero() && time.Now().After(p.Created.Add(pendingTTL)) {
		delete(r.pending, id)
		return Pending{}, false
	}
	return p, true
}

func (r *Runtime) GetPending(id string) (Pending, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.livePendingLocked(id)
}

func (r *Runtime) TakePending(id string) (Pending, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.livePendingLocked(id)
	if ok {
		delete(r.pending, id)
	}
	return p, ok
}

func (r *Runtime) PutCode(c AuthCode) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.codes[c.Code] = c
}

func (r *Runtime) TakeCode(code string) (AuthCode, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.codes[code]
	if ok {
		delete(r.codes, code)
	}
	return c, ok
}

func (r *Runtime) PutRefresh(t Refresh) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refresh[t.Token] = t
}

func (r *Runtime) GetRefresh(token string) (Refresh, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.refresh[token]
	return t, ok
}

func (r *Runtime) TakeRefresh(token string) (Refresh, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.refresh[token]
	if ok {
		delete(r.refresh, token)
	}
	return t, ok
}

func (r *Runtime) PutSession(s LoginSession) LoginSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.ID == "" {
		s.ID = randomID()
	}
	r.sessions[s.ID] = s
	return s
}

func (r *Runtime) GetSession(id string) (LoginSession, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[id]
	if ok && !s.Expires.IsZero() && time.Now().After(s.Expires) {
		delete(r.sessions, id)
		return LoginSession{}, false
	}
	return s, ok
}

func (r *Runtime) ListSessions() []LoginSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	out := make([]LoginSession, 0, len(r.sessions))
	for id, s := range r.sessions {
		if !s.Expires.IsZero() && now.After(s.Expires) {
			delete(r.sessions, id)
			continue
		}
		out = append(out, s)
	}
	return out
}

func (r *Runtime) ExpireSession(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[id]
	if !ok {
		return false
	}
	delete(r.sessions, id)
	r.purgeUserLocked(s.UserID)
	return true
}

func (r *Runtime) purgeUserLocked(userID string) {
	for k, c := range r.codes {
		if c.UserID == userID {
			delete(r.codes, k)
		}
	}
	for k, t := range r.refresh {
		if t.UserID == userID {
			delete(r.refresh, k)
		}
	}
}

func (r *Runtime) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pending = map[string]Pending{}
	r.codes = map[string]AuthCode{}
	r.refresh = map[string]Refresh{}
	r.sessions = map[string]LoginSession{}
	r.paused = false
	r.forceFail = false
	r.inject = ""
}

func (r *Runtime) SetPaused(v bool)    { r.mu.Lock(); r.paused = v; r.mu.Unlock() }
func (r *Runtime) Paused() bool        { r.mu.Lock(); defer r.mu.Unlock(); return r.paused }
func (r *Runtime) SetForceFail(v bool) { r.mu.Lock(); r.forceFail = v; r.mu.Unlock() }
func (r *Runtime) ForceFail() bool     { r.mu.Lock(); defer r.mu.Unlock(); return r.forceFail }
func (r *Runtime) SetInject(v string)  { r.mu.Lock(); r.inject = v; r.mu.Unlock() }
func (r *Runtime) Inject() string      { r.mu.Lock(); defer r.mu.Unlock(); return r.inject }

func (r *Runtime) TakeInject() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	v := r.inject
	r.inject = ""
	return v
}

func randomID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func snapshotOf(store *snapshot.Store) *snapshot.Snapshot {
	if store == nil {
		return nil
	}
	return store.Load()
}
