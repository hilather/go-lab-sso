package oidc

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/hilather/go-lab-sso/internal/snapshot"
	"github.com/hilather/go-lab-sso/internal/totp"
)

type Pending struct {
	Generation  int
	ID          string
	Protocol    string
	ClientID    string
	RedirectURI string
	Scope       string
	State       string
	Nonce       string
	Challenge   string
	Method      string
	ACSURL      string
	RequestID   string
	SPEntityID  string
	RelayState  string
	Created     time.Time
}

const ProtocolOIDC = "oidc"
const ProtocolSAML = "saml"

type AuthCode struct {
	Generation   int
	Code         string
	ClientID     string
	RedirectURI  string
	UserID       string
	Username     string
	Scope        string
	Nonce        string
	Challenge    string
	Expires      time.Time
	MFACompleted bool
}

type Refresh struct {
	Generation   int
	Token        string
	ClientID     string
	UserID       string
	Username     string
	Scope        string
	Expires      time.Time
	MFACompleted bool
}

type LoginSession struct {
	Generation   int
	ID           string
	UserID       string
	Username     string
	Expires      time.Time
	MFACompleted bool
}

type Runtime struct {
	mu                sync.Mutex
	minimumGeneration int
	reject            func(string)
	pending           map[string]Pending
	codes             map[string]AuthCode
	refresh           map[string]Refresh
	sessions          map[string]LoginSession
	totpOverlay       map[string][]byte
	totpLastStep      map[string]int64
	paused            bool
	forceFail         bool
	forceConsent      bool
	inject            string
}

func NewRuntime() *Runtime {
	return &Runtime{
		pending:      map[string]Pending{},
		codes:        map[string]AuthCode{},
		refresh:      map[string]Refresh{},
		sessions:     map[string]LoginSession{},
		totpOverlay:  map[string][]byte{},
		totpLastStep: map[string]int64{},
	}
}

func (r *Runtime) PutPending(p Pending) Pending {
	if !PendingBounded(p) {
		return Pending{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if p.Generation != 0 && p.Generation < r.minimumGeneration {
		return Pending{}
	}
	r.cleanupLocked(time.Now())
	if _, exists := r.pending[p.ID]; !exists && len(r.pending) >= 4096 {
		return Pending{}
	}
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

func (r *Runtime) PutCode(c AuthCode) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c.Generation != 0 && c.Generation < r.minimumGeneration {
		return false
	}
	r.cleanupLocked(time.Now())
	if _, exists := r.codes[c.Code]; !exists && len(r.codes) >= 4096 {
		return false
	}
	r.codes[c.Code] = c
	return true
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

func (r *Runtime) PutRefresh(t Refresh) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if t.Generation != 0 && t.Generation < r.minimumGeneration {
		return false
	}
	r.cleanupLocked(time.Now())
	if _, exists := r.refresh[t.Token]; !exists && len(r.refresh) >= 4096 {
		return false
	}
	r.refresh[t.Token] = t
	return true
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
	if s.Generation != 0 && s.Generation < r.minimumGeneration {
		return LoginSession{}
	}
	r.cleanupLocked(time.Now())
	if _, exists := r.sessions[s.ID]; !exists && len(r.sessions) >= 4096 {
		return LoginSession{}
	}
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

func (r *Runtime) ExpireAll() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := len(r.sessions)
	r.sessions = map[string]LoginSession{}
	r.codes = map[string]AuthCode{}
	r.refresh = map[string]Refresh{}
	return n
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

func (r *Runtime) PurgeProtocol() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.purgeProtocolLocked()
}

func (r *Runtime) purgeProtocolLocked() {
	r.pending = map[string]Pending{}
	r.codes = map[string]AuthCode{}
	r.refresh = map[string]Refresh{}
	r.sessions = map[string]LoginSession{}
}

func (r *Runtime) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.purgeProtocolLocked()
	r.totpOverlay = map[string][]byte{}
	r.totpLastStep = map[string]int64{}
	r.paused = false
	r.forceFail = false
	r.forceConsent = false
	r.inject = ""
}

func (r *Runtime) GetTOTPOverlay(userID string) ([]byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.totpOverlay[userID]
	if !ok {
		return nil, false
	}
	out := make([]byte, len(s))
	copy(out, s)
	return out, true
}

func (r *Runtime) SetTOTPOverlay(userID string, secret []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]byte, len(secret))
	copy(out, secret)
	r.totpOverlay[userID] = out
	delete(r.totpLastStep, userID)
}

func (r *Runtime) ClearTOTPOverlay(userID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.totpOverlay, userID)
	delete(r.totpLastStep, userID)
}

func (r *Runtime) HasTOTPOverlay(userID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.totpOverlay[userID]
	return ok
}

func (r *Runtime) VerifyAndRecordTOTP(userID string, secret []byte, code string, now time.Time) bool {
	return r.VerifyAndRecordTOTPGeneration(userID, secret, code, now, 0)
}

// VerifyAndRecordTOTPGeneration rejects delayed requests before changing the replay ledger.
// Verification runs outside the runtime mutex; admission and replay recording are atomic.
func (r *Runtime) VerifyAndRecordTOTPGeneration(userID string, secret []byte, code string, now time.Time, generation int) bool {
	step, ok := totp.Verify(secret, code, now)
	if !ok {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if generation != 0 && generation < r.minimumGeneration {
		return false
	}
	if last, seen := r.totpLastStep[userID]; seen && step <= last {
		return false
	}
	r.totpLastStep[userID] = step
	return true
}

func (r *Runtime) ExpireIncompleteMFA() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, s := range r.sessions {
		if !s.MFACompleted {
			delete(r.sessions, id)
		}
	}
	for k, c := range r.codes {
		if !c.MFACompleted {
			delete(r.codes, k)
		}
	}
	for k, t := range r.refresh {
		if !t.MFACompleted {
			delete(r.refresh, k)
		}
	}
}

func SessionUsable(sess LoginSession, mode string) bool {
	if mode == "force-fail" || (mode == "always" && !sess.MFACompleted) {
		return false
	}
	return true
}

func (r *Runtime) SetPaused(v bool)       { r.mu.Lock(); r.paused = v; r.mu.Unlock() }
func (r *Runtime) Paused() bool           { r.mu.Lock(); defer r.mu.Unlock(); return r.paused }
func (r *Runtime) SetForceFail(v bool)    { r.mu.Lock(); r.forceFail = v; r.mu.Unlock() }
func (r *Runtime) ForceFail() bool        { r.mu.Lock(); defer r.mu.Unlock(); return r.forceFail }
func (r *Runtime) SetForceConsent(v bool) { r.mu.Lock(); r.forceConsent = v; r.mu.Unlock() }
func (r *Runtime) ForceConsent() bool     { r.mu.Lock(); defer r.mu.Unlock(); return r.forceConsent }
func (r *Runtime) SetInject(v string)     { r.mu.Lock(); r.inject = v; r.mu.Unlock() }
func (r *Runtime) Inject() string         { r.mu.Lock(); defer r.mu.Unlock(); return r.inject }

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

// cleanupLocked bounds abandoned authentication state without a management dependency.
func (r *Runtime) cleanupLocked(now time.Time) {
	for id, p := range r.pending {
		if now.After(p.Created.Add(pendingTTL)) {
			delete(r.pending, id)
		}
	}
	for id, c := range r.codes {
		if now.After(c.Expires) {
			delete(r.codes, id)
		}
	}
	for id, t := range r.refresh {
		if now.After(t.Expires) {
			delete(r.refresh, id)
		}
	}
	for id, s := range r.sessions {
		if !s.Expires.IsZero() && now.After(s.Expires) {
			delete(r.sessions, id)
		}
	}
}

// InvalidateBefore revokes protocol state and prevents delayed requests from restoring it.
func (r *Runtime) InvalidateBefore(generation int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.minimumGeneration = generation
	r.purgeProtocolLocked()
}
func (r *Runtime) GenerationUsable(generation int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return generation == 0 || generation >= r.minimumGeneration
}

// PendingBounded limits attacker-controlled flow context before retaining it in memory.
// These are byte limits; opaque browser context is never truncated.
func PendingBounded(p Pending) bool {
	if len(p.Nonce) > 1024 || len(p.Scope) > 1024 || len(p.RequestID) > 1024 {
		return false
	}
	total := 0
	for _, field := range []string{p.ID, p.Protocol, p.ClientID, p.RedirectURI, p.Scope, p.State, p.Nonce, p.Challenge, p.Method, p.ACSURL, p.RequestID, p.SPEntityID, p.RelayState} {
		if len(field) > 4096 {
			return false
		}
		total += len(field)
	}
	return total <= 16<<10
}
