package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"github.com/hilather/go-lab-sso/internal/model"
	"github.com/hilather/go-lab-sso/internal/snapshot"
	"github.com/hilather/go-lab-sso/internal/totp"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTOTPMonotonicAndConcurrentReplay(t *testing.T) {
	secret := []byte("12345678901234567890")
	now := time.Unix(1800000020, 0)
	r := NewRuntime()
	if !r.VerifyAndRecordTOTP("u", secret, totp.Code(secret, now), now) {
		t.Fatal("first use")
	}
	for _, offset := range []int{-1, 0} {
		if r.VerifyAndRecordTOTP("u", secret, totp.Code(secret, now.Add(time.Duration(offset)*30*time.Second)), now) {
			t.Fatal("replayed or earlier step")
		}
	}
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if r.VerifyAndRecordTOTP("u", secret, totp.Code(secret, now.Add(30*time.Second)), now) {
				accepted.Add(1)
			}
		})
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("accepted %d concurrent codes", accepted.Load())
	}
	if r.VerifyAndRecordTOTP("u", secret, totp.Code(secret, now), now) {
		t.Fatal("older code after future step")
	}
}
func TestPKCEConstraints(t *testing.T) {
	for _, v := range []string{"a", strings.Repeat("a", 129), strings.Repeat("!", 43)} {
		if validVerifier(v) {
			t.Fatal(v)
		}
	}
	if !validVerifier(strings.Repeat("a", 43)) || validChallenge("abc") || validChallenge(strings.Repeat("A", 43)+"=") {
		t.Fatal("PKCE syntax")
	}
}
func TestRuntimeCleanupAndStaleGeneration(t *testing.T) {
	r := NewRuntime()
	past := time.Now().Add(-time.Hour)
	r.PutPending(Pending{ID: "expired", Created: past})
	r.PutCode(AuthCode{Code: "expired", Expires: past})
	r.PutRefresh(Refresh{Token: "expired", Expires: past})
	r.PutSession(LoginSession{ID: "expired", Expires: past})
	r.PutPending(Pending{ID: "live"})
	if len(r.pending) != 1 || len(r.codes)+len(r.refresh)+len(r.sessions) != 0 {
		t.Fatal("expired state retained")
	}
	for range 4200 {
		r.PutPending(Pending{})
	}
	if len(r.pending) > 4096 {
		t.Fatal("unbounded pending state")
	}
	r.InvalidateBefore(3)
	if r.PutSession(LoginSession{Generation: 2}).ID != "" {
		t.Fatal("stale request restored session")
	}
	r.PutCode(AuthCode{Generation: 2, Code: "stale"})
	if _, ok := r.TakeCode("stale"); ok {
		t.Fatal("stale grant restored")
	}
}
func TestInactiveLimiterBuckets(t *testing.T) {
	l := newLimiter(2, time.Minute)
	l.hits["old"] = []time.Time{time.Now().Add(-time.Hour)}
	if !l.allow("new") || len(l.hits) != 1 {
		t.Fatal("inactive bucket retained")
	}
}
func TestECDSACurvesAndStableKeyIDs(t *testing.T) {
	previous := ""
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, _ := x509.MarshalPKCS8PrivateKey(key)
		b := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		s, err := newSigner(b)
		if err != nil {
			t.Fatal(err)
		}
		again, _ := newSigner(b)
		if s.keyID != again.keyID || s.keyID == previous {
			t.Fatal("key ID stability/rotation")
		}
		previous = s.keyID
		token, err := s.mint("https://lab.example", "u", "app", "", time.Minute, map[string]any{"token_use": "access"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parseAndVerify(token, s.jwk, "https://lab.example", true); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAccessRequiresGeneration(t *testing.T) {
	p := &Provider{rt: NewRuntime()}
	snap := &snapshot.Snapshot{Canonical: &model.Document{}, UsersByID: map[string]model.User{"u": {ID: "u"}}, ClientsByClientID: map[string]model.Client{"app": {ClientID: "app"}}}
	p.rt.InvalidateBefore(2)
	for _, generation := range []any{nil, float64(0), float64(1)} {
		if p.accessUsable(snap, "u", []string{"app"}, map[string]any{"generation": generation}) {
			t.Fatal("unversioned/stale access accepted")
		}
	}
	if !p.accessUsable(snap, "u", []string{"app"}, map[string]any{"generation": float64(2)}) {
		t.Fatal("current access rejected")
	}
}

func TestPendingContextBounds(t *testing.T) {
	for _, pending := range []Pending{{State: strings.Repeat("s", 4097)}, {Nonce: strings.Repeat("n", 1025)}, {RelayState: strings.Repeat("r", 4097)}, {Scope: strings.Repeat("x", 1025)}, {RequestID: strings.Repeat("i", 1025)}, {State: strings.Repeat("s", 4096), RelayState: strings.Repeat("r", 4096), ClientID: strings.Repeat("c", 4096), ACSURL: strings.Repeat("a", 4096), RedirectURI: "x"}} {
		r := NewRuntime()
		if PendingBounded(pending) || r.PutPending(pending).ID != "" || len(r.pending) != 0 {
			t.Fatal("oversized context retained")
		}
	}
	if !PendingBounded(Pending{State: strings.Repeat("s", 4096), Nonce: strings.Repeat("n", 1024), RelayState: strings.Repeat("r", 4096)}) {
		t.Fatal("supported context rejected")
	}
}

func TestFullSessionsRetainedWhenPendingInserted(t *testing.T) {
	r := NewRuntime()
	for range 4096 {
		if r.PutSession(LoginSession{Expires: time.Now().Add(time.Hour)}).ID == "" {
			t.Fatal("session capacity")
		}
	}
	before := r.ListSessions()
	if r.PutPending(Pending{}).ID == "" {
		t.Fatal("unrelated pending admission failed")
	}
	if len(r.ListSessions()) != 4096 {
		t.Fatal("pending admission evicted session")
	}
	for _, s := range before {
		if _, ok := r.GetSession(s.ID); !ok {
			t.Fatal("live session evicted")
		}
	}
	if r.PutSession(LoginSession{Expires: time.Now().Add(time.Hour)}).ID != "" {
		t.Fatal("full target admitted")
	}
	if len(r.ListSessions()) != 4096 {
		t.Fatal("full target changed existing sessions")
	}
}

func TestClientBasicEncodingAndFormSingleDecoding(t *testing.T) {
	p := &Provider{}
	id := "client+id:percent%"
	secret := "p+a:ss%word"
	snap := &snapshot.Snapshot{ClientsByClientID: map[string]model.Client{id: {ClientID: id}}, ClientSecrets: map[string][]byte{id: []byte(secret)}}
	for _, basic := range []bool{true, false} {
		form := url.Values{"client_id": {id}, "client_secret": {secret}}
		req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if basic {
			req.SetBasicAuth(url.QueryEscape(id), url.QueryEscape(secret))
		}
		if _, got, err := p.clientFromRequest(req, snap); err != nil || got != id {
			t.Fatal("credential encoding", basic, err)
		}
	}
	req := httptest.NewRequest("POST", "/token", nil)
	req.SetBasicAuth("invalid%", "invalid%")
	if _, _, err := p.clientFromRequest(req, snap); err == nil {
		t.Fatal("malformed Basic escape accepted")
	}
}

func TestStaleTOTPVerificationDoesNotPoisonFreshLedger(t *testing.T) {
	r := NewRuntime()
	now := time.Unix(1800000020, 0)
	oldSeed := []byte("12345678901234567890")
	newSeed := []byte("09876543210987654321")
	r.SetTOTPOverlay("u", oldSeed)
	r.InvalidateBefore(2)
	r.ClearTOTPOverlay("u")
	r.SetTOTPOverlay("u", newSeed)
	if r.VerifyAndRecordTOTPGeneration("u", oldSeed, totp.Code(oldSeed, now), now, 1) {
		t.Fatal("stale request admitted")
	}
	if _, seen := r.totpLastStep["u"]; seen {
		t.Fatal("stale request poisoned fresh replay ledger")
	}
	if !r.VerifyAndRecordTOTPGeneration("u", newSeed, totp.Code(newSeed, now), now, 2) {
		t.Fatal("fresh seed code blocked by stale request")
	}
	if r.VerifyAndRecordTOTPGeneration("u", newSeed, totp.Code(newSeed, now), now, 2) {
		t.Fatal("current generation replay admitted")
	}
}

func TestRuntimeRotateRefresh(t *testing.T) {
	r := NewRuntime()
	live := time.Now().Add(time.Hour)
	r.PutRefresh(Refresh{Token: "old", Expires: live})
	if !r.RotateRefresh("old", Refresh{Token: "new", Expires: live}) {
		t.Fatal("first rotation failed")
	}
	if r.RotateRefresh("old", Refresh{Token: "again", Expires: live}) {
		t.Fatal("second rotation of the same grant succeeded")
	}
	if _, ok := r.GetRefresh("new"); !ok || len(r.refresh) != 1 {
		t.Fatalf("rotation left %d rows", len(r.refresh))
	}
	r.refresh["expired"] = Refresh{Token: "expired", Expires: time.Now().Add(-time.Second)}
	if r.RotateRefresh("expired", Refresh{Token: "x", Expires: live}) {
		t.Fatal("expired grant rotated")
	}
	r.InvalidateBefore(3)
	r.PutRefresh(Refresh{Generation: 3, Token: "current", Expires: live})
	if r.RotateRefresh("current", Refresh{Generation: 2, Token: "stale", Expires: live}) {
		t.Fatal("stale generation rotated")
	}
	if _, ok := r.GetRefresh("current"); !ok {
		t.Fatal("rejected rotation consumed the grant")
	}
}
