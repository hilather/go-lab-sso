package loginui

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hilather/go-lab-sso/internal/model"
	"github.com/hilather/go-lab-sso/internal/oidc"
	"github.com/hilather/go-lab-sso/internal/password"
	"github.com/hilather/go-lab-sso/internal/snapshot"
)

func passwordTestUI(t *testing.T, users []model.User, credentials map[string]password.Credential) (*UI, string) {
	t.Helper()
	client := model.Client{ID: "app", ClientID: "app", Public: true, RedirectURIs: []string{"https://sut.example.net/cb"}}
	snap := &snapshot.Snapshot{
		Generation:        1,
		Canonical:         &model.Document{Spec: model.Spec{Users: users}},
		ClientsByClientID: map[string]model.Client{client.ClientID: client},
	}
	snap.SetUserSecrets(credentials, nil)
	store := snapshot.NewStore()
	store.InstallBootstrap(snap)
	provider := oidc.New(store)
	pending := provider.Runtime().PutPending(oidc.Pending{Generation: 1, ClientID: client.ClientID, RedirectURI: client.RedirectURIs[0]})
	if pending.ID == "" {
		t.Fatal("could not create pending login")
	}
	return New(store, provider, nil, nil, ""), pending.ID
}

func postPassword(t *testing.T, u *UI, pending, username string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"pending": {pending}, "username": {username}, "password": {"submitted-password"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	u.postLogin(rec, req)
	return rec
}

func TestRejectedLoginAlwaysVerifiesPassword(t *testing.T) {
	credential, err := password.Parse([]byte("known-password"), false)
	if err != nil {
		t.Fatal(err)
	}
	users := []model.User{
		{ID: "known", Username: "known", PasswordRef: "known.password"},
		{ID: "disabled", Username: "disabled", PasswordRef: "disabled.password", Enabled: model.Ptr(false)},
		{ID: "missing", Username: "missing", PasswordRef: "missing.password"},
	}
	for _, username := range []string{"known", "unknown", "disabled", "missing"} {
		t.Run(username, func(t *testing.T) {
			u, pending := passwordTestUI(t, users, map[string]password.Credential{"known": credential, "disabled": credential})
			calls := 0
			u.verifyPassword = func(c password.Credential, provided []byte) error {
				calls++
				if string(provided) != "submitted-password" {
					t.Fatal("verification did not receive submitted password")
				}
				return errors.New("mismatch")
			}
			rec := postPassword(t, u, pending, username)
			if calls != 1 {
				t.Errorf("password verifications = %d; want 1 for every admitted login", calls)
			}
			if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "invalid credentials") || rec.Header().Get("Set-Cookie") != "" {
				t.Fatalf("credential rejection = %d, cookie %q", rec.Code, rec.Header().Get("Set-Cookie"))
			}
		})
	}
}

func testHashCredential(t *testing.T) password.Credential {
	t.Helper()
	phc := "$argon2id$v=19$m=65536,t=3,p=4$" + base64.RawStdEncoding.EncodeToString([]byte("test-salt-16byte")) + "$" + base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	credential, err := password.Parse([]byte(phc), true)
	if err != nil {
		t.Fatal(err)
	}
	return credential
}

func TestLoginVerificationCostMatchesSnapshot(t *testing.T) {
	plain, err := password.Parse([]byte("known-password"), false)
	if err != nil {
		t.Fatal(err)
	}
	argon := testHashCredential(t)
	plainUser := model.User{ID: "plain", Username: "plain", PasswordRef: "plain.password"}
	argonUser := model.User{ID: "argon", Username: "argon", PasswordHashRef: "argon.phc"}
	disabledPlain := model.User{ID: "disabled-plain", Username: "disabled-plain", PasswordRef: "disabled.password", Enabled: model.Ptr(false)}
	disabledArgon := model.User{ID: "disabled-argon", Username: "disabled-argon", PasswordHashRef: "disabled.phc", Enabled: model.Ptr(false)}
	for _, tc := range []struct {
		name    string
		users   []model.User
		wantKDF int
	}{
		{"empty", nil, 0},
		{"plaintext", []model.User{plainUser, disabledPlain}, 0},
		{"argon2", []model.User{argonUser, disabledArgon}, 1},
		{"mixed", []model.User{plainUser, argonUser, disabledPlain, disabledArgon}, 1},
		{"disabled-argon2-only", []model.User{disabledArgon}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			credentials := map[string]password.Credential{}
			for _, user := range tc.users {
				credential := plain
				if user.PasswordHashRef != "" {
					credential = argon
				}
				credentials[user.ID] = credential
			}
			for _, username := range []string{"plain", "argon", "disabled-plain", "disabled-argon", "unknown"} {
				t.Run(username, func(t *testing.T) {
					u, pending := passwordTestUI(t, tc.users, credentials)
					calls, kdfs := 0, 0
					u.verifyPassword = func(c password.Credential, _ []byte) error {
						calls++
						if c == argon || c == password.Dummy(true) {
							kdfs++
						}
						return errors.New("mismatch")
					}
					rec := postPassword(t, u, pending, username)
					if kdfs != tc.wantKDF || calls < 1 || calls > 2 {
						t.Fatalf("verifications = %d, KDFs = %d; want 1..2 verifications and %d KDFs", calls, kdfs, tc.wantKDF)
					}
					if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "invalid credentials") {
						t.Fatalf("credential rejection = %d", rec.Code)
					}
				})
			}
		})
	}
}

func TestDummyVerificationCannotAuthenticate(t *testing.T) {
	users := []model.User{{ID: "disabled", Username: "disabled", PasswordHashRef: "disabled.phc", Enabled: model.Ptr(false)}}
	for _, username := range []string{"unknown", "disabled"} {
		t.Run(username, func(t *testing.T) {
			u, pending := passwordTestUI(t, users, map[string]password.Credential{"disabled": testHashCredential(t)})
			calls := 0
			u.verifyPassword = func(c password.Credential, _ []byte) error {
				calls++
				if c != password.Dummy(true) {
					t.Error("unusable user did not select dummy Argon2 credential")
				}
				return nil
			}
			rec := postPassword(t, u, pending, username)
			if calls != 1 || rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "invalid credentials") || rec.Header().Get("Set-Cookie") != "" || len(u.oidc.Runtime().ListSessions()) != 0 {
				t.Fatal("dummy verification must not create a session even if verifier accepts")
			}
		})
	}
}

func TestMixedCredentialsPreservePlaintextAuthentication(t *testing.T) {
	plain, err := password.Parse([]byte("submitted-password"), false)
	if err != nil {
		t.Fatal(err)
	}
	users := []model.User{
		{ID: "plain", Username: "plain", PasswordRef: "plain.password"},
		{ID: "argon", Username: "argon", PasswordHashRef: "argon.phc"},
	}
	u, pending := passwordTestUI(t, users, map[string]password.Credential{"plain": plain, "argon": testHashCredential(t)})
	rec := postPassword(t, u, pending, "plain")
	if rec.Code != http.StatusFound || rec.Header().Get("Set-Cookie") == "" || len(u.oidc.Runtime().ListSessions()) != 1 {
		t.Fatal("dummy padding must preserve successful plaintext login")
	}
}

func TestDummyVerificationRespectsAdmission(t *testing.T) {
	for _, admission := range []string{"pending", "rate"} {
		t.Run(admission, func(t *testing.T) {
			u, pending := passwordTestUI(t, nil, nil)
			wantStatus := http.StatusBadRequest
			if admission == "pending" {
				pending = "invalid"
			} else {
				u.limit = newLimiter(0, time.Minute)
				wantStatus = http.StatusTooManyRequests
			}
			u.verifyPassword = func(password.Credential, []byte) error {
				t.Error("password verification ran before admission")
				return nil
			}
			if rec := postPassword(t, u, pending, "unknown"); rec.Code != wantStatus {
				t.Fatalf("admission status = %d; want %d", rec.Code, wantStatus)
			}
		})
	}
}

func TestDummyVerificationConcurrencyBound(t *testing.T) {
	u, pending := passwordTestUI(t, []model.User{{ID: "argon", Username: "argon", PasswordHashRef: "argon.phc"}}, map[string]password.Credential{"argon": testHashCredential(t)})
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	var wg sync.WaitGroup
	defer func() { close(release); wg.Wait() }()
	u.verifyPassword = func(c password.Credential, _ []byte) error {
		if c != password.Dummy(true) {
			t.Error("unknown user must perform dummy Argon2 verification")
		}
		entered <- struct{}{}
		<-release
		return errors.New("mismatch")
	}
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			postPassword(t, u, pending, "unknown")
		}()
	}
	for range 4 {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("admitted request did not reach verification")
		}
	}
	result := make(chan *httptest.ResponseRecorder, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		result <- postPassword(t, u, pending, "unknown")
	}()
	select {
	case rec := <-result:
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("concurrency overflow status = %d; want 429", rec.Code)
		}
	case <-entered:
		t.Fatal("fifth concurrent request reached password verification")
	case <-time.After(5 * time.Second):
		t.Fatal("concurrency overflow did not reject promptly")
	}
}
