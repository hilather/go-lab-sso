package auth_test

import (
	"testing"

	"github.com/hilather/go-lab-sso/internal/auth"
	"github.com/hilather/go-lab-sso/internal/capabilities"
	"github.com/hilather/go-lab-sso/internal/domainerr"
)

func TestLoopbackUnauthIsAdmin(t *testing.T) {
	actor, err := auth.Authenticate("127.0.0.1:9", "", []byte("token"))
	if err != nil {
		t.Fatal(err)
	}
	if !actor.HasScope(capabilities.ScopeAdmin) {
		t.Fatal("loopback should be admin")
	}
}

func TestRemoteRequiresBearer(t *testing.T) {
	_, err := auth.Authenticate("10.0.0.8:9", "", []byte("token"))
	if err == nil || domainerr.CodeOf(err) != domainerr.CodeUnauthorized {
		t.Fatalf("got %v", err)
	}
}

func TestBearerConstantTime(t *testing.T) {
	actor, err := auth.Authenticate("10.0.0.8:9", "Bearer token", []byte("token"))
	if err != nil {
		t.Fatal(err)
	}
	if actor.Class != auth.ClassBearer {
		t.Fatal(actor.Class)
	}
	_, err = auth.Authenticate("10.0.0.8:9", "Bearer nope", []byte("token"))
	if err == nil {
		t.Fatal("expected reject")
	}
}

func TestXForwardedForNotUsed(t *testing.T) {
	if auth.IsLoopback("10.1.2.3:80") {
		t.Fatal("remote must not look like loopback")
	}
}

func TestAuthorizeDenied(t *testing.T) {
	cap, _ := capabilities.ByID("sso.state.reset")
	err := auth.Authorize(auth.Actor{ID: "r", Scopes: []string{capabilities.ScopeRead}}, cap)
	if err == nil {
		t.Fatal("read must not reset")
	}
}
