package app_test

import (
	"testing"

	"github.com/hilather/go-lab-sso/internal/app"
	"github.com/hilather/go-lab-sso/internal/auth"
	"github.com/hilather/go-lab-sso/internal/capabilities"
	"github.com/hilather/go-lab-sso/internal/domainerr"
)

func TestDirectoryEmpty(t *testing.T) {
	a, _ := bootApp(t)
	clients, err := a.ListClients(admin())
	if err != nil || len(clients) != 0 {
		t.Fatalf("%v %v", clients, err)
	}
	if _, err := a.GetClient(admin(), "missing"); err == nil || domainerr.CodeOf(err) != domainerr.CodeNotFound {
		t.Fatalf("got %v", err)
	}
}

func TestReadScopeDeniedForReset(t *testing.T) {
	a, _ := bootApp(t)
	reader := auth.Actor{ID: "r", Scopes: []string{capabilities.ScopeRead}}
	if _, err := a.Reset(reader, app.ResetIn{Reason: "nope"}); err == nil {
		t.Fatal("expected forbidden")
	}
}
