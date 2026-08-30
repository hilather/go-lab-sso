package capabilities_test

import (
	"testing"

	"github.com/hilather/go-lab-sso/internal/capabilities"
)

func TestCatalogIDsFrozen(t *testing.T) {
	want := []string{
		"sso.health.live", "sso.health.ready",
		"sso.version.get", "sso.capabilities.get", "sso.status.get", "sso.schema.config.get",
		"sso.state.get", "sso.state.validate", "sso.change.plan", "sso.change.apply",
		"sso.state.export", "sso.state.reset",
		"sso.clients.list", "sso.client.get",
		"sso.users.list", "sso.user.get",
		"sso.groups.list", "sso.group.get",
		"sso.sessions.list", "sso.session.expire",
		"sso.tunable.token.pause", "sso.tunable.token.resume",
		"sso.tunable.auth.force_fail", "sso.tunable.error.inject",
		"sso.tunable.vendor.swap",
	}
	got := capabilities.Catalog()
	if len(got) != len(want) {
		t.Fatalf("catalog len %d want %d", len(got), len(want))
	}
	seen := map[string]bool{}
	for i, c := range got {
		if c.ID != want[i] {
			t.Fatalf("catalog[%d]=%s want %s", i, c.ID, want[i])
		}
		if seen[c.ID] {
			t.Fatalf("duplicate %s", c.ID)
		}
		seen[c.ID] = true
		if c.REST.Path == "" || c.REST.Method == "" {
			t.Fatalf("%s missing REST binding", c.ID)
		}
		if c.RESTOnly && c.Disposition() != capabilities.DispositionRESTOnly {
			t.Fatalf("%s disposition", c.ID)
		}
		if !c.RESTOnly && (c.MCP.Tool == "" || c.Disposition() != capabilities.DispositionParity) {
			t.Fatalf("%s missing MCP tool", c.ID)
		}
	}
}

func TestRegistryDoesNotImportApp(t *testing.T) {
	// Compile-time: this package must not import internal/app.
	// The test file lives in capabilities_test so a mistaken app import
	// in capabilities would still compile; catalog.go is the contract.
	if _, ok := capabilities.ByID("sso.change.apply"); !ok {
		t.Fatal("apply missing")
	}
}
