package compiler_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-sso/internal/compiler"
	"github.com/hilather/go-lab-sso/internal/config"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

func TestCompileStandaloneUsesYAMLIssuer(t *testing.T) {
	root := repoRoot(t)
	doc, err := config.LoadFile(filepath.Join(root, "testdata/config/valid/minimal.yaml"), config.Options{BaseDir: root})
	if err != nil {
		t.Fatal(err)
	}
	snap, err := compiler.Compile(doc, compiler.Options{BaseDir: root})
	if err != nil {
		t.Fatal(err)
	}
	if snap.Issuer != "https://lab.example.net" {
		t.Fatalf("issuer %q", snap.Issuer)
	}
	if len(snap.TLSCert) == 0 || len(snap.SigningKey) == 0 || len(snap.AccessToken) == 0 {
		t.Fatal("expected resolved secret files")
	}
}

func TestCompileIssuerEnvMismatch(t *testing.T) {
	root := repoRoot(t)
	doc, err := config.LoadFile(filepath.Join(root, "testdata/config/valid/minimal.yaml"), config.Options{BaseDir: root})
	if err != nil {
		t.Fatal(err)
	}
	_, err = compiler.Compile(doc, compiler.Options{
		BaseDir: root,
		Env:     compiler.Env{PublicHost: "other.example.net"},
	})
	if err == nil {
		t.Fatal("expected issuer mismatch")
	}
}

func TestCompileIssuerEnvMatch(t *testing.T) {
	root := repoRoot(t)
	doc, err := config.LoadFile(filepath.Join(root, "testdata/config/valid/minimal.yaml"), config.Options{BaseDir: root})
	if err != nil {
		t.Fatal(err)
	}
	snap, err := compiler.Compile(doc, compiler.Options{
		BaseDir: root,
		Env:     compiler.Env{PublicHost: "lab.example.net"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if snap.Issuer != "https://lab.example.net" {
		t.Fatalf("issuer %q", snap.Issuer)
	}
}

func TestCompileEntraClothesDefaultTenant(t *testing.T) {
	root := repoRoot(t)
	doc, err := config.LoadFile(filepath.Join(root, "testdata/config/valid/entra.yaml"), config.Options{BaseDir: root})
	if err != nil {
		t.Fatal(err)
	}
	snap, err := compiler.Compile(doc, compiler.Options{BaseDir: root})
	if err != nil {
		t.Fatal(err)
	}
	if snap.Canonical.Spec.Profile.TenantID != "" {
		t.Fatalf("canonical tenantId should stay empty, got %q", snap.Canonical.Spec.Profile.TenantID)
	}
	if snap.Clothes.Vendor != "entra" || snap.Clothes.AuthorizePath != "/oauth2/v2.0/authorize" {
		t.Fatalf("clothes %+v", snap.Clothes)
	}
	if snap.Clothes.TenantID != "00000000-0000-0000-0000-000000000001" {
		t.Fatalf("compiled tid %s", snap.Clothes.TenantID)
	}
	if snap.Clothes.CookieName != "labsso_entra" {
		t.Fatalf("cookie %s", snap.Clothes.CookieName)
	}
}

func TestCompilePingRejected(t *testing.T) {
	root := repoRoot(t)
	doc, err := config.LoadFile(filepath.Join(root, "testdata/config/compile-reject/ping.yaml"), config.Options{BaseDir: root})
	if err != nil {
		t.Fatal(err)
	}
	_, err = compiler.Compile(doc, compiler.Options{BaseDir: root})
	if err == nil || !strings.Contains(err.Error(), "clothes not implemented") {
		t.Fatalf("want clothes not implemented, got %v", err)
	}
}
