package compiler_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
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
	if len(snap.SigningCert) == 0 || !strings.Contains(string(snap.SigningCert), "BEGIN CERTIFICATE") {
		t.Fatal("expected lab self-signed signing cert")
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

func TestCompilePingOK(t *testing.T) {
	root := repoRoot(t)
	doc, err := config.LoadFile(filepath.Join(root, "testdata/config/valid/ping.yaml"), config.Options{BaseDir: root})
	if err != nil {
		t.Fatal(err)
	}
	snap, err := compiler.Compile(doc, compiler.Options{BaseDir: root})
	if err != nil {
		t.Fatal(err)
	}
	if snap.Clothes.Vendor != "ping" || snap.Clothes.AuthorizePath != "/as/authorization.oauth2" {
		t.Fatalf("clothes %+v", snap.Clothes)
	}
}

func TestCompileKeycloakRealm(t *testing.T) {
	root := repoRoot(t)
	doc, err := config.LoadFile(filepath.Join(root, "testdata/config/valid/ping.yaml"), config.Options{BaseDir: root})
	if err != nil {
		t.Fatal(err)
	}
	doc.Metadata.Name = "realm-a"
	doc.Spec.Profile.Vendor = "keycloak"
	snap, err := compiler.Compile(doc, compiler.Options{BaseDir: root})
	if err != nil {
		t.Fatal(err)
	}
	if snap.Clothes.Realm != "realm-a" {
		t.Fatalf("realm %s", snap.Clothes.Realm)
	}
	if snap.Clothes.AuthorizePath != "/realms/realm-a/protocol/openid-connect/auth" {
		t.Fatalf("auth %s", snap.Clothes.AuthorizePath)
	}
}

func TestCompileSAMLRequiresRSA(t *testing.T) {
	root := repoRoot(t)
	doc, err := config.LoadFile(filepath.Join(root, "testdata/config/valid/minimal.yaml"), config.Options{BaseDir: root})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	ecPath := filepath.Join(dir, "ec.pem")
	if err := os.WriteFile(ecPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	doc.Spec.Signing.KeyRef = ecPath
	on := true
	doc.Spec.Protocols.SAML.Enabled = &on
	_, err = compiler.Compile(doc, compiler.Options{BaseDir: root})
	if err == nil || !strings.Contains(err.Error(), "RSA") {
		t.Fatalf("want RSA reject, got %v", err)
	}
}

func TestCompileNegativeGenericCapRejected(t *testing.T) {
	root := repoRoot(t)
	doc, err := config.LoadFile(filepath.Join(root, "testdata/config/valid/minimal.yaml"), config.Options{BaseDir: root})
	if err != nil {
		t.Fatal(err)
	}
	doc.Spec.GroupOverage.GenericCap = -1
	_, err = compiler.Compile(doc, compiler.Options{BaseDir: root})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "positive") {
		t.Fatalf("want positive cap reject, got %v", err)
	}
}
