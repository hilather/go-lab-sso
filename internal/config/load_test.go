package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hilather/go-lab-sso/internal/config"
	"github.com/hilather/go-lab-sso/internal/model"
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

func TestLoadMinimal(t *testing.T) {
	root := repoRoot(t)
	doc, err := config.LoadFile(filepath.Join(root, "testdata/config/valid/minimal.yaml"), config.Options{BaseDir: root})
	if err != nil {
		t.Fatal(err)
	}
	if doc.Spec.Profile.Vendor != "generic" {
		t.Fatalf("vendor: %s", doc.Spec.Profile.Vendor)
	}
	if !doc.Spec.Protocols.OIDC.IsEnabled(false) {
		t.Fatal("oidc should be enabled")
	}
	if doc.Spec.Signing.KeyRef == "" || doc.Spec.Listeners.HTTPS.CertRef == "" {
		t.Fatal("tls/signing refs required")
	}
}

func TestUnknownField(t *testing.T) {
	mustReject(t, "testdata/config/invalid/unknown-field.yaml")
}

func TestMemberUserIDsUnknown(t *testing.T) {
	mustReject(t, "testdata/config/invalid/member-user-ids.yaml")
}

func TestBareDurationRejected(t *testing.T) {
	mustReject(t, "testdata/config/invalid/bare-duration.yaml")
}

func TestInlinePEMRejected(t *testing.T) {
	mustReject(t, "testdata/config/invalid/inline-secret.yaml")
}

func TestDanglingGroupIDs(t *testing.T) {
	mustReject(t, "testdata/config/invalid/dangling-group-ids.yaml")
}

func TestTrailingDocumentRejected(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "testdata/config/valid/minimal.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, []byte("\n---\nnotARealField: true\n")...)
	if _, err := config.Load(raw, config.Options{BaseDir: root}); err == nil {
		t.Fatal("expected trailing YAML document to reject")
	}
}

func mustReject(t *testing.T, rel string) {
	t.Helper()
	root := repoRoot(t)
	_, err := config.LoadFile(filepath.Join(root, rel), config.Options{BaseDir: root})
	if err == nil {
		t.Fatalf("expected reject for %s", rel)
	}
}

func TestNormalizeDefaults(t *testing.T) {
	doc := model.Document{APIVersion: model.APIVersion, Kind: model.Kind, Metadata: model.Metadata{Name: "lab"}}
	config.Normalize(&doc)
	if doc.Spec.Profile.Vendor != "generic" {
		t.Fatal(doc.Spec.Profile.Vendor)
	}
	if !doc.Spec.Protocols.OIDC.IsEnabled(false) || doc.Spec.Protocols.SAML.IsEnabled(true) {
		t.Fatal("protocol defaults")
	}
}
