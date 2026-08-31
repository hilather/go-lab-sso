package config_test

import (
	"os"
	"path/filepath"
	"strings"
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

func TestUnknownProfileField(t *testing.T) {
	mustReject(t, "testdata/config/invalid/unknown-profile-field.yaml")
}

func TestLoadOktaAccepted(t *testing.T) {
	root := repoRoot(t)
	doc, err := config.LoadFile(filepath.Join(root, "testdata/config/valid/okta.yaml"), config.Options{BaseDir: root})
	if err != nil {
		t.Fatal(err)
	}
	if doc.Spec.Profile.Vendor != "okta" {
		t.Fatalf("vendor %s", doc.Spec.Profile.Vendor)
	}
}

func TestLoadPingAccepted(t *testing.T) {
	root := repoRoot(t)
	doc, err := config.LoadFile(filepath.Join(root, "testdata/config/valid/ping.yaml"), config.Options{BaseDir: root})
	if err != nil {
		t.Fatal(err)
	}
	if doc.Spec.Profile.Vendor != "ping" {
		t.Fatalf("vendor %s", doc.Spec.Profile.Vendor)
	}
}

func TestLoadDuoAccepted(t *testing.T) {
	root := repoRoot(t)
	doc, err := config.LoadFile(filepath.Join(root, "testdata/config/valid/duo.yaml"), config.Options{BaseDir: root})
	if err != nil {
		t.Fatal(err)
	}
	if doc.Spec.Profile.Vendor != "duo" {
		t.Fatalf("vendor %s", doc.Spec.Profile.Vendor)
	}
}

func TestLoadSiteminderAccepted(t *testing.T) {
	root := repoRoot(t)
	doc, err := config.LoadFile(filepath.Join(root, "testdata/config/valid/siteminder.yaml"), config.Options{BaseDir: root})
	if err != nil {
		t.Fatal(err)
	}
	if doc.Spec.Profile.Vendor != "siteminder" {
		t.Fatalf("vendor %s", doc.Spec.Profile.Vendor)
	}
}

func TestLoadShibbolethAccepted(t *testing.T) {
	root := repoRoot(t)
	doc, err := config.LoadFile(filepath.Join(root, "testdata/config/valid/shibboleth.yaml"), config.Options{BaseDir: root})
	if err != nil {
		t.Fatal(err)
	}
	if doc.Spec.Profile.Vendor != "shibboleth" {
		t.Fatalf("vendor %s", doc.Spec.Profile.Vendor)
	}
}

func TestTenantIDOmitSetRoundTrip(t *testing.T) {
	root := repoRoot(t)
	omit, err := config.LoadFile(filepath.Join(root, "testdata/config/valid/entra.yaml"), config.Options{BaseDir: root})
	if err != nil {
		t.Fatal(err)
	}
	if omit.Spec.Profile.TenantID != "" {
		t.Fatalf("omit tenantId want empty, got %q", omit.Spec.Profile.TenantID)
	}
	canon, err := config.CanonicalYAML(omit)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(canon), "tenantId") {
		t.Fatalf("empty tenantId should omit from canonicalize: %s", canon)
	}
	set, err := config.LoadFile(filepath.Join(root, "testdata/config/valid/entra-tenant.yaml"), config.Options{BaseDir: root})
	if err != nil {
		t.Fatal(err)
	}
	if set.Spec.Profile.TenantID != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("set tenantId %s", set.Spec.Profile.TenantID)
	}
	setCanon, err := config.CanonicalYAML(set)
	if err != nil {
		t.Fatal(err)
	}
	again, err := config.Load(setCanon, config.Options{BaseDir: root})
	if err != nil {
		t.Fatal(err)
	}
	if again.Spec.Profile.TenantID != set.Spec.Profile.TenantID {
		t.Fatalf("round-trip tenantId %s", again.Spec.Profile.TenantID)
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
	if doc.Spec.GroupOverage.OktaFailAt != 100 || doc.Spec.GroupOverage.GenericCap != 200 {
		t.Fatalf("overage defaults %+v", doc.Spec.GroupOverage)
	}
}
