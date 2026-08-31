package app_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-sso/internal/app"
	"github.com/hilather/go-lab-sso/internal/auth"
	"github.com/hilather/go-lab-sso/internal/capabilities"
	"github.com/hilather/go-lab-sso/internal/config"
	"github.com/hilather/go-lab-sso/internal/domainerr"
	"github.com/hilather/go-lab-sso/internal/model"
	"github.com/hilather/go-lab-sso/internal/oidc"
)

func admin() auth.Actor { return auth.AdminActor() }

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

func bootApp(t *testing.T) (*app.App, string) {
	t.Helper()
	root := repoRoot(t)
	dir := t.TempDir()
	boot := filepath.Join(dir, "config.yaml")
	src, err := os.ReadFile(filepath.Join(root, "testdata/config/valid/minimal.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(boot, src, 0o644); err != nil {
		t.Fatal(err)
	}
	a := app.New(app.Options{BootstrapPath: boot, BaseDir: root})
	if _, err := a.InstallBootstrapFile(); err != nil {
		t.Fatal(err)
	}
	return a, boot
}

func TestCanonicalizeRoundTrip(t *testing.T) {
	root := repoRoot(t)
	doc, err := config.LoadFile(filepath.Join(root, "testdata/config/valid/minimal.yaml"), config.Options{BaseDir: root})
	if err != nil {
		t.Fatal(err)
	}
	a := app.New(app.Options{BaseDir: root})
	first, err := a.Canonicalize(doc)
	if err != nil {
		t.Fatal(err)
	}
	again, err := config.Load(first, config.Options{BaseDir: root})
	if err != nil {
		t.Fatal(err)
	}
	second, err := a.Canonicalize(again)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatalf("canonicalize not stable\n%s\n----\n%s", first, second)
	}
}

func TestExportRedactsSecrets(t *testing.T) {
	a, _ := bootApp(t)
	ex, err := a.Export(admin())
	if err != nil {
		t.Fatal(err)
	}
	s := string(ex.YAML)
	if strings.Contains(s, "-----BEGIN ") {
		t.Fatal("export leaked PEM")
	}
	if strings.Contains(s, "lab-dev-token-not-for-production") {
		t.Fatal("export leaked token value")
	}
	if !strings.Contains(s, "testdata/secrets/labsso-token") {
		t.Fatal("export should keep tokenRef")
	}
}

func TestRevisionConflict(t *testing.T) {
	a, _ := bootApp(t)
	_, err := a.Apply(admin(), app.ChangeIn{
		ExpectedRevision: "sha256:deadbeef",
		Reason:           "nope",
		Operations:       []model.Operation{{Op: model.OpUpdate, Target: model.Target{Kind: model.TargetIssuer}, Value: json.RawMessage(`{"issuer":"https://lab.example.net"}`)}},
	})
	if err == nil || domainerr.CodeOf(err) != domainerr.CodeRevisionConflict {
		t.Fatalf("expected revision_conflict, got %v", err)
	}
	if a.Status().Generation != 1 {
		t.Fatalf("generation %d", a.Status().Generation)
	}
}

func TestResetDoesNotWriteBootstrap(t *testing.T) {
	a, boot := bootApp(t)
	before, err := os.ReadFile(boot)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(boot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Reset(admin(), app.ResetIn{Reason: "test"}); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(boot)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("reset wrote the bootstrap file")
	}
	info2, err := os.Stat(boot)
	if err != nil {
		t.Fatal(err)
	}
	if info2.ModTime() != info.ModTime() || info2.Size() != info.Size() {
		t.Fatal("bootstrap file metadata changed")
	}
}

func TestResetBadFileKeepsLive(t *testing.T) {
	a, boot := bootApp(t)
	live := a.Status()
	if err := os.WriteFile(boot, []byte("not: yaml: ["), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Reset(admin(), app.ResetIn{Reason: "bad"}); err == nil {
		t.Fatal("expected reset to fail")
	}
	got := a.Status()
	if got.RuntimeRevision != live.RuntimeRevision || got.Generation != live.Generation {
		t.Fatalf("live snapshot changed: %+v vs %+v", live, got)
	}
}

func TestApplyThenResetClearsDrift(t *testing.T) {
	a, _ := bootApp(t)
	st := a.Status()
	val, _ := json.Marshal(model.Client{ID: "app-1", ClientID: "app-1", Public: true, RedirectURIs: []string{"https://sut.example.net/cb"}})
	res, err := a.Apply(admin(), app.ChangeIn{
		ExpectedRevision: st.RuntimeRevision,
		Reason:           "add client",
		Operations: []model.Operation{{
			Op:     model.OpAdd,
			Target: model.Target{Kind: model.TargetClient, ID: "app-1"},
			Value:  val,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Plan.Drifted {
		t.Fatal("expected drift after apply")
	}
	if _, err := a.Reset(admin(), app.ResetIn{Reason: "restore"}); err != nil {
		t.Fatal(err)
	}
	if a.Status().Drifted {
		t.Fatal("reset should match bootstrap")
	}
}

func TestApplyRejectsMissingPasswordRef(t *testing.T) {
	a, _ := bootApp(t)
	val, _ := json.Marshal(model.User{ID: "u1", Username: "alice"})
	_, err := a.Apply(admin(), app.ChangeIn{
		ExpectedRevision: a.Status().RuntimeRevision,
		Reason:           "user",
		Operations: []model.Operation{{
			Op: model.OpAdd, Target: model.Target{Kind: model.TargetUser, ID: "u1"}, Value: val,
		}},
	})
	if err == nil {
		t.Fatal("apply must reject user without passwordRef")
	}
}

func TestApplyRejectsMemberUserIDs(t *testing.T) {
	a, _ := bootApp(t)
	_, err := a.Apply(admin(), app.ChangeIn{
		ExpectedRevision: a.Status().RuntimeRevision,
		Reason:           "group",
		Operations: []model.Operation{{
			Op:     model.OpAdd,
			Target: model.Target{Kind: model.TargetGroup, ID: "g1"},
			Value:  json.RawMessage(`{"id":"g1","name":"lab","memberUserIds":["u1"]}`),
		}},
	})
	if err == nil {
		t.Fatal("apply must reject memberUserIds")
	}
}

func TestApplyRejectsDuplicateClientID(t *testing.T) {
	a, _ := bootApp(t)
	val, _ := json.Marshal(model.Client{ID: "a", ClientID: "same", Public: true, RedirectURIs: []string{"https://sut.example.net/cb"}})
	if _, err := a.Apply(admin(), app.ChangeIn{
		ExpectedRevision: a.Status().RuntimeRevision, Reason: "a",
		Operations: []model.Operation{{Op: model.OpAdd, Target: model.Target{Kind: model.TargetClient, ID: "a"}, Value: val}},
	}); err != nil {
		t.Fatal(err)
	}
	val2, _ := json.Marshal(model.Client{ID: "b", ClientID: "same", Public: true, RedirectURIs: []string{"https://sut.example.net/cb"}})
	if _, err := a.Apply(admin(), app.ChangeIn{
		ExpectedRevision: a.Status().RuntimeRevision, Reason: "b",
		Operations: []model.Operation{{Op: model.OpAdd, Target: model.Target{Kind: model.TargetClient, ID: "b"}, Value: val2}},
	}); err == nil {
		t.Fatal("duplicate clientId must reject")
	}
}

func TestPlanImpactSeesMembershipEdit(t *testing.T) {
	a, _ := bootApp(t)
	gval, _ := json.Marshal(model.Group{ID: "g1", Name: "lab"})
	if _, err := a.Apply(admin(), app.ChangeIn{
		ExpectedRevision: a.Status().RuntimeRevision, Reason: "g",
		Operations: []model.Operation{{Op: model.OpAdd, Target: model.Target{Kind: model.TargetGroup, ID: "g1"}, Value: gval}},
	}); err != nil {
		t.Fatal(err)
	}
	uval, _ := json.Marshal(model.User{ID: "u1", Username: "alice", PasswordRef: "testdata/secrets/users/alice.password", GroupIDs: []string{"g1"}})
	if _, err := a.Apply(admin(), app.ChangeIn{
		ExpectedRevision: a.Status().RuntimeRevision, Reason: "u",
		Operations: []model.Operation{{Op: model.OpAdd, Target: model.Target{Kind: model.TargetUser, ID: "u1"}, Value: uval}},
	}); err != nil {
		t.Fatal(err)
	}
	u2, _ := json.Marshal(model.User{ID: "u1", Username: "alice", PasswordRef: "testdata/secrets/users/alice.password", GroupIDs: []string{}})
	p, err := a.Plan(admin(), app.ChangeIn{
		ExpectedRevision: a.Status().RuntimeRevision, Reason: "edit",
		Operations: []model.Operation{{Op: model.OpUpdate, Target: model.Target{Kind: model.TargetUser, ID: "u1"}, Value: u2}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Impact.UsersChanged {
		t.Fatal("membership edit must set usersChanged")
	}
}

func TestPlanIdempotencyDoesNotIgnoreLaterApply(t *testing.T) {
	a, _ := bootApp(t)
	gval, _ := json.Marshal(model.Group{ID: "g1", Name: "lab"})
	in := app.ChangeIn{
		ExpectedRevision: a.Status().RuntimeRevision,
		IdempotencyKey:   "plan-1",
		Reason:           "g",
		Operations:       []model.Operation{{Op: model.OpAdd, Target: model.Target{Kind: model.TargetGroup, ID: "g1"}, Value: gval}},
	}
	if _, err := a.Plan(admin(), in); err != nil {
		t.Fatal(err)
	}
	cval, _ := json.Marshal(model.Client{ID: "c1", ClientID: "c1", Public: true, RedirectURIs: []string{"https://sut.example.net/cb"}})
	if _, err := a.Apply(admin(), app.ChangeIn{
		ExpectedRevision: a.Status().RuntimeRevision, Reason: "c",
		Operations: []model.Operation{{Op: model.OpAdd, Target: model.Target{Kind: model.TargetClient, ID: "c1"}, Value: cval}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Plan(admin(), in); err == nil || domainerr.CodeOf(err) != domainerr.CodeRevisionConflict {
		t.Fatalf("stale plan cache must revision-conflict, got %v", err)
	}
}

func TestResetClearsOIDCRuntime(t *testing.T) {
	a, _ := bootApp(t)
	a.OIDC().Runtime().PutCode(mustCode())
	if _, err := a.Reset(admin(), app.ResetIn{Reason: "wipe"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.OIDC().Runtime().TakeCode("code1"); ok {
		t.Fatal("reset must drop auth codes")
	}
}

func TestValidateDoesNotMutateLive(t *testing.T) {
	a, _ := bootApp(t)
	val, _ := json.Marshal(model.Client{ID: "app-1", ClientID: "app-1", Public: true, RedirectURIs: []string{"https://sut.example.net/cb"}})
	if _, err := a.Apply(admin(), app.ChangeIn{
		ExpectedRevision: a.Status().RuntimeRevision, Reason: "add",
		Operations: []model.Operation{{Op: model.OpAdd, Target: model.Target{Kind: model.TargetClient, ID: "app-1"}, Value: val}},
	}); err != nil {
		t.Fatal(err)
	}
	rev := a.Status().RuntimeRevision
	upd, _ := json.Marshal(model.Client{ID: "app-1", ClientID: "renamed", Public: true, RedirectURIs: []string{"https://sut.example.net/cb"}})
	if _, err := a.Validate(admin(), app.ValidateIn{
		Operations: []model.Operation{{Op: model.OpUpdate, Target: model.Target{Kind: model.TargetClient, ID: "app-1"}, Value: upd}},
	}); err != nil {
		t.Fatal(err)
	}
	if a.Status().RuntimeRevision != rev {
		t.Fatal("validate must not change revision")
	}
	c, err := a.GetClient(admin(), "app-1")
	if err != nil {
		t.Fatal(err)
	}
	if c.ClientID != "app-1" {
		t.Fatalf("validate mutated live clientId: %s", c.ClientID)
	}
	items, err := a.ListClients(admin())
	if err != nil || len(items) != 1 || items[0].ClientID != "app-1" {
		t.Fatalf("canonical list mutated: %+v %v", items, err)
	}
}

func TestSetOverageMergeAndScopes(t *testing.T) {
	a, _ := bootApp(t)
	writer := auth.Actor{ID: "w", Scopes: []string{capabilities.ScopeWrite}}
	off := false
	_, err := a.SetOverage(writer, app.SetOverageIn{
		EntraGraphStub: &off, ExpectedRevision: a.Status().RuntimeRevision, Reason: "x",
	})
	if domainerr.CodeOf(err) != domainerr.CodeForbidden {
		t.Fatalf("write without tunables: %v", err)
	}
	if !a.Store().Load().Canonical.Spec.GroupOverage.EntraGraphStub {
		t.Fatal("denied set must not change stub")
	}
	tun := auth.Actor{ID: "t", Scopes: []string{capabilities.ScopeTunables}}
	if _, err := a.SetOverage(tun, app.SetOverageIn{
		ExpectedRevision: a.Status().RuntimeRevision, Reason: "omit keeps stub",
	}); err != nil {
		t.Fatal(err)
	}
	if !a.Store().Load().Canonical.Spec.GroupOverage.EntraGraphStub {
		t.Fatal("omit entraGraphStub must keep true")
	}
	cap := 0
	if _, err := a.SetOverage(tun, app.SetOverageIn{
		EntraGraphStub: &off, GenericCap: &cap, ExpectedRevision: a.Status().RuntimeRevision, Reason: "zero cap",
	}); err != nil {
		t.Fatal(err)
	}
	ov := a.Store().Load().Canonical.Spec.GroupOverage
	if ov.EntraGraphStub {
		t.Fatal("explicit false must set stub off")
	}
	if ov.GenericCap != 200 {
		t.Fatalf("Normalize must lift 0 → 200, got %d", ov.GenericCap)
	}
}

func TestImportApplyAndRedirectRewrite(t *testing.T) {
	a, _ := bootApp(t)
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "testdata/import/oidc-client.json"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := a.ImportApply(admin(), app.ImportIn{
		Kind: "oidc-client", Document: string(raw),
		ExpectedRevision: a.Status().RuntimeRevision, Reason: "import",
	})
	if err != nil || !out.Applied {
		t.Fatalf("import %v %+v", err, out)
	}
	if out.Unmapped == nil {
		t.Fatal("unmapped missing from response")
	}
	ex, err := a.Export(admin())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(ex.YAML), "token_endpoint_auth_method") {
		t.Fatal("vendor blob key leaked into export")
	}
	if !strings.Contains(string(ex.YAML), "oidc-app") {
		t.Fatal("imported client missing from export")
	}
	if _, err := a.RewriteRedirect(admin(), app.RewriteRedirectIn{
		ClientID: "oidc-app", RedirectURIs: []string{"https://sut.example.net/new"},
		ExpectedRevision: a.Status().RuntimeRevision, Reason: "rewrite",
	}); err != nil {
		t.Fatal(err)
	}
	cl, err := a.GetClient(admin(), "imported-oidc-app")
	if err != nil {
		t.Fatal(err)
	}
	if len(cl.RedirectURIs) != 1 || cl.RedirectURIs[0] != "https://sut.example.net/new" {
		t.Fatalf("rewrite %v", cl.RedirectURIs)
	}
}

func TestAuditAndExpireAllScopes(t *testing.T) {
	a, _ := bootApp(t)
	reader := auth.Actor{ID: "r", Scopes: []string{capabilities.ScopeRead}}
	if _, err := a.ListAudit(reader); domainerr.CodeOf(err) != domainerr.CodeForbidden {
		t.Fatalf("audit without audit.read: %v", err)
	}
	if _, err := a.ExpireAllSessions(reader); domainerr.CodeOf(err) != domainerr.CodeForbidden {
		t.Fatalf("expire-all without sessions: %v", err)
	}
	aud := auth.Actor{ID: "a", Scopes: []string{capabilities.ScopeAuditRead}}
	if _, err := a.ListAudit(aud); err != nil {
		t.Fatal(err)
	}
	sess := auth.Actor{ID: "s", Scopes: []string{capabilities.ScopeSessions}}
	if _, err := a.ExpireAllSessions(sess); err != nil {
		t.Fatal(err)
	}
}

func TestMintTokenAndForceConsent(t *testing.T) {
	a, _ := bootApp(t)
	cval, _ := json.Marshal(model.Client{ID: "app-1", ClientID: "app-1", Public: true, RedirectURIs: []string{"https://sut.example.net/cb"}})
	uval, _ := json.Marshal(model.User{ID: "u1", Username: "alice", PasswordRef: "testdata/secrets/users/alice.password"})
	if _, err := a.Apply(admin(), app.ChangeIn{
		ExpectedRevision: a.Status().RuntimeRevision, Reason: "mint",
		Operations: []model.Operation{
			{Op: model.OpAdd, Target: model.Target{Kind: model.TargetClient, ID: "app-1"}, Value: cval},
			{Op: model.OpAdd, Target: model.Target{Kind: model.TargetUser, ID: "u1"}, Value: uval},
		},
	}); err != nil {
		t.Fatal(err)
	}
	writer := auth.Actor{ID: "w", Scopes: []string{capabilities.ScopeWrite}}
	if _, err := a.MintToken(writer, app.MintTokenIn{UserID: "u1", ClientID: "app-1"}); domainerr.CodeOf(err) != domainerr.CodeForbidden {
		t.Fatalf("mint without tunables: %v", err)
	}
	out, err := a.MintToken(admin(), app.MintTokenIn{UserID: "u1", ClientID: "app-1", Scope: "openid"})
	if err != nil || out.AccessToken == "" || out.IDToken == "" {
		t.Fatalf("mint %v %+v", err, out)
	}
	if err := a.ForceConsent(admin(), true); err != nil {
		t.Fatal(err)
	}
	if !a.OIDC().Runtime().ForceConsent() {
		t.Fatal("force consent not set")
	}
}

func TestSwapVendorScopes(t *testing.T) {
	a, _ := bootApp(t)
	writer := auth.Actor{ID: "w", Scopes: []string{capabilities.ScopeWrite}}
	_, err := a.SwapVendor(writer, app.SwapVendorIn{
		Vendor: "entra", ExpectedRevision: a.Status().RuntimeRevision, Reason: "x",
	})
	if domainerr.CodeOf(err) != domainerr.CodeForbidden {
		t.Fatalf("write without tunables: %v", err)
	}
	tun := auth.Actor{ID: "t", Scopes: []string{capabilities.ScopeTunables}}
	if _, err := a.SwapVendor(tun, app.SwapVendorIn{
		Vendor: "entra", ExpectedRevision: a.Status().RuntimeRevision, Reason: "x",
	}); err != nil {
		t.Fatal(err)
	}
	if a.Store().Load().Clothes.Vendor != "entra" {
		t.Fatal("swap did not compile entra clothes")
	}
}

func TestSwapVendorMergesTenantID(t *testing.T) {
	a, _ := bootApp(t)
	tid := "11111111-1111-1111-1111-111111111111"
	val, _ := json.Marshal(model.Profile{Vendor: "entra", TenantID: tid})
	if _, err := a.Apply(admin(), app.ChangeIn{
		ExpectedRevision: a.Status().RuntimeRevision, Reason: "set tid",
		Operations: []model.Operation{{Op: model.OpUpdate, Target: model.Target{Kind: model.TargetProfile}, Value: val}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.SwapVendor(admin(), app.SwapVendorIn{
		Vendor: "okta", ExpectedRevision: a.Status().RuntimeRevision, Reason: "omit tid",
	}); err != nil {
		t.Fatal(err)
	}
	if got := a.Store().Load().Canonical.Spec.Profile.TenantID; got != tid {
		t.Fatalf("omit tenantId must keep Canonical %q, got %q", tid, got)
	}
	empty := ""
	if _, err := a.SwapVendor(admin(), app.SwapVendorIn{
		Vendor: "okta", TenantID: &empty, ExpectedRevision: a.Status().RuntimeRevision, Reason: "clear tid",
	}); err != nil {
		t.Fatal(err)
	}
	if got := a.Store().Load().Canonical.Spec.Profile.TenantID; got != "" {
		t.Fatalf("empty tenantId must clear Canonical, got %q", got)
	}
	val, _ = json.Marshal(model.Profile{Vendor: "entra", TenantID: tid})
	if _, err := a.Apply(admin(), app.ChangeIn{
		ExpectedRevision: a.Status().RuntimeRevision, Reason: "restore tid",
		Operations: []model.Operation{{Op: model.OpUpdate, Target: model.Target{Kind: model.TargetProfile}, Value: val}},
	}); err != nil {
		t.Fatal(err)
	}
	wipe, _ := json.Marshal(model.Profile{Vendor: "okta"})
	if _, err := a.Apply(admin(), app.ChangeIn{
		ExpectedRevision: a.Status().RuntimeRevision, Reason: "full replace",
		Operations: []model.Operation{{Op: model.OpUpdate, Target: model.Target{Kind: model.TargetProfile}, Value: wipe}},
	}); err != nil {
		t.Fatal(err)
	}
	if got := a.Store().Load().Canonical.Spec.Profile.TenantID; got != "" {
		t.Fatalf("Apply TargetProfile full replace must zero tenantId, got %q", got)
	}
}

func TestApplyPingOK(t *testing.T) {
	a, _ := bootApp(t)
	val, _ := json.Marshal(model.Profile{Vendor: "ping"})
	if _, err := a.Apply(admin(), app.ChangeIn{
		ExpectedRevision: a.Status().RuntimeRevision, Reason: "ping",
		Operations: []model.Operation{{Op: model.OpUpdate, Target: model.Target{Kind: model.TargetProfile}, Value: val}},
	}); err != nil {
		t.Fatal(err)
	}
	if got := a.Store().Load().Clothes.Vendor; got != "ping" {
		t.Fatalf("clothes vendor %s", got)
	}
}

func TestSchemaConfigVendorImplemented(t *testing.T) {
	a, _ := bootApp(t)
	out, err := a.SchemaConfig(admin())
	if err != nil {
		t.Fatal(err)
	}
	prof, _ := out["profile"].(map[string]any)
	v, _ := prof["vendor"].(string)
	for _, name := range []string{"generic", "entra", "okta", "ping", "adfs", "google", "keycloak", "iam-identity-center", "duo", "siteminder", "shibboleth"} {
		if !strings.Contains(v, name) {
			t.Fatalf("schema missing %s: %s", name, v)
		}
	}
	if strings.Contains(v, "other ValidVendor values compile-reject") {
		t.Fatalf("stale VEN-001 schema: %s", v)
	}
}

func mustCode() oidc.AuthCode {
	return oidc.AuthCode{
		Code: "code1", ClientID: "app-1", RedirectURI: "https://sut.example.net/cb",
		UserID: "u1", Username: "alice", Scope: "openid",
		Expires: time.Now().Add(time.Minute),
	}
}
