package app_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-sso/internal/app"
	"github.com/hilather/go-lab-sso/internal/model"
	"github.com/hilather/go-lab-sso/internal/oidc"
	"github.com/hilather/go-lab-sso/internal/totp"
)

func addUser(t *testing.T, a *app.App, id, username string) {
	t.Helper()
	val, _ := json.Marshal(model.User{ID: id, Username: username, PasswordRef: "testdata/secrets/users/alice.password"})
	if _, err := a.Apply(admin(), app.ChangeIn{
		ExpectedRevision: a.Status().RuntimeRevision, Reason: "user",
		Operations: []model.Operation{{Op: model.OpAdd, Target: model.Target{Kind: model.TargetUser, ID: id}, Value: val}},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSetMFAKeepsSessionTTL(t *testing.T) {
	a, _ := bootApp(t)
	before := a.Store().Load().Canonical.Spec.Auth.SessionTTL
	if before == 0 {
		t.Fatal("fixture sessionTTL")
	}
	if _, err := a.SetMFA(admin(), app.SetMFAIn{
		Mode: "always", ExpectedRevision: a.Status().RuntimeRevision, Reason: "mfa",
	}); err != nil {
		t.Fatal(err)
	}
	got := a.Store().Load().Canonical.Spec.Auth
	if got.MFA.Mode != "always" {
		t.Fatalf("mode %s", got.MFA.Mode)
	}
	if got.SessionTTL != before {
		t.Fatalf("sessionTTL %s want %s", got.SessionTTL, before)
	}
}

func TestSetMFARejectsEmptyMode(t *testing.T) {
	a, _ := bootApp(t)
	if _, err := a.SetMFA(admin(), app.SetMFAIn{
		Mode: "", ExpectedRevision: a.Status().RuntimeRevision, Reason: "mfa",
	}); err == nil {
		t.Fatal("empty mode")
	}
}

func TestEnrollClearUserViewAndLeak(t *testing.T) {
	a, _ := bootApp(t)
	addUser(t, a, "u1", "alice")
	if _, err := a.EnrollTOTP(admin(), "missing", "x"); err == nil {
		t.Fatal("enroll missing user")
	}
	out, err := a.EnrollTOTP(admin(), "u1", "lab")
	if err != nil {
		t.Fatal(err)
	}
	if out.Secret == "" || !strings.Contains(out.OTPAuth, "otpauth://totp/") || strings.Contains(out.Secret, "=") {
		t.Fatalf("%+v", out)
	}
	view, err := a.GetUser(admin(), "u1")
	if err != nil {
		t.Fatal(err)
	}
	if !view.TOTP.Configured || view.TOTP.Source != "overlay" {
		t.Fatalf("view %+v", view.TOTP)
	}
	blob, _ := json.Marshal(view)
	if strings.Contains(string(blob), out.Secret) || strings.Contains(string(blob), "otpauth") {
		t.Fatalf("get leaked seed: %s", blob)
	}
	ex, err := a.Export(admin())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(ex.YAML), out.Secret) || strings.Contains(string(ex.YAML), "otpauth") {
		t.Fatal("export leaked seed")
	}
	events, err := a.ListAudit(admin())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if strings.Contains(e.Reason, out.Secret) || strings.Contains(e.Reason, "otpauth") {
			t.Fatalf("audit leaked: %+v", e)
		}
		if e.Capability == "sso.user.totp.enroll" && strings.Contains(e.Reason, "enroll u1") {
			found = true
		}
	}
	if !found {
		t.Fatal("enroll audit missing")
	}
	if err := a.ClearTOTP(admin(), "u1", "done"); err != nil {
		t.Fatal(err)
	}
	view, _ = a.GetUser(admin(), "u1")
	if view.TOTP.Configured {
		t.Fatal("clear must drop overlay")
	}
}

func TestOverlaySurviveClothesSwapAndEmailApply(t *testing.T) {
	a, _ := bootApp(t)
	addUser(t, a, "u1", "alice")
	if _, err := a.EnrollTOTP(admin(), "u1", "e"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.SwapVendor(admin(), app.SwapVendorIn{
		Vendor: "okta", ExpectedRevision: a.Status().RuntimeRevision, Reason: "clothes",
	}); err != nil {
		t.Fatal(err)
	}
	if !a.OIDC().Runtime().HasTOTPOverlay("u1") {
		t.Fatal("clothes swap cleared overlay")
	}
	uval, _ := json.Marshal(model.User{
		ID: "u1", Username: "alice", Email: "alice@lab.example.net",
		PasswordRef: "testdata/secrets/users/alice.password",
	})
	if _, err := a.Apply(admin(), app.ChangeIn{
		ExpectedRevision: a.Status().RuntimeRevision, Reason: "email",
		Operations: []model.Operation{{Op: model.OpUpdate, Target: model.Target{Kind: model.TargetUser, ID: "u1"}, Value: uval}},
	}); err != nil {
		t.Fatal(err)
	}
	if !a.OIDC().Runtime().HasTOTPOverlay("u1") {
		t.Fatal("email-only apply with omitted totpSecretRef (same empty) must keep overlay")
	}
	// Same totpSecretRef empty→empty is not a change. Changing the ref must clear.
	withRef, _ := json.Marshal(model.User{
		ID: "u1", Username: "alice", Email: "alice@lab.example.net",
		PasswordRef:   "testdata/secrets/users/alice.password",
		TOTPSecretRef: "testdata/secrets/users/alice.totp",
	})
	if _, err := a.Apply(admin(), app.ChangeIn{
		ExpectedRevision: a.Status().RuntimeRevision, Reason: "ref",
		Operations: []model.Operation{{Op: model.OpUpdate, Target: model.Target{Kind: model.TargetUser, ID: "u1"}, Value: withRef}},
	}); err != nil {
		t.Fatal(err)
	}
	if a.OIDC().Runtime().HasTOTPOverlay("u1") {
		t.Fatal("totpSecretRef change must clear overlay")
	}
	if _, err := a.EnrollTOTP(admin(), "u1", "again"); err != nil {
		t.Fatal(err)
	}
	keep, _ := json.Marshal(model.User{
		ID: "u1", Username: "alice", Email: "new@lab.example.net",
		PasswordRef:   "testdata/secrets/users/alice.password",
		TOTPSecretRef: "testdata/secrets/users/alice.totp",
	})
	if _, err := a.Apply(admin(), app.ChangeIn{
		ExpectedRevision: a.Status().RuntimeRevision, Reason: "email2",
		Operations: []model.Operation{{Op: model.OpUpdate, Target: model.Target{Kind: model.TargetUser, ID: "u1"}, Value: keep}},
	}); err != nil {
		t.Fatal(err)
	}
	if !a.OIDC().Runtime().HasTOTPOverlay("u1") {
		t.Fatal("same totpSecretRef email apply must keep overlay")
	}
}

func TestResetDropsOverlay(t *testing.T) {
	a, _ := bootApp(t)
	addUser(t, a, "u1", "alice")
	if _, err := a.EnrollTOTP(admin(), "u1", "e"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Reset(admin(), app.ResetIn{Reason: "wipe"}); err != nil {
		t.Fatal(err)
	}
	if a.OIDC().Runtime().HasTOTPOverlay("u1") {
		t.Fatal("reset must drop overlay")
	}
}

func TestNeverToAlwaysExpiresIncomplete(t *testing.T) {
	a, _ := bootApp(t)
	addUser(t, a, "u1", "alice")
	a.OIDC().Runtime().PutSession(oidc.LoginSession{ID: "s1", UserID: "u1", Username: "alice", MFACompleted: false, Expires: time.Now().Add(time.Hour)})
	a.OIDC().Runtime().PutCode(oidc.AuthCode{Code: "c1", ClientID: "app-1", UserID: "u1", Username: "alice", MFACompleted: false, Expires: time.Now().Add(time.Minute)})
	a.OIDC().Runtime().PutRefresh(oidc.Refresh{Token: "r1", ClientID: "app-1", UserID: "u1", Username: "alice", MFACompleted: false, Expires: time.Now().Add(time.Hour)})
	if _, err := a.SetMFA(admin(), app.SetMFAIn{
		Mode: "always", ExpectedRevision: a.Status().RuntimeRevision, Reason: "on",
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.OIDC().Runtime().GetSession("s1"); ok {
		t.Fatal("incomplete session survived")
	}
	if _, ok := a.OIDC().Runtime().TakeCode("c1"); ok {
		t.Fatal("incomplete code survived")
	}
	if _, ok := a.OIDC().Runtime().TakeRefresh("r1"); ok {
		t.Fatal("incomplete refresh survived")
	}
}

func TestUserViewApplyTotpRejected(t *testing.T) {
	a, _ := bootApp(t)
	addUser(t, a, "u1", "alice")
	view, err := a.GetUser(admin(), "u1")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(view)
	if _, err := a.Apply(admin(), app.ChangeIn{
		ExpectedRevision: a.Status().RuntimeRevision, Reason: "copy",
		Operations: []model.Operation{{Op: model.OpUpdate, Target: model.Target{Kind: model.TargetUser, ID: "u1"}, Value: raw}},
	}); err == nil {
		t.Fatal("GET totp view must not apply")
	}
}

func TestSchemaConfigTOTP(t *testing.T) {
	a, _ := bootApp(t)
	out, err := a.SchemaConfig(admin())
	if err != nil {
		t.Fatal(err)
	}
	user, _ := out["user"].(map[string]any)
	if user == nil || !strings.Contains(user["totpSecretRef"].(string), "totpSecretRef") && user["totpSecretRef"] == nil {
		t.Fatalf("schema user %v", out["user"])
	}
	if _, ok := user["totpSecretRef"]; !ok {
		t.Fatal("schema missing totpSecretRef")
	}
	_ = totp.Digits
}
