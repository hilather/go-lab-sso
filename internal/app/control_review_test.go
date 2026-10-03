package app_test

import (
	"encoding/json"
	"github.com/hilather/go-lab-sso/internal/app"
	"github.com/hilather/go-lab-sso/internal/model"
	"github.com/hilather/go-lab-sso/internal/oidc"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReviewTypedIdempotencyAfterInterveningEdit(t *testing.T) {
	a, _ := bootApp(t)
	cap := 5
	in := app.SetOverageIn{GenericCap: &cap, ExpectedRevision: a.Status().RuntimeRevision, IdempotencyKey: "review", Reason: "test"}
	first, err := a.SetOverage(admin(), in)
	if err != nil {
		t.Fatal(err)
	}
	off := false
	_, err = a.SetOverage(admin(), app.SetOverageIn{EntraGraphStub: &off, ExpectedRevision: a.Status().RuntimeRevision, Reason: "second"})
	if err != nil {
		t.Fatal(err)
	}
	again, err := a.SetOverage(admin(), in)
	if err != nil {
		t.Fatalf("identical replay must return first result gen=%d, got %v", first.Generation, err)
	}
	if again.Generation != first.Generation {
		t.Fatalf("replay changed generation")
	}
}

func TestReviewOperationTargetIDMustMatch(t *testing.T) {
	a, _ := bootApp(t)
	_, err := a.Apply(admin(), app.ChangeIn{ExpectedRevision: a.Status().RuntimeRevision, Reason: "mismatch", Operations: []model.Operation{{Op: model.OpAdd, Target: model.Target{Kind: model.TargetGroup, ID: "intended"}, Value: json.RawMessage(`{"id":"other","name":"Other"}`)}}})
	if err == nil {
		t.Fatal("operation targeting intended silently created other")
	}
}

func TestReviewImportPlanWithoutSnapshot(t *testing.T) {
	a := app.New(app.Options{})
	defer func() {
		if v := recover(); v != nil {
			t.Fatalf("panicked instead of validation error: %v", v)
		}
	}()
	_, err := a.ImportPlan(admin(), app.ImportIn{Kind: "oidc-client", Document: `{"client_id":"x","redirect_uris":["https://sut.example/cb"]}`})
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestReviewSemanticIdempotency(t *testing.T) {
	a, _ := bootApp(t)
	in := app.ChangeIn{ExpectedRevision: a.Status().RuntimeRevision, Reason: "semantic", IdempotencyKey: "semantic", Operations: []model.Operation{{Op: model.OpAdd, Target: model.Target{Kind: model.TargetGroup, ID: "g1"}, Value: json.RawMessage(`{"name":"Group","id":"g1"}`)}}}
	_, err := a.Apply(admin(), in)
	if err != nil {
		t.Fatal(err)
	}
	in.Operations[0].Value = json.RawMessage(`{"id":"g1","name":"Group"}`)
	_, err = a.Apply(admin(), in)
	if err != nil {
		t.Fatalf("equivalent JSON replay conflicts: %v", err)
	}
}

func TestReviewConfidentialImportPlanReturnsFragment(t *testing.T) {
	a, _ := bootApp(t)
	out, err := a.ImportPlan(admin(), app.ImportIn{Kind: "oidc-client", Document: `{"client_id":"x","redirect_uris":["https://sut.example/cb"],"token_endpoint_auth_method":"client_secret_basic"}`})
	if err != nil {
		t.Fatalf("need editable fragment/warning but got %v", err)
	}
	if out.Client.ID == "" || len(out.Warnings) == 0 {
		t.Fatal("missing fragment or warning")
	}
}

func TestResetRequiresRevisionAndSupportsPlanReplay(t *testing.T) {
	a, _ := bootApp(t)
	if _, err := a.Reset(admin(), app.ResetIn{Reason: "reset"}); err == nil {
		t.Fatal("unguarded reset accepted")
	}
	in := app.ResetIn{Reason: "reset", ExpectedRevision: a.Status().RuntimeRevision, IdempotencyKey: "reset", DryRun: true}
	generation := a.Status().Generation
	plan, err := a.Reset(admin(), in)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Applied || a.Status().Generation != generation {
		t.Fatal("reset dry run mutated state")
	}
	in.DryRun = false
	first, err := a.Reset(admin(), in)
	if err != nil {
		t.Fatal(err)
	}
	second, err := a.Reset(admin(), in)
	if err != nil {
		t.Fatal(err)
	}
	if second.Generation != first.Generation || a.Status().Generation != first.Generation {
		t.Fatal("reset retry applied twice")
	}
}

func TestTypedReplaySurvivesTargetRemoval(t *testing.T) {
	a, _ := bootApp(t)
	val := json.RawMessage(`{"id":"retry","clientId":"retry","public":true,"redirectURIs":["https://sut.example/cb"]}`)
	_, err := a.Apply(admin(), app.ChangeIn{Reason: "add", ExpectedRevision: a.Status().RuntimeRevision, Operations: []model.Operation{{Op: model.OpAdd, Target: model.Target{Kind: model.TargetClient, ID: "retry"}, Value: val}}})
	if err != nil {
		t.Fatal(err)
	}
	in := app.RewriteRedirectIn{ClientID: "retry", RedirectURIs: []string{"https://sut.example/new"}, ExpectedRevision: a.Status().RuntimeRevision, IdempotencyKey: "redirect", Reason: "rewrite"}
	first, err := a.RewriteRedirect(admin(), in)
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Apply(admin(), app.ChangeIn{Reason: "remove", ExpectedRevision: a.Status().RuntimeRevision, Operations: []model.Operation{{Op: model.OpRemove, Target: model.Target{Kind: model.TargetClient, ID: "retry"}}}})
	if err != nil {
		t.Fatal(err)
	}
	replay, err := a.RewriteRedirect(admin(), in)
	if err != nil {
		t.Fatal(err)
	}
	if replay.Generation != first.Generation {
		t.Fatal("replay changed")
	}
	in.RedirectURIs = []string{"https://sut.example/different"}
	if _, err = a.RewriteRedirect(admin(), in); err == nil {
		t.Fatal("changed input replay accepted")
	}
}

func TestReadinessConcurrentFlags(t *testing.T) {
	a, _ := bootApp(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 10000 {
			a.SetRequireHTTPS(true)
			a.SetHTTPSBound(true)
			a.SetHTTPSBound(false)
		}
	}()
	for range 10000 {
		a.HealthReady()
	}
	<-done
}

func TestLiveListenerMutationRejected(t *testing.T) {
	a, _ := bootApp(t)
	a.SetRequireHTTPS(true)
	listeners := a.Store().Load().Canonical.Spec.Listeners
	listeners.Management.RESTPath = "/admin"
	value, _ := json.Marshal(listeners)
	before := a.Status().Generation
	_, err := a.Apply(admin(), app.ChangeIn{Reason: "route", ExpectedRevision: a.Status().RuntimeRevision, Operations: []model.Operation{{Op: model.OpUpdate, Target: model.Target{Kind: model.TargetListeners}, Value: value}}})
	if err == nil || a.Status().Generation != before {
		t.Fatal("live route change accepted")
	}
}

func TestIdempotencyActorAndCapabilityIsolation(t *testing.T) {
	a, _ := bootApp(t)
	cap := 5
	in := app.SetOverageIn{GenericCap: &cap, ExpectedRevision: a.Status().RuntimeRevision, IdempotencyKey: "same", Reason: "first"}
	first, err := a.SetOverage(admin(), in)
	if err != nil {
		t.Fatal(err)
	}
	other := admin()
	other.ID = "other"
	in.ExpectedRevision = a.Status().RuntimeRevision
	second, err := a.SetOverage(other, in)
	if err != nil {
		t.Fatal(err)
	}
	if second.Generation <= first.Generation {
		t.Fatal("different actor received another actor replay")
	}
	_, err = a.SwapVendor(admin(), app.SwapVendorIn{Vendor: "generic", ExpectedRevision: a.Status().RuntimeRevision, IdempotencyKey: "same", Reason: "vendor"})
	if err != nil {
		t.Fatalf("different capability key collision: %v", err)
	}
}

func TestMissingReasonRejectedAndAuditedSafely(t *testing.T) {
	a, _ := bootApp(t)
	before := a.Status().Generation
	_, err := a.Apply(admin(), app.ChangeIn{ExpectedRevision: a.Status().RuntimeRevision})
	if err == nil || a.Status().Generation != before {
		t.Fatal("missing reason applied")
	}
	events := a.Audit().Recent()
	last := events[len(events)-1]
	if last.Result != "error" || last.ErrorCode != "validation_failed" || last.Reason != "" {
		t.Fatalf("unsafe or missing rejection event: %+v", last)
	}
}

func TestDataPlaneRejectEmitsSafeAudit(t *testing.T) {
	a, _ := bootApp(t)
	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader("grant_type=password&password=sensitive-marker"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	a.HTTPSHandler().ServeHTTP(rec, req)
	events := a.Audit().Recent()
	found := false
	for _, event := range events {
		if event.Capability == "sso.auth.rejected" {
			found = true
			if event.Transport != "data-plane" || event.Result != "denied" {
				t.Fatalf("bad rejection: %+v", event)
			}
		}
	}
	data, _ := json.Marshal(events)
	if !found || strings.Contains(string(data), "sensitive-marker") {
		t.Fatalf("missing or unsafe audit: %s", data)
	}
}

func TestPaginationRejectsBadStaleCursorAndLimit(t *testing.T) {
	a, _ := bootApp(t)
	for _, id := range []string{"cursor-a", "cursor-b"} {
		value, _ := json.Marshal(model.Group{ID: id, Name: id})
		_, err := a.Apply(admin(), app.ChangeIn{ExpectedRevision: a.Status().RuntimeRevision, Reason: "cursor fixture", Operations: []model.Operation{{Op: model.OpAdd, Target: model.Target{Kind: model.TargetGroup, ID: id}, Value: value}}})
		if err != nil {
			t.Fatal(err)
		}
	}
	first, err := a.PageGroups(admin(), app.ListIn{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if first.NextCursor == "" || len(first.Items) != 1 {
		t.Fatal("missing pagination")
	}
	for _, in := range []app.ListIn{{Cursor: "bad"}, {Limit: -1}, {Limit: 1001}} {
		if _, err := a.PageGroups(admin(), in); err == nil {
			t.Fatalf("invalid list input accepted %+v", in)
		}
	}
	_, err = a.Apply(admin(), app.ChangeIn{ExpectedRevision: a.Status().RuntimeRevision, Reason: "remove", Operations: []model.Operation{{Op: model.OpRemove, Target: model.Target{Kind: model.TargetGroup, ID: "cursor-b"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.PageGroups(admin(), app.ListIn{Cursor: first.NextCursor}); err == nil {
		t.Fatal("stale cursor accepted")
	}
	if _, err := a.Export(admin(), "xml"); err == nil {
		t.Fatal("unsupported export accepted")
	}
}

type reviewCallbackReader struct {
	fn     func()
	r      *strings.Reader
	called bool
}

func (r *reviewCallbackReader) Read(b []byte) (int, error) {
	if !r.called {
		r.called = true
		r.fn()
	}
	return r.r.Read(b)
}

func TestIntegrationReviewSameRefPasswordRotationRevokesDelayedLogin(t *testing.T) {
	a, _ := bootApp(t)
	h := a.HTTPSHandler()
	file := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(file, []byte("old-password"), 0600); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(model.User{ID: "u1", Username: "alice", PasswordRef: file})
	_, err := a.Apply(admin(), app.ChangeIn{ExpectedRevision: a.Status().RuntimeRevision, Reason: "rotation fixture", Operations: []model.Operation{{Op: model.OpAdd, Target: model.Target{Kind: model.TargetUser, ID: "u1"}, Value: b}, {Op: model.OpAdd, Target: model.Target{Kind: model.TargetClient, ID: "app-1"}, Value: json.RawMessage(`{"id":"app-1","clientId":"app-1","public":true,"redirectURIs":["https://sut.example.net/cb"]}`)}}})
	if err != nil {
		t.Fatal(err)
	}
	old := a.Store().Load()
	rt := a.OIDC().Runtime()
	pend := rt.PutPending(oidc.Pending{Generation: old.Generation, ClientID: "app-1", RedirectURI: "https://sut.example.net/cb"})
	form := url.Values{"pending": {pend.ID}, "username": {"alice"}, "password": {"old-password"}}
	body := &reviewCallbackReader{r: strings.NewReader(form.Encode()), fn: func() {
		if err := os.WriteFile(file, []byte("new-password"), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := a.Apply(admin(), app.ChangeIn{ExpectedRevision: a.Status().RuntimeRevision, Reason: "activate rotated password"})
		if err != nil {
			t.Fatal(err)
		}
	}}
	req := httptest.NewRequest("POST", "/login", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if a.Store().Load().Generation <= old.Generation {
		t.Fatal("no activation")
	}
	if rec.Header().Get("Set-Cookie") != "" {
		t.Fatalf("old-password login survived rotated active credential: status%d sessions%d min-admits-old=%v", rec.Code, len(rt.ListSessions()), rt.GenerationUsable(old.Generation))
	}
}
