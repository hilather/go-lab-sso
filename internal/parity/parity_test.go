package parity_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/hilather/go-lab-sso/internal/app"
	"github.com/hilather/go-lab-sso/internal/control/mcp"
	"github.com/hilather/go-lab-sso/internal/control/rest"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
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

func bootBoth(t *testing.T) (*app.App, http.Handler, *sdk.ClientSession) {
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
	rh := rest.New(a, "/v1").Handler()
	ms, err := mcp.New(a, false)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(ms.Handler())
	t.Cleanup(ts.Close)
	client := sdk.NewClient(&sdk.Implementation{Name: "parity", Version: "dev"}, nil)
	cs, err := client.Connect(t.Context(), &sdk.StreamableClientTransport{
		Endpoint: ts.URL, DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return a, rh, cs
}

func restJSON(t *testing.T, h http.Handler, method, path string, body any) map[string]any {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.RemoteAddr = "127.0.0.1:1"
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code >= 400 {
		t.Fatalf("REST %s %s: %d %s", method, path, rec.Code, rec.Body)
	}
	if rec.Header().Get("Content-Type") == "application/yaml" {
		return map[string]any{"yaml": rec.Body.String()}
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func mcpTool(t *testing.T, cs *sdk.ClientSession, name string, args any) map[string]any {
	t.Helper()
	res, err := cs.CallTool(t.Context(), &sdk.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		msg := ""
		for _, c := range res.Content {
			if tc, ok := c.(*sdk.TextContent); ok {
				msg += tc.Text
			}
		}
		t.Fatalf("MCP %s error: %s", name, msg)
	}
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		var wrap any
		if err2 := json.Unmarshal(b, &wrap); err2 != nil {
			t.Fatal(err)
		}
		return map[string]any{"value": wrap}
	}
	return out
}

func TestParityStatusExportReset(t *testing.T) {
	_, rh, cs := bootBoth(t)
	rs := restJSON(t, rh, "GET", "/v1/status", nil)
	ms := mcpTool(t, cs, "sso_status_get", map[string]any{})
	if rs["runtimeRevision"] != ms["runtimeRevision"] || rs["bootstrapRevision"] != ms["bootstrapRevision"] {
		t.Fatalf("status mismatch REST=%v MCP=%v", rs, ms)
	}
	re := restJSON(t, rh, "GET", "/v1/state:export", nil)
	me := mcpTool(t, cs, "sso_state_export", map[string]any{})
	if re["yaml"] == "" || me["yaml"] == "" {
		t.Fatal("export empty")
	}
	if re["yaml"] != me["yaml"] {
		t.Fatal("export yaml mismatch")
	}
	rr := restJSON(t, rh, "POST", "/v1/state:reset", map[string]any{"reason": "parity"})
	if rr["applied"] != true {
		t.Fatalf("reset REST %v", rr)
	}
}

func TestParityValidatePlanApply(t *testing.T) {
	a, rh, cs := bootBoth(t)
	rev := a.Status().RuntimeRevision
	ops := []map[string]any{{
		"op":     "add",
		"target": map[string]any{"kind": "client", "id": "parity-1"},
		"value":  map[string]any{"id": "parity-1", "clientId": "parity-1", "public": true, "redirectURIs": []string{"https://sut.example.net/cb"}},
	}}
	body := map[string]any{"expectedRevision": rev, "reason": "parity", "operations": ops}
	rp := restJSON(t, rh, "POST", "/v1/changes:plan", body)
	mp := mcpTool(t, cs, "sso_change_plan", body)
	if rp["candidateRevision"] != mp["candidateRevision"] {
		t.Fatalf("plan revision REST=%v MCP=%v", rp["candidateRevision"], mp["candidateRevision"])
	}
	rv := restJSON(t, rh, "POST", "/v1/state:validate", body)
	mv := mcpTool(t, cs, "sso_state_validate", body)
	if rv["candidateRevision"] != mv["candidateRevision"] {
		t.Fatalf("validate revision REST=%v MCP=%v", rv["candidateRevision"], mv["candidateRevision"])
	}
	ma := mcpTool(t, cs, "sso_change_apply", body)
	if ma["applied"] != true {
		t.Fatalf("apply MCP %v", ma)
	}
	rs := restJSON(t, rh, "GET", "/v1/status", nil)
	if rs["runtimeRevision"] == rev {
		t.Fatal("apply did not change revision")
	}
}

func TestParityVendorSwap(t *testing.T) {
	a, rh, cs := bootBoth(t)
	rev := a.Status().RuntimeRevision
	body := map[string]any{"vendor": "entra", "expectedRevision": rev, "reason": "parity"}
	rr := restJSON(t, rh, "POST", "/v1/tunables/vendor:swap", body)
	if rr["applied"] != true {
		t.Fatalf("REST swap %v", rr)
	}
	if a.Store().Load().Clothes.Vendor != "entra" {
		t.Fatal("REST swap did not change clothes")
	}
	rev2 := a.Status().RuntimeRevision
	mr := mcpTool(t, cs, "sso_tunable_vendor_swap", map[string]any{
		"vendor": "okta", "expectedRevision": rev2, "reason": "parity",
	})
	if mr["applied"] != true {
		t.Fatalf("MCP swap %v", mr)
	}
	if a.Store().Load().Clothes.Vendor != "okta" {
		t.Fatal("MCP swap did not change clothes")
	}
}

func TestParityImportPlan(t *testing.T) {
	a, rh, cs := bootBoth(t)
	doc := `{"client_id":"parity-app","redirect_uris":["https://sut.example.net/cb"],"token_endpoint_auth_method":"none"}`
	body := map[string]any{"kind": "oidc-client", "document": doc, "reason": "parity"}
	rp := restJSON(t, rh, "POST", "/v1/import:plan", body)
	mp := mcpTool(t, cs, "sso_import_plan", body)
	if rp["client"] == nil || mp["client"] == nil {
		t.Fatalf("plan REST=%v MCP=%v", rp, mp)
	}
	body["expectedRevision"] = a.Status().RuntimeRevision
	ra := restJSON(t, rh, "POST", "/v1/import:apply", body)
	if ra["applied"] != true {
		t.Fatalf("apply %v", ra)
	}
}

func TestParityAuditList(t *testing.T) {
	_, rh, cs := bootBoth(t)
	req := httptest.NewRequest("GET", "/v1/audit", nil)
	req.RemoteAddr = "127.0.0.1:1"
	rec := httptest.NewRecorder()
	rh.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("REST audit %d %s", rec.Code, rec.Body)
	}
	mr := mcpTool(t, cs, "sso_audit_query", map[string]any{})
	if mr == nil {
		t.Fatal("MCP audit missing")
	}
}

func TestParityOverageSet(t *testing.T) {
	a, rh, cs := bootBoth(t)
	rev := a.Status().RuntimeRevision
	off := false
	body := map[string]any{"entraGraphStub": off, "expectedRevision": rev, "reason": "parity"}
	rr := restJSON(t, rh, "POST", "/v1/tunables/overage:set", body)
	if rr["applied"] != true {
		t.Fatalf("REST overage %v", rr)
	}
	if a.Store().Load().Canonical.Spec.GroupOverage.EntraGraphStub {
		t.Fatal("REST overage did not clear stub")
	}
	rev2 := a.Status().RuntimeRevision
	cap := 50
	mr := mcpTool(t, cs, "sso_tunable_overage_set", map[string]any{
		"genericCap": cap, "expectedRevision": rev2, "reason": "parity",
	})
	if mr["applied"] != true {
		t.Fatalf("MCP overage %v", mr)
	}
	ov := a.Store().Load().Canonical.Spec.GroupOverage
	if ov.EntraGraphStub || ov.GenericCap != 50 {
		t.Fatalf("MCP merge want stub=false cap=50 got %+v", ov)
	}
}
