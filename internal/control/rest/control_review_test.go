package rest_test

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReviewRejectInvalidMutationBody(t *testing.T) {
	a, h := boot(t)
	valid, _ := json.Marshal(map[string]any{"reason": "reset", "expectedRevision": a.Status().RuntimeRevision})
	cases := []string{string(valid) + ` garbage`, string(valid) + ` {"unexpected":true}`, string(valid) + strings.Repeat(" ", 1<<20), strings.TrimSuffix(string(valid), "}") + `,"dryRunn":true}`, `null`, ``}
	for i, body := range cases {
		generation := a.Status().Generation
		rec := do(t, h, "POST", "/v1/state:reset", "127.0.0.1:9", "", []byte(body))
		if rec.Code != 400 || a.Status().Generation != generation {
			t.Fatalf("case %d invalid body applied status=%d generation=%d", i, rec.Code, a.Status().Generation)
		}
	}
}

func TestBodylessMutationRejectsSuppliedInvalidBody(t *testing.T) {
	for _, path := range []string{"/v1/tunables/token:pause", "/v1/tunables/token:resume", "/v1/sessions:expire-all", "/v1/session"} {
		for _, body := range []string{`null`, `{} garbage`, `{} {}`, `{"unexpected":true}`, `{}` + strings.Repeat(" ", 1<<20)} {
			_, h := boot(t)
			rec := do(t, h, "POST", path, "127.0.0.1:9", "", []byte(body))
			if rec.Code != 400 {
				t.Fatalf("%s accepted body status=%d", path, rec.Code)
			}
		}
	}
}

func TestResetRevisionHeadersAndMalformedBodyAudit(t *testing.T) {
	a, h := boot(t)
	req := httptest.NewRequest("POST", "/v1/state:reset", strings.NewReader(`{"reason":"header reset"}`))
	req.RemoteAddr = "127.0.0.1:9"
	req.Header.Set("X-LabSSO-Expected-Revision", a.Status().RuntimeRevision)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("revision header ignored: %d %s", rec.Code, rec.Body)
	}
	rec = do(t, h, "POST", "/v1/state:reset", "127.0.0.1:9", "", []byte(`{"secret":"never-record-marker"} garbage`))
	if rec.Code != 400 {
		t.Fatal(rec.Code)
	}
	events := a.Audit().Recent()
	last := events[len(events)-1]
	if last.Capability != "sso.management.input.rejected" || last.Transport != "rest" || last.Result != "error" {
		t.Fatalf("missing safe malformed input audit: %+v", last)
	}
	encoded, _ := json.Marshal(events)
	if strings.Contains(string(encoded), "never-record-marker") {
		t.Fatal("rejected bytes in audit")
	}
}
