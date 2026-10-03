package mcp_test

import (
	"strings"
	"testing"
)

func TestReviewRejectLegacyInitializeInPinnedMode(t *testing.T) {
	_, s := bootMCP(t, false)
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"legacy","version":"0"}}}`
	rec := raw(t, s.Handler(), body, map[string]string{"Mcp-Protocol-Version": "2026-07-28"}, "127.0.0.1:9")
	t.Logf("status %d response %s", rec.Code, rec.Body)
	if rec.Code == 200 && strings.Contains(rec.Body.String(), `"protocolVersion":"2025-06-18"`) {
		t.Fatalf("pinned server negotiated legacy version: %s", rec.Body)
	}
}

func TestReviewResourceErrorsPreserveDomainCode(t *testing.T) {
	_, s := bootMCP(t, true)
	body := `{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"labsso://users/missing"}}`
	rec := raw(t, s.Handler(), body, nil, "127.0.0.1:9")
	if !strings.Contains(rec.Body.String(), `"not_found"`) {
		t.Fatalf("resource error loses domain code: %s", rec.Body)
	}
}

func TestReviewValidateDoesNotNeedRevision(t *testing.T) {
	_, s := bootMCP(t, true)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sso_state_validate","arguments":{"operations":[]}}}`
	rec := raw(t, s.Handler(), body, nil, "127.0.0.1:9")
	if strings.Contains(rec.Body.String(), `expectedRevision`) {
		t.Fatalf("read-only validation wrongly requires revision: %s", rec.Body)
	}
}
