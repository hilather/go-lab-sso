package mcp_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-sso/internal/app"
	"github.com/hilather/go-lab-sso/internal/control/mcp"
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

func bootMCP(t *testing.T, legacy bool) (*app.App, *mcp.Server) {
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
	s, err := mcp.New(a, legacy)
	if err != nil {
		t.Fatal(err)
	}
	return a, s
}

func raw(t *testing.T, h http.Handler, body string, hdr map[string]string, remote string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader([]byte(body)))
	req.RemoteAddr = remote
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestProtocolVersionRequired(t *testing.T) {
	_, s := bootMCP(t, false)
	rec := raw(t, s.Handler(), `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`, nil, "127.0.0.1:1")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "unsupported_protocol_version") {
		t.Fatal(rec.Body.String())
	}
}

func TestProtocolVersionMismatch(t *testing.T) {
	_, s := bootMCP(t, false)
	rec := raw(t, s.Handler(), `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`, map[string]string{
		"Mcp-Protocol-Version": "2025-11-25",
	}, "127.0.0.1:1")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d %s", rec.Code, rec.Body)
	}
}

func TestAllowLegacyClientsSkipsPin(t *testing.T) {
	_, s := bootMCP(t, true)
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"legacy","version":"0"}}}`
	rec := raw(t, s.Handler(), body, nil, "127.0.0.1:1")
	if rec.Code != http.StatusOK && rec.Code != http.StatusAccepted {
		t.Fatalf("legacy initialize %d %s", rec.Code, rec.Body)
	}
}

func TestCookiesIgnored(t *testing.T) {
	_, s := bootMCP(t, true)
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2026-07-28","capabilities":{},"clientInfo":{"name":"x","version":"0"}}}`)))
	req.RemoteAddr = "10.1.2.3:9"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Cookie", "labsso_session=stolen")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("cookie must not authenticate, code %d %s", rec.Code, rec.Body)
	}
}

func connect(t *testing.T, s *mcp.Server) *sdk.ClientSession {
	t.Helper()
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	client := sdk.NewClient(&sdk.Implementation{Name: "labsso-test", Version: "dev"}, nil)
	session, err := client.Connect(t.Context(), &sdk.StreamableClientTransport{
		Endpoint:             ts.URL,
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func TestPinnedInitialize(t *testing.T) {
	_, s := bootMCP(t, false)
	cs := connect(t, s)
	ir := cs.InitializeResult()
	if ir == nil || ir.ProtocolVersion != mcp.ProtocolVersion {
		t.Fatalf("negotiated %+v want %s", ir, mcp.ProtocolVersion)
	}
}

func TestStatusTool(t *testing.T) {
	_, s := bootMCP(t, false)
	cs := connect(t, s)
	res, err := cs.CallTool(t.Context(), &sdk.CallToolParams{Name: "sso_status_get", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("tool error: %+v", res)
	}
}

func TestLoopbackEvilHostRejected(t *testing.T) {
	_, s := bootMCP(t, true)
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	req.RemoteAddr = "127.0.0.1:1"
	req.Host = "evil.example"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("evil Host on loopback MCP want 403 got %d %s", rec.Code, rec.Body)
	}
}
