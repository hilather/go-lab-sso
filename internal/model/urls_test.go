package model

import "testing"

func TestRecipientURIValidation(t *testing.T) {
	for _, raw := range []string{"https://sut.example/cb", "http://127.0.0.1:1234/cb", "com.example.app:/callback", "https://[::1]:8443/cb"} {
		if err := ValidateURI(raw, false); err != nil {
			t.Errorf("valid %q: %v", raw, err)
		}
	}
	for _, raw := range []string{"https://", "https:///cb", "https://user:pass@sut.example/cb", "https://sut.example/cb#frag", "https://*.example/cb", "https://sut.example:0/cb", "https://sut.example:65536/cb", "javascript:alert(1)", "https://sut.example:/cb"} {
		if ValidateURI(raw, false) == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	if ValidateURI("com.example.app:/callback", true) == nil {
		t.Fatal("HTTPS-only accepts native scheme")
	}
}
func TestListenerValidation(t *testing.T) {
	for _, raw := range []string{":8080", "127.0.0.1:8080", "[::1]:8080", ":0"} {
		if ValidateListenAddress(raw, true) != nil {
			t.Fatal(raw)
		}
	}
	for _, raw := range []string{":443", ":0443", ":65536", "::1:8080", "localhost:abc"} {
		if ValidateListenAddress(raw, true) == nil {
			t.Fatal(raw)
		}
	}
}
func TestManagementPathsValidation(t *testing.T) {
	if ValidateManagementPaths("/v1", "/mcp") != nil {
		t.Fatal("defaults rejected")
	}
	for _, paths := range [][2]string{{"/v1", "/"}, {"/v1", "/v1"}, {"/v1", "/v1/mcp"}, {"/{x}", "/mcp"}, {"GET /v1", "/mcp"}, {"/a/../v1", "/mcp"}, {"/app.js", "/mcp"}, {"/v1", "/mcp/"}, {"/v1", "/mcp%2f"}} {
		if ValidateManagementPaths(paths[0], paths[1]) == nil {
			t.Fatal(paths)
		}
	}
}
