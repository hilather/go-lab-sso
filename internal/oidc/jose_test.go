package oidc

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseAndVerifyRejectsExpired(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
	pem, err := os.ReadFile(filepath.Join(dir, "testdata/secrets/oidc/signing.pem"))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := newSigner(pem)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := sig.mint("https://lab.example.net", "u1", "app-1", "", -time.Hour, map[string]any{"token_use": "access"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseAndVerify(tok, sig.jwk, "https://lab.example.net", true); err == nil {
		t.Fatal("expired access token must fail")
	}
}
