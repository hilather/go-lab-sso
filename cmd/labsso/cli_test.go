package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

func TestValidateMinimal(t *testing.T) {
	root := repoRoot(t)
	var out, errb bytes.Buffer
	code := run([]string{"validate", "--config", filepath.Join(root, "testdata/config/valid/minimal.yaml"), "--base-dir", root}, &out, &errb)
	if code != 0 {
		t.Fatalf("code %d err=%s", code, errb.String())
	}
	if !strings.Contains(out.String(), "sha256:") {
		t.Fatal(out.String())
	}
}

func TestValidateUnknownField(t *testing.T) {
	root := repoRoot(t)
	var out, errb bytes.Buffer
	code := run([]string{"validate", "--config", filepath.Join(root, "testdata/config/invalid/unknown-field.yaml"), "--base-dir", root}, &out, &errb)
	if code == 0 {
		t.Fatal("expected reject")
	}
}

func TestVersion(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"version"}, &out, &errb); code != 0 {
		t.Fatal(errb.String())
	}
	if !strings.Contains(out.String(), "labsso") {
		t.Fatal(out.String())
	}
}

func TestDest443ErrorText(t *testing.T) {
	err := wrapListenErr(":10443", os.ErrExist)
	if !strings.Contains(err.Error(), "LABSSO_HTTPS_PORT") || !strings.Contains(err.Error(), "nginx") {
		t.Fatal(err)
	}
}
