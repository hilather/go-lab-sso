package capabilities_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSourceDoesNotImportApp(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "internal/app") {
			t.Fatalf("%s must not import internal/app", e.Name())
		}
	}
}
