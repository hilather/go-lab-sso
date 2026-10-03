package main

import (
	"github.com/hilather/go-lab-sso/internal/compiler"
	"github.com/hilather/go-lab-sso/internal/config"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestDocumentationExamples(t *testing.T) {
	root := repoRoot(t)
	paths := []string{filepath.Join(root, "README.md")}
	docs, err := filepath.Glob(filepath.Join(root, "docs", "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	paths = append(paths, docs...)
	blocks := regexp.MustCompile("(?s)```yaml\\n(.*?)```")
	full := 0
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for i, block := range blocks.FindAllSubmatch(raw, -1) {
			var value any
			if err := yaml.Unmarshal(block[1], &value); err != nil {
				t.Errorf("%s YAML block %d: %v", path, i, err)
			}
			if !strings.Contains(string(block[1]), "apiVersion:") || !strings.Contains(string(block[1]), "  issuer:") {
				continue
			}
			doc, err := config.Load(block[1], config.Options{BaseDir: root})
			if err != nil {
				t.Errorf("%s YAML block %d: %v", path, i, err)
				continue
			}
			if _, err := compiler.Compile(doc, compiler.Options{BaseDir: root}); err != nil {
				t.Errorf("%s full config block %d: %v", path, i, err)
			}
			full++
		}
	}
	if full == 0 {
		t.Fatal("no full documented config validated")
	}
	fixtures, err := filepath.Glob(filepath.Join(root, "testdata/config/valid", "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range fixtures {
		doc, err := config.LoadFile(fixture, config.Options{BaseDir: root})
		if err != nil {
			t.Fatal(fixture, err)
		}
		if _, err := compiler.Compile(doc, compiler.Options{BaseDir: root}); err != nil {
			t.Fatal(fixture, err)
		}
	}
}
