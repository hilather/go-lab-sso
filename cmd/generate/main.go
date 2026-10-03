// Command generate writes deterministic public contracts from model and registry sources.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hilather/go-lab-sso/internal/capabilities"
	"github.com/hilather/go-lab-sso/internal/contracts"
)

func main() {
	out := flag.String("out", "docs/generated", "output directory")
	flag.Parse()
	if err := generate(*out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func generate(out string) error {
	if err := os.MkdirAll(out, 0755); err != nil {
		return err
	}
	bindings := []any{}
	for _, c := range capabilities.Catalog() {
		if !c.RESTOnly {
			bindings = append(bindings, map[string]any{"capability": c.ID, "mcp": c.MCP, "rest": c.REST, "requiredScopes": c.RequiredScopes, "mutating": c.Mutating, "idempotent": c.Idempotent})
		}
	}
	for _, entry := range []struct {
		name  string
		value any
	}{{"config.schema.json", contracts.ConfigSchema()}, {"capabilities.json", capabilities.Catalog()}, {"mcp-bindings.json", bindings}} {
		b, err := json.MarshalIndent(entry.value, "", "  ")
		if err != nil {
			return err
		}
		b = append(b, '\n')
		if err := os.WriteFile(filepath.Join(out, entry.name), b, 0644); err != nil {
			return err
		}
	}
	return nil
}
