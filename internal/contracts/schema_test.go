package contracts_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/hilather/go-lab-sso/internal/contracts"
	"gopkg.in/yaml.v3"
)

func TestConfigSchemaValidRawAndRejectsInvalid(t *testing.T) {
	data, _ := json.Marshal(contracts.ConfigSchema())
	var schema jsonschema.Schema
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	resolved, err := schema.Resolve(nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../testdata/config/valid/minimal.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if err := resolved.Validate(document); err != nil {
		t.Fatal(err)
	}
	spec := document["spec"].(map[string]any)
	spec["clients"] = []any{map[string]any{"id": "fallback", "public": true, "redirectURIs": []any{"https://sut.example/cb"}}}
	spec["protocols"] = map[string]any{"oidc": map[string]any{"enabled": nil}}
	spec["auth"] = map[string]any{"sessionTTL": ".5h"}
	if err := resolved.Validate(document); err != nil {
		t.Fatalf("valid defaults/client fallback/null rejected: %v", err)
	}
	for _, bad := range []map[string]any{{"unknown": true}, {"auth": map[string]any{"sessionTTL": 60}}, {"profile": map[string]any{"vendor": "unknown"}}} {
		encoded, _ := json.Marshal(document)
		var candidate map[string]any
		_ = json.Unmarshal(encoded, &candidate)
		candidateSpec := candidate["spec"].(map[string]any)
		for key, value := range bad {
			candidateSpec[key] = value
		}
		if err := resolved.Validate(candidate); err == nil {
			t.Fatalf("invalid schema accepted %v", bad)
		}
	}
}
