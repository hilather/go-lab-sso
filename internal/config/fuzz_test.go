package config

import (
	"bytes"
	"github.com/hilather/go-lab-sso/internal/model"
	"gopkg.in/yaml.v3"
	"testing"
)

// FuzzYAMLDecode exercises strict decoding without resolving attacker-supplied file refs.
func FuzzYAMLDecode(f *testing.F) {
	f.Add([]byte("apiVersion: labsso.dev/v1alpha1\nkind: LabSSO\nmetadata:\n  name: lab\nspec: {}\n"))
	f.Add([]byte("---\na: [&a a, *a]\n"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 64<<10 {
			return
		}
		decoder := yaml.NewDecoder(bytes.NewReader(raw))
		decoder.KnownFields(true)
		var doc model.Document
		if decoder.Decode(&doc) != nil {
			return
		}
		Normalize(&doc)
		_ = doc.ValidateIDs()
	})
}
