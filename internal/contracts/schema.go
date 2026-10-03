// Package contracts derives public documents from domain types and the capability catalog.
package contracts

import (
	"reflect"
	"strings"

	"github.com/hilather/go-lab-sso/internal/model"
)

// ConfigSchema describes serialized configuration structure. Compiler validation
// additionally checks file availability, relationships, addresses and protocol semantics.
func ConfigSchema() map[string]any {
	schema := schemaType(reflect.TypeFor[model.Document]())
	schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	schema["$id"] = "https://labsso.dev/schema/v1alpha1/config"
	schema["title"] = "LabSSO configuration"
	schema["required"] = []string{"apiVersion", "kind", "metadata", "spec"}
	props := schema["properties"].(map[string]any)
	props["apiVersion"].(map[string]any)["const"] = model.APIVersion
	props["kind"].(map[string]any)["const"] = model.Kind
	return schema
}
func schemaType(t reflect.Type) map[string]any {
	if t == reflect.TypeFor[model.Duration]() {
		return map[string]any{"type": "string", "description": "Go duration string. Compiler enforces nonnegative duration and default semantics."}
	}
	if t.Kind() == reflect.Pointer {
		return map[string]any{"anyOf": []any{schemaType(t.Elem()), map[string]any{"type": "null"}}}
	}

	switch t.Kind() {
	case reflect.Struct:
		props := map[string]any{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if name == "" || name == "-" {
				continue
			}
			props[name] = schemaType(f.Type)
		}
		out := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
		required := map[string][]string{"Metadata": {"name"}, "Spec": {"listeners", "signing", "access"}, "Listeners": {"https"}, "HTTPSListener": {"certRef", "keyRef"}, "Signing": {"keyRef"}, "Access": {"tokenRef"}, "Client": {"id"}, "User": {"id", "username"}, "Group": {"id"}}
		if fields := required[t.Name()]; len(fields) > 0 {
			out["required"] = fields
			for _, name := range fields {
				if p, ok := props[name].(map[string]any); ok && p["type"] == "string" {
					p["minLength"] = 1
				}
			}
		}
		if t == reflect.TypeFor[model.Profile]() {
			props["vendor"].(map[string]any)["enum"] = append([]string{""}, model.Vendors()...)
			props["vendor"].(map[string]any)["default"] = "generic"
		}
		if t == reflect.TypeFor[model.MFA]() {
			props["mode"].(map[string]any)["enum"] = []string{"", "never", "always", "force-fail"}
			props["mode"].(map[string]any)["default"] = "never"
		}
		return out
	case reflect.Slice:
		return map[string]any{"type": []string{"array", "null"}, "items": schemaType(t.Elem())}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.String:
		return map[string]any{"type": "string"}
	default:
		return map[string]any{"type": "integer"}
	}
}

// ChangeSchema overrides SDK reflection for raw operation values and duration JSON.
func ChangeSchema(validation bool) map[string]any {
	properties := map[string]any{
		"expectedRevision": map[string]any{"type": "string"}, "idempotencyKey": map[string]any{"type": "string"}, "reason": map[string]any{"type": "string"},
		"operations": map[string]any{"type": "array", "items": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"op", "target"}, "properties": map[string]any{"op": map[string]any{"type": "string", "enum": []string{"add", "update", "remove"}}, "target": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"kind"}, "properties": map[string]any{"kind": map[string]any{"type": "string"}, "id": map[string]any{"type": "string"}}}, "value": map[string]any{}}}},
	}
	result := map[string]any{"type": "object", "additionalProperties": false, "properties": properties}
	if validation {
		document := ConfigSchema()
		delete(document, "$id")
		delete(document, "$schema")
		removeDefaults(document)
		properties["document"] = map[string]any{"anyOf": []any{document, map[string]any{"type": "null"}}}
	} else {
		result["required"] = []string{"expectedRevision"}
	}
	return result
}

func removeDefaults(value any) {
	switch v := value.(type) {
	case map[string]any:
		delete(v, "default")
		for _, child := range v {
			removeDefaults(child)
		}
	case []any:
		for _, child := range v {
			removeDefaults(child)
		}
	}
}

func ListSchema() map[string]any {
	return map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{"cursor": map[string]any{"type": "string"}, "limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 1000}}}
}
