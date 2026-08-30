package app

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/hilather/go-lab-sso/internal/domainerr"
	"github.com/hilather/go-lab-sso/internal/model"
)

func applyOperations(doc *model.Document, ops []model.Operation) error {
	for i, op := range ops {
		if err := applyOne(doc, op); err != nil {
			return fmt.Errorf("operations[%d]: %w", i, err)
		}
	}
	return nil
}

func applyOne(doc *model.Document, op model.Operation) error {
	if op.Op != model.OpAdd && op.Op != model.OpUpdate && op.Op != model.OpRemove {
		return domainerr.Validation("op must be add, update, or remove")
	}
	if !model.ValidTarget(op.Target.Kind) {
		return domainerr.Validation(fmt.Sprintf("unknown target kind %q", op.Target.Kind))
	}
	switch op.Target.Kind {
	case model.TargetClient:
		return mutateList(&doc.Spec.Clients, op, func(c model.Client) string { return c.ID }, "client")
	case model.TargetUser:
		return mutateList(&doc.Spec.Users, op, func(u model.User) string { return u.ID }, "user")
	case model.TargetGroup:
		return mutateList(&doc.Spec.Groups, op, func(g model.Group) string { return g.ID }, "group")
	case model.TargetProfile:
		return mutateSingleton(&doc.Spec.Profile, op, model.Profile{})
	case model.TargetProtocols:
		return mutateSingleton(&doc.Spec.Protocols, op, model.Protocols{})
	case model.TargetAuth:
		return mutateSingleton(&doc.Spec.Auth, op, model.Auth{})
	case model.TargetGroupOverage:
		return mutateSingleton(&doc.Spec.GroupOverage, op, model.GroupOverage{})
	case model.TargetListeners:
		return mutateSingleton(&doc.Spec.Listeners, op, model.Listeners{})
	case model.TargetAccess:
		return mutateSingleton(&doc.Spec.Access, op, model.Access{})
	case model.TargetUI:
		return mutateSingleton(&doc.Spec.UI, op, model.UI{})
	case model.TargetManagement:
		return mutateSingleton(&doc.Spec.Listeners.Management, op, model.ManagementListener{})
	case model.TargetIssuer:
		if op.Op == model.OpRemove {
			doc.Spec.Issuer = ""
			return nil
		}
		var v struct {
			Issuer string `json:"issuer"`
		}
		if err := decodeValue(op.Value, &v); err != nil {
			var s string
			if err2 := decodeValue(op.Value, &s); err2 != nil {
				return domainerr.Validation("issuer value must be a string or {issuer}")
			}
			doc.Spec.Issuer = s
			return nil
		}
		if v.Issuer == "" {
			return domainerr.Validation("issuer is required")
		}
		doc.Spec.Issuer = v.Issuer
		return nil
	default:
		return domainerr.Validation("unsupported target")
	}
}

func mutateList[T any](list *[]T, op model.Operation, idOf func(T) string, kind string) error {
	id := op.Target.ID
	idx := -1
	for i, item := range *list {
		if idOf(item) == id {
			idx = i
			break
		}
	}
	switch op.Op {
	case model.OpRemove:
		if idx < 0 {
			return domainerr.NotFound(kind + " " + id + " not found")
		}
		*list = append((*list)[:idx], (*list)[idx+1:]...)
		return nil
	case model.OpAdd:
		if idx >= 0 {
			return domainerr.Conflict(kind + " " + id + " already exists")
		}
		var v T
		if err := decodeValue(op.Value, &v); err != nil {
			return domainerr.Validation(kind + " value: " + err.Error())
		}
		*list = append(*list, v)
		return nil
	case model.OpUpdate:
		if idx < 0 {
			return domainerr.NotFound(kind + " " + id + " not found")
		}
		var v T
		if err := decodeValue(op.Value, &v); err != nil {
			return domainerr.Validation(kind + " value: " + err.Error())
		}
		(*list)[idx] = v
		return nil
	}
	return nil
}

func mutateSingleton[T any](dst *T, op model.Operation, zero T) error {
	if op.Op == model.OpRemove {
		*dst = zero
		return nil
	}
	var v T
	if err := decodeValue(op.Value, &v); err != nil {
		return domainerr.Validation("value: " + err.Error())
	}
	*dst = v
	return nil
}

func decodeValue(raw json.RawMessage, dst any) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		return fmt.Errorf("value is required")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	return nil
}
