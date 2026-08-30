package model_test

import (
	"testing"

	"github.com/hilather/go-lab-sso/internal/model"
)

func TestValidateIDsRejectsDanglingGroup(t *testing.T) {
	doc := model.Document{
		APIVersion: model.APIVersion,
		Kind:       model.Kind,
		Metadata:   model.Metadata{Name: "lab"},
		Spec: model.Spec{
			Users: []model.User{{ID: "u1", Username: "alice", PasswordRef: "x", GroupIDs: []string{"missing"}}},
		},
	}
	if err := doc.ValidateIDs(); err == nil {
		t.Fatal("expected dangling groupIds")
	}
}

func TestValidateIDsRejectsDuplicateUsername(t *testing.T) {
	doc := model.Document{
		APIVersion: model.APIVersion,
		Kind:       model.Kind,
		Metadata:   model.Metadata{Name: "lab"},
		Spec: model.Spec{
			Users: []model.User{
				{ID: "u1", Username: "alice", PasswordRef: "x"},
				{ID: "u2", Username: "alice", PasswordRef: "x"},
			},
		},
	}
	if err := doc.ValidateIDs(); err == nil {
		t.Fatal("expected duplicate username")
	}
}

func TestValidateIDsRejectsDuplicateUser(t *testing.T) {
	doc := model.Document{
		APIVersion: model.APIVersion,
		Kind:       model.Kind,
		Metadata:   model.Metadata{Name: "lab"},
		Spec: model.Spec{
			Users: []model.User{{ID: "u1", Username: "a", PasswordRef: "x"}, {ID: "u1", Username: "b", PasswordRef: "x"}},
		},
	}
	if err := doc.ValidateIDs(); err == nil {
		t.Fatal("expected duplicate user id")
	}
}
