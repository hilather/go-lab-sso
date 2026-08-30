package model

import "encoding/json"

type OpKind string

const (
	OpAdd    OpKind = "add"
	OpUpdate OpKind = "update"
	OpRemove OpKind = "remove"
)

type TargetKind string

const (
	TargetClient       TargetKind = "client"
	TargetUser         TargetKind = "user"
	TargetGroup        TargetKind = "group"
	TargetProfile      TargetKind = "profile"
	TargetProtocols    TargetKind = "protocols"
	TargetAuth         TargetKind = "auth"
	TargetGroupOverage TargetKind = "groupOverage"
	TargetListeners    TargetKind = "listeners"
	TargetAccess       TargetKind = "access"
	TargetUI           TargetKind = "ui"
	TargetManagement   TargetKind = "management"
	TargetIssuer       TargetKind = "issuer"
)

var AllTargetKinds = []TargetKind{
	TargetClient, TargetUser, TargetGroup, TargetProfile, TargetProtocols,
	TargetAuth, TargetGroupOverage, TargetListeners, TargetAccess, TargetUI,
	TargetManagement, TargetIssuer,
}

type Operation struct {
	Op     OpKind          `json:"op"`
	Target Target          `json:"target"`
	Value  json.RawMessage `json:"value,omitempty"`
}

type Target struct {
	Kind TargetKind `json:"kind"`
	ID   string     `json:"id,omitempty"`
}

func ValidTarget(k TargetKind) bool {
	for _, known := range AllTargetKinds {
		if k == known {
			return true
		}
	}
	return false
}
