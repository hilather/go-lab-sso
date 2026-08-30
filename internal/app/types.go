package app

import "github.com/hilather/go-lab-sso/internal/model"

type ChangeIn struct {
	ExpectedRevision string
	IdempotencyKey   string
	Reason           string
	Operations       []model.Operation
}

type ValidateIn struct {
	Document   *model.Document
	Operations []model.Operation
}

type ResetIn struct {
	Reason string
}

type Plan struct {
	PreviousRevision  string            `json:"previousRevision"`
	CandidateRevision string            `json:"candidateRevision"`
	Drifted           bool              `json:"drifted"`
	Diff              []DiffEntry       `json:"diff"`
	Impact            Impact            `json:"impact"`
	Operations        []model.Operation `json:"operations,omitempty"`
}

type ApplyResult struct {
	Plan         Plan   `json:"plan"`
	Applied      bool   `json:"applied"`
	Generation   int    `json:"generation"`
	AuditEventID string `json:"auditEventId,omitempty"`
}

type DiffEntry struct {
	Path   string `json:"path"`
	Op     string `json:"op"`
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`
}

type Impact struct {
	ClientsChanged bool `json:"clientsChanged"`
	UsersChanged   bool `json:"usersChanged"`
	GroupsChanged  bool `json:"groupsChanged"`
	IssuerChanged  bool `json:"issuerChanged"`
	VendorChanged  bool `json:"vendorChanged"`
}

type Export struct {
	Format   string
	YAML     []byte
	Revision string
}

type Status struct {
	BootstrapRevision string `json:"bootstrapRevision"`
	RuntimeRevision   string `json:"runtimeRevision"`
	Generation        int    `json:"generation"`
	Drifted           bool   `json:"drifted"`
	Issuer            string `json:"issuer"`
}
