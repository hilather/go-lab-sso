package capabilities

const (
	ScopeRead      = "sso.read"
	ScopeWrite     = "sso.write"
	ScopeAdmin     = "sso.admin"
	ScopeSessions  = "sso.sessions"
	ScopeTunables  = "sso.tunables"
	ScopeAuditRead = "sso.audit.read"
)

const (
	DispositionParity   = "PARITY_REQUIRED"
	DispositionRESTOnly = "REST_ONLY_PROTOCOL"
)

type RESTBinding struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

type MCPBinding struct {
	Tool     string `json:"tool,omitempty"`
	Resource string `json:"resource,omitempty"`
}

type Capability struct {
	ID             string      `json:"id"`
	Title          string      `json:"title"`
	Version        string      `json:"version"`
	Description    string      `json:"description"`
	RequiredScopes []string    `json:"requiredScopes"`
	Mutating       bool        `json:"mutating"`
	Idempotent     bool        `json:"idempotent"`
	RESTOnly       bool        `json:"restOnly"`
	REST           RESTBinding `json:"rest"`
	MCP            MCPBinding  `json:"mcp"`
}

func (c Capability) Disposition() string {
	if c.RESTOnly {
		return DispositionRESTOnly
	}
	return DispositionParity
}
