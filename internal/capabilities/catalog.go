package capabilities

func Catalog() []Capability {
	return append([]Capability(nil), catalog...)
}

func ByID(id string) (Capability, bool) {
	for _, c := range catalog {
		if c.ID == id {
			return c, true
		}
	}
	return Capability{}, false
}

var catalog = []Capability{
	restOnly("sso.health.live", "Health live", "GET", "/v1/health/live", nil, true),
	restOnly("sso.health.ready", "Health ready", "GET", "/v1/health/ready", nil, true),
	parity("sso.version.get", "Version", "GET", "/v1/version", "sso_version_get", "", []string{ScopeRead}, false, true),
	parity("sso.capabilities.get", "Capabilities", "GET", "/v1/capabilities", "sso_capabilities_get", "labsso://capabilities", []string{ScopeRead}, false, true),
	parity("sso.status.get", "Status", "GET", "/v1/status", "sso_status_get", "labsso://status", []string{ScopeRead}, false, true),
	parity("sso.schema.config.get", "Config schema", "GET", "/v1/schema/config", "sso_schema_get", "labsso://schema/config", []string{ScopeRead}, false, true),
	parity("sso.state.get", "Get state", "GET", "/v1/state", "sso_state_get", "labsso://state", []string{ScopeRead}, false, true),
	parity("sso.state.validate", "Validate state", "POST", "/v1/state:validate", "sso_state_validate", "", []string{ScopeWrite}, false, true),
	parity("sso.change.plan", "Plan changes", "POST", "/v1/changes:plan", "sso_change_plan", "", []string{ScopeWrite}, false, true),
	parity("sso.change.apply", "Apply changes", "POST", "/v1/changes:apply", "sso_change_apply", "", []string{ScopeWrite}, true, true),
	parity("sso.state.export", "Export state", "GET", "/v1/state:export", "sso_state_export", "", []string{ScopeRead}, false, true),
	parity("sso.state.reset", "Reset state", "POST", "/v1/state:reset", "sso_state_reset", "", []string{ScopeAdmin}, true, false),
	parity("sso.clients.list", "List clients", "GET", "/v1/clients", "sso_clients_list", "", []string{ScopeRead}, false, true),
	parity("sso.client.get", "Get client", "GET", "/v1/clients/{id}", "sso_client_get", "labsso://clients/{id}", []string{ScopeRead}, false, true),
	parity("sso.users.list", "List users", "GET", "/v1/users", "sso_users_list", "", []string{ScopeRead}, false, true),
	parity("sso.user.get", "Get user", "GET", "/v1/users/{id}", "sso_user_get", "labsso://users/{id}", []string{ScopeRead}, false, true),
	parity("sso.groups.list", "List groups", "GET", "/v1/groups", "sso_groups_list", "", []string{ScopeRead}, false, true),
	parity("sso.group.get", "Get group", "GET", "/v1/groups/{id}", "sso_group_get", "labsso://groups/{id}", []string{ScopeRead}, false, true),
	parity("sso.sessions.list", "List sessions", "GET", "/v1/sessions", "sso_sessions_list", "", []string{ScopeSessions}, false, true),
	parity("sso.session.expire", "Expire session", "POST", "/v1/sessions/{id}:expire", "sso_session_expire", "", []string{ScopeSessions}, true, true),
	parity("sso.tunable.token.pause", "Pause token", "POST", "/v1/tunables/token:pause", "sso_tunable_token_pause", "", []string{ScopeTunables}, true, true),
	parity("sso.tunable.token.resume", "Resume token", "POST", "/v1/tunables/token:resume", "sso_tunable_token_resume", "", []string{ScopeTunables}, true, true),
	parity("sso.tunable.auth.force_fail", "Force auth fail", "POST", "/v1/tunables/auth:force-fail", "sso_tunable_auth_force_fail", "", []string{ScopeTunables}, true, true),
	parity("sso.tunable.error.inject", "Inject error", "POST", "/v1/tunables/error:inject", "sso_tunable_error_inject", "", []string{ScopeTunables}, true, true),
}

func restOnly(id, title, method, path string, scopes []string, idempotent bool) Capability {
	return Capability{
		ID: id, Title: title, Version: "v1", Description: title,
		RequiredScopes: scopes, Idempotent: idempotent, RESTOnly: true,
		REST: RESTBinding{Method: method, Path: path},
	}
}

func parity(id, title, method, path, tool, resource string, scopes []string, mutating, idempotent bool) Capability {
	return Capability{
		ID: id, Title: title, Version: "v1", Description: title,
		RequiredScopes: scopes, Mutating: mutating, Idempotent: idempotent,
		REST: RESTBinding{Method: method, Path: path},
		MCP:  MCPBinding{Tool: tool, Resource: resource},
	}
}
