# MCP API Design

Status: design (not implemented)
Owners: MCP, Application
Last reviewed: 2026-08-30
Target protocol baseline: 2026-07-28
Related ADRs: 0004
Implementation (later): `internal/control/mcp` wrapping `github.com/modelcontextprotocol/go-sdk v1.7.0`

## Problem statement

Agents need a first-class control interface that is schema-rich, safe, and equivalent to REST. MCP must not be a thin HTTP client pointed at `/v1`. Protocol versions move; LabSSO pins **2026-07-28**.

## Goals

- Official MCP protocol through the official Go SDK behind an adapter.
- Expose all public control capabilities with REST parity.
- Stateless, per-request metadata behavior for the pinned protocol.
- Small, typed tools rather than a generic command executor.
- Structured content and stable domain errors.
- `allowLegacyClients: true` for MCPJungle.

## Non-goals

- Generic shell execution.
- Arbitrary file or network access.
- Hidden agent-only mutations.
- MCP proxying REST.
- Depending on connection identity for state or authorization.

## Transport

Primary transport:

- Streamable HTTP at `/mcp` on the management listener.
- One POST endpoint.
- Request-scoped JSON or SSE responses as required by the pinned protocol.
- Origin validation.
- Authentication and authorization shared with REST (bearer; cookies ignored).
- Explicit protocol-version negotiation. Default: require `Mcp-Protocol-Version: 2026-07-28`.

`spec.management.mcp.allowLegacyClients: true` skips that HTTP pin so older SDK clients (MCPJungle) can initialize without `MCP-Protocol-Version`. It does not add a claimed protocol version and does not disable bearer auth.

Optional developer transport:

- Stdio adapter exposing the same registry.
- Logs go to stderr, never stdout.
- Not required in the production scratch image.

## Statelessness

Do not rely on connection-scoped initialization, selected client, or previous tool calls. Every tool input contains the information needed to process the operation. Multi-step application state uses explicit revisions passed by the caller.

## Tools (planned twins)

```text
sso_version_get
sso_capabilities_get
sso_status_get
sso_schema_get

sso_state_get
sso_state_validate
sso_change_plan
sso_change_apply
sso_state_export
sso_state_reset

sso_import_plan
sso_import_apply

sso_clients_list
sso_client_get
sso_users_list
sso_user_get
sso_groups_list
sso_group_get

sso_sessions_list
sso_session_expire

sso_tunable_auth_force_fail
sso_tunable_consent_force
sso_tunable_token_mint
sso_tunable_token_pause
sso_tunable_token_resume
sso_tunable_error_inject
sso_tunable_overage_set
sso_tunable_vendor_swap
sso_tunable_redirect_rewrite

sso_audit_query
sso_audit_get
```

Health live/ready have no tools. Browser session create/delete have no tools.

Tools use explicit nouns and verbs, stable schemas, and descriptions that state whether the operation is read-only, state-changing, reversible, or high-impact.

## Resources

```text
labsso://state
labsso://capabilities
labsso://status
labsso://schema/config
labsso://clients/{id}
labsso://users/{id}
labsso://groups/{id}
labsso://audit/recent
```

A resource mirrors a REST representation. Authorization matches the equivalent GET capability. Secret values never appear.

## Prompts

Optional prompts may guide safe workflows:

- Plan a client + redirect URI for a SUT.
- Diagnose an `invalid_grant`.
- Import an Entra manifest into a commit-able fragment.
- Convert runtime drift into a deployment-repository change.

Prompts do not introduce new capabilities and do not bypass parity or authorization.

## Mutation workflow

Agents should normally:

1. Read current state and revision (`sso_state_get`).
2. Call a typed plan tool (or import plan).
3. Review normalized diff, clothes impact, overage, and unmapped import keys.
4. Obtain human approval when required by the host.
5. Apply with expected revision and idempotency key.
6. Probe data-plane discovery `iss` and a token request (outside MCP, or via a future read-only `sso_oidc_discover` if added with an ADR — not required in v1).
7. Export if the operator wants Git to catch up.

## Structured results

Each tool returns machine-readable structured content. Human-readable summaries are secondary.

Example pause-token result:

```json
{
  "stateRevision": "sha256:…",
  "tokenEndpoint": "paused",
  "dataPlaneOtherwise": "up",
  "authorize": "available",
  "jwks": "available",
  "loginHTML": "available"
}
```

## Domain errors

Map shared domain errors to MCP JSON-RPC errors with stable `data.code`, `data.retryable`, revision fields, field violations, and remediation hints. Do not encode failures only as unstructured text. One shared mapper; adapters must not invent a second mapping.

## Security considerations

- Tool descriptions are not authorization.
- The server validates every request independent of client-provided annotations.
- High-impact tools (`token_mint`, `token_pause`, `vendor_swap`, import apply) require dedicated scopes.
- Origin validation protects against DNS rebinding.
- Exposed tools do not allow arbitrary paths, commands, or outbound URLs.
- `allowLegacyClients` is not an auth bypass.

## Observability

Record tool name, protocol version, result, latency, auth result, and request correlation. Do not log authorization codes, passwords, or raw bearers.

## Testing strategy

- Official SDK conformance tests where available.
- Pinned protocol-version tests.
- `allowLegacyClients` true/false matrix.
- Streamable HTTP tests.
- Origin validation tests.
- REST/MCP parity goldens.
- Authorization and cancellation tests.

## Compatibility implications

MCP protocol versions, tool names, schemas, resource URIs, and result/error structures are public surfaces.

## First implementation pin

- Protocol **2026-07-28** only by default.
- Official SDK `github.com/modelcontextprotocol/go-sdk v1.7.0`.
- Stateless Streamable HTTP.
- Integrator YAML **must** set `allowLegacyClients: true` for MCPJungle.
- Auth matches REST: loopback may omit a bearer under `dev-loopback-unauth`; remote peers need `Authorization: Bearer`.

## Open questions

- Whether a read-only `sso_oidc_discover` tool should exist so agents need not speak HTTPS to dest-443 from the MCP host. Default: no; labinfo connection block covers that after integrator last.
