# Control Plane and REST/MCP Parity

Status: FND catalog + REST/MCP adapters implemented; `make test-parity` is the cross-transport gate
Owners: Application, REST, MCP, UI
Last reviewed: 2026-08-30
Related ADRs: 0004

## Problem statement

Two independently implemented control planes would drift, authorize differently, return different errors, and create unsafe agent behavior. REST and MCP must be two protocol adapters over one capability model. MCP-by-proxying-REST is forbidden.

## Goals

- Semantic parity between REST and MCP.
- Shared schemas, domain types, authorization, validation, planning, apply, and audit behavior.
- Agent-friendly introspection and structured errors.
- Deterministic mutation and conflict handling.
- Operator UI (later) binds the same registry. Mira reviews after the first UI implementation.

## Non-goals

- Mapping every HTTP transport detail directly to MCP.
- Letting MCP prompts create hidden capabilities.
- Transport-specific business logic.
- Building the operator SPA in this design landing.

## Capability registry

Each public capability is declared once. Adapters bind service methods by name so the registry package does not import the application package.

```text
Capability
  ID, Title, Version, Description
  InputSchema, OutputSchema
  RequiredScopes
  Mutating, Idempotent
  RESTOnly
  REST bindings
  MCP binding
  UI binding (later)
  ServiceMethods
```

Disposition is **derived** from `RESTOnly`: `RESTOnly` → `REST_ONLY_PROTOCOL`, otherwise `PARITY_REQUIRED`. A third value (`PARITY_DIFFERENT_BINDING`) requires an ADR.

| Disposition | Meaning |
|---|---|
| `PARITY_REQUIRED` | REST + MCP + (later) UI |
| `REST_ONLY_PROTOCOL` | No MCP tool (health probes, browser session, SPA assets) |
| `MCP_ONLY_PROTOCOL` | Protocol machinery only; not used in the planned catalog |
| `PARITY_DIFFERENT_BINDING` | Requires an ADR; reserved |

## Parity rules

- Every public REST write operation has one or more MCP tools with equivalent semantics, except `REST_ONLY_PROTOCOL`.
- Every MCP mutation tool has a REST operation.
- REST GET representations may map to MCP resources or read tools.
- Status codes and JSON-RPC codes differ by transport, but domain error codes and error data match.
- Pagination, filtering, revisions, and authorization semantics match.
- Default values are applied in the shared application layer.
- Audit records identify the original transport but otherwise use the same event schema.
- Data-plane login HTML is **not** a management capability and is not in this registry.

## Planned core capabilities

Frozen names will live in `internal/capabilities` when implemented. Prefix `sso_` for MCP tools.

| Capability | REST | MCP tool / resource | Scopes |
|---|---|---|---|
| Health live | `GET /v1/health/live` | *not a tool* | none |
| Health ready | `GET /v1/health/ready` | *not a tool* | none |
| Version | `GET /v1/version` | `sso_version_get` | `sso.read` |
| Capabilities | `GET /v1/capabilities` | `sso_capabilities_get`, `labsso://capabilities` | `sso.read` |
| Status | `GET /v1/status` | `sso_status_get`, `labsso://status` | `sso.read` |
| Config schema | `GET /v1/schema/config` | `sso_schema_get`, `labsso://schema/config` | `sso.read` |
| Get state | `GET /v1/state` | `sso_state_get`, `labsso://state` | `sso.read` |
| Validate | `POST /v1/state:validate` | `sso_state_validate` | `sso.write` |
| Plan | `POST /v1/changes:plan` | `sso_change_plan` | `sso.write` |
| Apply | `POST /v1/changes:apply` | `sso_change_apply` | `sso.write` |
| Export | `GET /v1/state:export` | `sso_state_export` | `sso.read` |
| Reset | `POST /v1/state:reset` | `sso_state_reset` | `sso.admin` |
| Import plan | `POST /v1/import:plan` | `sso_import_plan` | `sso.write` |
| Import apply | `POST /v1/import:apply` | `sso_import_apply` | `sso.write` |
| Clients list/get | `GET /v1/clients`, `GET /v1/clients/{id}` | `sso_clients_list`, `sso_client_get` | `sso.read` |
| Users list/get | `GET /v1/users`, `GET /v1/users/{id}` | `sso_users_list`, `sso_user_get` | `sso.read` |
| Groups list/get | `GET /v1/groups`, `GET /v1/groups/{id}` | `sso_groups_list`, `sso_group_get` | `sso.read` |
| Sessions list/expire | `GET /v1/sessions`, `POST /v1/sessions/{id}:expire` | `sso_sessions_list`, `sso_session_expire` | `sso.sessions` |
| Tunables (force fail, force consent, pause token, inject error, mint claims, set overage, swap vendor) | `POST /v1/tunables/...` | `sso_tunable_*` twins | `sso.tunables` |
| Audit list/get | `GET /v1/audit`, `GET /v1/audit/{eventId}` | `sso_audit_query`, `sso_audit_get` | `sso.audit.read` |
| Session create/get/delete (SPA) | `POST/GET/DELETE /v1/session` | *not a tool* | none |
| UI assets | `GET /` | *not a tool* | none |

Health live/ready are REST-only process probes. Cookie session routes are REST-only.

## Mutation contract

All desired-state mutations accept:

- Expected revision.
- Idempotency key.
- Reason.
- Optional change ticket.
- Dry-run or apply mode.
- Operations or typed desired object.

All mutations return:

- Previous and candidate revision.
- Normalized diff (secrets redacted).
- Validation warnings and errors.
- Impact summary (clients, users, vendor clothes, data-plane paths, overage).
- Authorization decision metadata safe for the caller.
- Audit event ID when applied.

Partial apply is forbidden. If commit fails, the active revision remains unchanged.

## Agent-first impact summary

A plan should include:

- Clients and redirect URIs that change.
- Users and groups that change.
- Whether vendor clothes / paths change (SUT restart implied).
- Whether issuer derivation still matches `LAB_PUBLIC_HOST` + port.
- Overage and MFA mode impact.
- Import unmapped keys parked.
- Required permissions.
- Suggested verification (discovery `iss`, authorize redirect, token `aud`).

## Authorization

Authorization is capability-aware. Planned scopes:

```text
sso.read
sso.write
sso.admin
sso.sessions
sso.tunables
sso.audit.read
```

`sso.admin` satisfies every scope. Reset requires admin. Tunables that mint arbitrary claims or pause token are `sso.tunables`, not ordinary write.

The application handler receives an authenticated actor context from the adapter and makes one shared authorization decision.

## MCP protocol

- Protocol **2026-07-28** only by default (`Mcp-Protocol-Version` required).
- Official `github.com/modelcontextprotocol/go-sdk` **v1.7.0** when implemented.
- `spec.management.mcp.allowLegacyClients: true` skips that HTTP pin so older SDK clients (MCPJungle) can initialize; it does not add a claimed protocol version.
- Lab static bearer. Cookies are ignored on `/mcp`.
- Stateless Streamable HTTP. Origin validation as in LabDNS family: missing Origin allowed; present Origin must be loopback or allowlisted.

## Failure modes

- Adapter schema mismatch: parity CI fails and blocks merge (once CI exists).
- Revision conflict: stable domain code `revision_conflict`.
- MCP client protocol mismatch: reject before invoking application logic unless `allowLegacyClients`.
- Partial apply: forbidden.

## Security considerations

MCP tools can mint tokens and rewrite redirect URIs. Mutation descriptions, scopes, dry-run results, and audit must be clear. Origin validation and authorization are mandatory for MCP over HTTP.

## Observability

Measure calls by capability, transport, result, latency, actor class, and authorization outcome. Avoid high-cardinality actor IDs in metrics.

## Testing strategy

- Registry completeness tests.
- Generated OpenAPI and MCP manifest comparison (once generated).
- Cross-transport golden input/output tests.
- Shared authorization tests.
- Error mapping tests.
- Idempotency and revision conflict tests.

## Compatibility implications

Capability names and schema versions are stable public surfaces. Renaming an MCP tool or changing REST semantics requires compatibility treatment.

## Open questions

- Exact tunable URL spellings (`/v1/tunables/token:pause` vs operation list). Freeze in API-001.
- Whether import is two capabilities or `changes:plan` with `op: import`.
