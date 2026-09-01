# REST API Design

Status: FND REST adapter implemented (`internal/control/rest`)
Owners: REST, Application
Last reviewed: 2026-09-01
Related ADRs: 0004, 0008

## Goals

- A versioned, discoverable, machine-readable API at `/v1`.
- OpenAPI generated or verified from the capability registry when code exists.
- Consistent pagination, filtering, errors, revisions, and idempotency.
- No business logic in handlers.
- Planned surface: state, changes:plan/apply, import, session knobs / tunables.

## Non-goals

- A second business layer in the REST package.
- Browser session tools on MCP.
- Exposing data-plane login HTML through `/v1`.

## Base behavior (planned)

- Base path: `/v1` on the management listener (default `:8080`).
- JSON request and response bodies unless exporting YAML (`GET /v1/state:export?format=yaml`).
- Problem responses use `application/problem+json` with a stable domain error code.
- Mutations accept `Idempotency-Key` and expected revision in the body, `If-Match`, or `X-LabSSO-Expected-Revision`.
- Request bodies default to a 1 MiB cap; import XML/JSON may use a separate documented cap still well under memory-safety limits.
- Authentication: unauthenticated access only from `127.0.0.1` / `::1` under `dev-loopback-unauth`. Remote peers need `Authorization: Bearer` or a live `labsso_session` cookie. Bearer wins and ignores CSRF. Health live/ready skip auth. `X-Forwarded-For` is not trusted.
- Cookie-authenticated non-GET requests send `X-LabSSO-CSRF`. CSRF secret is never written to `localStorage`.
- `spec.ui.enabled: false` 404s `GET /` SPA paths only. `/v1` remains.
- No permissive CORS by default.

## Endpoints

### Health and build

```text
GET /v1/health/live
GET /v1/health/ready
GET /v1/version
GET /v1/capabilities
GET /v1/status
GET /v1/schema/config
```

Health live/ready are process-local probes and are not MCP tools. Ready means a runtime revision exists and required listeners that were requested at serve-time are bound. Data-plane HTTPS bind is required for ready when `serve` requested it. Management-only `--management-listen=off` is a serve-time choice; ready then means HTTPS is bound.

### State

```text
GET  /v1/state
POST /v1/state:validate
GET  /v1/state:export
POST /v1/state:reset
POST /v1/changes:plan
POST /v1/changes:apply
```

`GET /v1/state` returns `bootstrapRevision`, `runtimeRevision`, `generation`, `drifted`, and `canonical` (secrets as refs). Export YAML is the file the operator commits back to Git.

### Import

```text
POST /v1/import:plan
POST /v1/import:apply
```

Body names the input kind (`entra-manifest` | `okta-app` | `saml-metadata` | `oidc-client`) and carries the blob or a file ref. Response is a `labsso.dev/v1alpha1` fragment plus `imported.unmapped`. Apply commits through the same snapshot swap as `changes:apply`. Not a silent live merge. See [docs/09-customer-config-import.md](09-customer-config-import.md).

### Directory and clients

```text
GET /v1/clients
GET /v1/clients/{id}
GET /v1/users
GET /v1/users/{id}
POST /v1/auth/mfa
POST /v1/users/{id}/totp:enroll
POST /v1/users/{id}/totp:clear
GET /v1/groups
GET /v1/groups/{id}
```

List/get users return `totp: { configured, source }` (`file` | `overlay`). Apply user values stay `model.User` — do not copy `totp` into `changes:apply`.

`POST /v1/auth/mfa` body: `{ "mode", "expectedRevision", "reason", "idempotencyKey" }`. Capability `sso.auth.mfa.set`, scope `sso.write`. Rejects empty `mode`, then merges onto current `Auth` (keeps `sessionTTL`).

`POST /v1/users/{id}/totp:enroll` body: `{ "reason" }`. Capability `sso.user.totp.enroll`, not idempotent. Returns `secret` + `otpauth` once. Overlay only; the process never writes `.totp` files. 404 if the user is missing.

`POST /v1/users/{id}/totp:clear` body: `{ "reason" }`. Drops overlay + last-step; file ref remains.

Typed writes compile to the same operations as `changes:apply` unless they are overlay-only (enroll/clear).

### Session knobs

```text
GET  /v1/sessions
POST /v1/sessions/{id}:expire
POST /v1/sessions:expire-all
```

These mutate runtime session memory, not Git canonical, except they still require reason + audit. `expectedRevision` is not required for pure session expiry; a dedicated concurrency token or “best effort” is documented in API-001. Design preference: require a management bearer and reason; do not require snapshot revision for ephemeral session tables.

### Agent tunables

```text
POST /v1/tunables/auth:force-fail
POST /v1/tunables/consent:force
POST /v1/tunables/token:mint
POST /v1/tunables/token:pause
POST /v1/tunables/token:resume
POST /v1/tunables/error:inject
POST /v1/tunables/overage:set
POST /v1/tunables/vendor:swap
POST /v1/tunables/client/redirect:rewrite
```

`vendor:swap` and `redirect:rewrite` and `overage:set` **are** desired-state changes and require `expectedRevision`. Pause/resume, force-fail, inject-error, expire-session, and one-shot mint are runtime overlays: they die on restart/reset unless an ADR persists them (none does). Clothes swap purges pending codes/sessions/refresh and does not clear those overlays.

`POST /v1/tunables/vendor:swap` body: `vendor` (required), `tenantId` (optional), `expectedRevision`, `reason`, `idempotencyKey`. Capability `sso.tunable.vendor.swap`, scope `sso.tunables`. Omit `tenantId` to keep the current Canonical value; `tenantId: ""` clears it. Not a full `TargetProfile` replace and not `sso.change.apply`.

`POST /v1/tunables/overage:set` body: optional pointers `entraGraphStub`, `oktaFailAt`, `genericCap`, plus `expectedRevision`, `reason`, `idempotencyKey`. Capability `sso.tunable.overage.set`, scope `sso.tunables`. Merges onto the current `GroupOverage` then `OpUpdate`s the full struct. Omit keeps; explicit `false` / `0` sets (Normalize may lift `0` → default). Not membership SoT.

`POST /v1/tunables/consent:force` body: `{ "on": true }`. Runtime overlay; every `PreConsent` shortcut is ignored (authorize session reuse, login HTML, SAML, WS-Fed).

`POST /v1/tunables/token:mint` body: `userId`, `clientId`, optional `scope` (default `openid`). Returns access + id tokens. Scoped (`sso.tunables`); audited. No secrets in the audit payload. Mint is password-only: it omits `amr`/`acr`.

Pause token: data plane otherwise stays up (authorize, JWKS, discovery, login HTML).

### Audit

```text
GET /v1/audit
GET /v1/audit/{eventId}
```

### Operator session and UI (UI-001)

```text
POST   /v1/session
GET    /v1/session
DELETE /v1/session
GET    /                 (SPA; 404 if ui.enabled false)
GET    /app.js
GET    /v1/audit
GET    /v1/audit/{eventId}
POST   /v1/sessions:expire-all
```

Cookie `labsso_session` (HttpOnly). CSRF header `X-LabSSO-CSRF` required on non-GET cookie calls. Bearer still wins and skips CSRF. MCP ignores cookies. SPA lives in `internal/web` and must not import `internal/app`. Tokens never go in `localStorage` / `sessionStorage` / IndexedDB / the URL.

Do not implement in this design landing. Mira reviews after first UI implementation.

## Example: plan/apply

```json
{
  "expectedRevision": "sha256:…",
  "reason": "add confidential client",
  "operations": [
    {
      "op": "add",
      "target": {"kind": "client", "id": "app-1"},
      "value": {
        "id": "app-1",
        "clientId": "app-1",
        "redirectURIs": ["https://sut.example.net/callback"],
        "secretRef": "/run/secrets/client-app-1"
      }
    }
  ]
}
```

## Error response

```json
{
  "type": "urn:labsso:error:revision-conflict",
  "title": "State revision conflict",
  "status": 409,
  "code": "revision_conflict",
  "detail": "The active state changed after the plan was created.",
  "instance": "urn:labsso:request:01J...",
  "currentRevision": "sha256:...",
  "expectedRevision": "sha256:...",
  "retryable": true
}
```

Data-plane OIDC errors stay on the HTTPS listener and use the vendor clothes dialect. They are not `application/problem+json` unless a later ADR says so.

## Pagination

Opaque `cursor` + `limit` on clients, users, groups, sessions, and audit lists. Filters are explicit typed fields.

## Conditional and idempotent writes

- Require expected revision for desired-state writes.
- Support `Idempotency-Key` with bounded in-memory retention.
- Return `409 Conflict` for revision mismatch or conflicting key reuse.

## Security considerations

Validate Origin where browser access is possible, disable permissive CORS by default, authenticate before parsing large import bodies, and rate-limit by actor and source network. First implementation trusts `RemoteAddr` only.

## Observability

Include request and trace IDs in headers. Metrics use operation IDs from the capability registry. Audit mutation bodies in normalized redacted form.

## Testing strategy

- OpenAPI validation (once generated).
- Handler/schema contract tests.
- Auth and scope tests.
- Import size and XXE reject tests.
- Pause-token isolation tests (authorize still 200).
- Parity goldens against MCP.
- Regression tests for every endpoint defect.

## Compatibility implications

Path, method, operation ID, field meaning, default, error code, and status behavior are versioned. Additive optional fields are preferred within `/v1`.

## Open questions

- Exact tunable path freeze vs encoding tunables as operations.
- Session-list authorization (does `sso.read` see usernames?).
- Session-knob concurrency (sweep 2): ephemeral knobs do not require snapshot `expectedRevision`; desired-state tunables do. See [skeptic-notes.md](skeptic-notes.md).
