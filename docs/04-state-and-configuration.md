# State and Configuration

Status: design (not implemented)
Owners: Configuration, Application
Last reviewed: 2026-08-30
Related ADRs: 0003, 0008

## Problem statement

Agents and operators need one reviewable desired-state document, runtime mutations that do not fork a second source of truth, and a reset that returns the process to Git. LabSSO uses fail-closed YAML, an in-memory overlay, and plan/apply/export/reset — the same family contract as LabDNS.

## Goals

- One document: `apiVersion: labsso.dev/v1alpha1`, `kind: LabSSO`.
- KnownFields / unknown fields reject.
- IDs user-supplied. Durations Go syntax. Secrets file refs only.
- Bootstrap file is read-only. The process never writes it.
- Runtime overlay is memory. Restart and reset reread the mount.
- Revisions, drift, plan, apply, export, reset.
- Import is a management plan/apply operation that emits a fragment, not a silent merge.

## Non-goals

- A database, journal, or hidden volume without a future ADR.
- JSON Patch as the mutation language.
- Inline passwords, tokens, or PEMs in YAML.
- Writing Git from the process.
- Multi-replica strongly consistent runtime mutation.

## Document shape

Normative sketch (also [testdata/config/valid/minimal.yaml](../testdata/config/valid/minimal.yaml)):

```yaml
apiVersion: labsso.dev/v1alpha1
kind: LabSSO
metadata:
  name: lab
spec:
  listeners:
    https:
      address: ":10443"
    management:
      address: ":8080"
      restPath: /v1
      mcpPath: /mcp
      mcp:
        allowLegacyClients: true
  issuer: "https://lab.example.net"
  profile:
    vendor: generic
  protocols:
    oidc:
      enabled: true
    saml:
      enabled: false
    wsfed:
      enabled: false
  clients: []
  users: []
  groups: []
  auth:
    sessionTTL: 1h
    mfa:
      mode: never
  groupOverage:
    entraGraphStub: true
    oktaFailAt: 100
  ui:
    enabled: true
  access:
    tokenRef: /run/secrets/labsso-token
```

Invalid fixture: [testdata/config/invalid/unknown-field.yaml](../testdata/config/invalid/unknown-field.yaml) — any unknown field under `spec` (or elsewhere) must reject.

## Decode rules

| Rule | Behavior |
|---|---|
| `apiVersion` | Exactly `labsso.dev/v1alpha1` |
| `kind` | Exactly `LabSSO` |
| Unknown fields | Reject (KnownFields) |
| IDs | User-supplied; required on clients, users, groups when present |
| Durations | Go syntax (`1h`, `30s`, `5m`). Bare numbers reject |
| Secrets | File refs (`tokenRef`, password refs, TLS refs). Inline secret material rejects |
| Empty lists | Allowed (`clients: []`) |
| Default vendor | `generic` if omitted after normalize (minimal sketch sets it explicitly) |
| Default protocols | OIDC on, SAML/WS-Fed off after normalize |
| `allowLegacyClients` | Required `true` for MCPJungle deployments; schema may default false in code — integrator YAML must set true |

## Field catalog (design)

This is the v1 design surface. Implementation may add optional fields only with docs + schema + tests.

### `spec.listeners`

- `https.address`: container bind, default `:10443`. Unprivileged.
- `management.address`: container bind, default `:8080`.
- `management.restPath`: `/v1`.
- `management.mcpPath`: `/mcp`.
- `management.mcp.allowLegacyClients`: skip MCP HTTP protocol-version pin.
- `management.allowedOrigins`: later; exact `http(s)://host[:port]` for published SPA.

### `spec.issuer`

Exact issuer string. In integrator deployments this is derived from `LAB_PUBLIC_HOST` + published HTTPS port (omit iff 443). A bootstrap may set it explicitly; compile must fail if it disagrees with the derived value when derivation env is present. Standalone `labsso serve` may take the YAML value as-is.

### `spec.profile.vendor`

Enum: `generic` | `entra` | `okta` | `ping` | `adfs` | `google` | `keycloak` | `iam-identity-center`.

### `spec.protocols`

Booleans `oidc.enabled`, `saml.enabled`, `wsfed.enabled`. Disabled protocols do not register data-plane routes.

### `spec.clients`

List of client objects (empty in minimal). Planned fields: `id`, `clientId`, `redirectURIs`, `public` / secret file ref, `scopes`, `preConsent`, vendor-specific extras parked only via import’s `imported.unmapped` (not as unknown spec fields).

### `spec.users` / `spec.groups`

Source of truth in v1. User: `id`, `username`, `passwordRef` or `passwordHashRef` (PHC file), `groupIds`, `enabled`. Group: `id`, `name`, `memberUserIds` or membership via user `groupIds` (pick one ownership in CFG; do not allow silent dual writes).

### `spec.auth`

- `sessionTTL`: Go duration.
- `mfa.mode`: `never` | `always` | `force-fail`.

### `spec.groupOverage`

- `entraGraphStub`: bool.
- `oktaFailAt`: int, default 100.
- Generic safety cap: default **200** (sweep 2). Exact field name lands in CFG / OVR-001; omitted from the minimal sketch.

### `spec.ui`

- `enabled`: operator SPA only. Default true in the sketch. `false` 404s SPA, not login HTML.

### `spec.access`

- `tokenRef`: management bearer file.

TLS leaf refs (`spec.listeners.https.certRef` / `keyRef` or equivalent) will be added in CFG; integrator uses `secrets/labsso-tls/`. Do not invent inline PEMs.

## Load pipeline

```text
read file
  -> reject unknown fields
  -> decode labsso.dev/v1alpha1
  -> resolve file-ref secrets into memory (values never re-serialized to export)
  -> normalize names, durations, defaults, IDs
  -> validate cross-references and policy
  -> compile immutable snapshot
  -> compute bootstrap + runtime revisions
  -> bind listeners
```

Invalid bootstrap does **not** listen.

## Revisions

- `bootstrapRevision`: hash of the mounted file bytes after canonicalize-or-raw policy (pick one in CFG; LabDNS uses compiled canonical). Design: hash of canonical exported form of the loaded document, excluding secret values.
- `runtimeRevision`: hash of the active canonical overlay.
- `generation`: monotonic integer, increments on successful apply and reset.
- `drifted`: `bootstrapRevision != runtimeRevision`.

Writes require `expectedRevision` (body, `If-Match`, or `X-LabSSO-Expected-Revision`). Optional `Idempotency-Key` retained in a bounded in-memory LRU (design default 256).

## Operations

Mutations are typed operations, not JSON Patch:

```text
add | update | remove
```

against `client`, `user`, `group`, `profile`, `protocols`, `auth`, `groupOverage`, `listeners`, `access`, `ui`, `management`, `issuer`, and later `import`.

Session knobs and agent tunables that do not belong in Git (expire session, pause token, inject next error) are **runtime capabilities** with the same auth/audit contract. They do not change `canonical` except when they are also desired-state fields (vendor swap, overage, redirect URI).

## Plan, apply, export, reset

| Verb | Effect |
|---|---|
| validate | Decode, normalize, validate. No swap. |
| canonicalize | Same, emit canonical YAML/JSON with defaults materialized. Secret values remain refs. |
| plan | Build candidate, return diff + impact. No swap. |
| apply | Plan then atomic swap on success. |
| export | Emit canonical YAML/JSON for Git. |
| reset | Reread mounted bootstrap, compile, swap only on success. Live snapshot untouched if the file is now bad. |
| import | Allow-list rewriter → fragment + plan; apply only when requested. See [docs/09-customer-config-import.md](09-customer-config-import.md). |

Reset never writes the bootstrap file.

## CLI (when implemented)

```text
labsso validate --config PATH
labsso canonicalize --config PATH [--format yaml|json]
labsso serve --config PATH
```

`serve` compiles, `Store.InstallBootstrap`, binds HTTPS + management. Flags (planned): `--https-listen`, `--management-listen ADDR|off`, `--shutdown-timeout`, `--pid-file`.

## Failure modes

- Unknown field: reject at decode with path.
- Dangling `groupIds`: reject at validate.
- Missing `tokenRef` file: fail closed at serve (loopback-unauth profile may be a later documented exception for management only).
- Apply revision mismatch: `revision_conflict`, no swap.
- Reset with broken file: error, previous snapshot remains.

## Testing strategy

Valid, invalid, normalization, round-trip, secret-redaction, revision-conflict, and reset-does-not-write tests. The two fixtures in `testdata/config/` are the minimum; CFG adds packs.

## Compatibility implications

Field names, duration syntax, vendor enum, and export shape are public. Adding optional fields is additive; renaming is breaking.

## Open questions

- Canonical membership ownership (user→groups vs group→members).
- Whether `issuer` in YAML is required when derivation env is set, or forbidden, or must match.
- Generic group safety-cap field name (sweep 2: numeric default **200**; field name lands in CFG / OVR-001).
