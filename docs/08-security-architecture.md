# Security Architecture

Status: through VEN-003 implemented
Owners: Security, Protocols, Control Plane
Last reviewed: 2026-09-02
Related ADRs: 0002, 0003, 0004, 0005, 0006, 0008, 0009, 0010, 0011

## Goals

- Prevent operation as an open public token mint on an unintended interface.
- Prevent unauthorized client, user, session, and clothes changes.
- Limit damage from malformed input, XXE on import, overload, and missing secrets.
- Protect credentials, audit data, and management interfaces.
- Keep data-plane login security independent of the operator SPA.
- Lab-first: this is not a production IdP assurance program.

## Trust boundaries

1. SUTs and browsers to data-plane HTTPS (host 443 → `:10443`).
2. Management clients and agents to REST/MCP listener (high port).
3. Browser operator SPA (later) to management cookie session.
4. Container to host/kernel (UID 65532, read-only, cap_drop ALL).
5. Runtime process to read-only bootstrap file and secret files.
6. Process to labsso-tls leaf (new leaf; not LabMITM / LabLDAP reuse).
7. Telemetry exporter to external observability systems.
8. Deployment pipeline to image registry and deployment host.
9. Customer-config import blob to rewriter (untrusted input).

LabSSO does **not** trust vendor-cloud hostnames and does not present them.

## Data-plane controls

- TLS with the lab-CA signed `labsso-tls` leaf. Hostname is `LAB_PUBLIC_HOST`.
- Authorization-code + PKCE S256; `plain` rejected.
- Exact redirect URI match.
- Passwords only via file refs / PHC; constant-time compare.
- Session TTL from YAML; restart drops sessions.
- Rate and concurrency limits on authorize, token, login POST.
- Disabled protocols still register data-plane routes; handlers **404**. `saml.enabled: false` 404s generic `/saml/*` and clothed `/idp/…`, `/saml2/…`, `/affwebservices/…`.
- SAML XML parse rejects DOCTYPE/ENTITY and is size-capped. Assertion signatures use `goxmldsig` on XML LabSSO generates (not hostile-input verification).
- Vendor clothes never change the issuer host to a vendor cloud.
- Graph-shaped stub (Entra overage) is local; no egress to Microsoft.
- Login / consent HTML is first-party. No third-party JS. Chrome may load IBM Plex from a Google Fonts CSS `<link>` (not a JS loader); fallback is `system-ui`.
- MFA `force-fail` is an explicit lab knob, not a bypass of `always`.

## Management-plane controls

- Bind to loopback or a dedicated management network by default.
- Shared auth middleware for REST and MCP.
- Lab static bearer from `tokenRef`.
- Resource-aware RBAC (scopes in [docs/05-control-plane-and-parity.md](05-control-plane-and-parity.md)).
- Origin validation for MCP and browser-reachable REST (`http.CrossOriginProtection`). Loopback management requests (REST and MCP) whose `Host` is not localhost / 127.0.0.1 / `::1` (or the httptest default `example.com`) are 403 (DNS-rebinding defense).
- Strict body, header, rate, and timeout limits. Login POST is 10/min per IP; authorize and token are 60/min per IP. Pending authorization requests expire after 10 minutes.
- No permissive CORS by default.
- `allowLegacyClients` skips only the MCP protocol-version header pin.

### Planned auth profiles

| Profile | Loopback | Non-loopback |
|---|---|---|
| `dev-loopback-unauth` (default) | Unauthenticated, treated as administrator | Bearer required |
| `bearer` | Same loopback exception or documented require-bearer | Bearer required; `tokenRef` must resolve |

`X-Forwarded-For` is not trusted.

### Browser session and CSRF (later UI slice)

Operator console authenticates with an in-process session table and cookie `labsso_session` (`HttpOnly`, `SameSite=Lax`, `Path=/`, host-only, `Secure` iff TLS). CSRF in memory / JSON, never `localStorage`. MCP ignores cookies.

`spec.ui.enabled: false` 404s SPA only. Data-plane login cookies (`HttpOnly`, `SameSite=Lax`, `Path=/` on the issuer host, host-only, `Secure` iff TLS): `labsso_login` (generic), `labsso_entra`, `labsso_okta`, `labsso_ping`, `labsso_adfs`, `labsso_google`, `labsso_keycloak`, `labsso_iamic`, `labsso_duo`, `labsso_siteminder`, `labsso_shibboleth`. Do not reuse `labsso_session`. Clothes swap orphans the previous cookie name.

## Secret management

Bootstrap contains **references**, not values:

- Management token: `spec.access.tokenRef`.
- User passwords: per-user file ref or PHC file.
- TOTP seeds: optional `totpSecretRef` file (base32) or in-memory enroll overlay. Overlay is never written to disk. Enroll secret is returned once on REST/MCP and must not appear in export, audit, logs, or MCP resources.
- Client secrets: per-client file ref.
- TLS: `secrets/labsso-tls/` (integrator), not inline PEM.

Secret material is excluded from state export, diffs, logs, MCP resources, and audit payloads. The process never writes secret files or the bootstrap YAML.

## Import hardening

Allow-list rewriter. Unknown keys dropped or parked in `imported.unmapped`. XML: no external entities, no DTD network fetch, entity expansion cap, size cap. Import is plan/apply, not a live merge. See [ADR 0008](adr/0008-import-allowlist-rewriter.md).

## Audit

Audit every mutation, reset, import, tunable, rejected authorization, and clothes swap. Record event ID, time, actor, transport, capability, reason, revisions, redacted diff, result.

Audit delivery failure cannot block the data plane. First implementation: in-memory ring; optional hook is best-effort.

## Supply chain (when implemented)

- Pin direct dependencies. Prefer Go stdlib.
- Pin GitHub Actions by commit SHA.
- SBOM and image scan on release.
- Scratch/distroless, UID 65532, read-only, cap_drop ALL, no-new-privileges.
- Official MCP SDK v1.7.0 only.

## Failure modes

- Auth unavailable: fail closed for writes.
- Missing secret file: fail compile / serve.
- XXE attempt: reject import, audit, no network.
- Token endpoint paused: other data-plane routes stay up; this is an authorized tunable, not an accident.
- Host 443 stolen by nginx: preflight fail closed (occupancy), not a silent bind to another port.

## Observability

Security metrics: management auth failures, scope denials, import rejects, data-plane login failures (bounded reason codes), rate-limit events. No password or token labels.

## Testing strategy

- Auth and RBAC matrix.
- Origin and DNS-rebinding defense.
- PKCE and redirect-URI negative tests.
- Import XXE and oversize tests.
- Container hardening (UID, read-only, caps).
- `ui.enabled: false` does not 404 `/login`.
- Clothes swap does not change `iss`.

## Compatibility implications

Weakening a default or broadening access is a security-significant breaking change even if schemas remain compatible.

## Open questions

- Remote management TLS (sweep 2): slice 1 is loopback HTTP; remote TLS is a later deployment choice.
- PHC allow-list (sweep 2): unknown id fails closed; plaintext/unsalted reject; family precedent Argon2id; parameters in CFG at LOGIN-001.
