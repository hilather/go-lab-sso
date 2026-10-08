# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project will use [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once an implementation tag exists.

## [Unreleased]

### Changed

- Go toolchain pinned to go1.26.8 (go.mod `toolchain`, CI `GO_VERSION`); 1.26.0–1.26.7 lack current stdlib security fixes. The image stays `golang:1.26-alpine` (not patch-pinned).
- `golang.org/x/crypto` moves v0.47.0 to v0.56.0 and `golang.org/x/sys` moves v0.41.0 to v0.47.0 (go directive `go 1.26` to `go 1.26.0`). This clears all 16 fixable govulncheck advisories in x/crypto v0.47.0 (GO-2026-5005, GO-2026-5006, GO-2026-5013 through GO-2026-5021, GO-2026-5023, GO-2026-5033, GO-2026-6303, GO-2026-6354, GO-2026-6355) and GO-2026-5024 in x/sys v0.41.0. GO-2026-5932 remains (`golang.org/x/crypto/openpgp` is unmaintained; no fix available).

## [1.0.0-rc.4] - 2026-10-04

Deep-review hardening ([#5](https://github.com/hilather/go-lab-sso/pull/5)), refresh-grant atomicity ([#6](https://github.com/hilather/go-lab-sso/pull/6)), and named force-fail token denials with the Entra 90033 mapping ([#7](https://github.com/hilather/go-lab-sso/pull/7)) after v1.0.0-rc.3. These are all the changes merged since rc.3.

### Changed

- RP-initiated logout is narrowed: a GET with a valid `id_token_hint` for the live session's user logs out directly. With a live session, a missing, invalid, expired, or mismatched hint, or any HEAD, gets a confirmation page and the session stays until the protected confirmation POST; without a live session, GET returns logged-out HTML or the validated redirect. Clients that relied on a hint-less GET clearing the session must submit the confirmation form ([#5](https://github.com/hilather/go-lab-sso/pull/5)). See also the QA follow-up entry under Fixed.
- Contract changes from the deep review ([#5](https://github.com/hilather/go-lab-sso/pull/5)) that clients and operators can see: reset and desired-state applies have new required fields, list responses are paginated with `items`/`nextCursor`, startup-only settings need a restart, and malformed configurations, weak PKCE values, and stale grants that used to slip through now reject (details in the Reset and REST/MCP contracts entries under Fixed). Security changes may require users to sign in again.
- Token errors caused by force-fail (the `auth:force-fail` tunable or `mfa.mode: force-fail`) now carry `error_description: "force-fail"`, matching authorize, so a refresh denial that keeps the grant is distinguishable from a consumed grant (an authorization code is single-use and is spent either way). Status and `error` stay `400 invalid_grant`; `token:pause` remains the `503 temporarily_unavailable` simulation. ([#7](https://github.com/hilather/go-lab-sso/pull/7))

### Fixed

- QA follow-up: preserve refresh grants after rejected scope widening while retaining single-use rotation; perform dummy password verification for unknown/disabled usernames and equalize KDF work in mixed credential configurations; end logout GET sessions only with a valid `id_token_hint` for the session's user, otherwise require a protected confirmation POST, and validate redirects before clearing sessions or cookies. ([#5](https://github.com/hilather/go-lab-sso/pull/5))
- Deep code/design review: prevent interleaved TOTP replay and cross-site login/consent, require a valid pending flow before authentication, and reject revoked users, clients, recipients, and protocol grants. Authentication requests retain one compiled snapshot; password and TOTP files are resolved during compilation. Strict Argon2id hash refs reject plaintext and unsalted hashes. ([#5](https://github.com/hilather/go-lab-sso/pull/5))
- OIDC: enforce PKCE syntax and configured scopes, support refresh scope narrowing, advertise the actual RSA/ECDSA signing algorithm, derive key IDs from public keys, and prevent caching sensitive responses. Bound abandoned authentication state, rate-limit buckets, and concurrent password verification; audit rejections without credentials. ([#5](https://github.com/hilather/go-lab-sso/pull/5))
- Configuration/import: validate TLS key pairs, exact HTTPS issuers, listener addresses and paths, and redirect/ACS URLs before activation. Detach snapshot indexes from caller-owned memory. Remove nested vendor credentials from import responses, reject ambiguous SAML metadata, and validate SAML request shape and destination. ([#5](https://github.com/hilather/go-lab-sso/pull/5))
- Control plane: reject malformed, oversized, trailing, or unknown JSON mutation fields; match operation target/value IDs; preserve semantic retries across REST/MCP and intervening changes; retain editable confidential-import fragments with validation blockers. Fix validation/resource-error parity and custom REST paths in the operator SPA. ([#5](https://github.com/hilather/go-lab-sso/pull/5))
- Reset now requires `expectedRevision` and a reason, supports dry-run planning and idempotent retries, and preserves live state on invalid bootstrap input. Desired-state applies require a reason. Runtime listener address, route, and MCP legacy-policy changes reject with a restart requirement. Existing tests that used invalid PKCE or unguarded resets were updated to exercise the corrected contracts. ([#5](https://github.com/hilather/go-lab-sso/pull/5))
- REST/MCP contracts: generate and verify configuration JSON Schema and capability/binding artifacts, implement shared cursor pagination and JSON export, preserve large integers in MCP mutation inputs, and record the originating transport in audits. List responses use `items` and optional `nextCursor`, including audit lists; the SPA follows all user/session pages. ([#5](https://github.com/hilather/go-lab-sso/pull/5))
- Serving and verification: rotate TLS certificates from the active validated snapshot, make readiness concurrent-safe, bound HTTP deadlines, and close both listeners and active connections on shutdown or serving failure. Replace unused generation, fuzz and integration targets with real checks, add required CI jobs, and strengthen documentation and container smoke checks. ([#5](https://github.com/hilather/go-lab-sso/pull/5))
- Refresh grants are consumed only atomically with storing the rotated replacement, so a failure while issuing tokens (force-fail tunable, overage limit, signing error) no longer leaves the client with a dead refresh token; revoked users and clients still lose the grant. ([#6](https://github.com/hilather/go-lab-sso/pull/6))
- Entra clothes map token `temporarily_unavailable` to `error_codes: [90033]` (AADSTS90033, a transient service error) instead of 50058 (UserInformationNotProvided, an interaction-required code). Affects paused, capacity, rate-limited, and injected `temporarily_unavailable` responses. ([#7](https://github.com/hilather/go-lab-sso/pull/7))

## [1.0.0-rc.3] - 2026-09-07

File-ref TOTP and operator chrome after v1.0.0-rc.2. Notes: [docs/releases/v1.0.0-rc.3.md](docs/releases/v1.0.0-rc.3.md).

### Added

- File-ref TOTP ([ADR 0011](docs/adr/0011-file-ref-totp.md)): RFC 6238 SHA-1 6-digit verification, optional `users[].totpSecretRef`, in-memory enroll/rotate/clear overlay, typed `POST /v1/auth/mfa` / `sso_auth_mfa_set`, `totp:enroll` / `totp:clear` REST+MCP twins, operator Users view. After MFA, OIDC `amr`/`acr` and SAML/WS-Fed `TimeSyncToken`. `lab-totp` is rejected. Fixture `testdata/config/valid/totp-alice.yaml`.

### Changed

- Operator chrome (Mira afters, [#3](https://github.com/hilather/go-lab-sso/pull/3)): Lab* family shell in `internal/web` (sessions + users list/inspector). SPA binds existing `POST /v1/sessions/{id}:expire` and `POST /v1/sessions:expire-all` (no `expectedRevision`). Data-plane `/login` `/consent` are a 380px lab IdP card, not the operator rail. Leftover groups/clients/status/audit keep JSON bodies. IBM Plex via Google Fonts CSS CDN; no third-party JS.

### Fixed

- None versus v1.0.0-rc.2.

### Removed or deprecated

- Shared literal `lab-totp` is rejected.

### Carried from earlier release candidates

Before rc.3 the changelog kept every entry under `[Unreleased]`. The entries below shipped in v1.0.0-rc.1 (2026-08-30) or, where marked (rc.2), in v1.0.0-rc.2 (2026-08-31); "(reworded in rc.2)" marks an rc.1 entry whose text changed in rc.2. They are part of v1.0.0-rc.3 and were moved here from `[Unreleased]`.

#### Added

- (rc.2) Product page polish: illustrated header banner, CI badge, and a user-guide table of contents.
- (rc.2) Operator docs: README rewrite with header banner, YAML and state-API quick starts, and `docs/user-guide.md`. Onboarding no longer talks like the CLI is future work.
- VEN-001: Entra and Okta clothes on the exact issuer (`internal/vendor`, snapshot `Clothes`, path dispatch). Optional `spec.profile.tenantId` (compile default, not Normalized). Cookie names `labsso_entra` / `labsso_okta`. Entra `oid`/`tid`/`ver` on id_token and userinfo. Entra token errors add `error_codes` + `trace_id`. `POST /v1/tunables/vendor:swap` / `sso_tunable_vendor_swap` merges profile and purges protocol memory (not pause/force-fail/inject).
- (reworded in rc.2) VEN-002: Remaining enum clothes (`ping`, `adfs`, `google`, `keycloak`, `iam-identity-center`) on the exact issuer. Keycloak realm = `metadata.name` (empty → `lab`). WS-Fed passive (`internal/wsfed`): `wsfed.enabled: false` 404s; metadata EntityID = issuer; `wa=wsignin1.0` auto-POST `wresult`/`wctx` to `wreply`; ADFS path clothes. Forbidden hosts include `accounts.google.com`, `pingidentity.com`, `sso.amazonaws.com`.
- (rc.2) VEN-003: `duo`, `siteminder`, `shibboleth` clothes on the exact issuer ([ADR 0010](docs/adr/0010-duo-siteminder-shibboleth-clothes.md)). OIDC paths plus SAML URL clothes (`metadata.name` path segment). Entra/Duo share a two-segment well-known dispatcher. Forbidden hosts include `duosecurity.com`, `duo.com`, `shibboleth.net`. Live issuer suffixes and Duo metadata-as-EntityID are not copied.
- IMP-001: Allow-list import (`entra-manifest` | `okta-app` | `saml-metadata` | `oidc-client`). `sso.import.plan` / `sso.import.apply`. `imported.unmapped` in the response. `redirect:rewrite`.
- INT-001: Integrator pin documented in `docs/11-deployment.md`. Do not implement compose from this repo.
- SCIM-001: Design-only outbound client (`docs/23-scim-outbound.md`). No inbound server. No SCIM YAML or catalog rows.
- OVR-001: `spec.groupOverage.genericCap` (Normalize `0 → 200`; also the Entra threshold). Scope-gated group claims on access token + id_token + userinfo. Generic cap omit + audit; Entra `_claim_names`/`_claim_sources` + local Graph stub `POST /v1.0/users/{oid}/getMemberGroups`; stub-off overage fails the token; Okta `oktaFailAt` fails code/refresh. `POST /v1/tunables/overage:set` / `sso_tunable_overage_set` pointer-merge. Leftover OIDC tunables: `consent:force`, `token:mint`. Canonicalize of YAML that omitted `genericCap` now emits `genericCap: 200`.
- UI-001: Operator SPA in `internal/web` (no app import). Cookie `labsso_session` + CSRF `X-LabSSO-CSRF`. Bearer wins; CSRF on non-GET cookie calls; MCP ignores cookies. REST-only `POST/GET/DELETE /v1/session`. Audit list/get + `labsso://audit/recent`. `POST /v1/sessions:expire-all`. `ui.enabled: false` 404s `GET /` only. First SPA is ready for Mira review (checklist in `docs/22-operator-spa.md`).
- (reworded in rc.2) SAML-001: SP-initiated SSO. `GET /saml/metadata` EntityID = exact issuer. `GET|POST /saml/sso`. Protocol-neutral pending (`oidc` | `saml`); same login/consent HTML; SAML completion auto-POSTs a signed assertion. `spec.clients[].saml.entityID` / `acsURLs` (empty ACS → `redirectURIs`). Compiler synthesizes a lab self-signed X.509 from `signing.keyRef`. Hardened XML (no DTD/ENTITY, 64KiB). New dep: `github.com/russellhaering/goxmldsig` (signing XML we generate; not a full IdP wrap). `saml.enabled: false` 404s.
- Cursor `.cursor/rules/` summaries of `AGENTS.md` (`repo-conventions.mdc`,
  `go-tests.mdc`). These are not vendored Origin/Cursor agent-skills.
- `go.mod` (Go 1.26), fail-closed Makefile, `.gitignore`.
- Testdata TLS leaf, OIDC signing key, and management token (`0644`).
- YAML sketch `certRef`/`keyRef`/`signing.keyRef` fields.
- README, START-HERE, AGENTS, SECURITY, CONTRIBUTING, MANIFEST, Apache-2.0 LICENSE.
- Normative docs `docs/01`–`docs/11`, `docs/18`–`docs/21`, known limitations, skeptic notes.
- (reworded in rc.2) ADRs 0001–0010.
- Program board and reviewer/agent templates.
- YAML fixtures and a non-runnable Compose sketch.

#### Design

- Landed the LabSSO design plan: two-plane IdP (HTTPS data plane + REST/MCP management), fail-closed YAML `labsso.dev/v1alpha1`, vendor clothes (not hostname clones), native host 443, no LabNTP time bus, allow-list customer-config import, and sequential protocol slices.
- Skeptic sweep 2 (2026-08-30, Keystone): review-plan **READY**, skeptic-plan-review sweep 1 **ACCEPT**. Sweep-2 questions written down in `docs/skeptic-notes.md`. No product invariant changed.
- Implementation **opened** at FND-001. CFG freezes: membership is `user.groupIds` only; `bootstrapRevision` is SHA-256 of canonical export; issuer must match derivation when `LAB_PUBLIC_HOST` is set; TLS leaf refs ≠ OIDC `spec.signing.keyRef`; login cookie `labsso_login`.
- Status is **M1 (FND-001) implemented**. OIDC not started.
- Wave 1: `labsso.dev/v1alpha1` KnownFields decode, normalize, and validate in `internal/model` + `internal/config`. Invalid packs cover unknown fields, bare durations, inline PEM, `memberUserIds`, and dangling `groupIds`.
- Wave 2: compiler, snapshot store, and plan/apply/reset/export. `bootstrapRevision` is SHA-256 of canonical export; issuer must match `LAB_PUBLIC_HOST` when set; the process never writes the bootstrap file.
- Wave 3: FND capability IDs frozen in `internal/capabilities`. Registry does not import `internal/app`. Audit is emit-only (in-memory ring; no list/get APIs).
- Wave 4: REST `/v1` and MCP Streamable HTTP `/mcp` adapters over the shared app. Protocol pin `2026-07-28`; official go-sdk v1.7.0. `make test-parity` covers validate/plan/apply/export/reset/status.
- Wave 5: `labsso` CLI, scratch image UID 65532, runnable `examples/compose.yaml` (`443:10443`), CI for real Make targets. FND-001 / M1 done. HTTPS binds TLS; OIDC routes 404.
- Wave 6: generic OIDC authorization-code + PKCE S256, discovery, JWKS, token, refresh, userinfo, logout. Authorize without a login session 302s to `{issuer}/login` and persists the pending request. `go-jose/v4`. Ephemeral tunables (pause token, expire session, force-fail) have no `expectedRevision`.
- Wave 7: data-plane login/consent HTML, cookie `labsso_login`, MFA knobs, Argon2id PHC allow-list, login POST rate limit. Default ship (M2) is generic OIDC + login HTML.

#### Fixed

- (rc.2) CI gate: gofmt alignment, errcheck/staticcheck, and govulncheck. Bump `go-jose/v4` to v4.1.4 (GO-2026-4945) and `goxmldsig` to v1.6.0 (GO-2026-4753).
- Skeptic review of the default-ship landing: PKCE errors no longer 302 to an unvalidated `redirect_uri`; token binds `client_id` and authenticates confidential clients; refresh tokens rotate; UserInfo rejects expired tokens and `id_token`; consent deny is an OAuth redirect; apply re-validates secret refs and unknown JSON fields; trailing YAML documents reject; plan impact sees in-place membership edits; reset clears the OIDC runtime; REST reset/tunable bodies fail closed; management REST uses `CrossOriginProtection`; `Validate` clones before applying ops; `domainerr.CodeOf` unwraps wrapped errors.
- Follow-up: RP logout honors registered `post_logout_redirect_uri`; optional user `email` plus UserInfo scoped claims; consent Deny button; `oidc.enabled: false` 404s protocol routes; compile failures are `validation_failed`; YAML MFA `force-fail` applies on authorize; authorize/token rate limits and 10m pending TTL; loopback Host allowlist; MCP resource templates and tool error codes; session expire requires `:expire`; unique usernames; pinned Argon2id params; SHA-256 password compare.

[Unreleased]: https://github.com/hilather/go-lab-sso/compare/v1.0.0-rc.4...HEAD
[1.0.0-rc.4]: https://github.com/hilather/go-lab-sso/compare/v1.0.0-rc.3...v1.0.0-rc.4
[1.0.0-rc.3]: https://github.com/hilather/go-lab-sso/compare/v1.0.0-rc.2...v1.0.0-rc.3
