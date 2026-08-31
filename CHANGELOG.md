# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project will use [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once an implementation tag exists.

## [Unreleased]

### Added

- Product page polish: illustrated header banner, CI badge, and a user-guide table of contents.
- Operator docs: README rewrite with header banner, YAML and state-API quick starts, and `docs/user-guide.md`. Onboarding no longer talks like the CLI is future work.
- VEN-001: Entra and Okta clothes on the exact issuer (`internal/vendor`, snapshot `Clothes`, path dispatch). Optional `spec.profile.tenantId` (compile default, not Normalized). Cookie names `labsso_entra` / `labsso_okta`. Entra `oid`/`tid`/`ver` on id_token and userinfo. Entra token errors add `error_codes` + `trace_id`. `POST /v1/tunables/vendor:swap` / `sso_tunable_vendor_swap` merges profile and purges protocol memory (not pause/force-fail/inject).
- VEN-002: Remaining enum clothes (`ping`, `adfs`, `google`, `keycloak`, `iam-identity-center`) on the exact issuer. Keycloak realm = `metadata.name` (empty → `lab`). WS-Fed passive (`internal/wsfed`): `wsfed.enabled: false` 404s; metadata EntityID = issuer; `wa=wsignin1.0` auto-POST `wresult`/`wctx` to `wreply`; ADFS path clothes. Forbidden hosts include `accounts.google.com`, `pingidentity.com`, `sso.amazonaws.com`.
- VEN-003: `duo`, `siteminder`, `shibboleth` clothes on the exact issuer ([ADR 0010](docs/adr/0010-duo-siteminder-shibboleth-clothes.md)). OIDC paths plus SAML URL clothes (`metadata.name` path segment). Entra/Duo share a two-segment well-known dispatcher. Forbidden hosts include `duosecurity.com`, `duo.com`, `shibboleth.net`. Live issuer suffixes and Duo metadata-as-EntityID are not copied.
- IMP-001: Allow-list import (`entra-manifest` | `okta-app` | `saml-metadata` | `oidc-client`). `sso.import.plan` / `sso.import.apply`. `imported.unmapped` in the response. `redirect:rewrite`.
- INT-001: Integrator pin documented in `docs/11-deployment.md`. Do not implement compose from this repo.
- SCIM-001: Design-only outbound client (`docs/23-scim-outbound.md`). No inbound server. No SCIM YAML or catalog rows.
- OVR-001: `spec.groupOverage.genericCap` (Normalize `0 → 200`; also the Entra threshold). Scope-gated group claims on access token + id_token + userinfo. Generic cap omit + audit; Entra `_claim_names`/`_claim_sources` + local Graph stub `POST /v1.0/users/{oid}/getMemberGroups`; stub-off overage fails the token; Okta `oktaFailAt` fails code/refresh. `POST /v1/tunables/overage:set` / `sso_tunable_overage_set` pointer-merge. Leftover OIDC tunables: `consent:force`, `token:mint`. Canonicalize of YAML that omitted `genericCap` now emits `genericCap: 200`.
- UI-001: Operator SPA in `internal/web` (no app import). Cookie `labsso_session` + CSRF `X-LabSSO-CSRF`. Bearer wins; CSRF on non-GET cookie calls; MCP ignores cookies. REST-only `POST/GET/DELETE /v1/session`. Audit list/get + `labsso://audit/recent`. `POST /v1/sessions:expire-all`. `ui.enabled: false` 404s `GET /` only. First SPA is ready for Mira review (checklist in `docs/22-operator-spa.md`).
- SAML-001: SP-initiated SSO. `GET /saml/metadata` EntityID = exact issuer. `GET|POST /saml/sso`. Protocol-neutral pending (`oidc` | `saml`); same login/consent HTML; SAML completion auto-POSTs a signed assertion. `spec.clients[].saml.entityID` / `acsURLs` (empty ACS → `redirectURIs`). Compiler synthesizes a lab self-signed X.509 from `signing.keyRef`. Hardened XML (no DTD/ENTITY, 64KiB). New dep: `github.com/russellhaering/goxmldsig` (signing XML we generate; not a full IdP wrap). `saml.enabled: false` 404s.

### Design

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

### Fixed

- CI gate: gofmt alignment, errcheck/staticcheck, and govulncheck. Bump `go-jose/v4` to v4.1.4 (GO-2026-4945) and `goxmldsig` to v1.6.0 (GO-2026-4753).
- Skeptic review of the default-ship landing: PKCE errors no longer 302 to an unvalidated `redirect_uri`; token binds `client_id` and authenticates confidential clients; refresh tokens rotate; UserInfo rejects expired tokens and `id_token`; consent deny is an OAuth redirect; apply re-validates secret refs and unknown JSON fields; trailing YAML documents reject; plan impact sees in-place membership edits; reset clears the OIDC runtime; REST reset/tunable bodies fail closed; management REST uses `CrossOriginProtection`; `Validate` clones before applying ops; `domainerr.CodeOf` unwraps wrapped errors.
- Follow-up: RP logout honors registered `post_logout_redirect_uri`; optional user `email` plus UserInfo scoped claims; consent Deny button; `oidc.enabled: false` 404s protocol routes; compile failures are `validation_failed`; YAML MFA `force-fail` applies on authorize; authorize/token rate limits and 10m pending TTL; loopback Host allowlist; MCP resource templates and tool error codes; session expire requires `:expire`; unique usernames; pinned Argon2id params; SHA-256 password compare.

### Added

- Cursor `.cursor/rules/` summaries of `AGENTS.md` (`repo-conventions.mdc`,
  `go-tests.mdc`). These are not vendored Origin/Cursor agent-skills.
- `go.mod` (Go 1.26), fail-closed Makefile, `.gitignore`.
- Testdata TLS leaf, OIDC signing key, and management token (`0644`).
- YAML sketch `certRef`/`keyRef`/`signing.keyRef` fields.
- README, START-HERE, AGENTS, SECURITY, CONTRIBUTING, MANIFEST, Apache-2.0 LICENSE.
- Normative docs `docs/01`–`docs/11`, `docs/18`–`docs/21`, known limitations, skeptic notes.
- ADRs 0001–0010.
- Program board and reviewer/agent templates.
- YAML fixtures and a non-runnable Compose sketch.

[Unreleased]: https://github.com/hilather/go-lab-sso/compare/main...HEAD
