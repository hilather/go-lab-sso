# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project will use [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once an implementation tag exists.

## [Unreleased]

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
- ADRs 0001–0009.
- Program board and reviewer/agent templates.
- YAML fixtures and a non-runnable Compose sketch.

[Unreleased]: https://github.com/hilather/go-lab-sso/compare/main...HEAD
