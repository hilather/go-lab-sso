# Repository Instructions for Agents

These instructions apply to every human or AI agent working in this repository. More specific `AGENTS.md` files may add stricter rules but may not weaken this file.

This repository has **implemented the default ship (FND-001 + OIDC-001 + LOGIN-001) plus VEN-001 (entra/okta clothes)**. SAML, SPA, import, overage, and the integrator pin are not started. Do not vendor Origin/Cursor agent-skills. Makefile targets that are not implemented must `false`, not no-op.

## Required reading

Before modifying design or (later) code, read:

1. `docs/01-architecture.md`
2. `docs/02-protocols.md`
3. `docs/03-vendor-profiles.md`
4. `docs/04-state-and-configuration.md`
5. `docs/05-control-plane-and-parity.md`
6. `docs/06-rest-api.md`
7. `docs/07-mcp-api.md`
8. `docs/08-security-architecture.md`
9. `docs/09-customer-config-import.md`
10. `docs/10-testing-strategy.md`
11. `docs/11-deployment.md`
12. `docs/18-roadmap-and-non-goals.md`
13. `docs/19-acceptance-criteria.md`
14. `docs/20-threat-model.md`
15. `docs/21-standards-and-references.md`
16. `docs/known-limitations.md`
17. `docs/skeptic-notes.md`
18. Every ADR relevant to the area being changed

## Architectural rules

- REST and MCP are adapters over **one operation registry**. Domain behavior belongs in the shared application, model, compiler, snapshot, and protocol packages.
- Never implement MCP by proxying REST. Never implement REST by calling MCP.
- REST handlers and MCP handlers must never implement independent business logic.
- Every public capability must be represented in the central capability registry.
- Data-plane HTTPS (authorize, token, JWKS, userinfo, logout, login HTML, later SAML) must operate against an immutable compiled snapshot and must keep working if management is slow or unbound.
- State changes must build and validate a complete candidate snapshot before atomically replacing the active snapshot.
- The service must not write to the bootstrap configuration file. Restart and reset reread the mounted bootstrap.
- Runtime overlay is **memory**. Do not add a database, journal, hidden volume, or other persistence mechanism without an approved ADR.
- Secrets are **file refs**, never inline in YAML, logs, diffs, MCP resources, or audit payloads.
- Unknown YAML fields reject (KnownFields / fail closed).
- Data-plane login + consent + MFA HTML is **required** and is distinct from the operator SPA. `spec.ui.enabled: false` 404s the operator SPA only.
- Operator SPA uses cookie + CSRF. Never store tokens in `localStorage`, `sessionStorage`, IndexedDB, or the URL.
- Do not wrap Keycloak, Dex, ORY Hydra, Authelia, Authentik, or any other IdP. LabSSO is from-scratch Go.
- Do not impersonate vendor hostnames (`login.microsoftonline.com`, `okta.com`, …). Vendor profiles are path and claim clothes on one exact issuer.
- One exact issuer string is derived from `LAB_PUBLIC_HOST` plus the published HTTPS port (omit the port iff 443).
- No LabNTP time bus. LabSSO uses the process clock. Kerberos / cert-expiry skew repros belong on the SUT via LabNTP.
- LabSSO is a **dest-443** service (integrator rule 15). It is not a forward proxy. Do not copy LabMITM’s “don’t use 443” rule.
- Host publish is TCP 443 → container unprivileged listen (e.g. `:10443`). Management is a high port, not 443.
- `EACCES` / `EPERM` on bind is not occupancy. Preflight fail-closed text must name the occupant-stop, extra-IP, or `LABSSO_HTTPS_PORT` escape.
- Do not flatten LabSSO onto LabLDAP. Optional LDAP bind is a later slice, not v1.
- go-jenkins-mcp is a separate product and is never in-scope.
- Integrator pin in `hilather/mcp-integration-lab` is **last**. Document the wiring; do not implement it there from this repo.
- Prefer the Go standard library when implementation starts. Pin the official MCP Go SDK at v1.7.0. Protocol **2026-07-28**. `allowLegacyClients: true` is required for MCPJungle.
- Language when implemented: **Go 1.26**. Future module `github.com/hilather/go-lab-sso`. Future binary `labsso`. Future image `ghcr.io/hilather/labsso`.
- Single process, distroless/scratch, unprivileged UID 65532, read-only root, `cap_drop ALL`.

## Tests and regressions (once code exists)

- Every area must have regression tests.
- Every code path, protocol behavior, API capability, configuration semantic, operational script, and bug fix must have appropriate automated regression coverage.
- A bug fix must begin with or include a test that fails before the fix and passes after it.
- New OIDC/SAML behavior requires protocol-level or integration coverage.
- New REST functionality requires contract tests and shared-domain tests.
- New MCP functionality requires protocol tests and REST/MCP parity tests.
- Configuration changes require valid, invalid, normalization, round-trip, and backward-compatibility tests.
- Never delete or weaken a test merely to make CI pass unless the test is provably incorrect; document the reason in the change.

## CI is mandatory (once code exists)

- All required CI checks must pass before merge and before a release tag is created.
- Do not bypass, skip, mark optional, or administratively override a failing check to ship a change.
- Treat every CI failure as either a product defect or a pipeline defect.
- Do not add CI in the design phase that would fail (no Go module, no image build, no empty workflow).
- If a Makefile is added later, missing targets must `false`, not no-op.

## Documentation is mandatory

- All documentation must be kept up to date.
- Update affected architecture, API, MCP, configuration, security, operation, testing, deployment, task, and ADR documents in the same change as the implementation (or design edit).
- Stale documentation is a defect and blocks task completion.
- Update `Last reviewed` metadata when a document receives a substantive review.
- Do not change an architectural invariant without an ADR.
- Placeholders fail closed. Do not land one-paragraph stubs for architecture or API docs.

## REST, MCP, and UI parity

- Every public REST control capability must have an MCP equivalent, except documented `REST_ONLY_PROTOCOL` rows (health probes, browser session).
- Every state-changing MCP tool must have a REST equivalent.
- Both adapters must use the same input and output domain types and the same authorization decision.
- Every mutation must support validation, dry-run planning, optimistic concurrency, idempotency, actor identity, reason, deterministic errors, audit emission, and an atomic commit.
- Operator UI (when implemented) binds the same registry. Mira reviews after the first UI implementation. Do not build UI in this design landing.

## Generated files (once code exists)

- Do not manually edit generated OpenAPI, JSON Schema, MCP manifest, mocks, golden capability maps, or generated documentation.
- Change the source model or specification and run the documented generation target.

## Dependencies (once code exists)

- Prefer the Go standard library and small, well-maintained libraries.
- Pin direct dependencies and review transitive changes.
- Hide OIDC, SAML, MCP, telemetry, and schema-library types behind internal adapters.
- New dependencies require a justification in the pull request and must pass license and vulnerability checks.

## Required completion commands (once code exists)

The implementation repository should provide equivalent targets for:

```text
make format
make lint
make generate
make verify-generated
make test
make test-race
make test-fuzz-smoke
make test-integration
make test-parity
make test-config-compat
make test-docs
make test-container
make security-scan
make test-changelog
```

If a target does not yet exist, the task that first needs it must add it rather than silently omitting the check. Placeholders must fail closed, not succeed as no-ops. Do not add a Makefile during design unless every referenced target exists or `false`s.
