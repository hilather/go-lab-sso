# Pack Manifest

Status: through VEN-003; INT-001 documented; SCIM design-only
Last reviewed: 2026-10-03

Inventory of the design pack and the implemented appliance. Source-generated config schema and capability/MCP binding manifests live in `docs/generated/`; OpenAPI generation remains outside the current contract.

## Root guidance

- `README.md`: product page, banner, quick start, YAML sketch, state APIs.
- `START-HERE.md`: short onboarding path. Through VEN-003; integrator pin last; SCIM design-only.
- `docs/user-guide.md`: operator guide.
- `docs/assets/header.svg`: README banner.
- `go.mod`: module `github.com/hilather/go-lab-sso`, Go 1.26.
- `Makefile`: format/lint/generated/unit/race/fuzz/integration/parity/config/docs/container/security/changelog checks.
- `Dockerfile`: scratch image, UID 65532.
- `.github/workflows/ci.yml`: mandatory jobs for every required Make check.
- `docs/README.md`: documentation catalog.
- `AGENTS.md`: repository instructions for contributors.
- `.cursor/rules/`: Cursor summaries of `AGENTS.md`. Not vendored agent-skills.
- `CONTRIBUTING.md`: contribution workflow.
- `SECURITY.md`: vulnerability reporting.
- `CHANGELOG.md`: curated history.
- `docs/releases/v1.0.0-rc.3.md`: 1.0.0-rc.3 notes (file-ref TOTP + operator chrome #3).
- `LICENSE`: Apache-2.0, Copyright 2026 hilather.

## Design documents

- `docs/01-architecture.md`
- `docs/02-protocols.md`
- `docs/03-vendor-profiles.md`
- `docs/04-state-and-configuration.md`
- `docs/05-control-plane-and-parity.md`
- `docs/06-rest-api.md`
- `docs/07-mcp-api.md`
- `docs/08-security-architecture.md`
- `docs/09-customer-config-import.md`
- `docs/10-testing-strategy.md`
- `docs/11-deployment.md`
- `docs/18-roadmap-and-non-goals.md`
- `docs/19-acceptance-criteria.md`
- `docs/22-operator-spa.md`
- `docs/23-scim-outbound.md`
- `docs/20-threat-model.md`
- `docs/21-standards-and-references.md`
- `docs/known-limitations.md`
- `docs/skeptic-notes.md`
- `docs/user-guide.md`

## Architecture decisions

- `docs/adr/0001-use-go.md`
- `docs/adr/0002-from-scratch-not-keycloak.md`
- `docs/adr/0003-ephemeral-state-and-gitops.md`
- `docs/adr/0004-shared-capability-registry.md`
- `docs/adr/0005-vendor-clothes-not-hostnames.md`
- `docs/adr/0006-native-host-443.md`
- `docs/adr/0007-no-labntp-time-bus.md`
- `docs/adr/0008-import-allowlist-rewriter.md`
- `docs/adr/0009-data-plane-login-ui.md`
- `docs/adr/0010-duo-siteminder-shibboleth-clothes.md`
- `docs/adr/0011-file-ref-totp.md`

## Agent task plans

- `tasks/README.md`
- `tasks/00-program-board.md`
- `tasks/agent-task-template.md`
- `tasks/reviewer-checklist.md`

## Fixtures and sketches

- `testdata/config/valid/minimal.yaml`
- `testdata/config/valid/totp-alice.yaml`
- `testdata/config/valid/duo.yaml`, `testdata/config/valid/siteminder.yaml`, `testdata/config/valid/shibboleth.yaml`
- `testdata/config/invalid/unknown-field.yaml`
- `testdata/secrets/tls/tls.crt`, `testdata/secrets/tls/tls.key` (self-signed leaf, `0644`)
- `testdata/secrets/oidc/signing.pem` (JWT signing key, `0644`)
- `testdata/secrets/labsso-token` (management bearer, `0644`)
- `testdata/secrets/users/alice.totp` (RFC 6238 Appendix B seed, `0644`)
- `examples/compose.yaml` (runnable `443:10443`)
- `docs/assets/header.svg`

## Explicitly absent (by design)

- Vendored Origin/Cursor agent-skills
- Fake CI / Go / Release badges

## Generated contracts and verification tools

- `cmd/generate`: deterministic model/catalog contract generator.
- `docs/generated/config.schema.json`, `docs/generated/capabilities.json`, `docs/generated/mcp-bindings.json`: generated public contracts (never edit manually).
- `scripts/fuzz-smoke.sh`: bounded YAML/XML fuzz runs.
- `scripts/check-markdown-links.py`: offline local Markdown link verification.
- `cmd/labsso/serve_hardening_test.go`: actual TLS rotation, data-plane isolation, shutdown, and listener cleanup regressions.
- `internal/password`: strict compiled Argon2id/plaintext credentials.
