# Pack Manifest

Status: through VEN-002; INT-001 documented; SCIM design-only
Last reviewed: 2026-08-30

This inventory is the design pack plus implementation through VEN-002. There is no generated OpenAPI or MCP manifest.

## Root guidance

- `README.md`: product one-liner, status, why LabSSO, two-plane mermaid, YAML sketch, documentation map.
- `START-HERE.md`: through VEN-002; integrator pin last; SCIM design-only.
- `go.mod`: module `github.com/hilather/go-lab-sso`, Go 1.26.
- `Makefile`: real format/lint/test/parity/container targets; unused stay `false`.
- `Dockerfile`: scratch image, UID 65532.
- `.github/workflows/ci.yml`: jobs for implemented Make targets.
- `docs/README.md`: full documentation catalog.
- `AGENTS.md`: mandatory repository instructions.
- `.cursor/rules/`: Cursor summaries of `AGENTS.md` (`repo-conventions.mdc`,
  `go-tests.mdc`). Not vendored Origin/Cursor agent-skills.
- `CONTRIBUTING.md`: contribution workflow.
- `SECURITY.md`: top-level security policy (GitHub private advisories).
- `CHANGELOG.md`: curated unreleased history (design-only).
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

## Agent task plans

- `tasks/README.md`
- `tasks/00-program-board.md`
- `tasks/agent-task-template.md`
- `tasks/reviewer-checklist.md`

## Fixtures and sketches

- `testdata/config/valid/minimal.yaml`
- `testdata/config/invalid/unknown-field.yaml`
- `testdata/secrets/tls/tls.crt`, `testdata/secrets/tls/tls.key` (self-signed leaf, `0644`)
- `testdata/secrets/oidc/signing.pem` (JWT signing key, `0644`)
- `testdata/secrets/labsso-token` (management bearer, `0644`)
- `examples/compose.yaml` (runnable `443:10443`)

## Explicitly absent (by design)

- Dockerfile that claims to build a server (until Wave 5)
- CI workflows (until Wave 5)
- Vendored Origin/Cursor agent-skills
- Header / social images
- Fake CI / Go / Release badges
