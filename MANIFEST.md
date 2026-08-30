# Pack Manifest

Status: design (not implemented)
Last reviewed: 2026-08-30

This inventory is the design pack. There is no generated OpenAPI, MCP manifest, JSON Schema, or container image in this repository yet.

## Root guidance

- `README.md`: product one-liner, status, why LabSSO, two-plane mermaid, YAML sketch, documentation map.
- `START-HERE.md`: this repo is the design; implementation is not scheduled.
- `docs/README.md`: full documentation catalog.
- `AGENTS.md`: mandatory repository instructions.
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
- `examples/compose.sketch.yaml` (NOT runnable until implemented)

## Explicitly absent (by design)

- `go.mod`, `go.sum`, `cmd/`, `internal/`
- Dockerfile that claims to build a server
- CI workflows
- Makefile
- Vendored Origin/Cursor agent-skills
- Header / social images
- Fake CI / Go / Release badges
