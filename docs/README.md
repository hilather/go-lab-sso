# Documentation

Operator front door: [README.md](../README.md). Onboarding: [START-HERE.md](../START-HERE.md). Agent rules: [AGENTS.md](../AGENTS.md).

This page is the catalog. Normative design documents win over task summaries.

Status: **default ship (generic OIDC + login HTML)**. Last reviewed: 2026-08-30.

## Root

| Path | Role |
|---|---|
| [README.md](../README.md) | Product page, two planes, YAML sketch |
| [START-HERE.md](../START-HERE.md) | Onboarding and definition of done |
| [AGENTS.md](../AGENTS.md) | Mandatory contributor / agent instructions |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | PR workflow |
| [SECURITY.md](../SECURITY.md) | Vulnerability reporting |
| [CHANGELOG.md](../CHANGELOG.md) | Curated history |
| [MANIFEST.md](../MANIFEST.md) | Pack inventory |
| [LICENSE](../LICENSE) | Apache-2.0 |

## Architecture

| Path | Topic |
|---|---|
| [01-architecture.md](01-architecture.md) | Two planes, snapshot, issuer, ports, TLS |
| [02-protocols.md](02-protocols.md) | OIDC/OAuth2, SAML, WS-Fed later |
| [03-vendor-profiles.md](03-vendor-profiles.md) | Vendor clothes |
| [04-state-and-configuration.md](04-state-and-configuration.md) | YAML, revisions, plan/apply/export/reset |
| [05-control-plane-and-parity.md](05-control-plane-and-parity.md) | Shared capability registry |

## Interfaces

| Path | Topic |
|---|---|
| [06-rest-api.md](06-rest-api.md) | Planned REST `/v1` |
| [07-mcp-api.md](07-mcp-api.md) | Planned MCP tools |
| [09-customer-config-import.md](09-customer-config-import.md) | Allow-list rewriter |

## Security, operations, program

| Path | Topic |
|---|---|
| [08-security-architecture.md](08-security-architecture.md) | Authn/z, trust boundaries |
| [20-threat-model.md](20-threat-model.md) | Lab-only threat model |
| [10-testing-strategy.md](10-testing-strategy.md) | Test layers |
| [11-deployment.md](11-deployment.md) | Host 443, preflight, UID 65532 |
| [18-roadmap-and-non-goals.md](18-roadmap-and-non-goals.md) | Sequential slices |
| [19-acceptance-criteria.md](19-acceptance-criteria.md) | Design and later-GA bar |
| [21-standards-and-references.md](21-standards-and-references.md) | RFCs and MCP pin |
| [known-limitations.md](known-limitations.md) | Honest residuals |
| [skeptic-notes.md](skeptic-notes.md) | Sweep-1 blockers folded; sweep 2 ACCEPT (2026-08-30) |

## Architecture decisions

| ADR | Decision |
|---|---|
| [0001](adr/0001-use-go.md) | Use Go |
| [0002](adr/0002-from-scratch-not-keycloak.md) | From scratch, not Keycloak |
| [0003](adr/0003-ephemeral-state-and-gitops.md) | Ephemeral state and GitOps |
| [0004](adr/0004-shared-capability-registry.md) | Shared capability registry |
| [0005](adr/0005-vendor-clothes-not-hostnames.md) | Vendor clothes, not hostnames |
| [0006](adr/0006-native-host-443.md) | Native host 443 |
| [0007](adr/0007-no-labntp-time-bus.md) | No LabNTP time bus |
| [0008](adr/0008-import-allowlist-rewriter.md) | Import allow-list rewriter |
| [0009](adr/0009-data-plane-login-ui.md) | Data-plane login UI |

## Task lists

See [tasks/README.md](../tasks/README.md) and the [program board](../tasks/00-program-board.md).

| Path | Role |
|---|---|
| [00-program-board.md](../tasks/00-program-board.md) | Ordered slices |
| [reviewer-checklist.md](../tasks/reviewer-checklist.md) | Review bar |
| [agent-task-template.md](../tasks/agent-task-template.md) | Task file template |

## Fixtures

| Path | Role |
|---|---|
| [testdata/config/valid/minimal.yaml](../testdata/config/valid/minimal.yaml) | Minimal valid document |
| [testdata/config/invalid/unknown-field.yaml](../testdata/config/invalid/unknown-field.yaml) | KnownFields reject |
| [examples/compose.yaml](../examples/compose.yaml) | Runnable 443:10443 compose |
