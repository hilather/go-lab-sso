# Documentation

Start with the [README](../README.md) and the [user guide](user-guide.md). Contributor rules: [AGENTS.md](../AGENTS.md).

This page is the catalog. When a design document and a task summary disagree, the design document wins.

## Root

| Path | Role |
|---|---|
| [README.md](../README.md) | Product page, quick start, YAML and state API sketch |
| [START-HERE.md](../START-HERE.md) | Short onboarding path |
| [user-guide.md](user-guide.md) | Operator guide: run, configure, load state |
| [AGENTS.md](../AGENTS.md) | Contributor / agent instructions |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | PR workflow |
| [SECURITY.md](../SECURITY.md) | Vulnerability reporting |
| [CHANGELOG.md](../CHANGELOG.md) | Curated history |
| [MANIFEST.md](../MANIFEST.md) | Pack inventory |
| [LICENSE](../LICENSE) | Apache-2.0 |

## Architecture

| Path | Topic |
|---|---|
| [01-architecture.md](01-architecture.md) | Two planes, snapshot, issuer, ports, TLS |
| [02-protocols.md](02-protocols.md) | OIDC/OAuth2, SAML, WS-Fed |
| [03-vendor-profiles.md](03-vendor-profiles.md) | Vendor clothes |
| [04-state-and-configuration.md](04-state-and-configuration.md) | YAML, revisions, plan/apply/export/reset |
| [05-control-plane-and-parity.md](05-control-plane-and-parity.md) | Shared capability registry |

## Interfaces

| Path | Topic |
|---|---|
| [06-rest-api.md](06-rest-api.md) | REST `/v1` |
| [07-mcp-api.md](07-mcp-api.md) | MCP tools |
| [22-operator-spa.md](22-operator-spa.md) | Operator UI |
| [09-customer-config-import.md](09-customer-config-import.md) | Allow-list rewriter |
| [23-scim-outbound.md](23-scim-outbound.md) | SCIM outbound (design only) |

## Security, operations, program

| Path | Topic |
|---|---|
| [08-security-architecture.md](08-security-architecture.md) | Authn/z, trust boundaries |
| [20-threat-model.md](20-threat-model.md) | Lab-only threat model |
| [10-testing-strategy.md](10-testing-strategy.md) | Test layers |
| [11-deployment.md](11-deployment.md) | Host 443, image, UID 65532 |
| [18-roadmap-and-non-goals.md](18-roadmap-and-non-goals.md) | Roadmap and non-goals |
| [19-acceptance-criteria.md](19-acceptance-criteria.md) | Acceptance bar |
| [21-standards-and-references.md](21-standards-and-references.md) | RFCs and MCP pin |
| [known-limitations.md](known-limitations.md) | Known gaps |
| [skeptic-notes.md](skeptic-notes.md) | Design review notes |

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

## Fixtures

| Path | Role |
|---|---|
| [testdata/config/valid/minimal.yaml](../testdata/config/valid/minimal.yaml) | Minimal valid document |
| [testdata/config/invalid/unknown-field.yaml](../testdata/config/invalid/unknown-field.yaml) | Unknown-field reject |
| [examples/compose.yaml](../examples/compose.yaml) | Compose with `443:10443` |
| [docs/assets/header.svg](assets/header.svg) | README banner |
