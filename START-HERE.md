# Start here

LabSSO is a from-scratch Go laboratory Identity Provider in the hilather lab-appliance family. This repository is the **design**. Implementation is **not scheduled**. There is no binary, no `go.mod`, and no image that claims to serve OIDC today.

If you want to understand the product, stay on this page, then read architecture and the program board. If you want to change the design, read [AGENTS.md](AGENTS.md) before touching a file.

## Five-minute path (design)

1. Read this page and the [README](README.md) product one-liner.
2. Read [docs/01-architecture.md](docs/01-architecture.md) — two planes, snapshot, issuer, ports, TLS.
3. Read [docs/04-state-and-configuration.md](docs/04-state-and-configuration.md) and the YAML sketch in [testdata/config/valid/minimal.yaml](testdata/config/valid/minimal.yaml).
4. Read [docs/05-control-plane-and-parity.md](docs/05-control-plane-and-parity.md) so REST and MCP stay adapters.
5. Read [tasks/00-program-board.md](tasks/00-program-board.md) for the ordered slices. Do not start implementation from a task summary while this repo is design-only.

There is no `labsso serve` yet. Do not invent a local build path.

## What to read next

| If you are… | Read |
|---|---|
| Deciding whether LabSSO is the right appliance | [README.md](README.md), [docs/18-roadmap-and-non-goals.md](docs/18-roadmap-and-non-goals.md) |
| Writing or reviewing YAML | [docs/04-state-and-configuration.md](docs/04-state-and-configuration.md), [testdata/config/](testdata/config/) |
| Wiring protocols | [docs/02-protocols.md](docs/02-protocols.md), [docs/21-standards-and-references.md](docs/21-standards-and-references.md) |
| Dressing Entra / Okta / Ping / ADFS | [docs/03-vendor-profiles.md](docs/03-vendor-profiles.md), [docs/adr/0005-vendor-clothes-not-hostnames.md](docs/adr/0005-vendor-clothes-not-hostnames.md) |
| Planning host 443 | [docs/11-deployment.md](docs/11-deployment.md), [docs/adr/0006-native-host-443.md](docs/adr/0006-native-host-443.md) |
| Wiring an agent | [docs/05-control-plane-and-parity.md](docs/05-control-plane-and-parity.md), [docs/07-mcp-api.md](docs/07-mcp-api.md) |
| Importing a customer blob | [docs/09-customer-config-import.md](docs/09-customer-config-import.md), [docs/adr/0008-import-allowlist-rewriter.md](docs/adr/0008-import-allowlist-rewriter.md) |
| Changing an invariant | [AGENTS.md](AGENTS.md), then the relevant ADR |
| Skeptical of the design | [docs/skeptic-notes.md](docs/skeptic-notes.md) |

The full catalog is in [docs/README.md](docs/README.md) and linked from the [README documentation map](README.md#documentation).

## For contributors and agents

This repo is docs-only until a later implementation slice is explicitly opened. Before changing the design:

1. Read [AGENTS.md](AGENTS.md) completely.
2. Read architecture, protocols, vendor clothes, state, control-plane parity, security, and testing: [docs/01-architecture.md](docs/01-architecture.md), [docs/02-protocols.md](docs/02-protocols.md), [docs/03-vendor-profiles.md](docs/03-vendor-profiles.md), [docs/04-state-and-configuration.md](docs/04-state-and-configuration.md), [docs/05-control-plane-and-parity.md](docs/05-control-plane-and-parity.md), [docs/08-security-architecture.md](docs/08-security-architecture.md), [docs/10-testing-strategy.md](docs/10-testing-strategy.md).
3. Read every ADR that affects the change (`docs/adr/`).
4. Update every affected document in the same change.
5. Do not add `go.mod`, a server `Dockerfile`, failing CI, or a Makefile whose missing targets no-op.
6. Do not vendor Origin/Cursor agent-skills.
7. Do not implement LabSSO inside [mcp-integration-lab](https://github.com/hilather/mcp-integration-lab). The integrator pin is last; document the wiring only.

Do not implement REST, MCP, OIDC, SAML, or YAML decode from a task summary when a normative design document exists. The design document is the source of truth. If an invariant must change, write an ADR and update the normative documentation first.

Coordinators allocate work with [tasks/00-program-board.md](tasks/00-program-board.md). Implementation slices stay `not-started` until this design is accepted and a later change opens code.

### Definition of done (design phase)

A design change is not done until:

- The affected normative documents are complete (several screens for architecture/API docs, not one-paragraph stubs).
- ADRs that the change depends on exist and use the family shape (Status, Date, Context, Decision, Consequences, Alternatives, Review triggers).
- YAML sketches and invalid fixtures stay consistent with [docs/04-state-and-configuration.md](docs/04-state-and-configuration.md).
- Status remains **design (not implemented)** unless a later ADR opens implementation.
- No Go, image, or CI artifact claims to build or serve a server.

### Definition of done (later implementation)

When code is opened, a task is not done until the bar in [AGENTS.md](AGENTS.md) is met: tests, docs, CI, REST+MCP+UI parity, and changelog. Mira reviews the operator SPA after the first UI implementation — do not build UI in this design landing.
