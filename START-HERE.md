# Start here

LabSSO is a laboratory identity provider written in Go. You load a YAML file, serve OIDC / SAML / WS-Fed on HTTPS, and drive live changes through REST or MCP. Reset returns the process to the file.

If you want to run it, use this page and the [user guide](docs/user-guide.md). If you want to change the code or the design contracts, read [AGENTS.md](AGENTS.md) first.

## Five-minute path

1. Skim the [README](README.md) so the two planes make sense.
2. Run the [quick start](README.md#quick-start): validate the sample YAML, then `labsso serve`.
3. Hit `GET /v1/state` and `GET /v1/state:export` as shown in the README.
4. Read [docs/user-guide.md](docs/user-guide.md) for YAML fields, plan/apply, and MCP twins.
5. When you need the exact schema or protocol behavior, open the docs listed below.

## What to read next

| If you are… | Read |
|---|---|
| Trying LabSSO for a lab | [README.md](README.md), [docs/user-guide.md](docs/user-guide.md) |
| Writing or reviewing YAML | [docs/04-state-and-configuration.md](docs/04-state-and-configuration.md), [testdata/config/](testdata/config/) |
| Wiring OIDC, SAML, or WS-Fed | [docs/02-protocols.md](docs/02-protocols.md) |
| Dressing Entra / Okta / Ping / ADFS | [docs/03-vendor-profiles.md](docs/03-vendor-profiles.md) |
| Publishing host 443 | [docs/11-deployment.md](docs/11-deployment.md) |
| Wiring an agent | [docs/07-mcp-api.md](docs/07-mcp-api.md), [docs/05-control-plane-and-parity.md](docs/05-control-plane-and-parity.md) |
| Importing a customer app blob | [docs/09-customer-config-import.md](docs/09-customer-config-import.md) |
| Changing an invariant | [AGENTS.md](AGENTS.md), then the matching ADR under `docs/adr/` |

Full catalog: [docs/README.md](docs/README.md).

## For contributors

Implementation is already in the tree. Before you edit:

1. Read [AGENTS.md](AGENTS.md).
2. Read the architecture, protocol, YAML, parity, and security docs that touch your change.
3. Update the affected documents in the same change.
4. Keep REST, MCP, and the operator UI on the same operation list. Do not implement MCP as a client of REST.

A change is done when tests pass, docs match the code, and [CHANGELOG.md](CHANGELOG.md) mentions it.
