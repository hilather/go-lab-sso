# Testing Strategy

Status: through VEN-003 tests implemented; SCIM design-only
Owners: Quality, Application, Protocols
Last reviewed: 2026-09-01
Related ADRs: 0001, 0004

## Problem statement

Once LabSSO is implemented, protocol mistakes become “the lab does not look like the customer.” Tests must cover YAML fail-closed behavior, snapshot swaps, OIDC/PKCE, login HTML vs SPA, vendor clothes (issuer stability), overage, import hardening, REST/MCP parity, and container dest-443 — without a CI graph that fails while this repo is docs-only.

## Goals

- Mandatory tests when code exists: unit, race, protocol, parity, config-compat, docs, container, changelog.
- Bug fixes start with a failing test.
- Placeholders fail closed.
- No CI workflows in the design landing (they would fail: no Go module).

## Non-goals

- Adding GitHub Actions now.
- Claiming coverage for unimplemented code.
- Vendoring huge protocol suites as git submodules.

## Layers (when implemented)

| Layer | What it proves |
|---|---|
| Unit | Model, normalize, clothes tables, rewriter allow-lists |
| Config fixtures | `testdata/config/valid/*` accept; `invalid/*` reject |
| Protocol | Authorization code + PKCE, discovery `iss`, JWKS, refresh, login HTML, RFC 6238 TOTP (`amr`/`acr`, SAML/WS-Fed `TimeSyncToken`), SAML metadata + AuthnRequest → ACS POST, XXE reject |
| Vendor | Path clothes change; `iss` does not; inactive paths 404; no vendor-cloud hostnames. Entra stub / Okta fail-at / generic cap: OVR-001. VEN-003: Duo/SiteMinder/Shibboleth OIDC + SAML Locations |
| Import | Goldens + XXE reject |
| REST contract | OpenAPI / handler goldens |
| MCP | Protocol 2026-07-28, allowLegacyClients matrix, official SDK |
| Parity | Same inputs → same domain results on REST and MCP |
| Race | Snapshot swap vs authorize; pause-token vs JWKS |
| Fuzz | YAML decoder, SAML XML (bounded), path router |
| Container | UID 65532, read-only, cap_drop, 443:10443 publish, ready |
| Docs | Internal links, example YAML still KnownFields-valid |

## Fixture policy

- Valid minimal document is [testdata/config/valid/minimal.yaml](../testdata/config/valid/minimal.yaml). Do not put users on that file.
- File-backed TOTP is [testdata/config/valid/totp-alice.yaml](../testdata/config/valid/totp-alice.yaml) plus [testdata/secrets/users/alice.totp](../testdata/secrets/users/alice.totp).
- Unknown-field reject is [testdata/config/invalid/unknown-field.yaml](../testdata/config/invalid/unknown-field.yaml). Invalid TOTP fixtures (`totp-missing-file`, `totp-bad-base32`, `totp-newline-ref`, `unknown-totp-field`) are named in `mustReject`.
- Do not put real customer secrets in testdata.
- XXE fixtures must be inert (no network, no host-file read on pass).

## Data-plane vs SPA tests

A required regression: `spec.ui.enabled: false` returns 404 for operator SPA routes and **200** (or login HTML) for data-plane `/login` and `/consent`. Mixing these is a product defect.

Pause-token tests must show authorize, discovery, JWKS, and login still succeed.

## CI (later)

Required jobs (no bypass), when REL opens:

```text
format lint unit race fuzz-smoke generated-file documentation
security-scan container-test changelog parity config-compat
```

Do not add an empty workflow today.

Make targets, when a Makefile appears, must exist or `false`.

## Design-phase verification

For this landing, verification is:

- Required files present and non-stub.
- YAML sketches parse as YAML.
- LICENSE is Apache-2.0 with Copyright 2026 hilather.
- No `go.mod`, no server Dockerfile, no CI, no Makefile.
- No vendored agent-skills.

## Failure modes

- Tests deleted to go green: forbidden.
- Flakes hidden by broad retries: forbidden.
- Docs examples drifting from KnownFields: a defect.

## Compatibility implications

Golden discovery documents and clothed paths are compatibility surfaces. Update goldens and docs in the same change.

## Open questions

- Exact golangci-lint and govulncheck pins (copy family versions at FND-001).
- Whether Playwright appears with UI-001 (Mira reviews then).
