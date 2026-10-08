# Testing Strategy

Status: through VEN-003 tests implemented; SCIM design-only
Owners: Quality, Application, Protocols
Last reviewed: 2026-10-03
Related ADRs: 0001, 0004

## Problem statement

Protocol mistakes become “the lab does not look like the customer.” Tests must cover YAML fail-closed behavior, snapshot swaps, OIDC/PKCE, login HTML vs SPA, vendor clothes (issuer stability), overage, import hardening, REST/MCP parity, and container dest-443.

## Goals

- Mandatory tests: unit, race, protocol, parity, config-compat, docs, container, changelog.
- Bug fixes start with a failing test.
- Placeholders fail closed.
- CI runs all implemented required checks; no failing gate may be bypassed.

## Non-goals

- Claiming exhaustive external protocol conformance.
- Claiming coverage for unimplemented code.
- Vendoring huge protocol suites as git submodules.

## Layers

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

## CI

Required jobs (no bypass):

```text
format lint unit race fuzz-smoke generated integration documentation
security-scan container-test changelog parity config-compat
```

The workflow pins action revisions and Go 1.26.8. Docker-dependent checks remain mandatory in CI.

All required Make targets execute real checks.

## Historical design-phase verification

The original design landing used the following checks; implementation now uses the CI graph above:

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

- Tool pins are declared in Makefile and CI.
- Whether Playwright appears with UI-001 (Mira reviews then).

## Implemented hardening checks

`make test-integration` starts actual TLS and management listeners on ephemeral loopback ports. It verifies OIDC discovery with management disabled, new TLS handshakes after certificate apply, failed TLS apply retaining the active snapshot, readiness/shutdown behavior, listener-error cleanup, and forced closure of stalled connections after the grace deadline. Tests never bind host 443.

`make test-fuzz-smoke` fuzzes strict YAML decoding (without resolving fuzzed secret paths), SAML metadata XML, and SAML AuthnRequest XML for two seconds each with two workers. `make generate` builds config schema and capability/MCP binding artifacts from source; `make verify-generated` compares regenerated temporary output. `make test-docs` checks repository-local Markdown links, YAML fence syntax, full documented config compilation, and valid fixture compilation without network access.

The container gate verifies UID/capabilities/read-only root plus real TLS OIDC discovery, public JWKS, login HTML, management readiness, and the compose dest-443 publish contract. External full OIDC/SAML certification and live vendor RP interoperability are not claimed.

QA follow-up regressions cover retrying a refresh token after rejected scope widening or a failure while issuing (force-fail tunable with its `force-fail` description, Okta overage, Entra stub-off overage, signer error) or a paused token endpoint (`503 temporarily_unavailable`), the `force-fail` description on code exchange for both the tunable and the MFA mode, the Entra `error_codes` value 90033 for paused and injected `temporarily_unavailable`, loss of the grant for revoked users and client scopes, a stale snapshot not consuming a newer grant, successful scope narrowing and rotation, and concurrent single-use redemption. Deterministic password-verifier tests cover unknown/disabled users and mixed plaintext/Argon2id configurations without wall-clock timing assertions. Logout HTTP tests cover direct logout by a valid `id_token_hint` across vendor clothes, confirmation fallback for missing, mismatched, forged, expired, wrong-issuer, unregistered-audience, and access-token hints, side-effect-free unhinted GET and HEAD, invalid redirects, protected confirmation, and cross-site or forged POST rejection.
