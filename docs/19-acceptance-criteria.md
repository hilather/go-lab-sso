# Acceptance Criteria

Status: through VEN-003 implemented; INT-001 documented; SCIM design-only
Owners: Program, Quality
Last reviewed: 2026-09-02

## Design landing (this repository)

The design is accepted when all of the following are true on `main`:

1. `README.md` states **Status: design (not implemented)** and has no fake CI/Go/Release badges.
2. `docs/01-architecture.md` describes two planes, snapshot, issuer, ports, TLS, with mermaid.
3. Apache-2.0 `LICENSE` with appendix **Copyright 2026 hilather**.
4. Required docs, ADRs, tasks, fixtures, and compose sketch exist and are real content (not one-paragraph stubs for architecture/API).
5. `testdata/config/valid/minimal.yaml` matches the normative sketch.
6. `testdata/config/invalid/unknown-field.yaml` demonstrates KnownFields reject.
7. `examples/compose.yaml` maps `443:10443`, management loopback, UID 65532 (runnable).
8. No `go.mod`, no server Dockerfile, no CI, no Makefile, no vendored agent-skills.
9. Sweep-1 blockers are folded into [skeptic-notes.md](skeptic-notes.md) and the ADRs. Sweep 2 (2026-08-30) is **ACCEPT**.
10. Repo description and topics are set on GitHub (human admin if the landing agent’s token cannot `gh repo edit`).

## M1 foundation (FND-001) — implemented

- `labsso validate|canonicalize|serve|healthcheck|version` exist.
- Unknown YAML fields reject.
- Process never writes bootstrap.
- Scratch image, UID 65532, read-only, cap_drop ALL.
- Compose publishes `443:10443` ([examples/compose.yaml](../examples/compose.yaml)). Container tests use an ephemeral host port mapped to `:10443` and still assert the compose file publishes `443:10443`.
- REST `/v1` and MCP `/mcp` share one registry. MCP is not a REST proxy.
- Protocol 2026-07-28, go-sdk v1.7.0, `allowLegacyClients` honored.
- Data-plane HTTPS binds real TLS. OIDC protocol routes are 404 until OIDC-001.

## M2 browser IdP (OIDC-001 + LOGIN-001) — implemented

- Authorization code + PKCE S256 works against the exact issuer.
- Discovery `iss` matches host+port derivation (port omitted iff 443).
- Login and consent HTML work. `ui.enabled: false` does not 404 them.
- MFA modes `never` | `always` | `force-fail` behave as documented. `always` verifies RFC 6238 TOTP (file ref or overlay). After MFA, OIDC `amr`/`acr` and SAML/WS-Fed `TimeSyncToken` are set. `lab-totp` is rejected.

## Clothes (VEN-001, implemented)

- `entra` / `okta` change paths, claims extras, login cookie names, and entra token-error extras — not hostname / `iss`.
- Active clothes paths only; discovery lists only the active endpoints.
- Unimplemented (non-enum) vendor strings compile-reject. All enum clothes are implemented (VEN-003).

## Overage (OVR-001, implemented)

- Entra overage uses LabSSO Graph-shaped stub on the exact issuer; no Microsoft egress; never `graph.microsoft.com`.
- `entraGraphStub: false` + overage triggered fails the token with clothed entra error.
- Okta fails token at `oktaFailAt` (code and refresh); does not truncate.
- Generic embeds at most `genericCap` (default 200); excess omitted + audit warning.
- When `groups` is scoped, access token carries the same groups / Entra overage claims as id_token + userinfo.
- `overage:set` merges policy pointers; membership counts stay user/group apply.

## Later implementation — SAML / SPA / import / integrator

- Slice 6 (SAML-001, implemented): SP-initiated SAML + metadata; EntityID = issuer; hardened XML; lab cert from `signing.keyRef`; login pending branches OIDC vs SAML.
- Slice 7 (UI-001, implemented): SPA cookie+CSRF; no `localStorage` tokens; `ui.enabled` 404s SPA only; audit list/get; sessions expire/expire-all bound; Mira afters in `docs/22-operator-spa.md`.
- Slice 8 (IMP-001, implemented): import allow-list rewriter; unmapped parked; plan/apply only; `redirect:rewrite`.
- Slice 9 (VEN-002, implemented): remaining enum clothes + WS-Fed passive; Keycloak realm = `metadata.name`; no hostname impersonation.
- Slice 10 (VEN-003, implemented): `duo`, `siteminder`, `shibboleth` OIDC + SAML URL clothes; exact issuer; [ADR 0010](adr/0010-duo-siteminder-shibboleth-clothes.md).
- Slice 11 (SCIM-001): design-only outbound client ([docs/23-scim-outbound.md](23-scim-outbound.md)); no inbound server; no YAML/catalog until a later implementation wave.
- Slice 12 (INT-001): documented in [docs/11-deployment.md](11-deployment.md). Pin is last, in mcp-integration-lab, not from this repo.

## Cross-cutting

- Tests, docs, and CI (once present) are mandatory. Placeholders fail closed.
- Pause-token leaves the rest of the data plane up.
- Preflight 443 error names occupant-stop, extra IP, or `LABSSO_HTTPS_PORT`.
- No LabNTP bus.
- No Keycloak wrap.
- No go-jenkins-mcp scope.

## Evidence

Design evidence is this repository on `main`. Implementation evidence will live under `docs/releases/` when tags exist. Do not invent release notes now.
