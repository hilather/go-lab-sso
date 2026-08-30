# Acceptance Criteria

Status: design (not implemented)
Owners: Program, Quality
Last reviewed: 2026-08-30

## Design landing (this repository)

The design is accepted when all of the following are true on `main`:

1. `README.md` states **Status: design (not implemented)** and has no fake CI/Go/Release badges.
2. `docs/01-architecture.md` describes two planes, snapshot, issuer, ports, TLS, with mermaid.
3. Apache-2.0 `LICENSE` with appendix **Copyright 2026 hilather**.
4. Required docs, ADRs, tasks, fixtures, and compose sketch exist and are real content (not one-paragraph stubs for architecture/API).
5. `testdata/config/valid/minimal.yaml` matches the normative sketch.
6. `testdata/config/invalid/unknown-field.yaml` demonstrates KnownFields reject.
7. `examples/compose.sketch.yaml` maps `443:10443`, management loopback, UID 65532, and is marked NOT runnable.
8. No `go.mod`, no server Dockerfile, no CI, no Makefile, no vendored agent-skills.
9. Sweep-1 blockers are folded into [skeptic-notes.md](skeptic-notes.md) and the ADRs.
10. Repo description and topics are set on GitHub.

## Later implementation — foundation (slice 1)

- `labsso validate|canonicalize|serve` exist.
- Unknown YAML fields reject.
- Process never writes bootstrap.
- Scratch image, UID 65532, read-only, cap_drop ALL.
- Compose can publish `443:10443`.
- REST `/v1` and MCP `/mcp` share one registry. MCP is not a REST proxy.
- Protocol 2026-07-28, go-sdk v1.7.0, `allowLegacyClients` honored.

## Later implementation — OIDC + login (slices 2–3)

- Authorization code + PKCE S256 works against the exact issuer.
- Discovery `iss` matches host+port derivation (port omitted iff 443).
- Login and consent HTML work. `ui.enabled: false` does not 404 them.
- MFA modes `never` | `always` | `force-fail` behave as documented.

## Later implementation — clothes and overage (slices 4–5)

- `entra` / `okta` change paths and claims, not hostname / `iss`.
- Entra overage uses LabSSO Graph-shaped stub; no Microsoft egress.
- Okta fails token at `oktaFailAt`.
- Generic embeds groups with a safety cap.

## Later implementation — SAML / SPA / import / integrator

- Slice 6: SP-initiated SAML + metadata; hardened XML.
- Slice 7: SPA parity; Mira review recorded; no `localStorage` tokens.
- Slice 8: import allow-list rewriter; unmapped parked; plan/apply only.
- Slice 11: mcp-integration-lab main compose, new `secrets/labsso-tls` leaf, labinfo `connection` block, token 0o644, `allowLegacyClients: true`.

## Cross-cutting

- Tests, docs, and CI (once present) are mandatory. Placeholders fail closed.
- Pause-token leaves the rest of the data plane up.
- Preflight 443 error names occupant-stop, extra IP, or `LABSSO_HTTPS_PORT`.
- No LabNTP bus.
- No Keycloak wrap.
- No go-jenkins-mcp scope.

## Evidence

Design evidence is this repository on `main`. Implementation evidence will live under `docs/releases/` when tags exist. Do not invent release notes now.
