# Reviewer Checklist

## Design and scope

- [ ] Change matches a tracked task (or an explicit design edit) and normative design.
- [ ] Any invariant change has an ADR.
- [ ] Scope is coherent and no hidden public behavior is introduced.
- [ ] Product decisions were not “improved”: dest-443, no LabNTP bus, clothes-not-hostnames, allow-list import, integrator last, login HTML ≠ SPA.

## Architecture

- [ ] REST/MCP adapters contain no independent business logic.
- [ ] MCP is not a REST proxy.
- [ ] Data plane uses one immutable snapshot per request.
- [ ] Candidate state is fully validated before atomic swap.
- [ ] Bootstrap file is never written.
- [ ] Third-party protocol types remain behind adapters.
- [ ] No Keycloak/Dex/ORY wrap.
- [ ] No vendor hostname impersonation.
- [ ] No LabNTP time bus.
- [ ] No go-jenkins-mcp scope.
- [ ] No vendored Origin/Cursor agent-skills.

## Protocol correctness

- [ ] Exact issuer; port omitted iff 443.
- [ ] PKCE S256; `plain` rejected.
- [ ] Redirect URIs exact match.
- [ ] Clothes change paths/claims, not `iss`.
- [ ] Data-plane login/consent/MFA HTML distinct from operator SPA.
- [ ] `spec.ui.enabled: false` 404s SPA only.

## Security

- [ ] Authentication, authorization, input limits, and audit are correct.
- [ ] Secrets are file refs; absent from export/diffs/logs.
- [ ] Import XML hardened (no XXE).
- [ ] Management is not on 443.
- [ ] New TLS leaf guidance preserved (`secrets/labsso-tls`).
- [ ] Operator tokens never in `localStorage`.

## Tests (once code exists)

- [ ] Every changed area has regression coverage.
- [ ] Bug fixes include a failing-before/passing-after test where practical.
- [ ] Negative, race, fuzz, leak, integration, parity, and compatibility tests are present as appropriate.
- [ ] No test was weakened to make CI pass.
- [ ] Any CI failure was fixed and hardened.

## Documentation and release

- [ ] All affected documentation is current.
- [ ] Examples and fixtures match KnownFields rules.
- [ ] Compatibility and migration impact is documented.
- [ ] Unreleased notes describe externally visible behavior (or design-only).
- [ ] Status remains design until implementation is explicitly opened.
- [ ] No fake CI/Go/Release badges; no server Dockerfile without a module; no failing CI; no Makefile no-ops.

## Completion

- [ ] Design-only changes have no `go.mod` / server image / CI.
- [ ] Handoff is complete.
