# Contributing

## Status

This repository has **opened implementation at FND-001**. Contributions may add Go under `internal/` and `cmd/labsso` for the current slice. Do not open a PR that adds OIDC, login HTML, SPA, import, or integrator wiring before those slices. Missing Make targets must `false`. Do not add CI until Wave 5.

When implementation is opened:

- Toolchain: **Go 1.26** (`go1.26.x`). Module path `github.com/hilather/go-lab-sso`. Binary `labsso`.
- MCP: protocol **2026-07-28**, official `github.com/modelcontextprotocol/go-sdk` **v1.7.0**.
- Operator console (later slice): Node pin will be documented then. Mira reviews after the first UI implementation.
- Missing Make targets must `false`, not no-op.

## Development workflow (design)

1. Choose a tracked design edit or program-board row.
2. Read the normative documents and relevant ADRs.
3. Change the smallest coherent set of documents.
4. Keep YAML sketches and invalid fixtures consistent with `docs/04-state-and-configuration.md`.
5. Do not “improve” the product decisions in the README and ADRs (dest-443, no LabNTP bus, clothes-not-hostnames, allow-list import, integrator last).

## Development workflow (later implementation)

1. Choose or create a tracked task whose dependencies are complete.
2. Read the normative design documents and relevant ADRs.
3. Add or update tests that express the intended behavior.
4. Implement the smallest coherent change.
5. Update all affected documentation.
6. Run local CI-equivalent targets.
7. Submit a reviewable pull request with risk, test, compatibility, and release-note information.

## Pull request requirements

Every pull request must state:

- Problem and intended outcome.
- Scope and explicit non-scope.
- Architectural invariants touched.
- Security and abuse considerations.
- Test evidence (or “docs-only; no runtime tests”).
- REST/MCP parity impact (or “design-only”).
- Configuration and compatibility impact.
- Documentation changed.
- Release-note entry or explicit reason that no externally observable behavior changed.
- Rollback strategy.

## Change sizing

Prefer small vertical slices. Do not merge partial public APIs, undocumented schema fields, or disabled tests as placeholders. Feature flags may be used only when their ownership, default, removal plan, and test matrix are documented.

## Commit and review discipline

- Do not mix broad refactors with protocol changes unless necessary.
- Require review from owners of protocols, API/MCP parity, security, and deployment when those areas change.
- Resolve review findings in documents (and later code/tests) rather than only in comments.
- Sign design landings as Keystone when acting in that role.

## Backward compatibility

Public REST paths, MCP tool schemas, configuration versions, issuer derivation, and vendor-clothes identifiers are compatibility surfaces once implementation exists. Breaking a documented invariant requires an ADR.
