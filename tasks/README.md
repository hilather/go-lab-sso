# Agent Task Plan

Status: design (not implemented)
Last reviewed: 2026-08-30

This directory divides the LabSSO program into reviewable work packages. Task files are implementation contracts, not substitutes for normative design documents. **Implementation is not scheduled.** All slices are `not-started`.

Do not start coding from this directory while the repository is design-only. Do not add `go.mod` to “get a head start.”

## Working rules

- Read `../AGENTS.md` before taking a task.
- Do not start a task whose required dependencies are incomplete.
- Do not implement REST, MCP, OIDC, or YAML decode from a summary when a normative document exists.
- Add regression tests for every behavior changed (once code exists).
- Update all affected documentation in the same change.
- All required CI must pass once CI exists. If CI fails, fix and harden it; do not bypass it.
- Placeholders fail closed. Makefile targets that do not exist must `false`.
- Do not vendor Origin/Cursor agent-skills.
- Integrator work is last and lives in `hilather/mcp-integration-lab`, not here.

## Task statuses

```text
not-started
in-progress
blocked
in-review
done
```

Update `00-program-board.md` rather than creating conflicting status edits.

## Required task output (when implementation opens)

Each task produces:

- Code and configuration changes.
- Unit and regression tests.
- Integration or protocol tests where applicable.
- Updated documentation.
- Updated generated contracts where applicable.
- Release-note entry.
- A handoff note listing public surfaces, risks, and follow-on work.

## Completion evidence

```text
Task ID
Commit or pull request
Design documents read
Files/packages changed
Tests added
Commands run and results
Generated artifacts changed
Compatibility impact
Security impact
Documentation updated
Release-note entry
Known limitations or follow-ups
```

## Program order

Start with `00-program-board.md`. Slices are sequential. Do not open SAML before OIDC+login. Do not open the integrator pin before the appliance exists. Mira reviews the operator SPA after the first UI implementation — do not build UI in this design landing.
