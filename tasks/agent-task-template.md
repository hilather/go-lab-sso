# TASK-ID: Task Title

Status: not-started
Recommended owner: Agent type
Dependencies: List task IDs
Exclusive ownership: Packages/files owned by this task

## Goal

State one measurable outcome.

## Design references

- [ ] `AGENTS.md`
- [ ] `docs/01-architecture.md`
- [ ] Relevant architecture documents
- [ ] Relevant ADRs

## Scope

- [ ] Work item
- [ ] Work item

## Explicit non-scope

- Keycloak wrap
- Hostname impersonation
- LabNTP time bus
- Integrator pin (unless this is INT-001)
- Operator SPA (unless this is UI-001)
- go-jenkins-mcp
- Item

## Required tests

- [ ] Unit tests
- [ ] Regression tests for every changed behavior
- [ ] Negative tests
- [ ] Integration/protocol tests where applicable
- [ ] Race/leak/fuzz tests where applicable
- [ ] REST/MCP parity tests where applicable
- [ ] Documentation example tests
- [ ] `ui.enabled: false` does not 404 data-plane login (if HTML touched)

## Security and safety review

- [ ] Authentication/authorization impact reviewed
- [ ] Input and resource limits reviewed
- [ ] Secret/privacy impact reviewed (file refs only)
- [ ] Import XXE reviewed if applicable
- [ ] Dest-443 / management-port split preserved

## Documentation updates

- [ ] Normative design
- [ ] API/config reference
- [ ] Operations/runbooks
- [ ] ADR if invariant changes
- [ ] Unreleased changelog/release-note entry

## CI requirements

- [ ] All relevant local CI-equivalent commands pass (once they exist)
- [ ] No skipped or weakened test
- [ ] Generated files are current
- [ ] Missing Make targets `false`, not no-op
- [ ] CI failure, if encountered, was fixed and hardened

## Acceptance criteria

- Criterion
- Criterion

## Handoff

```text
Task ID:
Commit/PR:
Packages changed:
Tests added:
Commands run:
Compatibility impact:
Security impact:
Docs updated:
Release-note entry:
Known limitations:
```
