# SCIM outbound client (SCIM-001)

Status: **design-only**. Not implemented. May trail M6 / INT-001.
Owners: Protocols, Application
Last reviewed: 2026-08-30
Related ADRs: none yet (no persistence or outbound-auth invariant is frozen here)

## Problem statement

Some SUTs expect a directory to **push** users and groups to them over SCIM. LabSSO already has an in-process membership source of truth (`user.groupIds`). An outbound client could replay that desired state to a lab SCIM endpoint the operator points at.

This slice is **underspecified** on purpose. Do not invent SCIM YAML fields or capability catalog rows until a later implementation wave accepts a tighter design.

## Goals

- Outbound SCIM **client** only.
- Push users and groups that already exist on the compiled snapshot.
- Stay on the exact lab issuer for any callback URLs we emit (none required at design time).
- Fail closed on secrets: file refs, never inline tokens in YAML, logs, diffs, MCP resources, or audit payloads.

## Non-goals

- **No inbound SCIM server.** LabSSO is not a SCIM service provider in v1.
- No Microsoft Graph / Okta Users API wrap.
- No persistence mechanism (database, journal, hidden volume) without an approved ADR.
- No new catalog IDs, REST paths, or MCP tools in this design landing.
- No `spec.scim` (or similar) YAML in `labsso.dev/v1alpha1` until an implementation wave + tests.

## Sequence

SCIM-001 **trails the integrator pin**. INT-001 is last in `hilather/mcp-integration-lab` and is not built from this repo. A SCIM client that needs a sibling lab service should wait until that pin exists, or be exercised standalone against a disposable SCIM stub.

## Open questions (do not invent answers in code)

1. **Trigger.** Snapshot swap? Explicit `scim:push` tunable? Both?
2. **Target.** How does the operator name the SCIM base URL without a new YAML object?
3. **Outbound auth.** Bearer file ref vs mutual TLS vs none. If the client must store a refreshable token across restarts, that is a persistence invariant and needs an ADR.
4. **Filter.** Which users/groups are in scope? All snapshot identities, or a later allow-list?
5. **Conflict.** Remote SCIM state vs LabSSO SoT. LabSSO must remain the membership source of truth (`user.groupIds`).
6. **Deletes.** Does a reset/remove emit SCIM DELETE, or only PUT/PATCH of remaining members?

## Implementation gate

A later wave may implement this document only after:

- The questions above are answered in this file (or an ADR if an invariant appears).
- Tests cover happy path, auth failure, and “inbound SCIM stays 404.”
- REST/MCP adapters (if any) bind the shared registry; no independent handler logic.

Until then, treat any SCIM YAML, catalog row, or HTTP route as a defect.
