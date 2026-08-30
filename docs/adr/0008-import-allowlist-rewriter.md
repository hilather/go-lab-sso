# ADR 0008: Customer config import is an allow-list rewriter

Status: Accepted for design
Date: 2026-08-30
Last reviewed: 2026-08-30

## Context

Operators have Entra app-registration manifests, Okta app JSON, SAML metadata XML, and OIDC client JSON. Those documents are not `labsso.dev/v1alpha1`. Applying KnownFields to them would reject almost every real export. Decoding them as LabSSO spec would either fail closed on unknown keys or silently accept a foreign schema into our snapshot.

XML metadata is an XXE hazard.

## Decision

Import is an **allow-list rewriter**. Each input kind maps a finite set of keys into a `labsso.dev/v1alpha1` fragment. Unknown keys are dropped or parked in `imported.unmapped`. `imported` is not LabSSO spec; it never passes KnownFields as `spec` fields.

Import is a management **plan/apply** operation (REST + MCP twins), not a silent live merge. XML is hardened: no external entities, no DTD fetch, size and expansion caps.

## Consequences

- Real vendor blobs can be ingested without pretending they are our schema.
- Operators see unmapped keys and decide whether to care.
- Implicit-flow-only apps warn; LabSSO still will not enable implicit.
- Keys stay file refs; PEMs are not inlined into the fragment.
- Tests must include XXE fixtures that fail closed.

## Alternatives considered

- KnownFields on vendor blobs: unusable on real exports.
- Store the blob verbatim and interpret at runtime: second schema, no Git review of clients.
- Silent live merge: undebuggable drift.
- Call vendor APIs to fetch config: network, credentials, not air-gapped.

## Review triggers

Review this decision when its assumptions no longer hold, a major protocol or library change occurs, or a new requirement conflicts with an invariant.
