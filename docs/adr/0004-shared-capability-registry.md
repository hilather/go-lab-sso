# ADR 0004: Use one capability registry for REST and MCP

Status: Accepted for design
Date: 2026-08-30
Last reviewed: 2026-08-30

## Context

Independent adapters drift in schema, defaults, authorization, errors, and audit behavior. MCP-by-proxying-REST looks simple and loses native tool schemas, resources, and a single auth decision. The family already rejected that pattern in LabDNS.

MCP protocol pin: **2026-07-28**. Official go-sdk **v1.7.0**. `allowLegacyClients: true` is required for MCPJungle and skips only the HTTP protocol-version pin.

## Decision

Declare every public application capability once and bind it to REST and MCP adapters. Generate or verify contracts and parity tests from the registry when code exists. Never implement MCP by calling REST, or REST by calling MCP.

Operator UI (later) binds the same registry. Mira reviews after the first UI implementation.

## Consequences

- Strong semantic parity.
- Shared authorization and mutation semantics.
- Registry design requires care to avoid a lowest-common-denominator API.
- Transport-specific envelopes remain in adapters.
- Health probes and browser cookie session stay `REST_ONLY_PROTOCOL`.

## Alternatives considered

- REST-first with MCP proxying HTTP: simple but loses native MCP schemas/resources and complicates auth/error mapping.
- Independent implementations: rejected due to drift risk.
- MCP-only: operators and healthchecks still need HTTP.

## Review triggers

Review this decision when its assumptions no longer hold, a major protocol or library change occurs, or a new requirement conflicts with an invariant.
