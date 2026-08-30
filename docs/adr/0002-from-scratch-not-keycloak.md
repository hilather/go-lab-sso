# ADR 0002: From scratch, not Keycloak (or Dex, ORY, …)

Status: Accepted for design
Date: 2026-08-30
Last reviewed: 2026-08-30

## Context

Standing up “something that looks like Entra” is often done by running Keycloak, Dex, ORY Hydra, Authelia, or Authentik and painting the login page. Those products have their own desired-state models, databases, operator UIs, and upgrade clocks. LabSSO must match the lab-appliance family: one YAML document, memory overlay, REST+MCP registry, scratch image, reset-to-file.

go-jenkins-mcp is a separate product and is never in-scope.

## Decision

Build a from-scratch Go laboratory Identity Provider. Do not wrap, embed, or sidecar Keycloak, Dex, ORY Hydra/Kratos, Authelia, Authentik, or any other IdP. Vendor similarity is **clothes** (ADR 0005), not a vendor binary.

## Consequences

- Protocol slices are sequential and smaller than “run Keycloak.”
- Snapshot/reset/parity stay consistent with LabDNS.
- We will not inherit Keycloak’s admin model, themes, or database.
- Features those products already have (full User Federation, all SAML profiles) wait for slices or stay non-goals.
- Agents get one registry instead of “shell into the IdP.”

## Alternatives considered

- Keycloak in compose plus a thin MCP adapter: fastest demo, permanent dual truth, not a family appliance.
- Dex or ORY: smaller, still a wrap with a foreign config language.
- SaaS tenant per lab: not air-gapped, not reset-to-file, hostname is the vendor.

## Review triggers

Review this decision when its assumptions no longer hold, a major protocol or library change occurs, or a new requirement conflicts with an invariant.
