# ADR 0001: Use Go for the service

Status: Accepted for design
Date: 2026-08-30
Last reviewed: 2026-08-30

## Context

LabSSO combines a latency-sensitive HTTPS data plane (authorize, token, JWKS, login HTML), concurrent session tables, HTTP management, MCP, immutable runtime state, container deployment, race testing, and fuzzing. The hilather lab-appliance family (LabDNS, LabMail, LabMITM, TacLab, LabLDAP) is already Go.

Language when implemented: **Go 1.26**. Module `github.com/hilather/go-lab-sso`. Binary `labsso`. Image `ghcr.io/hilather/labsso`.

## Decision

Implement the service in Go. Use the official MCP Go SDK (`v1.7.0`) behind an internal adapter. Prefer the standard library for HTTP, TLS, JWT/JWK where practical, and small pinned libraries only when stdlib is not enough. Hide protocol types behind adapters.

## Consequences

- A single static binary fits scratch/distroless and UID 65532.
- Go concurrency and context cancellation fit token pause, session expiry, and bounded delays.
- Race detection and fuzzing support hardening.
- Family contributors already know the snapshot/registry patterns.
- Contributors must follow Go memory, cancellation, and error-handling discipline.

## Alternatives considered

- Rust: strong safety, but higher implementation complexity and a family split.
- TypeScript or Python: productive control planes, poorer fit for a minimal static container and a dual HTTPS + MCP process.
- Java / Kotlin: mature IdP ecosystem (and a temptation to wrap Keycloak), heavier runtime. Rejected with ADR 0002.
- Wrap an existing IdP in any language: rejected in ADR 0002.

## Review triggers

Review this decision when its assumptions no longer hold, a major protocol or library change occurs, or a new requirement conflicts with an invariant.
