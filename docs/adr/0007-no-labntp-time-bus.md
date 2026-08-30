# ADR 0007: No LabNTP time bus

Status: Accepted for design
Date: 2026-08-30
Last reviewed: 2026-08-30

## Context

Some lab failures (Kerberos, certificate expiry, token `nbf`/`exp`) need clock skew. A previous idea was to give LabSSO a time bus shared with LabNTP so the IdP and the SUT could step together. That couples two appliances, implies privileged time control, and puts skew in the wrong place: **the SUT** must see the skewed clock for Kerberos and cert checks. The IdP minting tokens with a warped clock makes every token look “wrong” relative to unskewed SUTs, or requires every client to share the bus.

## Decision

LabSSO uses the **process clock** (`time.Now` and monotonic durations). No LabNTP time bus, no in-process virtual clock API, no `SYS_TIME`, no sidecar that steps LabSSO’s clock.

Kerberos and certificate-expiry skew reproductions belong on the SUT via LabNTP, not inside LabSSO.

## Consequences

- Token `iat`/`exp`/`nbf` follow the host clock of the LabSSO container.
- Session TTL is a Go duration from process time.
- Skew tests point LabNTP at the SUT (or the SUT’s VM), not at LabSSO.
- Agents who want “expired token” use the expire-session / mint-with-chosen-claims tunables or a short TTL in YAML, not a time bus.

## Alternatives considered

- Shared LabNTP bus into LabSSO: rejected (wrong place, privilege, coupling).
- In-process offset tunable: tempting; reopen only with an ADR if mint-with-chosen-claims is insufficient.
- Privileged container to set system time: rejected (UID 65532, cap_drop ALL).

## Review triggers

Review this decision when its assumptions no longer hold, a major protocol or library change occurs, or a new requirement conflicts with an invariant.
