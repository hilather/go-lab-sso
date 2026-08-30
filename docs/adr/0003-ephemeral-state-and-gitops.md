# ADR 0003: Use ephemeral runtime state with GitOps desired state

Status: Accepted for design
Date: 2026-08-30
Last reviewed: 2026-08-30

## Context

Lab deployments need easy reset and reviewable configuration. An internal durable store would create a second source of truth and complicate disaster recovery. Family appliances already load strict YAML, keep runtime in memory, and never rewrite bootstrap.

## Decision

Load one fail-closed `labsso.dev/v1alpha1` document at startup. Keep runtime overlay in **memory**. Expose revisions and drift. Never write the bootstrap file. Restart and reset reread the mounted file. No database without a future ADR. Secrets are file refs, never inline.

Sessions, authorization codes, and refresh handles are process memory and die on restart. That is intended.

## Consequences

- Restart returns to Git-controlled state.
- Runtime experiments (tunables, extra clients) are easy to discard.
- Export and deployment-repo workflows are required for durability.
- Multi-replica runtime mutation is not strongly consistent.
- SUTs must re-login after container recreate.

## Alternatives considered

- Embedded database: durable but conflicts with reset and Git ownership.
- Direct Git writes from the service: broad credentials and coupling.
- No runtime writes: safer but too restrictive for agents (tunables, import apply).
- Inline secrets in YAML: convenient and a leak.

## Review triggers

Review this decision when its assumptions no longer hold, a major protocol or library change occurs, or a new requirement conflicts with an invariant.
