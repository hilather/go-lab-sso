# ADR 0011: File-ref TOTP replaces the lab-totp stub

Status: Accepted
Date: 2026-09-01
Last reviewed: 2026-09-01

## Context

[ADR 0009](0009-data-plane-login-ui.md) required MFA HTML and knobs `never` | `always` | `force-fail`, with TOTP verification as a later stub. LOGIN-001 shipped a shared literal `lab-totp`. That is not RFC 6238, does not survive Git as a per-user secret, and cannot be enrolled from REST, the operator SPA, or MCP without writing files.

The process must not write bootstrap YAML or secret files ([ADR 0003](0003-ephemeral-state-and-gitops.md)). Secrets stay file refs. Login HTML stays first-party. Duo Auth API remains out ([ADR 0010](0010-duo-siteminder-shibboleth-clothes.md)). No LabNTP ([ADR 0007](0007-no-labntp-time-bus.md)).

## Decision

Replace the stub with RFC 6238 TOTP (SHA-1, 30s, 6 digits, process clock, ±1 step).

- Durable: optional `users[].totpSecretRef` (base32 file). `spec.auth.mfa.mode` is unchanged.
- Ephemeral enroll/rotate/clear: in-memory overlay on `oidc.Runtime`. Restart and `state:reset` drop it. The process never writes `.totp` files.
- Typed management: `sso.auth.mfa.set`, `sso.user.totp.enroll`, `sso.user.totp.clear` over one `App` path. REST, MCP, and the operator SPA are adapters.
- `lab-totp` is rejected. Missing seed + `always` fail-closed at login.
- After MFA, OIDC emits `amr`/`acr`; SAML/WS-Fed emit `TimeSyncToken`. Password-only omits `amr`/`acr`. The MFA flag is copied onto auth codes, refresh rows, consent, and cookie-reuse — not only `LoginSession`.

## Consequences

- Local `dev-loopback-unauth` can enroll without editing Git. Restart-safe MFA needs a file ref.
- Enroll is not idempotent; a retry rotates the seed.
- Overlay seeds must not appear in export, audit, MCP resources, or logs.
- Token mint remains a password-only lab bypass.

## Alternatives considered

- Inline `totpSecret` on apply: rejected (file-ref invariant).
- Writing secret files from the process: rejected (ADR 0003).
- Keeping `lab-totp` as a backdoor: rejected.
- Duo Auth API / WebAuthn / LabMail OTP: rejected (scope and invariants).

## Review triggers

Review when enroll needs durability across restart without a file ref, when `acr_values` step-up is added, or when a second factor other than TOTP is required.
