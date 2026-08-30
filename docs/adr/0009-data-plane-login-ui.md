# ADR 0009: Data-plane login UI is required and distinct from the operator SPA

Status: Accepted for design
Date: 2026-08-30
Last reviewed: 2026-08-30

## Context

An IdP without a login page is not an IdP. Authorization-code flows need HTML for login, consent, and MFA. The family also has an **operator SPA** on the management listener (LabDNS) that uses cookie + CSRF and never `localStorage` for tokens. Those two UIs serve different users on different listeners.

`spec.ui.enabled: false` in LabDNS 404s the operator SPA only. Copying that flag onto login pages would break every browser SUT when an operator hid the console.

Mira reviews the operator SPA after the first UI implementation. This design landing does not build either UI.

## Decision

Data-plane login + consent + MFA HTML is **required** (slice 3) and is served on the HTTPS issuer listener. It is not the operator SPA.

MFA knobs: `never` | `always` | `force-fail`. TOTP stub later.

`spec.ui.enabled: false` 404s the operator SPA only. It does not disable data-plane login pages.

Operator SPA (slice 7) uses cookie + CSRF, never `localStorage` for tokens, and binds the capability registry. Mira reviews after first UI implementation.

## Consequences

- Slice 2 (OIDC) is incomplete until slice 3 (login HTML) exists for browser SUTs. Resource-owner-free automation can still use a later documented lab grant only if an ADR adds one; v1 assumes HTML login.
- Two HTML stacks: loginui vs web/. Do not share session cookies across planes.
- Tests must prove `ui.enabled: false` leaves `/login` up.
- No UI work in this design landing.

## Alternatives considered

- Headless-only IdP (device code / client credentials): does not look like customer SSO for browser SUTs.
- Reuse the operator SPA for login: wrong authn, wrong listener, `ui.enabled` footgun.
- Redirect login to a vendor-hosted page: hostname impersonation (ADR 0005).

## Review triggers

Review this decision when its assumptions no longer hold, a major protocol or library change occurs, or a new requirement conflicts with an invariant.
