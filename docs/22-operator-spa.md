# Operator SPA (UI-001)

Status: first SPA implemented; Mira afters landed (sessions / users / data-plane login chrome)
Owners: UI, Application
Last reviewed: 2026-09-02
Related ADRs: 0004

## Surface

- `GET /` and `GET /app.js` from `internal/web`. The package must not import `internal/app`.
- `spec.ui.enabled: false` 404s the SPA only (`GET /`). Login HTML and REST stay up. `/app.js` is not separately gated.
- Cookie `labsso_session` (HttpOnly, SameSite=Lax). CSRF token in session JSON + header `X-LabSSO-CSRF`.
- Bearer still wins. CSRF is required on non-GET when the actor is the cookie.
- MCP strips cookies.

## Chrome (Mira afters, Matt-approved)

Lab* family shell: 56px masthead, 196px rail (IDENTITY: Sessions, Users, Groups, Clients / LAB: Status, Audit), IBM Plex via Google Fonts CSS CDN (not a JS loader). Structured work is **sessions** and **users**. Groups, clients, status, and audit inherit the shell and keep leftover JSON bodies.

Masthead binds existing reads: issuer from `GET /v1/status`, ready chip from `GET /v1/health/ready`, actor from `GET /v1/session` (`actorId · actorClass`), MFA mode from `GET /v1/state` `canonical.spec.auth.mfa.mode`. Sign out is `DELETE /v1/session`. A loopback cookie is minted **once** via `POST /v1/session`; Sign out does not remint.

Sessions list+inspector paints **LoginSession only**: `ID`, `UserID`, `Username`, `Expires`, `MFACompleted` (Go default JSON names). Expire binds existing `POST /v1/sessions/{id}:expire` and `POST /v1/sessions:expire-all`. No `expectedRevision` (REST does not take it). Do not paint `clientId`, `protocol`, `issued`, or `scope` until `GET /v1/sessions` returns them.

Users list+inspector paints `UserView`: `id`, `username`, `totp.configured`, `totp.source`, `totpSecretRef` (path), `passwordRef`, `groupIds`. Mutations stay `POST /v1/auth/mfa`, `POST /v1/users/{id}/totp:enroll`, `POST /v1/users/{id}/totp:clear`. Enroll seed is `lastEnroll` page memory, shown once, dismissible.

Data-plane `/login` and `/consent` are a lab IdP card (generic clothes: LabSSO / Sign in), not the operator rail. Consent stays Allow/Deny.

This change implements approved chrome. It is not a first-UI without Mira review.

## First-implementation Mira checklist

Recorded so Mira can review the first SPA without hunting:

1. No `localStorage` / `sessionStorage` / IndexedDB / URL tokens (`internal/web/web_test.go`).
2. Cookie + CSRF contract (`TestCookieCSRFAndSPA`).
3. `ui.enabled` matrix (`GET /` 200 vs 404).
4. REST/MCP parity still holds for management tools (`make test-parity`).
5. SPA binds existing capabilities only (status, clients, users, groups, sessions, audit, plus Users-view `mfa:set` / `totp:enroll` / `totp:clear`, plus Sessions-view `session.expire` / `sessions.expire_all`). No independent business logic in JS. Enroll seed is shown once in page memory; never `localStorage` / `sessionStorage` / IndexedDB / the URL.
6. Login HTML remains `/login` `/consent` on the data plane.

Mira reviewed the afters before this chrome landing. Blockers remain (1)–(5) failing, not a second visual pass.
