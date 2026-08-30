# Operator SPA (UI-001)

Status: first SPA implemented; **Mira review requested**
Owners: UI, Application
Last reviewed: 2026-08-30
Related ADRs: 0004

## Surface

- `GET /` and `GET /app.js` from `internal/web`. The package must not import `internal/app`.
- `spec.ui.enabled: false` 404s the SPA only. Login HTML and REST stay up.
- Cookie `labsso_session` (HttpOnly, SameSite=Lax). CSRF token in session JSON + header `X-LabSSO-CSRF`.
- Bearer still wins. CSRF is required on non-GET when the actor is the cookie.
- MCP strips cookies.

## First-implementation Mira checklist

Recorded so Mira can review the first SPA without hunting:

1. No `localStorage` / `sessionStorage` / IndexedDB / URL tokens (`internal/web/web_test.go`).
2. Cookie + CSRF contract (`TestCookieCSRFAndSPA`).
3. `ui.enabled` matrix (`GET /` 200 vs 404).
4. REST/MCP parity still holds for management tools (`make test-parity`).
5. SPA binds existing capabilities only (status, clients, users, groups, sessions, audit). No independent business logic in JS.
6. Login HTML remains `/login` `/consent` on the data plane.

Mira: mark this document reviewed after the first visual pass. Blockers are (1)–(5) failing, not chrome.
