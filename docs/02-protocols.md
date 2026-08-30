# Protocols

Status: design (not implemented)
Owners: Protocols, Application
Last reviewed: 2026-08-30
Related ADRs: 0002, 0005, 0009

## Problem statement

SUTs and browsers speak standard SSO protocols at an IdP. LabSSO must implement enough of those protocols that a lab looks like a customer deployment, without implementing every vendor extension on day one and without impersonating vendor hostnames.

Protocols land as **sequential slices**. Do not start SAML before OIDC works. Do not start vendor clothes before generic OIDC plus data-plane login HTML exist.

## Goals

- OIDC/OAuth2 authorization code + PKCE as the first protocol slice after repo foundation.
- Discovery, JWKS, `id_token`, `access_token`, and refresh under generic clothes.
- Required data-plane login + consent + MFA HTML (MFA knobs: `never` | `always` | `force-fail`; TOTP stub later).
- SAML 2.0 SP-initiated SSO + IdP metadata after group overage.
- WS-Fed later, with ADFS clothes.
- Vendor clothes change paths, claims, cookies, and errors — not the protocol state machine.

## Non-goals

- Being a certified production OpenID Provider or SAML IdP for the public Internet.
- Implementing every Entra / Okta / Ping proprietary API on the data plane.
- Real Microsoft Graph. Group overage uses a **minimal Graph-shaped stub served by LabSSO**.
- LDAP bind in v1.
- SCIM inbound server (outbound client is a later slice).
- SAML IdP-initiated SSO in the first SAML slice (SP-initiated only).
- Full WS-Federation feature parity in v1.

## Slice order (normative)

1. Repo foundation + YAML schema + snapshot/plan/apply + REST+MCP registry + CLI `validate|canonicalize|serve` + scratch image + example compose mapping 443:10443.
2. OIDC/OAuth2 authorization code + PKCE + discovery + JWKS + id_token/access_token + refresh (generic clothes).
3. Data-plane login + consent HTML (required; distinct from operator SPA). MFA knobs: `never` | `always` | `force-fail` (TOTP stub later).
4. Vendor clothes: `entra`, `okta` (paths, claims `oid`/`tid`/`ver` vs Okta groups, cookies, error dialect).
5. Group overage: Entra `_claim_names` / `_claim_sources` + minimal Graph-shaped stub; Okta fail-the-token after 100 groups (configurable); generic embed groups with a safety cap.
6. SAML 2.0 SP-initiated SSO + IdP metadata.
7. Operator SPA with REST+MCP+UI parity (Mira reviews after first UI implementation — do not build UI now).
8. Customer-config import (allow-list rewriter).
9. More vendor clothes: ping, adfs, google, keycloak, iam-identity-center. WS-Fed with ADFS clothes.
10. SCIM outbound client (later).
11. Integrator last in mcp-integration-lab.

Default ship: `spec.protocols.oidc.enabled: true`. SAML and WS-Fed default **false**.

## OIDC / OAuth 2.0

### Flows

First implementation implements:

| Flow | Status |
|---|---|
| Authorization code | Required |
| PKCE (RFC 7636), S256 | Required; plain rejected |
| Refresh token | Required |
| Discovery (`/.well-known/openid-configuration` plus vendor path clothes) | Required |
| JWKS | Required |
| UserInfo | Required |
| RP-initiated logout | Required (generic path; vendor path clothes later) |
| Client credentials | Out of first OIDC slice |
| Device code | Out of first OIDC slice |
| Implicit / hybrid | Reject |

Confidential clients authenticate at the token endpoint with a secret file ref. Public clients must use PKCE and must not present a secret.

### Tokens

- `id_token` and `access_token` are JWTs signed with keys from file refs.
- `iss` is the exact issuer string. No vendor-cloud issuer alias.
- Generic clothes use standard OIDC claims (`sub`, `aud`, `exp`, `iat`, `nonce`, `email`, `groups` when in scope).
- Entra clothes add `oid`, `tid`, `ver` and Entra-shaped group overage. They do not change `iss` to a Microsoft tenant URL.
- Okta clothes add Okta-shaped `groups` handling and fail-closed overage.
- Refresh tokens are opaque handles in process memory, not JWTs, in the first slice. Restart invalidates them.

### Endpoints (generic clothes)

Exact paths are clothes. Generic defaults:

```text
GET  {issuer}/.well-known/openid-configuration
GET  {issuer}/oauth2/authorize
POST {issuer}/oauth2/token
GET  {issuer}/oauth2/jwks
GET  {issuer}/oauth2/userinfo
GET  {issuer}/oauth2/logout
GET  {issuer}/login          (HTML)
POST {issuer}/login
GET  {issuer}/consent        (HTML)
POST {issuer}/consent
```

Vendor clothes replace the path templates. See [docs/03-vendor-profiles.md](03-vendor-profiles.md).

Discovery document `issuer` is always the exact issuer. `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `userinfo_endpoint`, and `end_session_endpoint` use the clothed paths on that issuer.

### PKCE

- `code_challenge_method=S256` required.
- `plain` rejected.
- Token request must present `code_verifier`. Mismatch is `invalid_grant` in the active error dialect.

### Redirect URIs

Clients list exact redirect URIs. No wildcard in v1. An agent tunable may rewrite a client redirect URI through plan/apply (management), not by silently accepting an extra URI on the authorize request.

### Error dialect

Generic clothes use RFC 6749 JSON (`error`, `error_description`). Vendor clothes may reshape field names and HTML error pages. Domain error codes in the management plane stay family-stable (`invalid_client`, `invalid_grant`, `access_denied`, …) and map to the clothed data-plane JSON.

## Login, consent, MFA

Required. Distinct from the operator SPA. See [ADR 0009](adr/0009-data-plane-login-ui.md).

- Login HTML collects username + password against `spec.users` (password file ref / PHC).
- Consent HTML is shown when the client is not pre-consented or when the `force-consent` tunable is on.
- MFA mode: `never` | `always` | `force-fail`. `always` challenges; TOTP verification is a stub in the first UI slice (accept a documented lab code or fail closed per fixture). `force-fail` always fails the MFA step so agents can reproduce locked-out users.
- `spec.ui.enabled: false` does **not** 404 these pages.

## SAML 2.0 (slice 6)

SP-initiated SSO:

- IdP metadata at a clothed path on the exact issuer (EntityID = issuer unless a later ADR says otherwise).
- `AuthnRequest` via HTTP-Redirect or HTTP-POST.
- Response via HTTP-POST with a signed assertion.
- Attribute maps follow the active vendor clothes (generic: `uid`, `mail`, `groups`).
- Hardened XML: no external entities, no DTD fetch, bounded size.

Out of the first SAML slice: IdP-initiated SSO, ECP, full artifact binding, metadata signing-key rollover UX beyond file refs.

## WS-Fed (slice 9)

WS-Federation passive profile with **ADFS clothes**. Same issuer. Not a second product. Land after ADFS path/claim clothes exist.

## Group overage (slice 5)

| Clothes | Behavior |
|---|---|
| `generic` | Embed `groups` in the token up to a safety cap. Excess groups are omitted and a warning is audited. |
| `entra` | Emit `_claim_names` / `_claim_sources` pointing at a **minimal Graph-shaped stub served by LabSSO** (not real Microsoft Graph). `entraGraphStub: true` in the YAML sketch. |
| `okta` | Fail the token request after `oktaFailAt` groups (default 100). |

The Graph stub is LabSSO data-plane HTTP on the same issuer, Graph-shaped paths only as far as group-overage clients need. It is not a Graph implementation.

## Agent tunables (document; do not implement in this landing)

These are management operations that affect the data plane. They go through the registry (plan/apply or dedicated capabilities with the same mutation contract):

| Tunable | Data-plane effect |
|---|---|
| Force auth fail | Authorize / login fails with a chosen error |
| Force consent | Consent page always shown |
| Expire session | Session and associated codes die |
| Mint token with chosen claims | Issue a token that carries operator-chosen claims (scoped; audited) |
| Set group overage | Flip overage policy / membership counts |
| Rewrite a client redirect URI | Canonical client change |
| Swap vendor clothes | `spec.profile.vendor` change; paths and claims update on next snapshot |
| Inject a specific error code/status | Next matching request returns that clothed error |
| Pause token endpoint | `/token` waits or 503s; authorize, JWKS, discovery, login stay up |

## Failure modes

- Unknown client_id: clothed `unauthorized_client` / SAML responder error. Do not leak other client IDs.
- PKCE mismatch: `invalid_grant`.
- Disabled protocol (`saml.enabled: false`): 404 or clothed “not supported”, not a hang.
- Signing key missing: compile fails; process does not listen.
- Clock step on the host: tokens follow the process clock; do not invent a bus.

## Testing strategy

- Authorization-code + PKCE happy path and negative matrix.
- Discovery document `iss` equals exact issuer under every vendor.
- JWKS serves only the compiled public keys.
- Refresh rotation and restart-drop.
- Login / consent HTML distinct from SPA 404 when `ui.enabled: false`.
- Overage: Entra stub vs Okta fail-at vs generic cap.
- SAML: hardened XML rejects external entities.

## Compatibility implications

Enabling a protocol, renaming a generic path, or changing `iss` derivation is a compatibility event. Vendor clothes identifiers (`generic`, `entra`, `okta`, …) are a public enum.

## Open questions

- Whether `id_token` encryption is ever needed in lab (default: unsigned request objects, signed tokens only).
- UserInfo vs token group placement per vendor beyond the clothes table.
- SAML EntityID exactly equal to issuer (sweep 2: **yes**; a later ADR would be required to change it).
