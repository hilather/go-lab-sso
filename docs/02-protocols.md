# Protocols

Status: through VEN-003 (OIDC + login + clothes + overage + SAML + WS-Fed)
Owners: Protocols, Application
Last reviewed: 2026-08-30
Related ADRs: 0002, 0005, 0009, 0010

## Problem statement

SUTs and browsers speak standard SSO protocols at an IdP. LabSSO must implement enough of those protocols that a lab looks like a customer deployment, without implementing every vendor extension on day one and without impersonating vendor hostnames.

Protocols land as **sequential slices**. Do not start SAML before OIDC works. Do not start vendor clothes before generic OIDC plus data-plane login HTML exist.

## Goals

- OIDC/OAuth2 authorization code + PKCE as the first protocol slice after repo foundation.
- Discovery, JWKS, `id_token`, `access_token`, and refresh under generic clothes.
- Required data-plane login + consent + MFA HTML (MFA knobs: `never` | `always` | `force-fail`; TOTP stub later).
- SAML 2.0 SP-initiated SSO + IdP metadata after group overage.
- WS-Fed passive profile with ADFS clothes (VEN-002).
- Duo / SiteMinder / Shibboleth clothes including SAML URL clothes (VEN-003).
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
10. Duo, SiteMinder, Shibboleth clothes including SAML URL clothes (VEN-003).
11. SCIM outbound client (later).
12. Integrator last in mcp-integration-lab.

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
| RP-initiated logout | Required (active clothes path). `post_logout_redirect_uri` must match a registered client redirect URI; otherwise 400. Missing URI returns a logged-out HTML page. |
| Client credentials | Out of first OIDC slice |
| Device code | Out of first OIDC slice |
| Implicit / hybrid | Reject |

Confidential clients authenticate at the token endpoint with a secret file ref. Public clients must use PKCE and must not present a secret.

### Tokens

- `id_token` and `access_token` are JWTs signed with keys from file refs.
- `iss` is the exact issuer string. No vendor-cloud issuer alias.
- Generic clothes use standard OIDC claims (`sub`, `aud`, `exp`, `iat`, `nonce`, `email`, `groups` when in scope).
- Entra clothes add `oid`, `tid`, `ver` on id_token and userinfo. They do not change `iss` to a Microsoft tenant URL. When `groups` is scoped, OVR-001 also puts `groups` or `_claim_names`/`_claim_sources` on the **access token** (same payload on id_token + userinfo).
- Okta clothes use `/oauth2/default/v1/…` paths. Token-time fail-closed group overage is OVR-001 (`count >= oktaFailAt`).
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

Vendor clothes replace the path templates. Active clothes only: inactive vendor paths 404. See [docs/03-vendor-profiles.md](03-vendor-profiles.md).

Entra (lab issuer):

```text
GET  {issuer}/oauth2/v2.0/authorize
POST {issuer}/oauth2/v2.0/token
GET  {issuer}/oauth2/v2.0/jwks
GET  {issuer}/oauth2/v2.0/userinfo
GET  {issuer}/oauth2/v2.0/logout
GET  {issuer}/{tenantId}/v2.0/.well-known/openid-configuration
```

Okta (`authServerId` clothes constant `default`):

```text
GET  {issuer}/oauth2/default/v1/authorize
POST {issuer}/oauth2/default/v1/token
GET  {issuer}/oauth2/default/v1/jwks
GET  {issuer}/oauth2/default/v1/userinfo
GET  {issuer}/oauth2/default/v1/logout
```

Login and consent stay `{issuer}/login` and `{issuer}/consent`.

Discovery document `issuer` is always the exact issuer. `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `userinfo_endpoint`, and `end_session_endpoint` use the clothed paths on that issuer.

### PKCE

- `code_challenge_method=S256` required.
- `plain` rejected.
- Token request must present `code_verifier`. Mismatch is `invalid_grant` in the active error dialect.

### Redirect URIs

Clients list exact redirect URIs. No wildcard in v1. An agent tunable may rewrite a client redirect URI through plan/apply (management), not by silently accepting an extra URI on the authorize request.

### Error dialect

Authorize redirect errors stay RFC 6749 query params (`error`, `error_description`) for every vendor. Token JSON is RFC 6749 (`error`, `error_description`) for generic and okta. Entra token errors add `error_codes` (array of ints) and `trace_id`. Domain error codes in the management plane stay family-stable (`invalid_client`, `invalid_grant`, `access_denied`, …).

## Login, consent, MFA

Required. Distinct from the operator SPA. See [ADR 0009](adr/0009-data-plane-login-ui.md).

- Login HTML collects username + password against `spec.users` (password file ref / PHC).
- Consent HTML is shown when the client is not pre-consented or when the `force-consent` tunable is on.
- MFA mode: `never` | `always` | `force-fail`. `always` challenges; TOTP verification is a stub in the first UI slice (accept a documented lab code or fail closed per fixture). `force-fail` always fails the MFA step so agents can reproduce locked-out users.
- `spec.ui.enabled: false` does **not** 404 these pages.

## SAML 2.0 (SAML-001)

SP-initiated SSO on the exact issuer. `saml.enabled: false` (default) 404s **all** SAML routes (generic and clothed).

- IdP metadata: `GET /saml/metadata` (generic and most clothes). EntityID = exact issuer. Duo / SiteMinder / Shibboleth clothe metadata and SSO URLs ([docs/03-vendor-profiles.md](03-vendor-profiles.md)).
- `AuthnRequest` via HTTP-Redirect (deflate+base64) or HTTP-POST (base64) at the active SSO path (`GET|POST /saml/sso` generic; Shibboleth uses distinct Redirect vs POST paths).
- Login is **not** drop-in on OIDC `CompleteLogin`. Pending records carry `Protocol` (`oidc` | `saml` | `wsfed`). Same `/login` `/consent` HTML; completion branches: OIDC → code redirect; SAML → signed assertion auto-POST to ACS; WS-Fed → `wa`/`wresult`/`wctx` auto-POST to `wreply`.
- Response via HTTP-POST with a signed assertion (`goxmldsig` enveloped signature on XML **we generate**; hostile-input dsig is not hand-rolled).
- Generic attributes: `uid`, `mail`, `groups`.
- SP identity: `spec.clients[].saml.entityID`. ACS: `spec.clients[].saml.acsURLs`; empty ACS → `redirectURIs`.
- Signing cert: compiler synthesizes a **lab self-signed X.509** from `signing.keyRef` onto the snapshot. Not a second secret. Lab-only. SAML or WS-Fed enabled requires an **RSA** `signing.keyRef` at compile (OIDC may still use ECDSA when both are off).
- Hardened XML: no DOCTYPE / ENTITY, size cap 64KiB.

Out of this slice: IdP-initiated SSO, ECP, full artifact binding, metadata signing-key rollover UX beyond file refs.

## WS-Fed (VEN-002)

WS-Federation **passive** sign-in on the exact issuer. Not a second product. Reuses the SAML lab self-signed cert. `wsfed.enabled: false` (default) 404s WS-Fed routes.

- Metadata: `GET /wsfed/metadata` (generic) or ADFS clothes `GET /FederationMetadata/2007-06/FederationMetadata.xml`. EntityID = exact issuer.
- Passive: `GET /wsfed/passive` or ADFS `GET /adfs/ls/?wa=wsignin1.0&wtrealm=…&wreply=…&wctx=…`.
- `wtrealm` matches `spec.clients[].saml.entityID` or `clientId`. `wreply` must be in `saml.acsURLs` (or `redirectURIs` when ACS is empty).
- Pending protocol is `wsfed`. Same `/login` `/consent` HTML. Completion auto-POSTs `wa=wsignin1.0`, `wresult` (signed SAML Response, lab), and `wctx` to `wreply`.
- Inactive clothes paths 404. Never vendor-cloud hosts.

Out of this slice: IdP-initiated WS-Fed, full RSTR wrapping, ADFS admin APIs.

## Group overage (OVR-001)

Counts use `len(user.groupIds)`. Overage is **scope-gated**: only when `groups` is in the token scope. Refresh uses `writeTokens` so it matches. This is an OVR clothes change: groups (or Entra overage claims) now also appear on the **access token** when scoped, not only id_token + userinfo.

| Clothes | Threshold | Behavior |
|---|---|---|
| `generic` | `genericCap` (default 200; `0` normalizes to 200) | Embed at most `genericCap` names (stable sort by group id). Excess omitted + audit warning. Same payload on access token, id_token, and userinfo. |
| `entra` | `genericCap` (same knob) | `count > genericCap`: omit `groups`, emit `_claim_names` / `_claim_sources` with `endpoint` `{iss}/v1.0/users/{oid}/getMemberGroups`. Never `graph.microsoft.com`. If `entraGraphStub: false`, **fail the token request** with the clothed entra error (no `_claim_names` at a missing stub; no Internet). Same payload on access + id_token + userinfo. |
| `okta` | `oktaFailAt` (default 100) | `count >= oktaFailAt` **fails** the token request (authorization_code and refresh). Do not truncate. Userinfo after a prior successful token is unchanged. |

Graph stub (`vendor` `entra` **and** `entraGraphStub: true` only): `POST /v1.0/users/{oid}/getMemberGroups` on the data-plane HTTPS listener. JSON `{"value":[<group names>]}` (names, not Graph object ids — lab limitation). Auth: Bearer access token whose `sub` (user.id / oid) equals `{oid}`. Inactive clothes / stub off → 404.

`overage:set` (`sso.tunable.overage.set`) merges pointers (`*bool entraGraphStub`, `*int oktaFailAt`, `*int genericCap`) onto the current `GroupOverage` and `OpUpdate`s the full merged struct. Requires `expectedRevision` + reason + idempotency. It is not `Apply` and not a membership source of truth.

## Agent tunables

These are management operations that affect the data plane. They go through the registry (plan/apply or dedicated capabilities with the same mutation contract):

| Tunable | Data-plane effect | Status |
|---|---|---|
| Force auth fail | Authorize / login fails with a chosen error | implemented |
| Force consent | Consent page always shown. Blocks every `PreConsent` shortcut (authorize session reuse, login HTML, SAML SSO, WS-Fed passive) | implemented (runtime overlay) |
| Expire session | Session and associated codes die | implemented |
| Mint token | Issue access + id tokens for a user/client/scope (scoped; audited) | implemented (runtime overlay) |
| Set group overage | Merge `groupOverage` policy (not membership counts) | implemented (desired-state) |
| Rewrite a client redirect URI | Canonical client change | IMP-001 |
| Swap vendor clothes | `spec.profile.vendor` change; paths and claims update on next snapshot | implemented |
| Inject a specific error code/status | Next matching request returns that clothed error | implemented |
| Pause token endpoint | `/token` waits or 503s; authorize, JWKS, discovery, login stay up | implemented |

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
