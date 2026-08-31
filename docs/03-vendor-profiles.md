# Vendor Profiles

Status: all enum clothes implemented (VEN-001 + VEN-002 + VEN-003). Group overage (OVR-001) implemented.
Owners: Protocols, Application
Last reviewed: 2026-08-31
Related ADRs: 0005, 0010

## Problem statement

A lab that “looks like Entra” is useful only if SUT clients can be pointed at LabSSO without believing they are talking to Microsoft’s hostname. Vendor profiles are **clothes**: path templates, claim names, cookies, error JSON, and group-overage policy on **one exact issuer**. They are not separate products and not DNS or TLS impersonation.

## Goals

- `spec.profile.vendor` selects clothes.
- Default ship: `generic` OIDC on.
- Entra and Okta clothes opt-in via YAML.
- Remaining enum clothes (VEN-002): ping, adfs, google, keycloak, iam-identity-center. WS-Fed with ADFS path clothes.
- Duo, SiteMinder, and Shibboleth clothes (VEN-003 / [ADR 0010](adr/0010-duo-siteminder-shibboleth-clothes.md)), including SAML URL clothes. `{name}` is `metadata.name` (empty → `lab`).

## Non-goals

- Serving TLS as `login.microsoftonline.com` or `*.okta.com`.
- Cloning vendor admin consoles or Graph / Okta Management APIs except the minimal Entra group-overage stub (OVR-001).
- Per-vendor processes or images.
- Changing the issuer hostname when clothes swap.

## Enum

```text
generic
entra
okta
ping
adfs
google
keycloak
iam-identity-center
duo
siteminder
shibboleth
```

Unknown values reject at decode. Default: `generic`. Every enum value is implemented. Unknown-to-compile remains fail-closed (`clothes not implemented`) if a string is not in `Implemented`.

## What clothes cover

| Surface | Clothes may change | Clothes must not change |
|---|---|---|
| Issuer | Display strings in HTML | The exact issuer URL |
| Authorize / token / jwks / userinfo / logout / SAML metadata and SSO paths | Templates | Being on that issuer |
| Claim names | `oid`/`tid`/`ver` vs `groups` vs Ping / ADFS names | `iss` value |
| Error JSON | Token JSON extras (`error_codes`, `trace_id` for entra) | Authorize query params (RFC 6749); management-plane domain codes |
| Cookies | Login cookie name on the login host | Operator SPA cookie name (`labsso_session` planned) |
| Group overage | Entra stub vs Okta fail-at vs generic cap (OVR-001) | Inventing a second issuer |
| HTML chrome | Titles, headings | Merging login HTML into the operator SPA |

## Clothes table (normative paths)

Paths are relative to the exact lab issuer. Hosts are **never** vendor-cloud hosts.

| Vendor | Authorize | Token | JWKS | UserInfo | Logout | Claims / cookies / errors | Overage | Slice |
|---|---|---|---|---|---|---|---|---|
| `generic` | `GET /oauth2/authorize` | `POST /oauth2/token` | `GET /oauth2/jwks` | `GET /oauth2/userinfo` | `GET /oauth2/logout` | Standard OIDC; cookie `labsso_login`; RFC 6749 JSON | Embed ≤ `genericCap` (default 200); excess omitted + audit | 2–3, 5 |
| `entra` | `GET /oauth2/v2.0/authorize` | `POST /oauth2/v2.0/token` | `GET /oauth2/v2.0/jwks` | `GET /oauth2/v2.0/userinfo` | `GET /oauth2/v2.0/logout` | `oid`=`user.id`, `tid`, `ver=2.0` on id_token and userinfo; cookie `labsso_entra`; token errors add `error_codes` + `trace_id`. When `groups` is scoped, access token also carries `groups` or `_claim_names`/`_claim_sources` | `count > genericCap` → `_claim_names` + local stub, or token fail if stub off | 4–5 |
| `okta` | `GET /oauth2/default/v1/authorize` | `POST /oauth2/default/v1/token` | `GET /oauth2/default/v1/jwks` | `GET /oauth2/default/v1/userinfo` | `GET /oauth2/default/v1/logout` | Same claims as generic; cookie `labsso_okta`; RFC 6749 token JSON. `authServerId` is clothes constant `default`. Access token carries `groups` when scoped | Fail at `oktaFailAt` (default 100); do not truncate | 4–5 |
| `ping` | `GET /as/authorization.oauth2` | `POST /as/token.oauth2` | `GET /pf/JWKS` | `GET /idp/userinfo.openid` | `GET /idp/startSLO.ping` | Same claims as generic; cookie `labsso_ping` | Generic cap | 9 |
| `adfs` | `GET /adfs/oauth2/authorize` | `POST /adfs/oauth2/token` | `GET /adfs/discovery/keys` | `GET /adfs/userinfo` | `GET /adfs/oauth2/logout` | Same claims as generic; cookie `labsso_adfs`. WS-Fed: `/FederationMetadata/2007-06/FederationMetadata.xml` + `/adfs/ls/` | Generic cap | 9 |
| `google` | `GET /o/oauth2/v2/auth` | `POST /token` | `GET /oauth2/v3/certs` | `GET /oauth2/v3/userinfo` | `GET /logout` | Same claims as generic; cookie `labsso_google` | Generic cap | 9 |
| `keycloak` | `GET /realms/{realm}/protocol/openid-connect/auth` | `POST …/token` | `GET …/certs` | `GET …/userinfo` | `GET …/logout` | Realm = `metadata.name` (empty → `lab`); cookie `labsso_keycloak` | Generic cap | 9 |
| `iam-identity-center` | `GET /authorize` | `POST /token` | `GET /jwks` | `GET /userinfo` | `GET /logout` | Same claims as generic; cookie `labsso_iamic` | Generic cap | 9 |
| `duo` | `GET /oidc/{name}/authorize` | `POST /oidc/{name}/token` | `GET /oidc/{name}/jwks` | `GET /oidc/{name}/userinfo` | `GET /oidc/{name}/logout` | Same claims as generic; cookie `labsso_duo`. SAML: `/saml2/sp/{name}/metadata`, `GET\|POST /saml2/sp/{name}/sso` | Generic cap | 10 |
| `siteminder` | `GET /affwebservices/CASSO/oidc/{name}/authorize` | `POST …/token` | `GET …/jwks` | `GET …/userinfo` | `GET …/logout` | Same claims as generic; cookie `labsso_siteminder`. SAML: `/affwebservices/public/saml2meta`, `GET\|POST /affwebservices/public/saml2sso` | Generic cap | 10 |
| `shibboleth` | `GET /idp/profile/oidc/authorize` | `POST …/token` | `GET …/keyset` | `GET …/userinfo` | `GET …/logout` | Same claims as generic; cookie `labsso_shibboleth`. SAML: `/idp/shibboleth`; GET Redirect SSO; POST POST SSO | Generic cap | 10 |

`{name}` is `metadata.name` (empty → `lab`). Operators set `name` to the SUT’s Duo app id or SiteMinder client name. Existing vendors keep `/saml/metadata` + `/saml/sso`.

`GET /.well-known/openid-configuration` is served for every implemented vendor and lists only the **active** clothed endpoints. After an entra swap, generic `/oauth2/authorize` (and the rest of the generic set) **404**. Entra and Duo share one two-segment well-known dispatcher (`GET /{a}/{b}/.well-known/openid-configuration`): entra when `a` is the compiled tenant id and `b` is `v2.0`; duo when `a` is `oidc` and `b` is `{name}`. SiteMinder serves `GET /affwebservices/CASSO/oidc/{name}/.well-known/openid-configuration`. Aliases emit the same `iss`. Wrong vendor or segment **404**.

Login and consent stay `/login` and `/consent` for all clothes.

## `spec.profile.tenantId`

Optional. `yaml:"tenantId,omitempty"`. Empty stays empty in Canonical, export, and `GET /v1/state`. The compiler fills `snapshot.Clothes.TenantID` with `00000000-0000-0000-0000-000000000001` when omitted. Entra `tid` and the Entra discovery alias use that compiled value. Do not Normalize the default into Canonical.

## Swap behavior

`spec.profile.vendor` is a snapshot field. Plan/apply that swaps clothes:

- Recompiles path tables and claim maps.
- Invalidates in-flight authorization codes, pending requests, refresh tokens, and login sessions (`Runtime.PurgeProtocol`) when **vendor** changes. A tenantId-only update does not purge. Pause / force-fail / inject overlays survive.
- Does **not** change `iss`.
- Does **not** rewrite `LAB_PUBLIC_HOST`.
- Audits the swap as a high-visibility mutation.

`POST /v1/tunables/vendor:swap` / MCP `sso_tunable_vendor_swap` (`sso.tunable.vendor.swap`, scope `sso.tunables`) merges `vendor` and optional `tenantId` onto the current profile and applies through the same compile/swap path. Omit `tenantId` to keep the current Canonical value; send `tenantId: ""` to clear it (compile default still fills Clothes). It is not `sso.change.apply`. Write-scoped `POST /v1/changes:apply` of `TargetProfile` remains a full replace (a `{vendor}`-only value zeros `tenantId`).

## Entra clothes (VEN-001)

- Paths resemble Entra v2 on the **lab issuer**.
- Claims: `oid` (YAML `user.id`), `tid` (compiled tenant id), `ver` (`2.0`) on id_token and userinfo.
- When `groups` is scoped, OVR-001 adds `groups` **or** `_claim_names`/`_claim_sources` to the **access token** as well (same payload on id_token + userinfo). This is an OVR clothes change, not a VEN revert.
- Overage: `count > genericCap` (default 200). Stub on: omit `groups`, emit `_claim_names`/`_claim_sources` with `endpoint` `{iss}/v1.0/users/{oid}/getMemberGroups`. Stub off: fail the token request with clothed entra error. Never `graph.microsoft.com`.
- Graph stub: `POST /v1.0/users/{oid}/getMemberGroups` only when vendor is `entra` and `entraGraphStub: true`. JSON `{"value":[<group names>]}`. Bearer access token `sub` must equal `{oid}`. Else 404.

## Okta clothes (VEN-001 + OVR-001)

- Paths resemble an Okta custom authorization server id `default` on the **lab issuer**.
- Groups embed when scoped, including on the access token. `count >= oktaFailAt` (default 100) fails the token request (code and refresh). Do not truncate.
- Okta `/keys` JWKS alias is later if a SUT needs it.

## HTML chrome

Login and consent pages may change titles and headings per clothes. They remain LabSSO pages on the lab issuer. Do not load vendor JavaScript from the Internet. Do not frame vendor login pages.

## Failure modes

- Unknown vendor enum: decode reject.
- String not in `Implemented` (not in the enum): compile / validate / apply reject.
- Clothes swap mid-flight: codes issued under old paths fail `invalid_grant`; clients must restart the authorize.
- Graph stub disabled while Entra overage is triggered: token fail; do not call the real Internet.

## Testing strategy

- Discovery `iss` identical across implemented vendor values for a fixed host+port.
- Path tables differ; token `iss` does not.
- Inactive clothes paths 404.
- Hostname literals for vendor clouds never appear in generated discovery or token JSON.
- Entra stub / Okta fail-at / generic cap: OVR-001 (implemented).
- SAML metadata Locations follow active clothes; Shibboleth Redirect vs POST are distinct; inactive `/saml/*` 404s under Duo, SiteMinder, and Shibboleth.

## Compatibility implications

Adding a vendor value is additive. Removing or renaming one is breaking. Changing a clothed path after a vendor ships is breaking for that vendor. Canonicalize now emits `genericCap: 200` on documents that omitted it (revision change).

## Open questions

- None for VEN-003. `metadata.name` is the path segment for Keycloak realm, Duo app id, and SiteMinder client name (`Resolve` uses `lab` only if called with an empty name). `genericCap` is the frozen Entra/generic threshold (default 200). Live issuer suffixes and Duo metadata-as-EntityID are not copied; see [docs/known-limitations.md](known-limitations.md).
