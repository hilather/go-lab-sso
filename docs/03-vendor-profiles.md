# Vendor Profiles

Status: entra and okta clothes implemented (VEN-001). Overage (OVR-001) and later vendors are not started.
Owners: Protocols, Application
Last reviewed: 2026-08-30
Related ADRs: 0005

## Problem statement

A lab that “looks like Entra” is useful only if SUT clients can be pointed at LabSSO without believing they are talking to Microsoft’s hostname. Vendor profiles are **clothes**: path templates, claim names, cookies, error JSON, and group-overage policy on **one exact issuer**. They are not separate products and not DNS or TLS impersonation.

## Goals

- `spec.profile.vendor` selects clothes.
- Default ship: `generic` OIDC on.
- Entra and Okta clothes opt-in via YAML.
- Later clothes: ping, adfs, google, keycloak, iam-identity-center.
- Duo, SiteMinder, and Shibboleth are **later clothes**, not separate products and not v1 vendors.

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
```

Unknown values reject at decode. Default: `generic`. Implemented clothes: `generic`, `entra`, `okta`. Other enum values load and canonicalize but **compile-reject** (`clothes not implemented`). They must not silently act as generic.

## What clothes cover

| Surface | Clothes may change | Clothes must not change |
|---|---|---|
| Issuer | Display strings in HTML | The exact issuer URL |
| Authorize / token / jwks / userinfo / logout paths | Templates | Being on that issuer |
| Claim names | `oid`/`tid`/`ver` vs `groups` vs Ping / ADFS names | `iss` value |
| Error JSON | Token JSON extras (`error_codes`, `trace_id` for entra) | Authorize query params (RFC 6749); management-plane domain codes |
| Cookies | Login cookie name on the login host | Operator SPA cookie name (`labsso_session` planned) |
| Group overage | Entra stub vs Okta fail-at vs generic cap (OVR-001) | Inventing a second issuer |
| HTML chrome | Titles, headings | Merging login HTML into the operator SPA |

## Clothes table (normative paths)

Paths are relative to the exact lab issuer. Hosts are **never** vendor-cloud hosts.

| Vendor | Authorize | Token | JWKS | UserInfo | Logout | Claims / cookies / errors | Overage | Slice |
|---|---|---|---|---|---|---|---|---|
| `generic` | `GET /oauth2/authorize` | `POST /oauth2/token` | `GET /oauth2/jwks` | `GET /oauth2/userinfo` | `GET /oauth2/logout` | Standard OIDC; cookie `labsso_login`; RFC 6749 JSON | Embed groups (cap in OVR-001) | 2–3 |
| `entra` | `GET /oauth2/v2.0/authorize` | `POST /oauth2/v2.0/token` | `GET /oauth2/v2.0/jwks` | `GET /oauth2/v2.0/userinfo` | `GET /oauth2/v2.0/logout` | `oid`=`user.id`, `tid`, `ver=2.0` on id_token and userinfo; cookie `labsso_entra`; token errors add `error_codes` + `trace_id` | Graph-shaped stub (OVR-001) | 4 |
| `okta` | `GET /oauth2/default/v1/authorize` | `POST /oauth2/default/v1/token` | `GET /oauth2/default/v1/jwks` | `GET /oauth2/default/v1/userinfo` | `GET /oauth2/default/v1/logout` | Same claims as generic; cookie `labsso_okta`; RFC 6749 token JSON. `authServerId` is clothes constant `default` | Fail at `oktaFailAt` (OVR-001) | 4 |
| `ping` | later | later | later | later | later | later | later | 9 |
| `adfs` | later | later | later | later | later | later | later | 9 |
| `google` | later | later | later | later | later | later | later | 9 |
| `keycloak` | later | later | later | later | later | later | later | 9 |
| `iam-identity-center` | later | later | later | later | later | later | later | 9 |

Duo, SiteMinder, Shibboleth: **later clothes**, same issuer rule, not rows in v1 enum until an ADR adds them.

`GET /.well-known/openid-configuration` is served for every implemented vendor and lists only the **active** clothed endpoints. After an entra swap, generic `/oauth2/authorize` (and the rest of the generic set) **404**. Entra also serves `GET /{tenantId}/v2.0/.well-known/openid-configuration` with the same `iss` (404 unless `{tenantId}` equals the compiled tenant id).

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
- Claims: `oid` (YAML `user.id`), `tid` (compiled tenant id), `ver` (`2.0`) on id_token and userinfo. Access token stays `token_use` + `scope`.
- Groups embed when `groups` is in scope. `_claim_names` / Graph stub land in OVR-001.

## Okta clothes (VEN-001)

- Paths resemble an Okta custom authorization server id `default` on the **lab issuer**.
- Groups embed when scoped. `oktaFailAt` lands in OVR-001.
- Okta `/keys` JWKS alias is later if a SUT needs it.

## HTML chrome

Login and consent pages may change titles and headings per clothes. They remain LabSSO pages on the lab issuer. Do not load vendor JavaScript from the Internet. Do not frame vendor login pages.

## Failure modes

- Unknown vendor enum: decode reject.
- Unimplemented vendor (`ping`, …): compile / validate / apply reject.
- Clothes swap mid-flight: codes issued under old paths fail `invalid_grant`; clients must restart the authorize.
- Graph stub disabled while Entra overage is triggered: OVR-001; do not call the real Internet.

## Testing strategy

- Discovery `iss` identical across implemented vendor values for a fixed host+port.
- Path tables differ; token `iss` does not.
- Inactive clothes paths 404.
- Hostname literals for vendor clouds never appear in generated discovery or token JSON.
- Entra stub / Okta fail-at: OVR-001.

## Compatibility implications

Adding a vendor value is additive. Removing or renaming one is breaking. Changing a clothed path after a vendor ships is breaking for that vendor.

## Open questions

- Exact Entra overage YAML field name (sweep 2: lab numeric default **200**; field name lands in CFG / OVR-001). Microsoft’s production threshold is not a lab requirement.
- Keycloak `realm` name source (`metadata.name` vs explicit field).
