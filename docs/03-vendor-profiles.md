# Vendor Profiles

Status: design (not implemented)
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
- Cloning vendor admin consoles or Graph / Okta Management APIs except the minimal Entra group-overage stub.
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

Unknown values reject at decode. Default: `generic`.

## What clothes cover

| Surface | Clothes may change | Clothes must not change |
|---|---|---|
| Issuer | Display strings in HTML | The exact issuer URL |
| Authorize / token / jwks / userinfo / logout paths | Templates | Being on that issuer |
| Claim names | `oid`/`tid`/`ver` vs `groups` vs Ping / ADFS names | `iss` value |
| Error JSON | Field names, error codes shown to the SUT | Management-plane domain codes |
| Cookies | Cookie names and flags on the login host | Operator SPA cookie name (`labsso_session` planned) |
| Group overage | Entra stub vs Okta fail-at vs generic cap | Inventing a second issuer |
| HTML chrome | Labels, CSS class names | Merging login HTML into the operator SPA |

## Clothes table

Paths below are illustrative templates relative to the exact issuer. Implementation freezes them in a generated catalog. Hosts are **never** vendor-cloud hosts.

| Vendor | Typical authorize path | Typical token path | Distinct claims / behavior | Cookies / errors | Overage | Slice |
|---|---|---|---|---|---|---|
| `generic` | `/oauth2/authorize` | `/oauth2/token` | Standard OIDC (`sub`, `email`, `groups`) | RFC 6749 JSON | Embed groups with safety cap | 2–3 |
| `entra` | Entra-shaped `/oauth2/v2.0/authorize` (on lab issuer) | `/oauth2/v2.0/token` | `oid`, `tid`, `ver`; optional `_claim_names` / `_claim_sources` | Entra-like error JSON and login cookies | Graph-shaped stub on LabSSO | 4–5 |
| `okta` | Okta-shaped `/oauth2/{authServerId}/v1/authorize` | `/oauth2/{authServerId}/v1/token` | Okta `groups`; `vid`/`ver` style only if needed for the SUT | Okta-like error dialect | Fail token after `oktaFailAt` (default 100) | 4–5 |
| `ping` | Ping-shaped authorize | Ping-shaped token | Ping claim names | Ping error dialect | Later; default generic cap until specified | 9 |
| `adfs` | ADFS-shaped OIDC and later WS-Fed | ADFS-shaped token | ADFS claim names | ADFS error / cookie dialect | Later | 9 |
| `google` | Google-shaped `/o/oauth2/v2/auth` | Google-shaped token | `hd`, Google-ish profile claims | Google-like errors | Later | 9 |
| `keycloak` | `/realms/{realm}/protocol/openid-connect/auth` | `…/token` | `realm_access` / `resource_access` shapes | Keycloak error dialect | Later | 9 |
| `iam-identity-center` | IAM IC-shaped authorize | IAM IC-shaped token | AWS IC-ish claims | IAM IC error dialect | Later | 9 |

Duo, SiteMinder, Shibboleth: **later clothes**, same issuer rule, not rows in v1 enum until an ADR adds them.

## Swap behavior

`spec.profile.vendor` is a snapshot field. Plan/apply that swaps clothes:

- Recompiles path tables and claim maps.
- Invalidates in-flight authorization codes (client still exists; path the SUT POSTs to may change).
- Does **not** change `iss`.
- Does **not** rewrite `LAB_PUBLIC_HOST`.
- Audits the swap as a high-visibility mutation.

Agents may use the “swap vendor clothes” tunable, which is this field change plus the same mutation contract.

## Entra clothes (slice 4–5)

- Paths resemble Entra v2 on the **lab issuer**.
- Claims: `oid` (user object id from YAML), `tid` (lab tenant id from YAML or a documented default), `ver` (`2.0`).
- Group overage: when group count exceeds the Entra-shaped threshold, tokens carry `_claim_names` / `_claim_sources` pointing at LabSSO’s Graph-shaped stub. `spec.groupOverage.entraGraphStub: true` enables the stub routes.
- The stub is **not** Microsoft Graph. It answers the group-list shape overage clients fetch. It does not implement directory objects, apps, or mail.

## Okta clothes (slice 4–5)

- Paths resemble an Okta custom authorization server on the **lab issuer**.
- Groups are embedded until `oktaFailAt` (default 100). At or above the cap, the token request **fails** (configurable). This matches the lab need to reproduce Okta’s “too many groups” failure, not to silently truncate.

## HTML chrome

Login and consent pages may change titles, logos-as-CSS, and field labels per clothes. They remain LabSSO pages on the lab issuer. Do not load vendor JavaScript from the Internet. Do not frame vendor login pages.

## Failure modes

- Unknown vendor enum: decode reject.
- Clothes swap mid-flight: codes issued under old paths fail `invalid_grant` on the new token path; clients must restart the authorize.
- Graph stub disabled while Entra overage is triggered: fail closed at compile or at token time with a clothed error — do not call the real Internet.

## Testing strategy

- Discovery `iss` identical across all vendor values for a fixed host+port.
- Path tables differ; token `iss` does not.
- Entra stub is served by LabSSO and does not egress.
- Okta fail-at is exact (99 groups succeed, 100 fail when cap is 100).
- Hostname literals for vendor clouds never appear in generated discovery except as documentation comments in this repo.

## Compatibility implications

Adding a vendor value is additive. Removing or renaming one is breaking. Changing a clothed path after a vendor ships is breaking for that vendor.

## Open questions

- Exact Entra overage YAML field name (sweep 2: lab numeric default **200**; field name lands in CFG / slice 5). Microsoft’s production threshold is not a lab requirement.
- Whether Okta `authServerId` is a YAML field or a clothes constant (`default` / `aus…` lab id).
- Keycloak `realm` name source (`metadata.name` vs explicit field).
