# Roadmap and Non-Goals

Status: through VEN-003 implemented; INT-001 documented here; SCIM-001 design-only
Owners: Architecture, Program
Last reviewed: 2026-09-01
Related ADRs: 0001–0011

## Problem statement

LabSSO is easy to over-scope (wrap Keycloak, clone Entra hostnames, add a time bus, pin the integrator first). This document freezes sequential slices and the things we will not do.

## Sequential slices (normative)

Implementation is opened at FND-001. Remaining slice order is:

1. **Repo foundation** — Go 1.26 module `github.com/hilather/go-lab-sso`, YAML schema, snapshot/plan/apply, REST+MCP registry, CLI `validate|canonicalize|serve`, scratch image, example compose mapping `443:10443`.
2. **OIDC/OAuth2** — authorization code + PKCE + discovery + JWKS + id_token/access_token + refresh (generic clothes).
3. **Data-plane login + consent HTML** — required; distinct from operator SPA. MFA knobs `never` | `always` | `force-fail`. RFC 6238 file-ref TOTP + overlay enroll ([ADR 0011](adr/0011-file-ref-totp.md)).
4. **Vendor clothes** — `entra`, `okta` (paths, claims `oid`/`tid`/`ver` vs Okta groups, cookies, error dialect). **Implemented.**
5. **Group overage** — **Implemented (OVR-001).** Entra `_claim_names`/`_claim_sources` + minimal Graph-shaped stub served by LabSSO (not real Microsoft Graph). Okta: fail the token request after `oktaFailAt` groups. Generic: embed at most `genericCap` groups.
6. **SAML 2.0** — **Implemented (SAML-001).** SP-initiated SSO + IdP metadata.
7. **Operator SPA** — **Implemented (UI-001).** REST+MCP+UI parity. First SPA ready for Mira (`docs/22-operator-spa.md`).
8. **Customer-config import** — **Implemented (IMP-001).** Allow-list rewriter.
9. **More vendor clothes** — **Implemented (VEN-002).** ping, adfs, google, keycloak, iam-identity-center. WS-Fed with ADFS clothes.
10. **Duo, SiteMinder, Shibboleth clothes** — **Implemented (VEN-003).** OIDC paths plus SAML URL clothes. [ADR 0010](adr/0010-duo-siteminder-shibboleth-clothes.md).
11. **SCIM outbound client** — design-only ([docs/23-scim-outbound.md](23-scim-outbound.md)); may trail M6.
12. **Integrator last** — documented here ([docs/11-deployment.md](11-deployment.md)); implement the pin in `hilather/mcp-integration-lab`, not from this repo.

Default ship after slice 3: generic OIDC + login HTML. Entra/Okta clothes are opt-in YAML (`spec.profile.vendor`).

## Agent tunables

Documented in [docs/02-protocols.md](02-protocols.md) and [docs/06-rest-api.md](06-rest-api.md). Implement with the registry, not as hidden flags. Pause token must leave the rest of the data plane up.

## Non-goals

- Production IdP, HA cluster, multi-region, or paid SLA.
- Keycloak / Dex / ORY / Authelia / Authentik wrap.
- Hostname impersonation of vendor clouds.
- LabNTP time bus inside LabSSO.
- Flattening onto LabLDAP in v1 (LDAP bind is a later slice and stays a bind, not a merge).
- go-jenkins-mcp scope (separate product).
- Implementing the integrator pin before the appliance exists.
- Database without a future ADR.
- MCP-by-proxying-REST.
- Operator SPA tokens in `localStorage`.
- Disabling data-plane login via `spec.ui.enabled: false`.
- MIT license or dual-license confusion. Apache-2.0 only.
- Vendoring Origin/Cursor agent-skills.
- Fake CI/Go/Release badges.
- Makefile no-op targets; CI that fails while docs-only.

## Family fit

| Appliance | LabSSO relationship |
|---|---|
| LabDNS | Peer. Issuer hostname may be a LabDNS A record. |
| LabMail | Peer. Not required for OIDC. |
| LabMITM | Peer. Dest-443 contrast: LabMITM is a forward proxy and must not steal 443; LabSSO **is** dest-443. |
| TacLab | Peer. Different protocol family. |
| LabLDAP | Peer. Optional later bind. Do not flatten. |
| mcp-integration-lab | Integrator **last**. |
| go-jenkins-mcp | Out of scope. |

## Documentation governance

Normative docs win over task summaries. Invariant changes need an ADR. Last-reviewed dates move on substantive edits.

## Open questions

- Sweep 2 recorded 2026-08-30 ([skeptic-notes.md](skeptic-notes.md)): **ACCEPT**.
- When implementation is scheduled (not this repository’s decision).
