# Roadmap and Non-Goals

Status: default ship implemented (FND-001 + OIDC-001 + LOGIN-001)
Owners: Architecture, Program
Last reviewed: 2026-08-30
Related ADRs: 0001–0009

## Problem statement

LabSSO is easy to over-scope (wrap Keycloak, clone Entra hostnames, add a time bus, pin the integrator first). This document freezes sequential slices and the things we will not do.

## Sequential slices (normative)

Implementation is opened at FND-001. Remaining slice order is:

1. **Repo foundation** — Go 1.26 module `github.com/hilather/go-lab-sso`, YAML schema, snapshot/plan/apply, REST+MCP registry, CLI `validate|canonicalize|serve`, scratch image, example compose mapping `443:10443`.
2. **OIDC/OAuth2** — authorization code + PKCE + discovery + JWKS + id_token/access_token + refresh (generic clothes).
3. **Data-plane login + consent HTML** — required; distinct from operator SPA. MFA knobs `never` | `always` | `force-fail` (TOTP stub later).
4. **Vendor clothes** — `entra`, `okta` (paths, claims `oid`/`tid`/`ver` vs Okta groups, cookies, error dialect).
5. **Group overage** — Entra `_claim_names`/`_claim_sources` + minimal Graph-shaped stub served by LabSSO (not real Microsoft Graph). Okta: fail the token request after 100 groups (configurable). Generic: embed groups with a safety cap.
6. **SAML 2.0** — SP-initiated SSO + IdP metadata.
7. **Operator SPA** — REST+MCP+UI parity. **Mira reviews after first UI implementation.** Do not build UI in this design landing.
8. **Customer-config import** — allow-list rewriter.
9. **More vendor clothes** — ping, adfs, google, keycloak, iam-identity-center. WS-Fed with ADFS clothes.
10. **SCIM outbound client** — later.
11. **Integrator last** — `hilather/mcp-integration-lab`, LabMITM-style service in main `docker-compose.yaml` (not an overlay). See [docs/11-deployment.md](11-deployment.md).

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
