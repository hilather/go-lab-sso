# Program Board

Status: through VEN-003 done; INT-001 documented here; SCIM-001 design-only
Last reviewed: 2026-09-01

Implementation is **opened** at FND-001. Later slices stay not-started until their wave.

## Work packages

| Order | Slice | ID | Depends on | Primary output | Status |
|---:|---|---|---|---|---|
| 1 | Repo foundation + YAML schema + snapshot/plan/apply + REST+MCP registry + CLI `validate\|canonicalize\|serve` + scratch image + compose mapping `443:10443` | FND-001 | Design accepted | Module, schema, registry, CLI, scratch image, compose runnable | done |
| 2 | OIDC/OAuth2 authorization code + PKCE + discovery + JWKS + id_token/access_token + refresh (generic clothes) | OIDC-001 | FND-001 | Generic OP | done |
| 3 | Data-plane login + consent HTML; MFA knobs `never` \| `always` \| `force-fail`; RFC 6238 file-ref TOTP + overlay enroll | LOGIN-001 | OIDC-001 | Login/consent HTML ≠ operator SPA | done |
| 4 | Vendor clothes: `entra`, `okta` (paths, claims, cookies, error dialect) | VEN-001 | LOGIN-001 | Clothes tables | done |
| 5 | Group overage: Entra `_claim_names`/`_claim_sources` + Graph-shaped stub; Okta fail-at; generic cap | OVR-001 | VEN-001 | Overage behaviors | done |
| 6 | SAML 2.0 SP-initiated SSO + IdP metadata | SAML-001 | OVR-001 | SAML IdP | done |
| 7 | Operator SPA with REST+MCP+UI parity | UI-001 | FND-001, LOGIN-001 | SPA; first implementation ready for Mira (`docs/22-operator-spa.md`) | done (Mira review requested) |
| 8 | Customer-config import (allow-list rewriter) | IMP-001 | FND-001 | Import plan/apply | done |
| 9 | More vendor clothes: ping, adfs, google, keycloak, iam-identity-center; WS-Fed with ADFS clothes | VEN-002 | VEN-001, SAML-001 | Additional clothes + WS-Fed | done |
| 10 | Duo, SiteMinder, Shibboleth clothes including SAML URL clothes | VEN-003 | VEN-002, SAML-001 | Remaining named SSO clothes | done |
| 11 | SCIM outbound client | SCIM-001 | FND-001 | Design-only (`docs/23-scim-outbound.md`); may trail M6 | design |
| 12 | Integrator last in mcp-integration-lab | INT-001 | Appliance exists | Wiring documented here; pin is last in mcp-integration-lab (not from this repo) | documented |

UI-001 must not start in this design landing. Mira reviews after the first UI implementation.

INT-001 is **last**. Document the wiring in [docs/11-deployment.md](../docs/11-deployment.md). Do not implement it from this repository. LabMITM-style service in the **main** `docker-compose.yaml` (not an overlay). BOM: vendor pin, `profile.env`, `publishedPortSpecs`, `CanonicalReloadApps`, `secrets.go` (token 0o644 for UID 65532), `register.go`, labinfo `connection` block (issuer, OIDC discovery, SAML metadata, JWKS, client_id, redirect URIs, dest port 443), mcpjungle `servers/labsso.json`, new TLS leaf under `secrets/labsso-tls/` (lab-CA signed; **new leaf**, do not reuse LabMITM or LabLDAP cert).

## Milestones

### M0: Design

- This repository on `main`.
- ADRs 0001–0010 accepted for design (0010 adds Duo / SiteMinder / Shibboleth clothes).
- Sweep 1 folded. Sweep 2 ACCEPT (2026-08-30). See [docs/skeptic-notes.md](../docs/skeptic-notes.md).

### M1: Foundation (FND-001)

- Go 1.26 module, fail-closed YAML, snapshot plan/apply/reset, REST+MCP adapters, scratch image, `443:10443`.

### M2: Browser IdP (OIDC-001 + LOGIN-001)

- Generic OIDC + login/consent HTML. Data plane independent of management.

### M3: Customer-shaped OIDC (VEN-001 + OVR-001)

- Entra/Okta clothes and overage.

### M4: SAML and operator console (SAML-001 + UI-001)

- SP-initiated SAML. SPA after Mira review.

### M5: Import and more clothes (IMP-001 + VEN-002 + VEN-003)

- Allow-list rewriter. Ping/ADFS/Google/Keycloak/IAM IC. WS-Fed. Duo/SiteMinder/Shibboleth.

### M6: Integrator last (INT-001)

- mcp-integration-lab main compose pin.

SCIM-001 may trail M6.

## Cross-cutting blockers

The coordinator must stop dependent work when any of these are unstable:

- Canonical IDs and YAML schema.
- Capability registry API.
- Exact issuer derivation.
- Vendor clothes tables (hostname must stay out).
- MCP protocol pin and `allowLegacyClients`.
- Dest-443 preflight error text.
- Data-plane login vs operator SPA cookie names.

## Agent tunables

Documented, not a separate board row: force auth fail, force consent, expire session, mint token with chosen claims, set group overage, rewrite redirect URI, swap vendor clothes, inject error, pause token (data plane otherwise up). Land with the registry in FND/OIDC as applicable.
