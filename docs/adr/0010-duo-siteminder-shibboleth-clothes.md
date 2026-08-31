# ADR 0010: Duo, SiteMinder, and Shibboleth clothes

Status: Accepted
Date: 2026-08-30
Last reviewed: 2026-08-30

## Context

[ADR 0005](0005-vendor-clothes-not-hostnames.md) selects vendor clothes on one exact issuer. [docs/03-vendor-profiles.md](../03-vendor-profiles.md) froze `duo`, `siteminder`, and `shibboleth` out of the enum until an ADR added them. VEN-002 shipped the remaining enum clothes and left SAML URLs generic (`docs/02-protocols.md`: “VEN-002 may clothe it”).

These three names complete the remaining SSO clothes. They need SAML URL clothes as well as OIDC path tables; OIDC-only clothes would leave SUTs on generic `/saml/sso`.

## Decision

Add `duo` | `siteminder` | `shibboleth` to `spec.profile.vendor`. Clothes-not-hostnames still holds.

- OIDC paths follow Duo SSO (`/oidc/{name}/…`), SiteMinder Access Gateway (`/affwebservices/CASSO/oidc/{name}/…`), and the Shibboleth OIDC plugin (`/idp/profile/oidc/…`).
- SAML metadata and SSO URLs are clothed for these three. Everyone else keeps `/saml/metadata` and `/saml/sso`.
- `{name}` is `metadata.name` (empty → `lab`), the same slot Keycloak already uses as realm. Operators set `name` to the SUT’s Duo app id or SiteMinder client name. Apply has no rename-name op.
- Discovery `iss`, token `iss`, and SAML EntityID stay the exact issuer. Live Duo/SiteMinder issuer suffixes and Shibboleth `/idp/shibboleth` EntityIDs are not copied. Live Duo SAML EntityID is often the metadata URL; LabSSO still uses the exact issuer.
- Duo target is Duo SSO (Duo Central), not Duo MFA / Auth API / Universal Prompt.

## Consequences

- Adding a vendor value is additive. Changing a clothed path after this ships is breaking.
- Go `ServeMux` cannot register `GET /oidc/{name}/.well-known/openid-configuration` beside Entra’s `GET /{tid}/v2.0/.well-known/openid-configuration` (both match `/oidc/v2.0/.well-known/…`). Entra and Duo share one two-segment well-known dispatcher.
- SAML `requirePath` needs Resolve defaults (`/saml/metadata`, `/saml/sso`) so existing vendors do not 404.
- Shibboleth metadata emits distinct Redirect and POST SSO Locations.

## Alternatives considered

- OIDC-only clothes: rejected; SUTs looking for Shibboleth / SiteMinder / Duo SAML URLs would still hit `/saml/sso`.
- Copying live issuer suffixes into `iss` / EntityID: rejected (ADR 0005).
- New YAML field for Duo app id / SiteMinder client name: rejected; `metadata.name` is already the path-segment slot.
- Duo Auth API (`api-*.duosecurity.com/oauth/v1/*`) as clothes: rejected; that is MFA, not an IdP.

## Review triggers

Review this decision when its assumptions no longer hold, a major protocol or library change occurs, or a new requirement conflicts with an invariant. See also [ADR 0005](0005-vendor-clothes-not-hostnames.md).
