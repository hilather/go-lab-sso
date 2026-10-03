# Known Limitations

Status: through VEN-003 implemented; SCIM design-only; integrator pin not in this repo
Last reviewed: 2026-10-03

Current limits of the implemented lab appliance. LabSSO does not claim production IdP certification.

## Historical design review

- **Sweep 2 recorded** 2026-08-30: review-plan **READY**, skeptic sweep 1 **ACCEPT**. See [skeptic-notes.md](skeptic-notes.md).
- That review preceded implementation. The repository now includes the Go binary, container build, protocol tests, and CI.

## Implemented appliance

- Single process, single replica. Runtime sessions and refresh handles are memory. Restart drops them.
- No database. No multi-replica consensus.
- TOTP overlay enroll is process memory; restart and `state:reset` drop it. Durable MFA needs `totpSecretRef`.
- `token:mint` stays password-only (no `amr`/`acr`). No `acr_values` step-up.
- Operator SPA chrome (sessions/users + data-plane login card) is implemented; leftover groups/clients/status/audit stay JSON dumps (`docs/22-operator-spa.md`).
- LDAP bind is not v1.
- SCIM outbound is later; no SCIM inbound server.
- No client-credentials or device-code grant in the first OIDC slice.
- Implicit / hybrid rejected.
- Redirect URIs are exact match; no wildcards.
- Logout `post_logout_redirect_uri` may match any registered client's redirect URI; it is not bound to the `id_token_hint` audience, and expired hints fall back to the confirmation page.
- Group overage Graph stub is minimal, not Microsoft Graph.
- Okta overage **fails** the token rather than truncating. Its error body (`400 invalid_grant`, `okta overage`) is a lab choice not verified against live Okta.
- `error:inject` on the token endpoint always answers HTTP 400, even for `temporarily_unavailable`; use `token:pause` to simulate a 503.
- Entra stub-off overage fails the token (`400 invalid_grant`, `entra stub disabled`); real Entra has no equivalent and always uses the overage claim.
- No LabNTP time bus; skew repros belong on the SUT.
- `LABSSO_HTTPS_PORT` escape breaks SUTs that cannot set dest port.
- Management loopback-unauth is powerful on a shared workstation.
- In-memory audit ring; no fail-closed external sink in v1.
- List APIs support cursor pagination; filtering remains unimplemented. The generated configuration schema and capability/binding manifests do not include full OpenAPI or all per-capability input/output schemas.
- Integrator pin is last and is not in this repository.
- Duo / SiteMinder live `iss` suffixes (`/oidc/{appId}`, `/affwebservices/CASSO/oidc/{client}`) and Shibboleth EntityID `/idp/shibboleth` are not copied; LabSSO keeps the exact issuer. Live Duo SAML EntityID is often the metadata URL; LabSSO still uses the exact issuer.

## Explicit non-limitations (do not “fix” by weakening)

- Dest-443 is intentional.
- From-scratch Go is intentional.
- One exact issuer is intentional.
- File-ref secrets are intentional.
- Data-plane login HTML is required and distinct from the SPA.
