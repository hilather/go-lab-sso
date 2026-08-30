# Skeptic Notes

Status: design (not implemented)
Last reviewed: 2026-08-30

This page records skeptic sweep findings. **Sweep 1 blockers are already folded** into the normative docs and ADRs. **Sweep 2 is pending** after this design landing.

Do not re-open a folded blocker by “improving” the product in a later edit. Change requires an ADR.

## Sweep 1 — folded

### 1. No LabNTP time bus

LabSSO uses the process clock. Kerberos and certificate-expiry skew reproductions belong on the SUT via LabNTP, not inside LabSSO.

Folded: [ADR 0007](adr/0007-no-labntp-time-bus.md), [docs/01-architecture.md](01-architecture.md), [AGENTS.md](../AGENTS.md).

### 2. Unprivileged container listen

The process listens unprivileged (e.g. `:10443`). Host 443 is a **publish**. `EACCES`/`EPERM` on bind is not occupancy; dockerd can still publish privileged host ports.

Folded: [ADR 0006](adr/0006-native-host-443.md), [docs/11-deployment.md](11-deployment.md).

### 3. Issuer is one exact string; vendor = path/claim clothes, not hostname clones

Entra/Okta/Ping/ADFS do not become `login.microsoftonline.com` / `okta.com`. Clothes are path templates, claims, cookies, errors, and overage policy on `LAB_PUBLIC_HOST` + published port (omit port iff 443).

Folded: [ADR 0005](adr/0005-vendor-clothes-not-hostnames.md), [docs/03-vendor-profiles.md](03-vendor-profiles.md).

### 4. Import is an allow-list rewriter, not KnownFields on vendor blobs

Customer manifests are not `labsso.dev/v1alpha1`. Unknown keys drop or park in `imported.unmapped`. Hardened XML. Plan/apply only.

Folded: [ADR 0008](adr/0008-import-allowlist-rewriter.md), [docs/09-customer-config-import.md](09-customer-config-import.md).

### 5. Integrator wiring is LabMITM-style main compose, not an overlay

`hilather/mcp-integration-lab` pin is **last**. Service goes in the main `docker-compose.yaml`. Not an overlay file.

Folded: [docs/11-deployment.md](11-deployment.md), [docs/18-roadmap-and-non-goals.md](18-roadmap-and-non-goals.md), program board slice 11.

### 6. New TLS leaf `secrets/labsso-tls`

Lab-CA signed. **New leaf.** Do not reuse LabMITM or LabLDAP certificates.

Folded: [docs/01-architecture.md](01-architecture.md), [docs/11-deployment.md](11-deployment.md), [docs/20-threat-model.md](20-threat-model.md).

### 7. labinfo `connection` block for the IdP

Catalog must carry issuer, OIDC discovery, SAML metadata, JWKS, client_id, redirect URIs, dest port 443.

Folded: [docs/11-deployment.md](11-deployment.md), slice 11.

### 8. Data-plane login/consent/MFA UI is required and distinct from the operator SPA

`spec.ui.enabled: false` 404s the operator SPA only. Login pages stay up. Mira reviews the SPA after first UI implementation; do not build UI now.

Folded: [ADR 0009](adr/0009-data-plane-login-ui.md), [docs/02-protocols.md](02-protocols.md).

## Sweep 2 — pending

Run after these documents are on `main`. Suggested questions (non-normative until sweep 2 writes them down):

- Is the generic group safety-cap number frozen?
- Is SAML EntityID exactly the issuer?
- Where does 443 occupancy preflight live (`mcplab` vs `labsso`)?
- Session-knob concurrency vs snapshot revision.
- PHC algorithm allow-list.
- Entra overage numeric threshold for the lab stub.
- Management TLS in slice 1 vs loopback HTTP only.

Sweep 2 must not silently reverse sweep 1.
