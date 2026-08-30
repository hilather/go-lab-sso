# ADR 0005: Vendor clothes, not hostname clones

Status: Accepted for design
Date: 2026-08-30
Last reviewed: 2026-08-30

## Context

A lab that “is Entra” tempts people to put `login.microsoftonline.com` on a hosts file or MITM TLS. That is a different product (and a legal/operational mess). SUTs in this family are pointed at `LAB_PUBLIC_HOST`. They already speak HTTPS to an IdP URL the operator chooses.

Vendor differences that matter in a lab are path templates, claim names (`oid`/`tid`/`ver` vs Okta groups), cookies, error JSON, and group-overage policy.

## Decision

One **exact** issuer string derived from `LAB_PUBLIC_HOST` plus the published HTTPS port (omit the port iff 443). `spec.profile.vendor` selects **clothes** on that issuer: authorize/token/jwks/userinfo/logout path templates, claim names, error JSON, cookies, group-overage policy.

Entra, Okta, Ping, ADFS, Google, Keycloak, and IAM Identity Center are clothes. They are **not** hostname clones of `login.microsoftonline.com` / `okta.com` / vendor CDNs.

Default ship: `generic`. Entra/Okta opt-in via YAML.

## Consequences

- Discovery `iss` is stable across clothes swaps.
- SUTs must be configured with the lab issuer, not vendor hostnames.
- TLS leaf is `LAB_PUBLIC_HOST` (`secrets/labsso-tls`), never a vendor CN.
- Clothes swap invalidates in-flight codes that targeted old paths.
- We will not serve real Microsoft Graph; Entra overage uses a local stub.

## Alternatives considered

- Hosts-file impersonation + forged vendor certs: rejected (scope, ethics, LabMITM confusion).
- Separate hostnames per vendor (`entra.lab`, `okta.lab`): extra DNS and certs; still not vendor clouds; adds no protocol value. One issuer is enough.
- Separate processes per vendor: operational cost, dual registries.

## Review triggers

Review this decision when its assumptions no longer hold, a major protocol or library change occurs, or a new requirement conflicts with an invariant.
