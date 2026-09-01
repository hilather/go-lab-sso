# Threat Model

Status: design (not implemented)
Owners: Security
Last reviewed: 2026-09-01
Related ADRs: 0002, 0005, 0006, 0008, 0011

## Scope

This is a **lab-only** threat model. LabSSO is not a production Identity Provider. We do not claim SOC2, FedRAMP, or IdP certification. We still refuse to be an accidental open token mint on a laptop’s public interface.

Out of scope: nation-state targeting of a lab VM, physical theft of a lab disk, and “make this safe to put on the Internet as a company’s real SSO.”

## Assets

| Asset | Why it matters in a lab |
|---|---|
| Signing keys (file refs) | Mint tokens SUTs will trust |
| User password files | Lab credentials often reused by operators by mistake |
| Management bearer | Rewrite clients and mint arbitrary claims |
| Authorization codes / refresh handles | Session theft inside the lab |
| Bootstrap YAML | Desired state; no secrets inline |
| labsso-tls leaf | HTTPS identity of the issuer |
| Import blobs | Untrusted customer XML/JSON |
| TOTP overlay seeds | One-shot enroll on a tool result; memory until reset |

## Actors

- **Lab operator / agent** — intended user of REST/MCP. Powerful by design.
- **SUT / browser on data plane** — intended user of OIDC/SAML. Not a management actor.
- **Confused SUT** — follows vendor hostname; we must not impersonate that hostname.
- **Adjacent process on the lab host** — nginx/caddy holding 443; compose stacks.
- **Remote Internet** — should not reach management; data plane may be published on a lab IP.
- **Malicious import file** — XXE, huge entities, unexpected keys.

## Threats and mitigations

| ID | Threat | Mitigation |
|---|---|---|
| T1 | Open management on 443 | Management is never 443; dest-443 is data plane only |
| T2 | Open token mint without auth on management tunables | Bearer + scopes; mint is `sso.tunables` |
| T3 | Hostname impersonation of Entra/Okta | Clothes only; one exact issuer; no vendor-cloud TLS |
| T4 | XXE on SAML metadata import | Hardened XML; tests |
| T5 | Secrets in Git | File refs; export redacts values |
| T6 | Process writes bootstrap | Forbidden; reset rereads |
| T7 | MCP bypasses auth via allowLegacyClients | Knob skips protocol pin only |
| T8 | SPA token theft via localStorage | Cookie + CSRF only |
| T9 | `ui.enabled: false` kills login | SPA 404 only |
| T10 | Foreign occupant on 443, silent remap | Preflight fail closed; named escapes |
| T11 | Pause-token taken as total outage | Other routes stay up; still authorized |
| T12 | Reused LabMITM cert as IdP | New `secrets/labsso-tls` leaf required |
| T13 | Flattening onto LabLDAP, unexpected binds | LDAP out of v1 |
| T14 | Keycloak sidecar as hidden IdP | ADR 0002; from scratch |
| T15 | Clock attacks via in-process time bus | No LabNTP bus; process clock; skew on SUT |
| T16 | Graph stub egress to Microsoft | Stub is local only |
| T17 | PKCE downgrade | `plain` rejected |
| T18 | Wildcard redirect URIs | Exact match in v1 |
| T19 | Overlay TOTP seed in export/audit/MCP resources | Enroll returns secret once on the tool/REST result; leak tests hunt that secret |
| T20 | Incomplete MFA cookie reused after `never`→`always` | `ExpireIncompleteMFA` drops sessions, codes, and refresh with `MFACompleted=false` |

## Residual lab risks (accepted)

- Loopback unauthenticated management (`dev-loopback-unauth`) on a shared workstation.
- Data-plane HTTPS published on a lab IP: anyone on that L2 can attempt passwords. Use lab passwords only.
- In-memory sessions die on restart (availability, not confidentiality).
- Single process: compromise of the container is compromise of the IdP. That is the lab model.

## What this model does not do

- Threaten “break Entra in production.”
- Require HSM or KMS in v1 (file-ref keys on tmpfs/secret mount).
- Require durable audit acknowledgment for tunables (in-memory ring).

## Review triggers

- First implementation of tunables that mint arbitrary claims.
- Any proposal to listen management on 443.
- Any proposal to present a vendor-cloud hostname.
- Integrator pin (new leaf, token mode 0o644, labinfo connection block).
