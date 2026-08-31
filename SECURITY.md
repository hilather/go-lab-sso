# Security Policy

## Security posture

LabSSO is a laboratory Identity Provider. A data-plane HTTPS listener can mint tokens, serve JWKS, and accept passwords. A management API can rewrite clients, users, sessions, and vendor clothes. This is **not** a production IdP threat model: the intended deployment is an isolated lab. Secure defaults are still mandatory so a lab host is not an open token mint on the public Internet.

Status: **design (not implemented)**. There is no supported binary or image yet.

## Reporting vulnerabilities

Report security vulnerabilities through [GitHub private vulnerability reporting](https://github.com/hilather/go-lab-sso/security/advisories/new) on [`hilather/go-lab-sso`](https://github.com/hilather/go-lab-sso). Do not file vulnerabilities in the public issue tracker before coordinated disclosure.

Include, when possible: affected version or commit, deployment mode (container flags, published 443, management bind, auth profile), a minimal reproduction, and impact (open token mint, secret leak, privilege escalation, vendor-hostname impersonation). Do not attach live tokens, password files, or production configs.

We will acknowledge the report, assess severity, and coordinate a fix and disclosure window. Do not request a CVE assignment in a public issue.

## Supported versions

| Version | Supported |
|---|---|
| Design documents on `main` | Yes — documentation and YAML sketches only |
| Any claimed `labsso` binary or image | No — not implemented |
| Any unreleased fork or modified image | No |

After a human tags a first implementation candidate, that tag becomes the supported line. There is no predecessor application version.

## Minimum security requirements (design)

- Management binds to loopback or a dedicated management network by default.
- REST and MCP share authentication, authorization, audit, and rate limiting.
- Secrets are file refs, never inline in bootstrap YAML committed to Git.
- Containers run as non-root UID 65532 with a read-only filesystem and no Linux capabilities.
- One exact issuer; vendor profiles are clothes, not hostname clones of Microsoft / Okta / Ping / ADFS / Duo / SiteMinder / Shibboleth.
- Data-plane login HTML is distinct from the operator SPA. `spec.ui.enabled: false` does not disable login pages.
- Operator SPA never stores tokens in `localStorage`.
- Customer-config import is an allow-list rewriter with hardened XML (no external entities), not a silent live merge.
- `allowLegacyClients: true` skips only the MCP HTTP protocol-version pin; it does not weaken bearer auth.

See [docs/08-security-architecture.md](docs/08-security-architecture.md) for the complete design and [docs/20-threat-model.md](docs/20-threat-model.md) for the lab-only threat model.
