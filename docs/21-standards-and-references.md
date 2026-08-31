# Standards and References

Status: through VEN-003 implemented; SCIM design-only
Owners: Protocols, MCP
Last reviewed: 2026-08-30

## Purpose

Normative protocol pins and reading list. LabSSO implements **enough** of these for a laboratory IdP. It does not claim certification.

## OpenID Connect and OAuth 2.0

| Document | Role in LabSSO |
|---|---|
| [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) OAuth 2.0 | Authorization code, token errors (generic clothes) |
| [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750) Bearer | Access token usage by SUTs |
| [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636) PKCE | Required S256; `plain` rejected |
| [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252) Native apps | Redirect URI exact-match still applies |
| [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) | `id_token`, UserInfo, `nonce`, logout |
| [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) | `/.well-known/openid-configuration` plus vendor path clothes |
| [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517) / [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) JWK / JWT | JWKS and signed tokens |
| [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) AS metadata | Informative; OIDC discovery is primary |

Implicit and hybrid flows are rejected. Client-credentials and device code are out of the first OIDC slice.

## SAML 2.0 (slice 6)

| Document | Role |
|---|---|
| [OASIS SAML 2.0 Core](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf) | Assertions, AuthnRequest |
| [SAML 2.0 Bindings](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf) | HTTP-Redirect, HTTP-POST |
| [SAML 2.0 Profiles](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf) | SP-initiated SSO |
| [SAML 2.0 Metadata](https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf) | IdP metadata |

XML: disable external entities. No DTD fetch.

## WS-Federation (slice 9)

WS-Federation 1.2 passive profile, clothed as ADFS. Informative until that slice.

## MCP

| Pin | Value |
|---|---|
| Protocol | **2026-07-28** |
| Go SDK | `github.com/modelcontextprotocol/go-sdk` **v1.7.0** |
| Transport | Streamable HTTP `/mcp`, stateless |
| Legacy | `spec.management.mcp.allowLegacyClients: true` required for MCPJungle |

MCP specification: [modelcontextprotocol.io](https://modelcontextprotocol.io).

## Language and deployment

| Pin | Value |
|---|---|
| Language | **Go 1.26** when implemented |
| Module | `github.com/hilather/go-lab-sso` |
| Binary | `labsso` |
| Image | `ghcr.io/hilather/labsso` |
| UID | 65532 |
| License | Apache-2.0 |

Prefer Go standard library. Hide protocol SDKs behind adapters.

## Family documents

- [hilather/go-lab-dns](https://github.com/hilather/go-lab-dns) — snapshot, registry, MCP pin, UI cookie rules.
- [hilather/go-lab-mitmproxy](https://github.com/hilather/go-lab-mitmproxy) — dest-443 contrast (LabMITM must not take 443).
- [hilather/mcp-integration-lab](https://github.com/hilather/mcp-integration-lab) — integrator last.
- [hilather/go-lab-ldap-mcp](https://github.com/hilather/go-lab-ldap-mcp) — peer directory; do not flatten.
- [hilather/go-jenkins-mcp](https://github.com/hilather/go-jenkins-mcp) — **out of scope**.

## Vendor clothes (informative, not hostname targets)

Documentation from Microsoft Entra, Okta, Ping, ADFS, Google, Keycloak, AWS IAM Identity Center, Duo SSO, Broadcom SiteMinder, and Shibboleth IdP informs **path and claim clothes** only. LabSSO does not implement those vendors’ control planes and does not serve their hostnames.

## Review triggers

- MCP protocol or official Go SDK major pin change.
- OIDC / SAML spec revisions that change `iss` or PKCE requirements.
- New vendor clothes row.
