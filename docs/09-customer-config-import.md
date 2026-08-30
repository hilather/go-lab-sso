# Customer Config Import

Status: IMP-001 implemented (allow-list rewriter + redirect:rewrite)
Owners: Configuration, Application, Security
Last reviewed: 2026-08-30
Related ADRs: 0008

## Problem statement

Operators want to drop a customer Entra app-registration manifest, Okta app JSON, SAML metadata, or OIDC client JSON into the lab and get something they can commit. Vendor blobs are messy, versioned independently, and full of keys LabSSO must not treat as schema. Import is an **allow-list rewriter**, not KnownFields on the vendor document.

## Goals

- Inputs: Entra app registration manifest, Okta app JSON, SAML metadata XML, OIDC client JSON.
- Output: a `labsso.dev/v1alpha1` fragment the operator commits (clients, maybe groups/claims hints).
- Unknown keys dropped or parked in `imported.unmapped`.
- Hardened XML (no external entities).
- Import is a management **plan/apply** operation, not a silent live merge.
- REST and MCP twins (`import:plan` / `import:apply`).

## Non-goals

- Validating vendor blobs with LabSSO KnownFields (that would reject almost every real export).
- Calling Microsoft Graph or Okta Management APIs to pull the blob.
- Implementing the full vendor admin model.
- Auto-committing Git.
- Merging imported users/passwords from production directories.

## Allow-list (design)

Each input kind has an explicit map. Keys not on the list never become `spec` fields.

### Entra app registration manifest

| Source (illustrative) | Target fragment |
|---|---|
| `appId` / `id` | `spec.clients[].clientId` (and user-supplied `id` if missing) |
| `replyUrlsWithType` / `redirectUris` | `redirectURIs` (https only; reject `urn:` unless a later ADR) |
| `oauth2AllowIdTokenImplicitFlow` etc. | ignore or unmapped; implicit stays rejected |
| `groupMembershipClaims` | hint toward `groups` scope / overage |
| Everything else | `imported.unmapped` |

### Okta app JSON

| Source | Target |
|---|---|
| `client_id` | `clientId` |
| `redirect_uris` / `settings.oauthClient.redirect_uris` | `redirectURIs` |
| `label` | metadata annotation on the client |
| Sign-on mode SAML vs OIDC | protocol enablement is **not** silently flipped; plan warns |
| Everything else | `imported.unmapped` |

### SAML metadata XML

| Source | Target |
|---|---|
| SPSSODescriptor ACS URLs | `spec.clients[].saml.acsURLs` (exists after SAML-001); empty ACS → `redirectURIs` |
| EntityID | `spec.clients[].saml.entityID` |
| Keys | file-ref suggestion only; do not copy PEMs into the fragment. A source blob that contains a cert is still imported (entityID + ACS). |
| Entity descriptors with DTD / XXE | **reject** |

### OIDC client JSON

| Source | Target |
|---|---|
| `client_id` | `clientId` |
| `redirect_uris` | `redirectURIs` |
| `token_endpoint_auth_method` | public vs `secretRef` required |
| `jwks` / PEM / `client_secret` | drop + warn; never copy into the fragment or `imported.unmapped` |
| Everything else | `imported.unmapped` |

## Output fragment

```yaml
apiVersion: labsso.dev/v1alpha1
kind: LabSSO
metadata:
  name: lab
  annotations:
    labsso.dev/imported-from: entra-manifest
spec:
  clients:
    - id: imported-app
      clientId: "11111111-2222-3333-4444-555555555555"
      redirectURIs:
        - https://sut.example.net/callback
imported:
  unmapped:
    displayName: Contoso App
    signInAudience: AzureADMyOrg
```

`imported` is **not** part of the fail-closed `LabSSO` spec schema. It rides on the import response and optionally as an annotation blob the operator may delete before commit. Applying import merges only allow-listed `spec` paths into canonical. `imported.unmapped` is never decoded as spec fields.

## Plan / apply

```text
POST /v1/import:plan
  -> parse + harden
  -> allow-list rewrite
  -> produce fragment + unmapped + warnings
  -> optional dry-run merge into a candidate snapshot
  -> return diff

POST /v1/import:apply
  -> same as plan
  -> expectedRevision
  -> atomic swap
```

MCP: `sso_import_plan`, `sso_import_apply`.

The operator is expected to export and commit. Apply without export is allowed (memory overlay) and drifted.

## XML hardening

- Reject DTDs and external entities.
- Do not resolve `SYSTEM` / `PUBLIC` identifiers.
- Cap expansion and document size.
- Use a hardened decoder (stdlib with DTD disabled, or a pinned library behind an adapter).
- Tests include a classic XXE fixture that must not read `/etc/passwd` or egress.

## Failure modes

- Unknown input kind: reject.
- Empty allow-list result (no client_id, no redirect): reject with remediation.
- XXE / billion-laughs: reject, no side effects.
- Apply revision conflict: no swap.
- Implicit-flow-only Entra app: plan warning; LabSSO still will not enable implicit.

## Testing strategy

- One golden per input kind (happy).
- Unmapped keys preserved in `imported.unmapped` and absent from `spec`.
- XXE and oversize XML.
- REST/MCP parity.
- Round-trip: apply fragment then export contains clients, not vendor blob keys.

## Compatibility implications

Allow-list additions are additive. Removing a mapped key is breaking for importers. Input kind names are a public enum.

## Implemented (IMP-001)

`POST /v1/import:plan` / `import:apply` and MCP twins. `imported.unmapped` is in the **response** only (not a spec KnownFields field). `POST /v1/tunables/client/redirect:rewrite` merges `client.redirectURIs` (`sso.tunable.redirect.rewrite`, `expectedRevision`).

## Open questions

- Whether `imported.unmapped` is persisted on canonical (annotation) or response-only. Implemented default: response-only.
