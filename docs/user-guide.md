# LabSSO user guide

How to run LabSSO, write the YAML file, and load or change state through the CLI, REST, and MCP. Design history and contributor rules live elsewhere.

## Contents

- [What LabSSO is](#what-labsso-is)
- [Install and run](#install-and-run)
- [How state works](#how-state-works)
- [Write the YAML](#write-the-yaml)
- [CLI loading](#cli-loading)
- [REST state APIs](#rest-state-apis)
- [MCP state tools](#mcp-state-tools)
- [Talk to the IdP](#talk-to-the-idp)
- [Day-to-day recipes](#day-to-day-recipes)
- [What not to expect](#what-not-to-expect)
- [Where to go next](#where-to-go-next)

## What LabSSO is

LabSSO is a laboratory identity provider. You give it a YAML file that describes the issuer, the vendor look, users, groups, and clients. It serves OIDC, SAML, and WS-Fed on HTTPS, and a management API on a separate port.

Use it when a product under test needs a fake-but-faithful SSO neighbor: the issuer string is exact, the paths and claims can look like Entra or Okta, and you can reset the box back to Git.

Do not use it as production SSO.

## Install and run

### From source

```bash
git clone https://github.com/hilather/go-lab-sso.git
cd go-lab-sso
go run ./cmd/labsso version
```

Validate the bundled minimal document, then serve it. Secret paths in that file are relative to the repo root.

```bash
go run ./cmd/labsso validate --config testdata/config/valid/minimal.yaml
go run ./cmd/labsso serve --config testdata/config/valid/minimal.yaml
```

`minimal.yaml` has no users. For file-backed TOTP without enroll:

```bash
go run ./cmd/labsso serve --config testdata/config/valid/totp-alice.yaml
```

That document is a full copy of minimal plus alice (`passwordRef` + `totpSecretRef`), a public lab client, and `auth.mfa.mode: always`. The seed is [testdata/secrets/users/alice.totp](../testdata/secrets/users/alice.totp) (RFC 6238 Appendix B secret). Empty-bootstrap path: apply a **client and** a user, `POST /v1/users/{id}/totp:enroll`, then `POST /v1/auth/mfa` with `mode: always`. The process never writes `.totp` files.

You should see something like:

```text
labsso serve https=:10443 management=:8080 issuer=https://lab.example.net
```

### Useful flags

| Flag | Meaning |
|---|---|
| `--config` | Bootstrap YAML. Required for `validate`, `canonicalize`, and `serve`. |
| `--base-dir` | Directory used to resolve relative secret refs. Defaults to the current working directory. |
| `--https-listen` | Override `spec.listeners.https.address`. Cannot be `off`. |
| `--management-listen` | Override the management bind, or `off` to skip REST/MCP/UI. |
| `--shutdown-timeout` | Graceful shutdown window. Default `5s`. |

### Container

```bash
docker compose -f examples/compose.yaml up --build
```

The example publishes host `443` to container `:10443` and management to `127.0.0.1:8080`. The image is scratch, UID `65532`, read-only root, all capabilities dropped.

### First checks

```bash
go run ./cmd/labsso healthcheck --url http://127.0.0.1:8080/v1/health/ready
curl -sS http://127.0.0.1:8080/v1/version
curl -sS http://127.0.0.1:8080/v1/capabilities
```

From `127.0.0.1` you can call management without a bearer. From anywhere else send:

```text
Authorization: Bearer <contents of spec.access.tokenRef>
```

The sample token file is `testdata/secrets/labsso-token`.

## How state works

Think of three layers:

1. **The file** — desired state in Git. LabSSO only reads it.
2. **The snapshot** — compiled, immutable view the data plane serves.
3. **The overlay** — live edits from plan/apply and some tunables. Gone on restart or reset.

Two hashes keep you honest:

- `bootstrapRevision` — SHA-256 of the canonical export of the file (secret values are not part of the hash).
- `runtimeRevision` — hash of the live overlay.

`drifted` is true when those two differ. `generation` goes up on a successful apply or reset.

Writes that change desired state must send the revision they planned against. If someone else applied first, you get `409` / `revision_conflict` and nothing swaps.

## Write the YAML

One document per process:

```yaml
apiVersion: labsso.dev/v1alpha1
kind: LabSSO
```

Unknown fields fail. That is deliberate. Copy [testdata/config/valid/minimal.yaml](../testdata/config/valid/minimal.yaml) and add only fields you understand.

### Listeners and issuer

```yaml
spec:
  listeners:
    https:
      address: ":10443"
      certRef: testdata/secrets/tls/tls.crt
      keyRef: testdata/secrets/tls/tls.key
    management:
      address: ":8080"
      restPath: /v1
      mcpPath: /mcp
      mcp:
        allowLegacyClients: true
  issuer: "https://lab.example.net"
```

`certRef` / `keyRef` are the TLS leaf. The OIDC/SAML signing key is separate: `spec.signing.keyRef`.

If `LAB_PUBLIC_HOST` is set, `spec.issuer` must match the derived public URL (`https://$LAB_PUBLIC_HOST` on port 443, otherwise the port is included). Standalone `serve` without that env uses the YAML issuer as written.

Set `allowLegacyClients: true` if an older MCP client (MCPJungle) will connect. That skips the HTTP protocol-version pin. It does not skip auth.

### Vendor clothes

```yaml
spec:
  profile:
    vendor: entra
    tenantId: "00000000-0000-0000-0000-000000000001"
```

| `vendor` | Look |
|---|---|
| `generic` | Plain OIDC |
| `entra` | Entra-shaped paths and claims |
| `okta` | Okta-shaped paths and claims |
| `ping` | Ping |
| `adfs` | ADFS, including WS-Fed clothes |
| `google` | Google-shaped clothes |
| `keycloak` | Keycloak; realm is `metadata.name` |
| `iam-identity-center` | IAM Identity Center |

LabSSO does not bind `login.microsoftonline.com` or `okta.com`. The hostname is yours. The clothes are paths, cookies, and claims.

Ready-made fixtures: [testdata/config/valid/](../testdata/config/valid/).

### Protocols

```yaml
spec:
  protocols:
    oidc:
      enabled: true
    saml:
      enabled: false
    wsfed:
      enabled: false
```

Disabled protocols do not register routes. SAML off means `/saml/metadata` and `/saml/sso` are 404. WS-Fed off means `/wsfed/*` is 404.

SAML or WS-Fed on requires an RSA signing key. OIDC-only may use ECDSA.

### Users, groups, clients

Membership lives on the user: `groupIds`. There is no `memberUserIds` field on a group. A document that includes it is rejected.

```yaml
spec:
  users:
    - id: alice
      username: alice
      email: alice@lab.example.net
      passwordRef: testdata/secrets/users/alice.password
      groupIds: [engineers]
      enabled: true
  groups:
    - id: engineers
      name: Engineers
  clients:
    - id: app-1
      clientId: app-1
      redirectURIs:
        - https://sut.example.net/callback
      public: true
      scopes: [openid, profile]
      preConsent: true
```

Confidential clients use a `secretRef` file, not an inline secret. Passwords are either plaintext file refs (`passwordRef`) or Argon2id PHC files (`passwordHashRef`).

Usernames must be unique. Dangling `groupIds` fail validation.

### Auth, overage, UI

```yaml
spec:
  auth:
    sessionTTL: 1h
    mfa:
      mode: never   # never | always | force-fail
  groupOverage:
    entraGraphStub: true
    oktaFailAt: 100
    genericCap: 200
  ui:
    enabled: true
```

`ui.enabled: false` hides the operator page at `GET /`. Login HTML on the data plane stays up.

### Secrets

Every secret is a file path. The loader reads the file into memory and never writes the value back into export YAML.

| Ref | Purpose |
|---|---|
| `spec.access.tokenRef` | Management bearer |
| `spec.listeners.https.certRef` / `keyRef` | TLS leaf |
| `spec.signing.keyRef` | Token and assertion signing key |
| `users[].passwordRef` or `passwordHashRef` | Login password |
| `clients[].secretRef` | Confidential client secret |

Invalid examples worth reading: [testdata/config/invalid/](../testdata/config/invalid/).

## CLI loading

### Validate

```bash
go run ./cmd/labsso validate --config testdata/config/valid/minimal.yaml
# ok revision=sha256:...
```

This is the same pipeline `serve` uses before it binds ports. A failing validate means `serve` will refuse to start.

### Canonicalize

```bash
go run ./cmd/labsso canonicalize --config testdata/config/valid/minimal.yaml
go run ./cmd/labsso canonicalize --config testdata/config/valid/minimal.yaml --format json
```

Defaults are filled in. Secret values stay as refs. This is the shape export produces for Git.

## REST state APIs

Base URL: `http://127.0.0.1:8080/v1` with the sample compose / YAML.

### `GET /v1/state`

Returns the live overlay plus revisions.

```bash
curl -sS http://127.0.0.1:8080/v1/state
```

Typical fields: `bootstrapRevision`, `runtimeRevision`, `generation`, `drifted`, `canonical`.

### `POST /v1/state:validate`

Send a document. LabSSO decodes and validates it. Live state does not change.

### `GET /v1/state:export`

```bash
curl -sS 'http://127.0.0.1:8080/v1/state:export?format=yaml' -o lab.yaml
```

Commit that file if you want Git to catch up with a live apply.

### `POST /v1/changes:plan` and `POST /v1/changes:apply`

Mutations are typed operations, not JSON Patch:

```text
op: add | update | remove
target.kind: client | user | group | profile | protocols | auth | groupOverage | ...
```

```json
{
  "expectedRevision": "sha256:…",
  "reason": "add confidential client",
  "operations": [
    {
      "op": "add",
      "target": {"kind": "client", "id": "app-1"},
      "value": {
        "id": "app-1",
        "clientId": "app-1",
        "redirectURIs": ["https://sut.example.net/callback"],
        "secretRef": "testdata/secrets/clients/app.secret"
      }
    }
  ]
}
```

Plan returns a diff and impact. Apply runs plan, then swaps the snapshot if the revision still matches.

Send the revision in the body, as `If-Match`, or as `X-LabSSO-Expected-Revision`. Add `Idempotency-Key` if you retry.

A conflict looks like:

```json
{
  "type": "urn:labsso:error:revision-conflict",
  "title": "State revision conflict",
  "status": 409,
  "code": "revision_conflict",
  "retryable": true
}
```

### `POST /v1/state:reset`

Re-reads the mounted bootstrap, compiles, and swaps only if that compile succeeds. A broken file leaves the live snapshot alone. The file on disk is never written.

### Import

```text
POST /v1/import:plan
POST /v1/import:apply
```

Kinds: `entra-manifest`, `okta-app`, `saml-metadata`, `oidc-client`. The response is a `labsso.dev/v1alpha1` fragment plus `imported.unmapped`. Nothing is silently merged into live state. See [docs/09-customer-config-import.md](09-customer-config-import.md).

### Tunables that are not Git state

These change runtime behavior and die on reset unless noted:

| Endpoint | Effect |
|---|---|
| `POST /v1/sessions/{id}:expire` | Drop one login session |
| `POST /v1/sessions:expire-all` | Drop all sessions |
| `POST /v1/auth/mfa` | Set `mfa.mode` (merge; keeps `sessionTTL`) |
| `POST /v1/users/{id}/totp:enroll` | Overlay TOTP seed (shown once) |
| `POST /v1/users/{id}/totp:clear` | Drop overlay; file ref remains |
| `POST /v1/tunables/auth:force-fail` | Next login fails |
| `POST /v1/tunables/consent:force` | Ignore pre-consent shortcuts |
| `POST /v1/tunables/token:pause` | Token endpoint pauses; authorize, JWKS, discovery, login stay up |
| `POST /v1/tunables/token:resume` | Clear the pause |
| `POST /v1/tunables/token:mint` | Issue tokens for a user/client without a browser |
| `POST /v1/tunables/error:inject` | Inject the next protocol error |

These **do** change desired state and need `expectedRevision`:

| Endpoint | Effect |
|---|---|
| `POST /v1/tunables/vendor:swap` | Change clothes; pending codes and sessions are purged |
| `POST /v1/tunables/overage:set` | Merge group-overage knobs |
| `POST /v1/tunables/client/redirect:rewrite` | Rewrite a client's redirect URIs |

## MCP state tools

Same operations, different door. Streamable HTTP at `/mcp`. Protocol pin `2026-07-28`. Bearer auth only; cookies are ignored.

| Tool | REST twin |
|---|---|
| `sso_state_get` | `GET /v1/state` |
| `sso_state_validate` | `POST /v1/state:validate` |
| `sso_change_plan` | `POST /v1/changes:plan` |
| `sso_change_apply` | `POST /v1/changes:apply` |
| `sso_state_export` | `GET /v1/state:export` |
| `sso_state_reset` | `POST /v1/state:reset` |
| `sso_schema_get` | `GET /v1/schema/config` |
| `sso_auth_mfa_set` | `POST /v1/auth/mfa` |
| `sso_user_totp_enroll` | `POST /v1/users/{id}/totp:enroll` |
| `sso_user_totp_clear` | `POST /v1/users/{id}/totp:clear` |

Resources: `labsso://state`, `labsso://capabilities`, `labsso://status`, `labsso://schema/config`.

Usual agent loop: read state → plan → review the diff → apply with the revision you just saw → export if Git should move.

## Talk to the IdP

With the sample config and `serve` running:

- Issuer: `https://lab.example.net` (or whatever you set; locally the listener is still `:10443`)
- Discovery lives on the data-plane HTTPS listener under the vendor clothes
- Login HTML is on that same listener
- Operator UI is `http://127.0.0.1:8080/` when `ui.enabled` is true

Trust the lab TLS leaf in `testdata/secrets/tls/tls.crt` for local browsers and curl (`curl -k` only in a throwaway lab).

## Day-to-day recipes

**Add a user live, then put it in Git**

1. `GET /v1/state` and keep `runtimeRevision`.
2. `POST /v1/changes:apply` with `op: add`, `target.kind: user`.
3. `GET /v1/state:export?format=yaml` and commit the file.
4. Next deploy mounts the new file. Reset is then a no-op.

**Throw away a messy lab**

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/state:reset
```

Or restart the process.

**Switch Entra clothes without editing YAML first**

`POST /v1/tunables/vendor:swap` with `vendor`, `expectedRevision`, and a reason. Export afterward if you want the file to match.

## What not to expect

- A database. Memory only.
- LabSSO writing back to Git.
- Hostname clones of public IdPs.
- Multi-replica session consistency.
- SCIM in this binary.

## Where to go next

- [Architecture](01-architecture.md)
- [Protocols](02-protocols.md)
- [Vendor clothes](03-vendor-profiles.md)
- [YAML and revisions](04-state-and-configuration.md)
- [REST](06-rest-api.md)
- [MCP](07-mcp-api.md)
- [Deployment](11-deployment.md)
