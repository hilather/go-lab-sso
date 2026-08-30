# Container Deployment

Status: design (not implemented)
Owners: Deployment, Operations, Security
Last reviewed: 2026-08-30
Related ADRs: 0003, 0006, 0007

## Goals

- Reproducible, non-root, read-only container deployment.
- Ephemeral process state.
- Native **host TCP 443** → container unprivileged HTTPS (e.g. `:10443`).
- Management on a high port, not 443.
- Fail-closed preflight when a non-lab process holds 443.
- Predictable startup, reset, and shutdown.

## Non-goals

- Copying LabMITM’s “don’t use 443” rule. LabSSO is dest-443 (integrator rule 15). It is not a forward proxy.
- A LabNTP sidecar or time bus.
- A runnable Compose file in this design landing (the sketch is marked NOT runnable).
- Reusing LabMITM or LabLDAP certificates.

## Image (when implemented)

Image: **`ghcr.io/hilather/labsso`**. Multi-stage build to **scratch** or distroless:

- One static `labsso` binary.
- CA certificates if the process ever fetches (import does not fetch).
- `LICENSE` and OCI labels (`org.opencontainers.image.licenses=Apache-2.0`).
- No shell. Healthcheck exec `/labsso healthcheck`.
- User numeric **`65532:65532`**.
- Runtime: `read_only: true`, `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, tmpfs `/tmp`.

Do not add a Dockerfile in this repo until FND/DEP that actually builds the binary. A Dockerfile that claims to build a server while `go.mod` is absent is a lie.

## Ports

| Role | Host | Container | Default? |
|---|---|---|---|
| Data-plane HTTPS | **443** | `:10443` | Yes |
| Management REST+MCP+SPA | 18443 or 8080-family, prefer `127.0.0.1` | `:8080` | Yes |
| Escape `LABSSO_HTTPS_PORT` | non-443 | still unprivileged | **No** — operator escape only |

`LABSSO_HTTPS_PORT` lives in `profile.env` when preflight cannot free 443. SUTs that cannot set dest port **cannot** follow the escape. Document that in the preflight error.

`EACCES` / `EPERM` on the **container** bind of `:10443` is **not** occupancy. dockerd can publish host 443 to an unprivileged process. Occupancy is “something else already holds host 443.”

## Preflight (fail closed)

Host-443 occupancy is an **integrator / `mcplab`** check (rule 15 class: every published host port; `internal/lab/ports.go` when INT-001 lands). The LabSSO process does **not** inspect host `:443` from inside an unprivileged container. Standalone `labsso serve` fail-closes on **its** listen address only.

Before compose up that expects dest-443:

1. Detect whether host TCP 443 is held by a **non-lab** process.
2. If yes, **fail closed**. Do not silently switch ports.
3. Error text **must** name the fix:

   - stop/disable the occupant (nginx, caddy, apache, another compose stack), **or**
   - extra IP for `LAB_PUBLIC_HOST`, **or**
   - escape `LABSSO_HTTPS_PORT` (and warn that SUTs which cannot set dest port cannot follow).

The appliance still **documents** that three-fix text and must emit it when it can detect a listen/publish failure that is not container-bind `EACCES`/`EPERM`. Lab-owned occupants (this stack’s previous LabSSO) may be replaced by the same compose project; do not treat “our own published 443” as a foreign occupant after a clean down.

## Issuer derivation

```text
if published HTTPS port == 443:
  issuer = https://$LAB_PUBLIC_HOST
else:
  issuer = https://$LAB_PUBLIC_HOST:$LABSSO_HTTPS_PORT
```

YAML `spec.issuer` must match when derivation env is present (see [docs/04-state-and-configuration.md](04-state-and-configuration.md)).

## CLI (when implemented)

```text
labsso serve --config=/etc/labsso/config.yaml
            [--https-listen ADDR] [--management-listen ADDR|off]
            [--shutdown-timeout 5s] [--pid-file /tmp/labsso.pid]
labsso validate --config=...
labsso canonicalize --config=... [--format yaml|json]
labsso healthcheck --url=http://127.0.0.1:8080/v1/health/ready
labsso version
```

The process never writes `--config`.

## Compose sketch

See [examples/compose.sketch.yaml](../examples/compose.sketch.yaml). It is **not runnable** until the image exists. Shape:

- `443:10443` for HTTPS.
- `127.0.0.1:8080:8080` for management.
- `user: "65532:65532"`.
- read-only, cap_drop ALL, tmpfs `/tmp`.
- bootstrap YAML and token file mounts.

## Integrator last (mcp-integration-lab)

Documented here so agents do not invent an overlay. **Do not implement in mcp-integration-lab from this repo.**

LabMITM-style service in the **main** `docker-compose.yaml` (not an overlay):

- BOM: vendor pin, `profile.env`, `publishedPortSpecs`, `CanonicalReloadApps`.
- `secrets.go`: token **0o644** for UID 65532.
- `register.go`.
- labinfo catalog `connection` block: issuer, OIDC discovery, SAML metadata, JWKS, client_id, redirect URIs, dest port **443**.
- mcpjungle `servers/labsso.json`.
- New TLS leaf under `secrets/labsso-tls/` (lab-CA signed; **new leaf**, do not reuse LabMITM or LabLDAP cert).
- `allowLegacyClients: true`.

## Kubernetes guidance (later)

- One replica for runtime mutation semantics.
- Service dest 443 / TLS.
- Isolate management with NetworkPolicy.
- Non-root, read-only, drop caps.
- Do not imply multi-replica session consistency.

## Startup and shutdown

Startup validates and compiles before reporting ready. Graceful shutdown:

1. Mark unready.
2. Stop accepting new management mutations.
3. Stop accepting new HTTPS handshakes after the deadline policy.
4. Complete or abandon requests within the shutdown deadline.
5. Flush bounded telemetry.
6. Exit. Sessions die. Bootstrap file untouched.

## Time

Process clock. No LabNTP sidecar, no `extra_hosts` for a time bus, no privileged `SYS_TIME`.

## Failure modes

- Invalid ConfigMap / YAML: do not bind.
- Container recreation: runtime drift disappears.
- Host 443 conflict: preflight fails with the three named fixes.
- Escape port used: issuer includes the port; SUTs that hardcode dest 443 break — that is expected.

## Testing strategy

Container tests for UID, read-only, port mappings, reset-to-bootstrap, preflight error strings, and “management is not 443.”

## Compatibility implications

Container ports, CLI flags, `LABSSO_HTTPS_PORT`, `LAB_PUBLIC_HOST`, health paths, and filesystem paths are deployment interfaces.

## Open questions

- Exact host management port number in the integrator (18443 vs 18080-family). Design allows either 18443 or 8080-family.
- Host-443 occupancy preflight (sweep 2): lives in integrator / `mcplab` (rule 15 class; `internal/lab/ports.go` when INT-001 lands). `labsso` documents and emits the three-fix error text; it does not inspect host `:443` from inside the unprivileged container. `EACCES`/`EPERM` on the container bind is not occupancy.
