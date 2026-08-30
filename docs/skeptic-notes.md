# Skeptic Notes

Status: design (not implemented)
Last reviewed: 2026-08-30

This page records skeptic sweep findings. **Sweep 1 blockers are already folded** into the normative docs and ADRs. **Sweep 2** (review-plan + skeptic-plan-review sweep 1) is recorded below. Verdict: **READY** / **ACCEPT**.

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

## Sweep 2 — 2026-08-30 — Keystone

Against `main` at `6b3d730fd0cfd66bbcb85e06d5bcae36d2dff2ba`. Skills fetched from `hilather/mcp-integration-lab` `@ 9b2551f` (`review-plan`, `skeptic-plan-review`, `knowledge/plan-skepticism`, `knowledge/dependencies`, `knowledge/documentation-and-tests`). Origin skills were **not** vendored here. No server, `go.mod`, Makefile, CI, badges, or integrator pin.

Sweep 2 must not silently reverse sweep 1. It did not.

### Review-plan

Verdict: **READY** (nits only; no docs rewrite required).

The landed design is the plan. Investigation is present (problem/goals/invariants before package sketch). Scope stays in-repo. `AGENTS.md` design-phase rules hold. Acceptance in [docs/19-acceptance-criteria.md](19-acceptance-criteria.md) items 1–9 are met on the tree. Item 10 (GitHub description + topics) was empty at review time; this agent’s `gh repo edit` received **HTTP 403** (read-only integration token). That is an operations leftover, not a plan defect.

#### Blocking findings

None.

#### Notes (concrete file + change if someone later tightens)

- `docs/07-mcp-api.md`: one line says `MCP-Protocol-Version`, the rest of the pack says `Mcp-Protocol-Version` (Go `CanonicalMIMEHeaderKey` form of the 2026-07-28 header). Same header; spelling should match.
- `tasks/00-program-board.md` “Depends on” is a DAG (`IMP-001` after `FND-001` only). Sequential order in `docs/18-roadmap-and-non-goals.md` and `tasks/README.md` still wins. Do not treat the DAG as permission to skip slices.
- Integrator `AGENTS.md` rule 15 (`mcp-integration-lab` `@ 9b2551f`) enumerates DNS/NTP/LDAP/SMTP/AAA/NFS native dests. It does **not** name LabSSO or host 443. Dest-443 is the same *class* (IANA dest SUTs already speak) and is decided **here** in [ADR 0006](adr/0006-native-host-443.md). Do not file an integrator FR from this repo.
- No `.gitignore` yet. Acceptable while docs-only; FND-001 adds one with the module.

#### What review-plan opened

`README.md`, `START-HERE.md`, `AGENTS.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`, `MANIFEST.md`, `LICENSE` (appendix **Copyright 2026 hilather**), `docs/README.md`, `docs/01-architecture.md` through `docs/11-deployment.md`, `docs/18-roadmap-and-non-goals.md` through `docs/21-standards-and-references.md`, `docs/known-limitations.md`, `docs/skeptic-notes.md`, `docs/adr/0001-use-go.md` through `docs/adr/0009-data-plane-login-ui.md`, `testdata/config/valid/minimal.yaml`, `testdata/config/invalid/unknown-field.yaml`, `examples/compose.sketch.yaml`, `tasks/README.md`, `tasks/00-program-board.md`, `tasks/agent-task-template.md`, `tasks/reviewer-checklist.md`. YAML fixtures and the compose sketch parsed. Confirmed absent: `go.mod`, `Makefile`, `.github/`, server Dockerfile, vendored `.cursor/skills`. Fetched (not edited): `mcp-integration-lab` `@ 9b2551f` `AGENTS.md` rule 15; MCP 2026-07-28 Streamable HTTP header name.

### Skeptic plan review — sweep 1 of 3

Prompt template used verbatim (not paraphrased). Fresh skeptic. Cap 3 then BLOCKED. Did not implement.

```
You are running a skeptic plan review. You did not write this plan.

Read these files first (do not skip):
- knowledge/plan-skepticism/README.md
- knowledge/dependencies/README.md
- knowledge/documentation-and-tests/README.md

Then read the plan. Open every path the plan treats as fact.

Sweep 1 of 3. Never skip sweep 1. Fresh skeptic each sweep. Cap 3 then BLOCKED.

Attack:
1. Claims that are not grounded in files you opened.
2. Missing investigation the plan treats as known.
3. Scope leaks (product work, vendor pins, third_party edits, extra machinery).
4. Docs/changelog/test gaps this repo’s own rules require.
5. “We’ll figure it out during implement” hiding a blocker.

Output exactly:
- ACCEPT or BLOCKED
- Blocking findings (if any)
- Non-blocking notes
- What you opened

Do not implement. Do not rewrite the plan unless the author asks.
Do not paraphrase this prompt.
```

**ACCEPT**

#### Blocking findings

None.

#### Non-blocking notes

Sweep-2 suggested questions, written down (not product reversals):

| Question | Answer from opened files |
|---|---|
| Generic group safety-cap number? | **200** is the documented CFG example in `docs/04-state-and-configuration.md`. Not a new minimal-YAML field. Exact field name lands in CFG / OVR-001. |
| SAML EntityID exactly the issuer? | **Yes.** `docs/01-architecture.md` already says EntityID uses the exact issuer. `docs/02-protocols.md` design default is yes. A later ADR would be required to change it. |
| Where does 443 occupancy preflight live? | **Integrator / `mcplab`** owns host occupancy for published ports (rule 15 already points at `internal/lab/ports.go`). The LabSSO process documents and must emit the three-fix error text; it does **not** inspect host `:443` from inside an unprivileged container. Container bind `EACCES`/`EPERM` is not occupancy. Standalone `labsso serve` fail-closes on **its** listen address only. |
| Session-knob concurrency vs snapshot revision? | Ephemeral knobs (expire session, pause/resume token, force-fail, inject-error, one-shot mint) **do not** require snapshot `expectedRevision`. Desired-state tunables (vendor swap, overage, redirect rewrite) **do**. Bearer + reason + audit still apply. Already the design preference in `docs/06-rest-api.md`. |
| PHC algorithm allow-list? | Not a single frozen id in this repo. Unknown PHC id **fails closed**. Plaintext and unsalted hashes reject. Family precedent in opened integrator `AGENTS.md`: TacLab Argon2id. LOGIN-001 / CFG documents the allow-list and parameters. |
| Entra overage numeric threshold? | Not Microsoft production. Lab default **200** (same magnitude as the generic-cap example). Exact YAML field name is slice 5 / CFG. Do not add it to `minimal.yaml` in this sweep. |
| Management TLS in slice 1 vs loopback HTTP? | Slice 1: management **HTTP on loopback**. Remote management TLS is a later deployment choice (`docs/01-architecture.md`). |

Other notes:

- “Integrator rule 15 ⇒ LabSSO dest-443” is class analogy, not a line in the current rule-15 port list. Decision lives in ADR 0006. No integrator FR.
- Membership SoT (`user.groupIds` vs `group.memberUserIds`) is still “pick one in CFG; no silent dual writes.” Named owner: FND-001. Not a hidden fork if that sentence is followed.
- `allowLegacyClients` sketch `true` vs “schema may default false in code” is documented: integrator YAML must set `true`.
- `spec.issuer` in YAML vs `LAB_PUBLIC_HOST` derivation: compile fails on mismatch when derivation env is present; standalone serve may take YAML as-is (`docs/04-state-and-configuration.md`).
- GitHub description/topics still empty after 403 on `gh repo edit`. Human with admin: `gh repo edit hilather/go-lab-sso --description "Laboratory SSO IdP (Entra/Okta/Ping/ADFS clothes). Design first. Not implemented." --add-topic sso --add-topic oidc --add-topic saml --add-topic mcp --add-topic golang`.
- This repo’s `AGENTS.md` does not require `make test` while docs-only. No changelog gap once this sweep is listed under `[Unreleased]`.
- `knowledge/dependencies` and `knowledge/documentation-and-tests` are written for `mcp-integration-lab`. Applied here as method only: no vendor pin, no `third_party/`, docs ship with the change, no fake implementation tests.

#### What the skeptic opened

Same tree as review-plan, plus the three knowledge READMEs at `mcp-integration-lab` `@ 9b2551f`, plus integrator `AGENTS.md` rule 15 and the 2026-07-28 Streamable HTTP header text. Did not open sibling appliance source trees (LabDNS/LabMail/LabMITM/TacLab/LabLDAP); family URLs in the README are citations, not in-repo facts.

### Sweep 2 status

**ACCEPT** after skeptic sweep **1** of 3. No re-sweep. No implementation. No product invariant changed.

— Keystone
