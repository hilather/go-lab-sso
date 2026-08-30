# ADR 0006: Native host TCP 443 (dest-443)

Status: Accepted for design
Date: 2026-08-30
Last reviewed: 2026-08-30

## Context

Integrator rule 15: LabSSO is a **dest-443** service. SUTs already speak HTTPS to an IdP on 443. LabMITM is a forward proxy and must **not** take 443; copying that rule here would force every SUT to set a non-default dest port.

The container process is unprivileged (UID 65532) and cannot bind host 443 itself. dockerd (or an equivalent) publishes `443:10443`. `EACCES`/`EPERM` on the container listen is not occupancy.

## Decision

- Host publish: **TCP 443** → container unprivileged listen (e.g. `:10443`).
- Management: high port (e.g. host 18443 or 8080-family), **not** 443.
- Operator escape `LABSSO_HTTPS_PORT` in `profile.env` when preflight cannot free 443. It is an escape, not the default.
- Preflight **fail closed** if a non-lab process holds host 443. Error text must name: stop/disable the occupant (nginx, caddy, apache, another compose stack) **or** extra IP for `LAB_PUBLIC_HOST` **or** escape `LABSSO_HTTPS_PORT` (SUTs that cannot set dest port cannot follow the escape).
- Do not treat container bind `EACCES`/`EPERM` as occupancy.

## Consequences

- Compose sketches map `443:10443`.
- Issuer omits port iff published 443.
- A workstation that already runs nginx on 443 will not silently come up wrong.
- LabMITM and LabSSO can coexist: MITM on a high proxy port, LabSSO on dest-443.
- Extra IP is a first-class fix when 443 is busy on the primary address.

## Alternatives considered

- Default to 8443 like many “dev IdPs”: breaks SUTs that cannot set dest port.
- Copy LabMITM’s no-443 rule: wrong service class.
- Bind 443 inside the container as root: violates UID 65532 and scratch policy.
- Silently remap when 443 is busy: undetectable SUT failures.

## Review triggers

Review this decision when its assumptions no longer hold, a major protocol or library change occurs, or a new requirement conflicts with an invariant.
