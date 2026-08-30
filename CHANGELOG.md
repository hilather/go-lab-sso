# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project will use [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once an implementation tag exists.

## [Unreleased]

### Design

- Landed the LabSSO design plan: two-plane IdP (HTTPS data plane + REST/MCP management), fail-closed YAML `labsso.dev/v1alpha1`, vendor clothes (not hostname clones), native host 443, no LabNTP time bus, allow-list customer-config import, and sequential protocol slices.
- Skeptic sweep 2 (2026-08-30, Keystone): review-plan **READY**, skeptic-plan-review sweep 1 **ACCEPT**. Sweep-2 questions written down in `docs/skeptic-notes.md`. No product invariant changed.
- Status remains **design (not implemented)**. No Go module, no server image, no CI.

### Added

- README, START-HERE, AGENTS, SECURITY, CONTRIBUTING, MANIFEST, Apache-2.0 LICENSE.
- Normative docs `docs/01`–`docs/11`, `docs/18`–`docs/21`, known limitations, skeptic notes.
- ADRs 0001–0009.
- Program board and reviewer/agent templates.
- YAML fixtures and a non-runnable Compose sketch.

[Unreleased]: https://github.com/hilather/go-lab-sso/compare/main...HEAD
