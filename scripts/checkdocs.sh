#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
need=(
	AGENTS.md README.md START-HERE.md CONTRIBUTING.md SECURITY.md CHANGELOG.md MANIFEST.md LICENSE
	docs/01-architecture.md docs/04-state-and-configuration.md docs/05-control-plane-and-parity.md
	docs/06-rest-api.md docs/07-mcp-api.md docs/08-security-architecture.md docs/11-deployment.md
	docs/19-acceptance-criteria.md testdata/config/valid/minimal.yaml examples/compose.yaml
)
for f in "${need[@]}"; do
	if [ ! -f "${ROOT}/${f}" ]; then
		echo "missing ${f}" >&2
		exit 1
	fi
done
if ! grep -q '443:10443' "${ROOT}/examples/compose.yaml"; then
	echo "compose must publish 443:10443" >&2
	exit 1
fi
echo "docs ok"
