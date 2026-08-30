#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if ! grep -q '\[Unreleased\]' "${ROOT}/CHANGELOG.md"; then
	echo "CHANGELOG.md must have an [Unreleased] section" >&2
	exit 1
fi
echo "changelog ok"
