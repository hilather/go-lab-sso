#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export GOMAXPROCS="${GOMAXPROCS:-2}"
GO_BIN="${GO:-go}"
FUZZ_TIME="${LABSSO_FUZZ_TIME:-2s}"
"${GO_BIN}" test ./internal/config -run '^$' -fuzz '^FuzzYAMLDecode$' -fuzztime "${FUZZ_TIME}" -parallel 2
"${GO_BIN}" test ./internal/saml -run '^$' -fuzz '^FuzzSAMLMetadata$' -fuzztime "${FUZZ_TIME}" -parallel 2
"${GO_BIN}" test ./internal/saml -run '^$' -fuzz '^FuzzSAMLAuthnRequest$' -fuzztime "${FUZZ_TIME}" -parallel 2
