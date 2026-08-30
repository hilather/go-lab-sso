# LabSSO task runner. Tool versions are pinned; do not use @latest.

GO ?= go
export GOTOOLCHAIN ?= local
export GOPROXY ?= https://proxy.golang.org,direct

GOLANGCI_LINT_VERSION ?= v2.12.2
GOVULNCHECK_MOD ?= golang.org/x/vuln/cmd/govulncheck@v1.1.4
GOLANGCI_LINT_MOD ?= github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

.PHONY: format lint generate verify-generated test test-race test-fuzz-smoke \
	test-integration test-parity test-config-compat test-docs test-container \
	security-scan test-changelog

format:
	$(GO) fmt ./...

lint:
	$(GO) vet ./...
	$(GO) run $(GOLANGCI_LINT_MOD) run ./...

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

test-parity:
	$(GO) test ./internal/parity/...

test-config-compat:
	$(GO) test ./internal/config/... ./internal/model/...

test-docs:
	bash scripts/checkdocs.sh

test-container:
	bash scripts/test-container.sh

security-scan:
	$(GO) run $(GOVULNCHECK_MOD) ./...

test-changelog:
	bash scripts/checkchangelog.sh

generate verify-generated test-fuzz-smoke test-integration:
	@echo "make $@: not implemented yet" >&2
	@false
