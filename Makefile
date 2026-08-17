.PHONY: fmt fmt-check vet lint sec vuln modcheck test build check ci hooks-install tools clean

GO      ?= go
BIN     ?= omt
GOLANGCI_VERSION ?= v2.12.2
GOSEC_VERSION    ?= v2.28.0

# ---- formatting -------------------------------------------------------

fmt: ## Reformat all Go source files in place.
	$(GO) fmt ./...

fmt-check: ## Fail if any Go file is not gofmt-formatted.
	@files=$$(gofmt -l .); \
	if [ -n "$$files" ]; then \
		echo "The following files are not gofmt'd:"; \
		echo "$$files"; \
		exit 1; \
	fi

# ---- static analysis ---------------------------------------------------

vet: ## Run go vet.
	$(GO) vet ./...

lint: ## Run golangci-lint (static analysis: unused code, ineffective assignments, style, ...).
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo "golangci-lint not found. Install: make tools"; \
		echo "(or see https://golangci-lint.run/docs/welcome/install/local/)"; \
		exit 1; \
	}
	golangci-lint run ./...

# ---- security ------------------------------------------------------------

sec: ## Run gosec (security-focused static analysis).
	@command -v gosec >/dev/null 2>&1 || { \
		echo "gosec not found. Install: make tools"; \
		echo "(or: go install github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION))"; \
		exit 1; \
	}
	gosec -quiet ./...

# ---- dependencies ----------------------------------------------------------

vuln: ## Run govulncheck (known CVEs in dependencies and the stdlib actually used).
	@command -v govulncheck >/dev/null 2>&1 || { \
		echo "govulncheck not found. Install: make tools"; \
		echo "(or: go install golang.org/x/vuln/cmd/govulncheck@latest)"; \
		exit 1; \
	}
	govulncheck ./...

modcheck: ## Verify module checksums, and fail if go.mod/go.sum are not tidy.
	$(GO) mod verify
	@cp go.mod /tmp/omt-go.mod.orig; \
	[ -f go.sum ] && cp go.sum /tmp/omt-go.sum.orig || rm -f /tmp/omt-go.sum.orig; \
	$(GO) mod tidy; \
	status=0; \
	diff -u /tmp/omt-go.mod.orig go.mod || status=1; \
	if [ -f /tmp/omt-go.sum.orig ]; then diff -u /tmp/omt-go.sum.orig go.sum || status=1; fi; \
	mv /tmp/omt-go.mod.orig go.mod; \
	if [ -f /tmp/omt-go.sum.orig ]; then mv /tmp/omt-go.sum.orig go.sum; else rm -f go.sum; fi; \
	if [ $$status -ne 0 ]; then \
		echo "go.mod/go.sum are not tidy. Run 'go mod tidy' and commit the result."; \
		exit 1; \
	fi

# ---- tests / build -----------------------------------------------------

test: ## Run the test suite with race detector and coverage.
	$(GO) test ./... -race -cover

build: ## Build the omt binary.
	$(GO) build -o $(BIN) .

# ---- aggregate targets ---------------------------------------------------

check: fmt-check vet lint sec vuln modcheck test ## Run the full local pipeline (static analysis + security + dependency check + tests).

ci: check build ## What CI runs: the full pipeline plus a build.

# ---- housekeeping ----------------------------------------------------------

tools: ## Install/update the external tools used by lint/sec/vuln.
	# golangci-lint recommend the install script over `go install` (see
	# https://golangci-lint.run/docs/welcome/install/local/) - it ships a
	# prebuilt binary instead of compiling against your local Go toolchain.
	curl -sSfL https://golangci-lint.run/install.sh | sh -s -- -b $$($(GO) env GOPATH)/bin $(GOLANGCI_VERSION)
	$(GO) install github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION)
	$(GO) install golang.org/x/vuln/cmd/govulncheck@latest

hooks-install: ## Wire up the tracked .githooks/ directory as this repo's git hooks path.
	git config core.hooksPath .githooks
	chmod +x .githooks/*
	@echo "Git hooks installed (core.hooksPath=.githooks). Pre-commit will now run fmt-check/vet/lint."

clean:
	rm -f $(BIN)
