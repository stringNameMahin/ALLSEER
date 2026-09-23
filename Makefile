# ALLSEER: Adaptive Language-guided Low-level System Execution Enforcement Runtime
#
# Layout note: eBPF-dependent code is guarded by `//go:build linux && ebpf`.
# The default targets build and vet everything EXCEPT that code, so the design
# and interface layers stay buildable on any OS. Use the `ebpf-*` targets on a
# Linux host with clang + libbpf to work on the collector implementation.

SHELL       := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

# --- Toolchain ---------------------------------------------------------------
GO        ?= go
CLANG     ?= clang
GOBIN     ?= $(shell $(GO) env GOPATH)/bin

# --- Build metadata ----------------------------------------------------------
MODULE    := github.com/stringNameMahin/ALLSEER
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT    ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE      ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X '$(MODULE)/internal/buildinfo.Version=$(VERSION)' \
	-X '$(MODULE)/internal/buildinfo.Commit=$(COMMIT)' \
	-X '$(MODULE)/internal/buildinfo.Date=$(DATE)'

# --- Paths -------------------------------------------------------------------
BIN_DIR   := bin
BPF_DIR   := bpf
CMDS      := allseerd allseerctl allseer-shim

# eBPF compilation. CO-RE requires BTF; ARCH maps to the __TARGET_ARCH_* define.
ARCH      := $(shell uname -m 2>/dev/null | sed 's/x86_64/x86/; s/aarch64/arm64/')
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -I$(BPF_DIR)/include -Wall -Werror

# libbpfgo binds to libbpf through cgo, but its own cgo directives ask only for
# -lelf -lz: libbpf itself has to come from the caller. Everything built or
# tested with `-tags ebpf` therefore needs this, and gets an undefined-reference
# link failure without it. pkg-config is the source of truth so a libbpf
# installed somewhere other than /usr/lib still resolves; the literal is a
# fallback for a host with the library but no .pc file.
CGO_LDFLAGS ?= $(shell pkg-config --libs libbpf 2>/dev/null || echo -lbpf)
export CGO_LDFLAGS

##@ General

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS=":.*##"; printf "\nALLSEER development targets\n\nUsage: make \033[36m<target>\033[0m\n"} \
		/^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2 } \
		/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)
	@echo ""

##@ Build

.PHONY: build
build: $(addprefix build-,$(CMDS)) ## Build all binaries (no eBPF)

.PHONY: build-%
build-%: ## Build a single binary, e.g. make build-allseerd
	@mkdir -p $(BIN_DIR)
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$* ./cmd/$*

.PHONY: build-ebpf
build-ebpf: bpf ## Build binaries with the eBPF collector linked in (Linux only)
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=1 $(GO) build -trimpath -tags "ebpf" -ldflags "$(LDFLAGS)" \
		-o $(BIN_DIR)/allseerd ./cmd/allseerd
	CGO_ENABLED=1 $(GO) build -tags "ebpf" ./...

.PHONY: bpf
bpf: ## Compile eBPF C sources to CO-RE objects (needs clang + bpftool)
	@command -v $(CLANG) >/dev/null || { echo "clang not found"; exit 1; }
	@test -f $(BPF_DIR)/include/vmlinux.h || $(MAKE) vmlinux
	@for src in $(BPF_DIR)/*.bpf.c; do \
		[ -e "$$src" ] || { echo "no eBPF sources yet, skipping"; exit 0; }; \
		echo "  CC  $$src"; \
		$(CLANG) $(BPF_CFLAGS) -c "$$src" -o "$${src%.c}.o"; \
	done

.PHONY: vmlinux
vmlinux: ## Generate bpf/include/vmlinux.h from the running kernel's BTF
	@mkdir -p $(BPF_DIR)/include
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(BPF_DIR)/include/vmlinux.h

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(BIN_DIR) $(BPF_DIR)/*.o coverage.out coverage.html

##@ Quality

.PHONY: check
check: fmt-check vet lint schema-check test ## Run every check the CI pipeline runs

.PHONY: fmt
fmt: ## Format all Go source
	$(GO) fmt ./...

.PHONY: fmt-check
fmt-check: ## Fail if any file is not gofmt-clean
	@out=$$(gofmt -l . 2>/dev/null); \
	if [ -n "$$out" ]; then echo "not gofmt-clean:"; echo "$$out"; exit 1; fi
	@echo "gofmt: clean"

.PHONY: vet
vet: ## Run go vet
	$(GO) vet ./...

.PHONY: lint
lint: ## Run golangci-lint. Required: a gate that skips itself is not a gate
	@command -v golangci-lint >/dev/null || { \
		echo "golangci-lint not found, and lint is part of check."; \
		echo "Install it with scripts/setup-dev.sh or from"; \
		echo "https://golangci-lint.run/usage/install/"; \
		exit 1; }
	golangci-lint run ./...

.PHONY: test
test: ## Run unit tests
	$(GO) test -race -count=1 ./...

# Not part of `check`. `check` is what CI runs and what has to pass on a
# developer laptop of any OS; this needs clang, libbpf and a kernel, and the
# tests that matter most in it need root as well. Keeping them apart is the same
# split the build tag makes: the portable layer must stay testable everywhere.
.PHONY: test-ebpf
test-ebpf: bpf ## Vet and test the eBPF-tagged code (Linux + libbpf; loading needs root)
	CGO_ENABLED=1 $(GO) vet -tags "ebpf" ./...
	CGO_ENABLED=1 $(GO) test -tags "ebpf" -count=1 ./...
	@echo ""
	@echo "Tests that load BPF skip unless run as root. For the full run:"
	@echo "  sudo -E env PATH=\$$PATH CGO_LDFLAGS=\"$(CGO_LDFLAGS)\" \\"
	@echo "    $(GO) test -tags ebpf -count=1 ./internal/telemetry/"

.PHONY: golden
golden: ## Regenerate the committed golden decision streams, then review the diff
	@echo "Regenerating test/testdata/golden/ from the real pipeline..."
	$(GO) test ./test/golden/ -run 'TestGolden$$' -update -count=1 -v
	@echo ""
	@echo "Golden streams rewritten. Review the diff before committing:"
	@echo "  git diff -- test/testdata/golden/"
	@echo "A change here is a change in what the system concludes about a session."

.PHONY: cover
cover: ## Run tests and open an HTML coverage report
	$(GO) test -race -count=1 -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "wrote coverage.html"

.PHONY: tidy
tidy: ## Tidy and verify go.mod / go.sum
	$(GO) mod tidy
	$(GO) mod verify

##@ Codegen

# The Go view of the kernel/user ABI is derived from bpf/include/allseer_event.h
# rather than written down twice. The header's own preamble states why: a
# mismatch between the two sides "does not produce a clean error; it produces
# plausible garbage that flows straight into governance decisions".
#
# Note that `make test` already enforces staleness, through
# TestGeneratedFileIsNotStale in internal/telemetry/abi. That is the stronger
# check of the two, because it runs anywhere `go test` runs — including hosts
# with no make at all. These targets exist so the check is also invocable by
# name, which is what the milestone issue asks for.

ABI_HEADER := $(BPF_DIR)/include/allseer_event.h
ABI_OUT    := internal/telemetry/abi/layout_gen.go

.PHONY: gen
gen: ## Regenerate the Go ABI from bpf/include/allseer_event.h
	$(GO) generate ./internal/telemetry/abi/
	@echo ""
	@echo "Review the diff before committing:"
	@echo "  git diff -- $(ABI_OUT)"
	@echo "A change here is a change in how kernel bytes are read."

.PHONY: gen-check
gen-check: ## Fail if the generated ABI is stale relative to the header
	$(GO) run ./internal/telemetry/abigen/cmd/abigen \
		-header $(ABI_HEADER) -out $(ABI_OUT) -package abi -check

##@ Benchmarks

# Deliberately absent from `check`. It needs root, a compiled object, a cgroup v2
# hierarchy and several hours, and it is a measurement rather than a gate: a
# result belongs in STATUS.md, not in a pipeline that has to pass before a merge.
.PHONY: bench-overhead
bench-overhead: ## Measure probe overhead against a cold build (root, hours; M5 W3)
	@echo "This needs root and takes hours. For the full acceptance run:"
	@echo "  sudo -E env PATH=\"\$$PATH\" GOMODCACHE=\"$$($(GO) env GOMODCACHE)\" \\"
	@echo "    CGO_LDFLAGS=\"$(CGO_LDFLAGS)\" \\"
	@echo "    bash scripts/bench-overhead.sh"
	@echo ""
	@echo "To check the harness without waiting (NOT acceptance-grade):"
	@echo "  ... bash scripts/bench-overhead.sh --quick"

.PHONY: bench-report
bench-report: ## Re-analyse a recorded session: make bench-report RUNS=bench/<id>.jsonl
	@test -n "$(RUNS)" || { echo "set RUNS=<session>.jsonl"; exit 2; }
	$(GO) run ./internal/telemetry/benchstat/cmd/benchstat -runs "$(RUNS)"

##@ Schemas

.PHONY: schema-check
schema-check: ## Validate example documents against the JSON schemas
	./scripts/validate-schemas.sh

##@ Meta

.PHONY: todo
todo: ## List every outstanding TODO in the tree
	@grep -rn "TODO" --include="*.go" --include="*.c" --include="*.h" --include="*.yaml" \
		cmd internal pkg bpf configs api || echo "no TODOs"

.PHONY: version
version: ## Print build metadata
	@echo "version=$(VERSION) commit=$(COMMIT) date=$(DATE)"

##@ CI

# One target per job in .github/workflows/ci.yml; `make ci` runs them all in
# pipeline order. Pinned tools install into bin/tools, outputs go to bin/ci.
include scripts/ci/versions.env

TOOLS_DIR   := $(CURDIR)/$(BIN_DIR)/tools
LIBBPF_DIR  := $(TOOLS_DIR)/libbpf
BPF_HDR_DIR := $(TOOLS_DIR)/libbpf-bpf
CI_OUT      := $(BIN_DIR)/ci
export PATH := $(TOOLS_DIR):$(PATH)

# cgo settings for the ebpf tag, against the pinned libbpf.
EBPF_ENV := CGO_ENABLED=1 CGO_CFLAGS="-I$(LIBBPF_DIR)/include" \
	CGO_LDFLAGS="$(LIBBPF_DIR)/lib/libbpf.a -lelf -lz"

# Default-tag builds need no libbpf. Without this the exported -lbpf fallback
# breaks every cgo link on a host with no libbpf-dev, such as the CI runners.
# The ebpf commands set their own CGO_LDFLAGS through EBPF_ENV.
tools ci-lint ci-static ci-build ci-unit ci-integration ci-security: CGO_LDFLAGS :=

.PHONY: tools
tools: ## Install every pinned CI tool into bin/tools
	./scripts/ci/tools.sh

.PHONY: ci
ci: ## Run the whole CI pipeline locally (integration uses sudo)
	$(MAKE) ci-lint
	$(MAKE) ci-static
	$(MAKE) ci-build
	$(MAKE) ci-unit
	$(MAKE) ci-integration
	$(MAKE) ci-security

.PHONY: ci-lint
ci-lint: ## CI job: gofmt, golangci-lint, go.mod tidiness, actionlint
	./scripts/ci/tools.sh golangci-lint actionlint shellcheck
	$(MAKE) fmt-check lint
	$(GO) mod tidy -diff
	actionlint

.PHONY: ci-static
ci-static: ## CI job: go vet for both tag sets, ABI staleness, schema examples
	./scripts/ci/tools.sh libbpf check-jsonschema
	$(GO) vet ./...
	$(EBPF_ENV) $(GO) vet -tags ebpf ./...
	$(MAKE) gen-check
	@command -v check-jsonschema >/dev/null || { echo "check-jsonschema missing"; exit 1; }
	$(MAKE) schema-check

.PHONY: ci-build
ci-build: ## CI job: binaries, BPF object, ebpf daemon, integration test binary
	./scripts/ci/tools.sh libbpf bpf-headers bpftool
	$(MAKE) build
	CPATH="$(BPF_HDR_DIR)/include" $(MAKE) bpf
	@mkdir -p $(CI_OUT)
	$(EBPF_ENV) $(GO) build -trimpath -tags ebpf -ldflags "$(LDFLAGS)" \
		-o $(BIN_DIR)/allseerd-ebpf ./cmd/allseerd
	$(EBPF_ENV) $(GO) build -tags ebpf ./...
	$(EBPF_ENV) $(GO) test -c -tags ebpf -cover -covermode=atomic \
		-coverpkg=./internal/telemetry/... -o $(CI_OUT)/telemetry-ebpf.test ./internal/telemetry

.PHONY: ci-unit
ci-unit: ## CI job: unit tests with race detector and coverage
	@mkdir -p $(CI_OUT)
	@status=0; \
	$(GO) test -race -count=1 -covermode=atomic -coverprofile=$(CI_OUT)/coverage.out \
		-json ./... > $(CI_OUT)/unit.json || status=$$?; \
	$(GO) tool cover -func=$(CI_OUT)/coverage.out > $(CI_OUT)/coverage.txt || true; \
	$(GO) tool cover -html=$(CI_OUT)/coverage.out -o $(CI_OUT)/coverage.html || true; \
	./scripts/ci/test-summary.sh "Unit tests" $(CI_OUT)/unit.json $(CI_OUT)/coverage.txt \
		> $(CI_OUT)/unit.md; \
	cat $(CI_OUT)/unit.md; \
	if [ -n "$${GITHUB_STEP_SUMMARY:-}" ]; then cat $(CI_OUT)/unit.md >> "$$GITHUB_STEP_SUMMARY"; fi; \
	exit $$status

# Runs the binary ci-build compiled, as root, from the package directory so the
# tests find ../../bpf/allseer.bpf.o. Building as the user keeps the Go caches
# free of root-owned files.
.PHONY: ci-integration
ci-integration: ## CI job: ebpf-tagged telemetry tests as root (run ci-build first)
	@test -x $(CI_OUT)/telemetry-ebpf.test && test -f $(BPF_DIR)/allseer.bpf.o || \
		{ echo "missing $(CI_OUT)/telemetry-ebpf.test or the BPF object: run make ci-build"; exit 1; }
	@status=0; sudo=; [ "$$(id -u)" = 0 ] || sudo=sudo; \
	( cd internal/telemetry && $$sudo ../../$(CI_OUT)/telemetry-ebpf.test -test.v=test2json \
		-test.count=1 -test.coverprofile=../../$(CI_OUT)/integration-coverage.out 2>&1 ) \
		| $(GO) tool test2json -t -p $(MODULE)/internal/telemetry > $(CI_OUT)/integration.json \
		|| status=$$?; \
	$$sudo chown "$$(id -u):$$(id -g)" $(CI_OUT)/integration-coverage.out 2>/dev/null || true; \
	$(GO) tool cover -func=$(CI_OUT)/integration-coverage.out > $(CI_OUT)/integration-coverage.txt || true; \
	./scripts/ci/test-summary.sh "Integration tests ($$(uname -m), kernel $$(uname -r))" \
		$(CI_OUT)/integration.json $(CI_OUT)/integration-coverage.txt > $(CI_OUT)/integration.md; \
	cat $(CI_OUT)/integration.md; \
	if [ -n "$${GITHUB_STEP_SUMMARY:-}" ]; then cat $(CI_OUT)/integration.md >> "$$GITHUB_STEP_SUMMARY"; fi; \
	exit $$status

.PHONY: ci-security
ci-security: ## CI job: gitleaks over git history, govulncheck, go mod verify
	./scripts/ci/tools.sh gitleaks govulncheck libbpf
	gitleaks git --no-banner --redact --exit-code 1 .
	govulncheck ./...
	$(EBPF_ENV) govulncheck -tags ebpf ./...
	$(GO) mod verify
