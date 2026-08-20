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
check: fmt-check vet lint test ## Run every check the CI pipeline runs

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
lint: ## Run golangci-lint if installed
	@command -v golangci-lint >/dev/null \
		&& golangci-lint run ./... \
		|| echo "golangci-lint not installed, skipping (see scripts/setup-dev.sh)"

.PHONY: test
test: ## Run unit tests
	$(GO) test -race -count=1 ./...

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
