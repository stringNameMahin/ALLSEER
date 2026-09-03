#!/usr/bin/env bash
# Set up an ALLSEER development environment.
#
# Go tooling works on any platform; the eBPF toolchain is Linux-only. The script
# reports what is missing rather than trying to install it, because package
# names differ across distributions and silently installing system packages is
# not a thing a setup script should do unasked.
set -euo pipefail

info()  { printf '  \033[32m[OK]\033[0m %s\n' "$1"; }
warn()  { printf '  \033[33m!\033[0m %s\n' "$1"; }
err()   { printf '  \033[31m[X]\033[0m %s\n' "$1"; }

missing=0

echo ""
echo "ALLSEER development environment check"
echo ""

# --- Required everywhere -----------------------------------------------------
echo "Core toolchain:"

if command -v go >/dev/null 2>&1; then
  info "go $(go version | awk '{print $3}')"
else
  err "go not found: https://go.dev/dl/"
  missing=1
fi

if command -v git >/dev/null 2>&1; then
  info "git $(git --version | awk '{print $3}')"
else
  err "git not found"
  missing=1
fi

# --- Linting and validation --------------------------------------------------
echo ""
echo "Optional tooling:"

if command -v golangci-lint >/dev/null 2>&1; then
  info "golangci-lint present"
else
  warn "golangci-lint not found, install: https://golangci-lint.run/usage/install/"
fi

if command -v check-jsonschema >/dev/null 2>&1; then
  info "check-jsonschema present"
else
  warn "check-jsonschema not found, install: pip install check-jsonschema"
fi

# --- eBPF toolchain (Linux only) ---------------------------------------------
echo ""
echo "eBPF toolchain:"

if [[ "$(uname -s)" != "Linux" ]]; then
  warn "not Linux; eBPF development requires a Linux host or VM"
  warn "the interface and design layers build fine here; use the replay"
  warn "telemetry source to develop everything downstream of collection"
else
  if command -v clang >/dev/null 2>&1; then
    info "clang $(clang --version | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
  else
    err "clang not found, required to compile eBPF programs"
    missing=1
  fi

  if command -v bpftool >/dev/null 2>&1; then
    info "bpftool present"
  else
    err "bpftool not found, required to generate vmlinux.h"
    missing=1
  fi

  # CO-RE needs kernel BTF. Without it, probes must be recompiled per kernel,
  # which defeats the point of compile-once-run-everywhere.
  if [[ -f /sys/kernel/btf/vmlinux ]]; then
    info "kernel BTF available (CO-RE supported)"
  else
    err "/sys/kernel/btf/vmlinux missing: kernel lacks BTF, CO-RE unavailable"
    missing=1
  fi

  kver=$(uname -r)
  info "kernel $kver"
  case "$kver" in
    [0-4].*) err "kernel too old: ring buffer needs 5.8+, LSM BPF needs 5.7+"; missing=1 ;;
    5.[0-7].*) warn "kernel $kver: BPF ring buffer requires 5.8+" ;;
  esac

  if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists libbpf 2>/dev/null; then
    info "libbpf $(pkg-config --modversion libbpf)"
  else
    warn "libbpf not found via pkg-config, required by libbpfgo (cgo)"
    warn "  Debian/Ubuntu: apt install libbpf-dev"
    warn "  Fedora:        dnf install libbpf-devel"
  fi
fi

# --- Go dependencies ---------------------------------------------------------
echo ""
if command -v go >/dev/null 2>&1; then
  echo "Fetching Go dependencies:"
  go mod download && info "modules downloaded"
fi

echo ""
if [[ $missing -eq 0 ]]; then
  echo "Environment ready. Run 'make check' to verify."
else
  echo "Some required tools are missing, see above."
  exit 1
fi
echo ""
