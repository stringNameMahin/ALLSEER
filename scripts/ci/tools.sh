#!/usr/bin/env bash
# Install the pinned CI tools into bin/tools. Versions live in versions.env.
# Usage: scripts/ci/tools.sh [tool...]   (no arguments installs everything)
# A stamp file per tool and version makes reruns free and a bump reinstall.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
# shellcheck source=scripts/ci/versions.env
source "$root/scripts/ci/versions.env"
tools="$root/bin/tools"
arch=$(uname -m)
mkdir -p "$tools"

have() { [[ -f "$tools/.stamp-$1-$2" ]]; }
mark() { rm -f "$tools/.stamp-$1-"*; touch "$tools/.stamp-$1-$2"; }

fetch() {
  curl -sSfL --retry 3 -o "$3" "$1"
  echo "$2  $3" | sha256sum -c --quiet -
}

# Go tools are rebuilt when the Go toolchain changes too: golangci-lint refuses
# to run when it was built with a Go older than the module targets.
go_tool() {
  local name=$1 pkg=$2 ver=$3
  local tag
  tag="$ver-$(go env GOVERSION)"
  have "$name" "$tag" && return 0
  echo "tools: installing $name $ver"
  # The tools are pure Go; without cgo the caller's CGO_LDFLAGS cannot break them.
  CGO_ENABLED=0 GOBIN="$tools" go install "$pkg@$ver"
  mark "$name" "$tag"
}

install_shellcheck() {
  have shellcheck "$SHELLCHECK_VERSION" && return 0
  local sum tmp
  case $arch in
    x86_64) sum=$SHELLCHECK_SHA256_X86_64 ;;
    aarch64) sum=$SHELLCHECK_SHA256_AARCH64 ;;
    *) echo "tools: no pinned shellcheck for $arch"; return 1 ;;
  esac
  echo "tools: installing shellcheck $SHELLCHECK_VERSION"
  tmp=$(mktemp -d)
  fetch "https://github.com/koalaman/shellcheck/releases/download/$SHELLCHECK_VERSION/shellcheck-$SHELLCHECK_VERSION.linux.$arch.tar.xz" \
    "$sum" "$tmp/shellcheck.tar.xz"
  tar -xJf "$tmp/shellcheck.tar.xz" -C "$tmp"
  install -m 0755 "$tmp/shellcheck-$SHELLCHECK_VERSION/shellcheck" "$tools/shellcheck"
  rm -rf "$tmp"
  mark shellcheck "$SHELLCHECK_VERSION"
}

install_bpftool() {
  have bpftool "$BPFTOOL_VERSION" && return 0
  local a sum tmp
  case $arch in
    x86_64) a=amd64 sum=$BPFTOOL_SHA256_AMD64 ;;
    aarch64) a=arm64 sum=$BPFTOOL_SHA256_ARM64 ;;
    *) echo "tools: no pinned bpftool for $arch"; return 1 ;;
  esac
  echo "tools: installing bpftool $BPFTOOL_VERSION"
  tmp=$(mktemp -d)
  fetch "https://github.com/libbpf/bpftool/releases/download/$BPFTOOL_VERSION/bpftool-$BPFTOOL_VERSION-$a.tar.gz" \
    "$sum" "$tmp/bpftool.tar.gz"
  tar -xzf "$tmp/bpftool.tar.gz" -C "$tmp"
  install -m 0755 "$tmp/bpftool" "$tools/bpftool"
  rm -rf "$tmp"
  mark bpftool "$BPFTOOL_VERSION"
}

# Without python3-venv, fall back to a check-jsonschema already on PATH so a
# developer machine can still run the check, and say that it is not the pin.
install_jsonschema() {
  have check-jsonschema "$CHECK_JSONSCHEMA_VERSION" && return 0
  if python3 -c 'import ensurepip' 2>/dev/null; then
    echo "tools: installing check-jsonschema $CHECK_JSONSCHEMA_VERSION"
    rm -rf "$tools/venv"
    python3 -m venv "$tools/venv"
    "$tools/venv/bin/pip" install -q "check-jsonschema==$CHECK_JSONSCHEMA_VERSION"
    ln -sf venv/bin/check-jsonschema "$tools/check-jsonschema"
    mark check-jsonschema "$CHECK_JSONSCHEMA_VERSION"
  elif command -v check-jsonschema >/dev/null; then
    echo "tools: python3-venv missing, using $(check-jsonschema --version) from PATH"
    echo "tools: CI pins check-jsonschema $CHECK_JSONSCHEMA_VERSION"
  else
    echo "tools: check-jsonschema needs python3-venv (apt install python3-venv)"
    return 1
  fi
}

libbpf_clone() {
  local ver=$1 commit=$2 dir=$3 got
  git -c advice.detachedHead=false clone -q --depth 1 --branch "$ver" \
    https://github.com/libbpf/libbpf.git "$dir"
  got=$(git -C "$dir" rev-parse HEAD)
  if [[ $got != "$commit" ]]; then
    echo "tools: libbpf $ver resolved to $got, expected $commit"
    return 1
  fi
}

# libbpf is built at the version libbpfgo pins. Its uapi headers come with it,
# which matters: cgo needs BPF_MAP_TYPE_ARENA, and older distro headers lack it.
install_libbpf() {
  have libbpf "$LIBBPF_VERSION" && return 0
  local dest="$tools/libbpf" tmp
  echo "tools: building libbpf $LIBBPF_VERSION"
  tmp=$(mktemp -d)
  libbpf_clone "$LIBBPF_VERSION" "$LIBBPF_COMMIT" "$tmp/src"
  rm -rf "$dest"
  # -Wno-error: libbpf 1.5.1 predates warnings that newer compilers enable.
  make -s -C "$tmp/src/src" -j"$(nproc)" BUILD_STATIC_ONLY=y EXTRA_CFLAGS=-Wno-error \
    OBJDIR="$tmp/obj" DESTDIR="$dest" PREFIX=/ LIBDIR=/lib INCLUDEDIR=/include UAPIDIR=/include \
    install install_uapi_headers
  grep -q BPF_MAP_TYPE_ARENA "$dest/include/linux/bpf.h" || {
    echo "tools: pinned libbpf uapi header lacks BPF_MAP_TYPE_ARENA"
    return 1
  }
  rm -rf "$tmp"
  mark libbpf "$LIBBPF_VERSION"
}

install_bpf_headers() {
  have bpf-headers "$LIBBPF_BPF_HEADERS_VERSION" && return 0
  local dest="$tools/libbpf-bpf" tmp
  echo "tools: installing BPF-side libbpf headers $LIBBPF_BPF_HEADERS_VERSION"
  tmp=$(mktemp -d)
  libbpf_clone "$LIBBPF_BPF_HEADERS_VERSION" "$LIBBPF_BPF_HEADERS_COMMIT" "$tmp/src"
  rm -rf "$dest"
  make -s -C "$tmp/src/src" DESTDIR="$dest" PREFIX=/ INCLUDEDIR=/include install_headers
  rm -rf "$tmp"
  mark bpf-headers "$LIBBPF_BPF_HEADERS_VERSION"
}

all=(golangci-lint actionlint shellcheck govulncheck gitleaks check-jsonschema bpftool libbpf bpf-headers)
(($#)) || set -- "${all[@]}"

for t in "$@"; do
  case $t in
    golangci-lint) go_tool golangci-lint github.com/golangci/golangci-lint/v2/cmd/golangci-lint "$GOLANGCI_LINT_VERSION" ;;
    actionlint) go_tool actionlint github.com/rhysd/actionlint/cmd/actionlint "$ACTIONLINT_VERSION" ;;
    govulncheck) go_tool govulncheck golang.org/x/vuln/cmd/govulncheck "$GOVULNCHECK_VERSION" ;;
    gitleaks) go_tool gitleaks github.com/zricethezav/gitleaks/v8 "$GITLEAKS_VERSION" ;;
    shellcheck) install_shellcheck ;;
    check-jsonschema) install_jsonschema ;;
    bpftool) install_bpftool ;;
    libbpf) install_libbpf ;;
    bpf-headers) install_bpf_headers ;;
    *) echo "tools: unknown tool '$t' (known: ${all[*]})"; exit 2 ;;
  esac
done
