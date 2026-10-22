#!/usr/bin/env bash
# Fail if a file, a directory, a .deb or .rpm package or a .tar contains an
# email address, in file contents, file names or symlink targets. Build
# outputs carry no identity: the package maintainer is a placeholder that is
# not an address, so any address found is a leak, most likely of whoever
# built it.
# Nothing needs to know the address, so the check runs the same with or
# without a git identity. Findings name the file only, so a CI log never
# shows the address.
#
# Usage: check-emails.sh <path>...
set -euo pipefail
export LC_ALL=C

addr='[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}'
# In binaries the domain must also end the match. Go test binaries hold
# length-prefixed strings, and a length of 64 is "@": "...Size@github.com/x"
# is two strings, not an address followed by a path.
bin_addr=$addr'([^A-Za-z0-9/-]|$)'
status=0
fail() {
  echo "check-emails: $*" >&2
  status=1
}

# Where a finding is, unless the path itself holds an address.
where() {
  local p=${1/#"$dir"/$path} rc=0
  grep -qE -- "$addr" <<<"$p" || rc=$?
  if ((rc == 1)); then echo "$p"; else echo "$path: a file whose name holds an address"; fi
}

(($#)) || {
  echo "usage: check-emails.sh <path>..." >&2
  exit 2
}

# A search that cannot match passes everything.
if ! grep -qE -- "$addr" <<<'someone@example.org' ||
  ! grep -qE -- "$bin_addr" <<<'someone@example.org'; then
  echo "check-emails: the search does not match a known address" >&2
  exit 2
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

n=0
for path in "$@"; do
  n=$((n + 1))
  dir=$path
  # Packages and tarballs are unpacked so each member is checked on its own.
  if [[ -f $path && $path == *.deb ]]; then
    dir=$tmp/x$n
    dpkg-deb --raw-extract "$path" "$dir" || {
      fail "$path: cannot extract"
      continue
    }
  elif [[ -f $path && $path == *.tar ]]; then
    dir=$tmp/x$n
    if ! mkdir "$dir" || ! tar -xf "$path" -C "$dir"; then
      fail "$path: cannot extract"
      continue
    fi
  elif [[ -f $path && $path == *.rpm ]]; then
    # The payload unpacked, and the header (packager, scripts, file names) as
    # text beside it.
    dir=$tmp/x$n
    if ! mkdir "$dir" || ! rpm -qp --nosignature --xml -- "$path" >"$dir/.rpm-header.xml" ||
      ! rpm2cpio "$path" | (cd "$dir" && cpio -idm --quiet --no-absolute-filenames); then
      fail "$path: cannot extract"
      continue
    fi
  elif [[ ! -e $path ]]; then
    fail "$path: does not exist"
    continue
  fi

  # Every listing goes to a file: a failed find in a pipeline would read as
  # "no match". Names include symlink targets.
  files=$tmp/files$n names=$tmp/names$n
  if ! find "$dir" -type f -print0 >"$files" ||
    ! find "$dir" -mindepth 1 -printf '%P\0%l\0' >"$names"; then
    fail "$path: cannot list"
    continue
  fi
  if [[ ! -s $files ]]; then
    fail "$path: no files to search"
    continue
  fi

  # grep sees compressed or archived bytes, not the text inside them.
  while IFS= read -r -d '' f; do
    magic=$(od -An -tx1 -N6 -- "$f" | tr -d ' \n') || {
      fail "$(where "$f"): cannot read"
      continue
    }
    case $magic in
      1f8b* | 425a68* | fd377a585a00 | 28b52ffd* | 504b0304* | 213c61726368 | edabeedb*)
        fail "$(where "$f"): compressed or archived, cannot be searched" ;;
    esac
  done <"$files"

  # grep exits 0 on a match, 1 on none, 2 on an error.
  rc=0
  grep -zqE -- "$addr" "$names" || rc=$?
  case $rc in
    0) fail "$path: a file name contains an email address" ;;
    1) ;;
    *) fail "$path: the file name search failed" ;;
  esac

  # Text files (-I skips binaries) with the plain pattern, every file with
  # the binary one.
  text=0 any=0
  grep -rlIE -D skip -- "$addr" "$dir" >"$tmp/text$n" || text=$?
  grep -rlaE -D skip -- "$bin_addr" "$dir" >"$tmp/any$n" || any=$?
  sort -u "$tmp/text$n" "$tmp/any$n" >"$tmp/found$n" || {
    fail "$path: the search failed"
    continue
  }
  while IFS= read -r f; do
    fail "$(where "$f"): contains an email address"
  done <"$tmp/found$n"
  if ((text > 1 || any > 1)); then
    fail "$path: the search failed"
  fi
done

[[ $status -eq 0 ]] && echo "check-emails: no email address in $*"
exit $status
