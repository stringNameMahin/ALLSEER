#!/usr/bin/env bash
# Check a staged make install: every file in place with its mode, the
# installed configuration valid and free of warnings, and the systemd unit
# accepted by systemd-analyze.
#
# Usage: check-install.sh <destdir> <bindir> <libdir> <sysconfdir> <unitdir>
set -euo pipefail

root=$1 bindir=$2 libdir=$3 sysconfdir=$4 unitdir=$5
status=0

fail() {
  echo "check-install: $*" >&2
  status=1
}

want() {
  local path=$root$1 mode=$2
  if [[ ! -f $path ]]; then
    fail "missing $1"
    return
  fi
  local got
  got=$(stat -c %a "$path")
  [[ $got == "$mode" ]] || fail "$1 has mode $got, want $mode"
}

want "$bindir/allseerd" 755
want "$bindir/allseer-shim" 755
want "$bindir/allseerctl" 755
want "$libdir/allseer.bpf.o" 644
want "$sysconfdir/allseerd.yaml" 644
want "$sysconfdir/rules.yaml" 644
want "$sysconfdir/sensitivity.yaml" 644
want "$unitdir/allseerd.service" 644
[[ -d $root/var/lib/allseer ]] || fail "missing /var/lib/allseer"

if grep -q '@[A-Z]*@' "$root$sysconfdir/allseerd.yaml" "$root$unitdir/allseerd.service"; then
  fail "a placeholder was not substituted"
fi

# The installed configuration must load cleanly. A warning here would be one
# every operator sees on every start.
out=$("$root$bindir/allseerd" --check --config "$root$sysconfdir/allseerd.yaml" 2>&1) ||
  fail "allseerd --check failed: $out"
if [[ $out != "configuration OK" ]]; then
  fail "the installed configuration is not clean: $out"
fi

# systemd-analyze checks ExecStart exists, so the copy it checks points into
# the staged tree.
if command -v systemd-analyze >/dev/null; then
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  sed "s|$bindir/allseerd|$root$bindir/allseerd|" "$root$unitdir/allseerd.service" >"$tmp/allseerd.service"
  if ! verify=$(systemd-analyze verify "$tmp/allseerd.service" 2>&1); then
    fail "systemd-analyze verify: $verify"
  elif [[ -n $verify ]]; then
    fail "systemd-analyze verify warned: $verify"
  fi
else
  echo "check-install: systemd-analyze not found; the unit was not verified"
fi

[[ $status -eq 0 ]] && echo "check-install: staged install is complete and valid"
exit $status
