#!/usr/bin/env bash
# Check a built .deb: its control fields, that every installed file is in it
# with root ownership and the right mode, and that configuration is marked
# as conffiles so an upgrade keeps an operator's edits.
#
# Usage: check-deb.sh <file.deb>
set -euo pipefail

deb=$1
status=0
fail() {
  echo "check-deb: $*" >&2
  status=1
}

for field in Package Version Architecture Maintainer Depends Description; do
  dpkg-deb --field "$deb" "$field" >/dev/null 2>&1 || fail "no $field field"
done
[[ $(dpkg-deb --field "$deb" Package) == allseer ]] || fail "package is not named allseer"

contents=$(dpkg-deb --contents "$deb")
want() {
  local mode=$1 path=$2
  local line
  line=$(grep -E " \\./${path#/}\$" <<<"$contents" || true)
  if [[ -z $line ]]; then
    fail "missing $path"
    return
  fi
  [[ $line == "$mode root/root "* ]] || fail "$path is not $mode root/root: $line"
}
want -rwxr-xr-x /usr/bin/allseerd
want -rwxr-xr-x /usr/bin/allseer-shim
want -rwxr-xr-x /usr/bin/allseerctl
want -rw-r--r-- /usr/lib/allseer/allseer.bpf.o
want -rw-r--r-- /usr/lib/systemd/system/allseerd.service
want -rw-r--r-- /etc/allseer/allseerd.yaml
want drwx------ /var/lib/allseer/

conffiles=$(dpkg-deb --ctrl-tarfile "$deb" | tar -xO ./conffiles)
for c in /etc/allseer/allseerd.yaml /etc/allseer/rules.yaml /etc/allseer/sensitivity.yaml; do
  grep -qxF "$c" <<<"$conffiles" || fail "$c is not a conffile"
done

# Nothing about whoever built the package may ship in it. The builder's git
# email is the identity most likely to leak, so the whole package, control
# files and payload, is searched for it.
email=$(git config user.email 2>/dev/null || true)
if [[ -n $email ]]; then
  # grep -c reads everything: grep -q would stop at the first match, the
  # writer would die of SIGPIPE, and pipefail would turn a find into a pass.
  found=$({ dpkg-deb --ctrl-tarfile "$deb"; dpkg-deb --fsys-tarfile "$deb"; } | grep -acF "$email" || true)
  if [[ $found != 0 ]]; then
    fail "the package contains the builder's email address"
  fi
fi

[[ $status -eq 0 ]] && echo "check-deb: $deb is complete"
exit $status
