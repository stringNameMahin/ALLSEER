#!/usr/bin/env bash
# Check a built .deb: its control fields, that every installed file is in it
# with root ownership and the right mode, that configuration is marked as
# conffiles so an upgrade keeps an operator's edits, and that no email
# address is in it.
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
# Not printed: a wrong value may be someone's address.
[[ $(dpkg-deb --field "$deb" Maintainer) == 'ALLSEER Maintainers <<placeholder>@gmail.com>' ]] ||
  fail "Maintainer is not the placeholder"

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

# Nothing about whoever built the package may ship in it, control files or
# payload.
"$(dirname "$0")/check-emails.sh" "$deb" || status=1

[[ $status -eq 0 ]] && echo "check-deb: $deb is complete"
exit $status
