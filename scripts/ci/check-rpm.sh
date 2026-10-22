#!/usr/bin/env bash
# Check a built .rpm the way check-deb.sh checks the .deb: its header, that
# every installed file is in it with root ownership and the right mode, that
# configuration survives an upgrade, that the build host is not recorded,
# and that no email address is in it.
#
# Usage: check-rpm.sh <file.rpm>
set -euo pipefail

rpm=$1
status=0
fail() {
  echo "check-rpm: $*" >&2
  status=1
}

q() { rpm -qp --nosignature --queryformat "$1" -- "$rpm"; }
fields=$(q '%{NAME}\n%{PACKAGER}\n%{BUILDHOST}\n%{VERSION}\n%{ARCH}\n%{SUMMARY}\n%{URL}\n') || {
  echo "check-rpm: cannot read $rpm" >&2
  exit 1
}
mapfile -t f <<<"$fields"
[[ ${f[0]} == allseer ]] || fail "package is not named allseer"
# Not printed: a wrong value may be someone's address or host name.
[[ ${f[1]} == 'ALLSEER Maintainers <<placeholder>@gmail.com>' ]] || fail "Packager is not the placeholder"
[[ ${f[2]} == allseer-build ]] || fail "the build host is recorded"
for i in 3 4 5 6; do
  [[ -n ${f[$i]} && ${f[$i]} != "(none)" ]] || fail "header field $i is empty"
done

contents=$(rpm -qplv --nosignature -- "$rpm")
want() {
  local mode=$1 path=$2 line m user group
  line=$(grep -E " ${path}\$" <<<"$contents" || true)
  if [[ -z $line ]]; then
    fail "missing $path"
    return
  fi
  read -r m _ user group _ <<<"$line"
  [[ $m == "$mode" && $user == root && $group == root ]] || fail "$path is not $mode root/root: $line"
}
want -rwxr-xr-x /usr/bin/allseerd
want -rwxr-xr-x /usr/bin/allseer-shim
want -rwxr-xr-x /usr/bin/allseerctl
want -rw-r--r-- /usr/lib/allseer/allseer.bpf.o
want -rw-r--r-- /usr/lib/systemd/system/allseerd.service
want -rw-r--r-- /etc/allseer/allseerd.yaml
want drwx------ /var/lib/allseer

# c is a config file and n is noreplace: an upgrade keeps an operator's edits.
flags=$(q '[%{FILEFLAGS:fflags} %{FILENAMES}\n]')
for c in /etc/allseer/allseerd.yaml /etc/allseer/rules.yaml /etc/allseer/sensitivity.yaml; do
  line=$(grep -E " ${c}\$" <<<"$flags" || true)
  [[ ${line%% *} == *c* && ${line%% *} == *n* ]] || fail "$c is not a noreplace config file"
done

# Nothing about whoever built the package may ship in it, header or payload.
"$(dirname "$0")/check-emails.sh" "$rpm" || status=1

[[ $status -eq 0 ]] && echo "check-rpm: $rpm is complete"
exit $status
