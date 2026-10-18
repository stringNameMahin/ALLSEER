#!/usr/bin/env bash
# Fail when a test that must run did not run.
#
# The integration job's value is that the privileged suites actually execute.
# Every one of them skips itself when it is not root, when kernel BTF is
# absent, or when the BPF object is missing, and a skipped Go test exits 0. So
# a runner that lost any of those prerequisites produces a green job with
# nothing tested, and the only trace is a line in the summary nobody has to
# read. This turns that into a failure.
#
# Usage: require-ran.sh <test.json> <name>...
#   <name> is a Go test name, matched exactly. Each must appear with a pass
#   action in the recorded output.
set -euo pipefail

json=$1
shift

if [[ ! -s $json ]]; then
  echo "require-ran: $json is missing or empty; no test results to check" >&2
  exit 1
fi

passed=$(jq -R 'fromjson? // empty' "$json" |
  jq -rs 'map(select(type == "object" and .Test != null and .Action == "pass") | .Test) | unique | .[]')

status=0
for want in "$@"; do
  if ! grep -qxF "$want" <<<"$passed"; then
    echo "require-ran: $want did not pass; it was skipped, failed or never ran" >&2
    status=1
  fi
done

if [[ $status -ne 0 ]]; then
  echo "" >&2
  echo "The privileged suite did not run. A skip is not a pass: this job exists" >&2
  echo "to prove the probes load and the governed paths work on a real kernel." >&2
  echo "Check that the job is root, that /sys/kernel/btf/vmlinux exists and that" >&2
  echo "bpf/allseer.bpf.o was built." >&2
  exit 1
fi

echo "require-ran: all $# required tests ran and passed"
