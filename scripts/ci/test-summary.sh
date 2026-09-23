#!/usr/bin/env bash
# Render `go test -json` output as a Markdown summary: totals, per-package
# results and coverage, every failed test, and every skipped test with the
# reason it gave. Skips are listed so a guarded suite never passes silently.
# Usage: test-summary.sh <title> <test.json> [coverage-func.txt]
set -euo pipefail

title=$1
json=$2
cover=${3:-}

total=""
if [[ -n $cover && -s $cover ]]; then
  total=$(awk '/^total:/ {print $NF}' "$cover")
fi

jq -R 'fromjson? // empty' "$json" | jq -rs --arg title "$title" --arg total "$total" '
  def esc: gsub("\\|"; "\\|") | gsub("[\r\n]+"; " ");
  def short: sub("^github.com/[^/]+/[^/]+/"; "");
  def result: .Action == "pass" or .Action == "fail" or .Action == "skip";

  map(select(type == "object")) as $ev
  | ($ev | map(select(.Test != null and result))) as $tests
  | ($ev | map(select(.Test == null and .Package != null and result))) as $pkgs
  | ($ev | map(select(.Action == "build-fail") | .ImportPath)) as $buildfail
  | ($ev | map(select(.Test != null and .Action == "output"))
      | group_by([.Package, .Test])
      | map({key: "\(.[0].Package) \(.[0].Test)",
             value: (map(.Output | sub("^\\s+"; "") | sub("\\s+$"; ""))
                     | map(select(length > 0 and (startswith("=== ") | not) and (startswith("--- ") | not)))
                     | last // "")})
      | from_entries) as $why
  | ([$ev[] | select(.Test == null and .Action == "output") | . as $e
       | (.Output | capture("coverage: (?<c>[0-9.]+)% of statements"))
       | {key: $e.Package, value: "\(.c)%"}] | from_entries) as $cov
  | ($tests | map(select(.Action == "pass")) | length) as $np
  | ($tests | map(select(.Action == "fail")) | length) as $nf
  | ($tests | map(select(.Action == "skip")) | length) as $ns
  | ($pkgs | map(select(.Action == "skip")) | map(.Package)) as $notests

  | "### \($title)\n",
    "**\($np) passed, \($nf) failed, \($ns) skipped** across \($pkgs | length) packages."
      + (if $total != "" then " Total statement coverage: **\($total)**." else "" end) + "\n",
    (if ($np + $nf + $ns) == 0 then "**No tests ran.**\n" else empty end),
    (if ($buildfail | length) > 0 then "**Build failed:** \($buildfail | map(short) | join(", "))\n" else empty end),
    "| Package | Result | Passed | Failed | Skipped | Coverage |",
    "|---|---|---:|---:|---:|---:|",
    ($pkgs | map(select(.Action != "skip")) | sort_by(.Package)[] as $p
      | ($tests | map(select(.Package == $p.Package))) as $t
      | "| \($p.Package | short) | \(if ($t | length) == 0 then "no tests" else $p.Action end) | \($t | map(select(.Action == "pass")) | length) | \($t | map(select(.Action == "fail")) | length) | \($t | map(select(.Action == "skip")) | length) | \($cov[$p.Package] // "-") |"),
    (if ($notests | length) > 0
      then "\nPackages with no test files: \($notests | map(short) | sort | join(", "))" else empty end),
    (if $nf > 0 then
      "\n#### Failed tests\n",
      "| Package | Test |",
      "|---|---|",
      ($tests | map(select(.Action == "fail")) | sort_by(.Package, .Test)[]
        | "| \(.Package | short) | \(.Test | esc) |")
    else empty end),
    (if $ns > 0 then
      "\n#### Skipped tests\n",
      "| Package | Test | Reason |",
      "|---|---|---|",
      ($tests | map(select(.Action == "skip")) | sort_by(.Package, .Test)[]
        | "| \(.Package | short) | \(.Test | esc) | \($why["\(.Package) \(.Test)"] // "" | esc) |")
    else empty end),
    ""
'
