#!/usr/bin/env bash
# Measure ALLSEER's probe overhead against a realistic build (M5 W3).
#
# The milestone's target is "under 5% wall clock, measured rather than assumed".
# This script takes the measurement; internal/telemetry/benchstat decides what it
# means. The split is deliberate — the statistics are unit-tested on any machine,
# and this file only has to schedule runs correctly.
#
# WHAT IT DOES NOT TOUCH
#
#   - the developer's GOCACHE. Every cold run gets a fresh temporary cache which
#     this script creates and removes. `go clean -cache` is never called: it would
#     impose minutes of rebuild penalty on every later command in exchange for
#     exactly what an empty GOCACHE gives for free.
#   - the developer's GOMODCACHE, which is read and passed through. Without it a
#     root process would resolve modules against an empty /root/go/pkg/mod and
#     turn a compile benchmark into a download benchmark.
#   - the repository. `go build ./...` writes no binaries.
#
# WHY IT IS SHAPED THIS WAY
#
#   Interleaved and paired. Every replicate runs all five arms in a shuffled
#   order and the analysis pairs arms by replicate. Blocking the arms — all the
#   baselines, then all the treatments — would alias thermal drift and host
#   contention straight onto the treatment effect, and on the machine this was
#   designed against that drift is fifteen percent while the effect is expected
#   to be under one.
#
#   Replicate 1 is discarded as warm-up, by a rule fixed here rather than chosen
#   after seeing the numbers.
#
#   Scoped to a cgroup. Each run puts its workload — and only its workload — in
#   a cgroup of its own, on every arm, and the tracked arms register that one
#   cgroup. Tracking the session's own cgroup instead would instrument this
#   script, the shell that started it, and anything else the operator left in
#   the login session, charging all of it to the treatment arms and none of it
#   to the baseline.
#
# It needs root, a compiled object, and a cgroup v2 hierarchy, and it takes
# hours. It is not part of `make check` and never should be.
set -euo pipefail

REPLICATES=23          # 23 minus the warm-up replicate gives 22 pairs, two more
                       # than benchstat's MinPairs. At 21 the session had no
                       # headroom at all: one lost replicate took it to 19 pairs
                       # and INCONCLUSIVE after two hours, and only the A0 and
                       # A3 runs matter for that — a failure in either costs the
                       # replicate's headline pair. The fail-closed GOCACHE
                       # check is a new and correct way for a single run to
                       # fail, so the margin is worth the ten extra runs it
                       # costs. Two spare covers a cache-guard trip plus one
                       # transient; a session losing more than two replicates
                       # has something systematic wrong that more replicates
                       # would not rescue.
ARMS=(A0 A1 A2 A3 A4)
WORKLOAD=cold-build
STORM_OPS=200000
SEED=""
OUTDIR="bench"
QUICK=0

usage() {
	cat <<'USAGE'
usage: bench-overhead.sh [options]

  -r, --replicates N   replicates to run (default 23; the first is warm-up, and
                       the remaining 22 leave two spare above the 20 pairs the
                       acceptance rule needs)
  -a, --arms LIST      comma-separated arms (default A0,A1,A2,A3,A4)
  -w, --workload W     cold-build | openat-storm | both   (default cold-build)
      --storm-ops N    openat calls in the adversarial workload (default 200000)
  -s, --seed N         arm-ordering seed (default: derived from the clock)
  -o, --outdir DIR     where session files are written (default ./bench)
      --quick          3 replicates, for checking the harness. NOT acceptance-grade:
                       benchstat will report INCONCLUSIVE on too few pairs, which is
                       the correct answer and not a defect
  -h, --help           this text

Runs as root. Every arm runs under the same privilege, including A0, because
comparing an unprivileged baseline against a privileged treatment would confound
the privilege with the treatment.

The arm runner links against libbpf, so CGO_LDFLAGS is derived from pkg-config
when it is not already set. Compiling the runner happens before any run is
timed and is never part of a measured interval: the wall clock that becomes the
headline covers only the workload subprocess.
USAGE
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	-r | --replicates) REPLICATES="$2"; shift 2 ;;
	-a | --arms) IFS=',' read -r -a ARMS <<<"$2"; shift 2 ;;
	-w | --workload) WORKLOAD="$2"; shift 2 ;;
	--storm-ops) STORM_OPS="$2"; shift 2 ;;
	-s | --seed) SEED="$2"; shift 2 ;;
	-o | --outdir) OUTDIR="$2"; shift 2 ;;
	--quick) QUICK=1; REPLICATES=3; shift ;;
	-h | --help) usage; exit 0 ;;
	*) echo "unknown option: $1" >&2; usage; exit 2 ;;
	esac
done

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

info() { printf '  \033[32m✓\033[0m %s\n' "$1"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$1"; }
die()  { printf '  \033[31m✗\033[0m %s\n' "$1" >&2; exit 1; }

# --- preflight ----------------------------------------------------------------
#
# Every check that can fail the session is made before the first seventy-second
# run rather than after it.

[[ $EUID -eq 0 ]] || die "must run as root: loading BPF programs and reading the drop counter both require it"
command -v go >/dev/null || die "go not found on PATH (sudo may not preserve it; try: sudo -E env PATH=\"\$PATH\" $0)"
[[ -f bpf/allseer.bpf.o ]] || die "bpf/allseer.bpf.o not found — run 'make bpf' first"
[[ -d /sys/fs/cgroup ]] || die "no cgroup v2 hierarchy at /sys/fs/cgroup"
[[ "$(stat -fc %T /sys/fs/cgroup)" == "cgroup2fs" ]] || die \
	"/sys/fs/cgroup is not a unified (v2) hierarchy; the workload cannot be scoped to its own cgroup"

# CLONE_INTO_CGROUP, which is how each run's workload is created inside its own
# cgroup rather than migrated into it after the fact, landed in 5.7. Checked
# here so a host that cannot do it says so in a second rather than after the
# first arm fails.
KREL="$(uname -r)"
KMAJ="${KREL%%.*}"; KREST="${KREL#*.}"; KMIN="${KREST%%.*}"
if [[ "$KMAJ" =~ ^[0-9]+$ && "$KMIN" =~ ^[0-9]+$ ]]; then
	if ((KMAJ < 5 || (KMAJ == 5 && KMIN < 7))); then
		die "kernel $KREL is older than 5.7 and has no CLONE_INTO_CGROUP"
	fi
else
	warn "could not parse kernel version $KREL; assuming CLONE_INTO_CGROUP is available"
fi

: "${GOMODCACHE:=$(go env GOMODCACHE)}"
[[ -d "$GOMODCACHE" ]] || die "GOMODCACHE $GOMODCACHE does not exist; pre-warm it as the normal user with 'go build ./...'"

# The arm runner is `-tags ebpf`, so it links against libbpf through cgo. The
# Makefile exports CGO_LDFLAGS for the commands it runs; this script is not one
# of them, and sudo does not carry it either, so without this every run in the
# session fails at the link step with an undefined reference to libbpf and the
# session records nothing. Derived the same way the Makefile derives it.
: "${CGO_LDFLAGS:=$(pkg-config --libs libbpf 2>/dev/null || echo -lbpf)}"
export CGO_LDFLAGS CGO_ENABLED=1

# Link it once, here, rather than discovering it cannot be linked after the
# first arm has already been reported as a failed run. `-run ^$` builds and
# links the test binary and executes nothing.
if ! go test -tags ebpf -count=1 -run '^$' ./internal/telemetry/ >/dev/null 2>&1; then
	die "the -tags ebpf test binary does not build or link (CGO_LDFLAGS=$CGO_LDFLAGS).
     Re-run the same command without the redirect to see the compiler's output:
       go test -tags ebpf -count=1 -run '^\$' ./internal/telemetry/"
fi

if [[ -z "$SEED" ]]; then SEED=$(date +%s); fi
SESSION="$(date -u +%Y%m%dT%H%M%SZ)-$SEED"

# A relative --outdir is resolved against the repository root, here, once.
#
# ALLSEER_BENCH_OUT is read by a test binary, and `go test` runs a test binary
# from the directory of the package under test rather than from the module
# root. A relative path therefore resolves under internal/telemetry/, where no
# such directory exists, and O_CREATE creates a file rather than a missing
# parent — so every run of every arm failed to record itself. An absolute path
# means the same file whoever opens it and from wherever.
case "$OUTDIR" in
/*) ;;
*) OUTDIR="$REPO/$OUTDIR" ;;
esac
mkdir -p "$OUTDIR"
RUNS="$OUTDIR/$SESSION.jsonl"
REPORT="$OUTDIR/$SESSION.md"

case "$WORKLOAD" in
cold-build | openat-storm) WORKLOADS=("$WORKLOAD") ;;
both) WORKLOADS=(cold-build openat-storm) ;;
*) die "unknown workload: $WORKLOAD" ;;
esac

info "session   $SESSION"
info "arms      ${ARMS[*]}"
info "workloads ${WORKLOADS[*]}"
info "replicates $REPLICATES (replicate 1 is warm-up and is excluded)"
info "seed      $SEED"
info "runs      $RUNS"
[[ $QUICK -eq 1 ]] && warn "--quick: this is a harness check, not an acceptance run"

TOTAL=$((REPLICATES * ${#ARMS[@]} * ${#WORKLOADS[@]}))
warn "$TOTAL runs. The cold build takes roughly a minute each, so budget accordingly."

# --- the schedule -------------------------------------------------------------
#
# Arms are shuffled within each replicate, seeded, so the ordering is
# reproducible from the seed recorded in the session's environment block.
#
# The permutation comes from internal/telemetry/benchstat rather than from
#
#   printf '%s\n' "${ARMS[@]}" | shuf --random-source=<(yes "$SEED-$rep")
#
# which is what this script used and which did not shuffle. GNU shuf draws a
# permutation of five items from a single byte at the head of its random source
# — changing byte 1 changes the permutation, changing bytes 2 through 40 does
# not — and `yes "$SEED-$rep"` puts the only part that varies with the replicate
# behind a constant multi-character prefix. Every replicate of a session was
# handed the same byte and returned the same permutation: the recorded session
# ran A4, A2, A0, A3, A1 twenty-three times in a row. That is the blocked design
# the note at the top of this file says must not happen, with arm perfectly
# confounded with position in the replicate, and nothing in the session output
# said so. benchstat.ArmOrder is tested for the properties the shell could not
# be: a different permutation per replicate, reproducible from the seed, every
# arm exactly once, and no arm pinned to a position.
#
# The whole schedule is built here, before the first timed run, for two reasons.
# A `go run` that cannot compile should fail in preflight rather than ninety
# minutes into a session. And the previous `done < <(shuffled_arms "$rep")` ran
# its process substitution concurrently with the replicate's first measured
# workload, which put work of the harness's own inside a measured interval.

arm_order() {
	go run ./internal/telemetry/benchstat/cmd/benchstat \
		-order -seed "$SEED" -replicate "$1" -arms "$(IFS=','; printf '%s' "${ARMS[*]}")"
}

declare -a SCHEDULE
for ((rep = 1; rep <= REPLICATES; rep++)); do
	if ! SCHEDULE[rep]="$(arm_order "$rep")"; then
		die "could not compute the arm order for replicate $rep"
	fi
done
info "order     rep1: ${SCHEDULE[1]}${SCHEDULE[2]:+  |  rep2: ${SCHEDULE[2]}}"

SEQ=0
FIRST=1
START_TIME=$(date +%s)

for ((rep = 1; rep <= REPLICATES; rep++)); do
	WARMUP=0
	[[ $rep -eq 1 ]] && WARMUP=1

	for workload in "${WORKLOADS[@]}"; do
		# Unquoted on purpose: SCHEDULE[rep] is a space-separated list of arm
		# names, which benchstat has already validated against its own arm
		# constants, so word splitting is the intent and cannot split anything
		# unexpected.
		# shellcheck disable=SC2086
		for arm in ${SCHEDULE[rep]}; do
			SEQ=$((SEQ + 1))

			# A fresh, empty GOCACHE for every cold run. Created here and
			# removed here, so the runner never has to own a directory it did
			# not make.
			GOCACHE_RUN=""
			if [[ "$workload" == "cold-build" ]]; then
				GOCACHE_RUN="$(mktemp -d -t allseer-bench-gocache-XXXXXX)"
			fi

			printf '  [%3d/%3d] rep %2d  %s  %-12s' "$SEQ" "$TOTAL" "$rep" "$arm" "$workload"

			set +e
			ALLSEER_BENCH_ARM="$arm" \
			ALLSEER_BENCH_WORKLOAD="$workload" \
			ALLSEER_BENCH_REPLICATE="$rep" \
			ALLSEER_BENCH_SEQUENCE="$SEQ" \
			ALLSEER_BENCH_SESSION="$SESSION" \
			ALLSEER_BENCH_WARMUP="$WARMUP" \
			ALLSEER_BENCH_OUT="$RUNS" \
			ALLSEER_BENCH_REPO="$REPO" \
			ALLSEER_BENCH_GOCACHE="$GOCACHE_RUN" \
			ALLSEER_BENCH_GOMODCACHE="$GOMODCACHE" \
			ALLSEER_BENCH_EMIT_ENV="$FIRST" \
			ALLSEER_BENCH_SEED="$SEED" \
			ALLSEER_BENCH_REPLICATES="$REPLICATES" \
			ALLSEER_BENCH_STORM_OPS="$STORM_OPS" \
			ALLSEER_BENCH_OBJECT="$REPO/bpf/allseer.bpf.o" \
				go test -tags ebpf -count=1 -timeout 30m \
					-run '^TestBenchmarkArm$' ./internal/telemetry/ \
					>/dev/null 2>&1
			rc=$?
			set -e

			# Cleanup is tidiness, not measurement, and must never be able to
			# end a session that is hours long. Two ways it could: the go build
			# cache leaves read-only files, whose directories a later rm can
			# refuse to unlink; and under `set -e` a bare `[[ -n "$X" ]] && rm`
			# aborts the script on the storm workload, where the variable is
			# empty by design and the test therefore fails.
			if [[ -n "$GOCACHE_RUN" ]]; then
				chmod -R u+w "$GOCACHE_RUN" 2>/dev/null || true
				rm -rf "$GOCACHE_RUN" || warn "could not remove $GOCACHE_RUN"
			fi

			if [[ $rc -ne 0 ]]; then
				printf ' \033[31mrun failed (rc=%d)\033[0m\n' "$rc"
				warn "re-run this one arm without the output redirect to see why"
				# A failed run writes no record, so it captured no environment
				# block either. FIRST stays set so the next run captures one:
				# clearing it here would leave the session with no environment
				# at all whenever its first run happened to fail.
			else
				printf ' ok\n'
				FIRST=0
			fi
		done
	done
done

ELAPSED=$(($(date +%s) - START_TIME))
info "measurement complete in $((ELAPSED / 60))m $((ELAPSED % 60))s"

# --- analysis -----------------------------------------------------------------

info "analysing $RUNS"
set +e
go run ./internal/telemetry/benchstat/cmd/benchstat -runs "$RUNS" -o "$REPORT"
VERDICT_RC=$?
set -e

info "report $REPORT"
if [[ $VERDICT_RC -ne 0 ]]; then
	warn "the session did not pass. The report states which rule it failed."
	warn "An INCONCLUSIVE result is not a failure of the probes; it is a statement"
	warn "that this session cannot answer the question. It must not be recorded as a pass."
fi
exit $VERDICT_RC
