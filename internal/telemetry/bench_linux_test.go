//go:build linux && ebpf

package telemetry

// The probe-overhead arm runner (M5 W3).
//
// This is not a `testing.B`. The thing being measured is a subprocess build
// against a cold cache, under a kernel configuration that has to be set up and
// torn down around it, and the comparison is between whole process invocations
// rather than between two functions. `go test -bench` can express none of that:
// it cannot interleave arms across process boundaries, cannot give each
// iteration a fresh GOCACHE, and reports ns/op for a thing whose unit is one
// seventy-second build.
//
// So this file is one arm of one replicate, invoked by
// scripts/bench-overhead.sh, emitting a single JSON line that
// internal/telemetry/benchstat later reads. It lives as a test rather than as a
// command for one reason: the cgroup and loader machinery every arm needs is
// already written, in this package's own `_test.go` files — trackedKV,
// rawOpenat, requireRoot, objectOrSkip, requireCgroupV2 — and
// re-implementing it in a `cmd/` would be a second copy of exactly the code
// whose correctness the runtime tests establish. The env-var-guarded test is a
// pattern this package already uses for a subprocess helper.
//
// Nothing here runs during an ordinary `go test`: without ALLSEER_BENCH_ARM the
// entry point skips immediately.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/stringNameMahin/ALLSEER/internal/telemetry/abi"
	"github.com/stringNameMahin/ALLSEER/internal/telemetry/benchstat"
)

// Environment variables the orchestrator sets. Every one is read once, in
// benchConfigFromEnv, so the contract with the shell is in one place.
const (
	envArm        = "ALLSEER_BENCH_ARM"        // A0..A4; unset means "not a benchmark run"
	envWorkload   = "ALLSEER_BENCH_WORKLOAD"   // cold-build | openat-storm
	envReplicate  = "ALLSEER_BENCH_REPLICATE"  // integer, the pairing key
	envSequence   = "ALLSEER_BENCH_SEQUENCE"   // integer, position in the session
	envSession    = "ALLSEER_BENCH_SESSION"    // session id
	envWarmUp     = "ALLSEER_BENCH_WARMUP"     // "1" to mark this run excluded
	envOut        = "ALLSEER_BENCH_OUT"        // JSONL file to append to
	envRepoRoot   = "ALLSEER_BENCH_REPO"       // repository root to build
	envGoCache    = "ALLSEER_BENCH_GOCACHE"    // the fresh, per-run GOCACHE
	envGoModCache = "ALLSEER_BENCH_GOMODCACHE" // the developer's, read-only in practice
	envEmitEnv    = "ALLSEER_BENCH_EMIT_ENV"   // "1" on the session's first run
	envSeed       = "ALLSEER_BENCH_SEED"       // arm-ordering seed, recorded not used here
	envReplicates = "ALLSEER_BENCH_REPLICATES" // planned replicate count, recorded
	envStormOps   = "ALLSEER_BENCH_STORM_OPS"  // openat count for the adversarial workload
)

type benchConfig struct {
	arm, workload, session, out   string
	replicate, sequence           int
	warmUp, emitEnv               bool
	repoRoot, goCache, goModCache string
	seed                          int64
	replicates, stormOps          int
}

// TestBenchmarkArm runs exactly one arm of one replicate.
//
// A test rather than a command, and guarded by an environment variable so an
// ordinary `go test -tags ebpf ./...` skips it in microseconds rather than
// starting a seventy-second build.
func TestBenchmarkArm(t *testing.T) {
	arm := os.Getenv(envArm)
	if arm == "" {
		t.Skip("not a benchmark run: " + envArm + " is unset")
	}

	cfg := benchConfigFromEnv(t, arm)

	// Every arm runs under identical privilege. A0 needs no root of its own,
	// but comparing an unprivileged baseline against a privileged treatment
	// would confound the privilege with the treatment — different ulimits,
	// different page cache, a different user's caches — so the orchestrator
	// runs the whole session as root and this check holds for all five.
	requireRoot(t)

	run := benchstat.Run{
		Schema:    benchstat.Schema,
		SessionID: cfg.session,
		Replicate: cfg.replicate,
		Sequence:  cfg.sequence,
		Arm:       cfg.arm,
		Workload:  cfg.workload,
		WarmUp:    cfg.warmUp,
	}

	// The workload's own cgroup, created before anything is loaded because the
	// tracked arms have to register its ID in the filter map before the first
	// process enters it. Created for every arm including A0, so that cgroup
	// placement is identical across the comparison and cannot be confounded
	// with the treatment.
	cg := newWorkloadCgroup(t)
	defer cg.remove(t)

	harness := setUpArm(t, cfg, cg, &run)
	defer harness.stop(t, &run)

	measureWorkload(t, cfg, cg, &run)
	harness.settle()

	// Stopped here rather than left to the deferred call above.
	//
	// stop is what reads the drop counter and collects the drained event
	// counts, and appendRun below is what serialises the record. Leaving stop
	// to the defer writes every record before those fields are populated, so
	// every run reports zero events and zero drops — which benchstat correctly
	// reads as a broken cgroup registration, and which no session could ever
	// pass. The defer stays as the path for a run that fails before this point.
	harness.stop(t, &run)

	if cfg.emitEnv {
		run.Env = captureEnvironment(t, cfg, harness, cg)
	}
	appendRun(t, cfg.out, run)

	t.Logf("arm %s replicate %d: wall %.3fs, user %.3fs, sys %.3fs, events %d, drops %d",
		run.Arm, run.Replicate, run.WallSeconds, run.UserSeconds, run.SysSeconds,
		run.EventsTotal, run.RingbufDrops)
	if other, ok := run.OtherCPUSeconds(); ok {
		t.Logf("  host: %v; cpu spent on anything but this workload %.1fs", run.Host, other)
	}
}

func benchConfigFromEnv(t *testing.T, arm string) benchConfig {
	t.Helper()

	atoi := func(key string, def int) int {
		v := os.Getenv(key)
		if v == "" {
			return def
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			t.Fatalf("%s=%q: %v", key, v, err)
		}
		return n
	}

	cfg := benchConfig{
		arm:        arm,
		workload:   os.Getenv(envWorkload),
		session:    os.Getenv(envSession),
		out:        os.Getenv(envOut),
		replicate:  atoi(envReplicate, 0),
		sequence:   atoi(envSequence, 0),
		warmUp:     os.Getenv(envWarmUp) == "1",
		emitEnv:    os.Getenv(envEmitEnv) == "1",
		repoRoot:   os.Getenv(envRepoRoot),
		goCache:    os.Getenv(envGoCache),
		goModCache: os.Getenv(envGoModCache),
		seed:       int64(atoi(envSeed, 0)),
		replicates: atoi(envReplicates, 0),
		stormOps:   atoi(envStormOps, 200000),
	}
	if cfg.workload == "" {
		cfg.workload = benchstat.WorkloadColdBuild
	}
	if cfg.out == "" {
		t.Fatalf("%s is required so the run can be recorded", envOut)
	}
	if cfg.workload == benchstat.WorkloadColdBuild {
		if cfg.repoRoot == "" || cfg.goCache == "" {
			t.Fatalf("%s and %s are required for the %s workload",
				envRepoRoot, envGoCache, benchstat.WorkloadColdBuild)
		}
	}
	// A relative output path is resolved against the repository root.
	//
	// `go test` runs a test binary from the directory of the package under
	// test rather than from the module root, so a relative ALLSEER_BENCH_OUT
	// resolves under internal/telemetry/ — a directory the session never
	// created. The orchestrator passes an absolute path now, and this keeps a
	// hand-run single arm writing where the session would have written it.
	if cfg.out != "" && !filepath.IsAbs(cfg.out) && cfg.repoRoot != "" {
		cfg.out = filepath.Join(cfg.repoRoot, cfg.out)
	}
	switch cfg.arm {
	case benchstat.ArmOff, benchstat.ArmLoaded, benchstat.ArmAttachedUntracked,
		benchstat.ArmTracked, benchstat.ArmDecoded, benchstat.ArmTrackedForceWake:
	default:
		t.Fatalf("%s=%q is not one of %v", envArm, cfg.arm, benchstat.Arms())
	}
	return cfg
}

// --- the telemetry harness, one shape per arm ---------------------------------

// armHarness is whatever telemetry the arm asked for, already running by the
// time the workload starts.
type armHarness struct {
	loader    *BPFLoader
	records   <-chan []byte
	stopDrain chan struct{}
	drained   chan struct{}

	byType       map[string]uint64
	total        uint64
	decodeErrors uint64

	programs []string
	ringSize int

	// stopped makes stop idempotent, because it is both called explicitly once
	// the workload is done and deferred as the path for a run that fails first.
	stopped bool
}

// settle gives the ring buffer's poll a moment to deliver records the workload
// produced just before it exited.
//
// A fixed pause rather than a drain-until-empty loop: the loop would run for as
// long as the kernel kept handing over records, which on a busy host is not
// bounded, and the count it produced would then depend on how long it chose to
// wait. A fixed, declared settle is a worse estimate of the true count and a
// better-behaved one, and the count is a diagnostic rather than a measurement.
func (h *armHarness) settle() {
	if h == nil || h.records == nil {
		return
	}
	time.Sleep(500 * time.Millisecond)
}

func (h *armHarness) stop(t *testing.T, run *benchstat.Run) {
	t.Helper()
	if h == nil || h.stopped {
		return
	}
	h.stopped = true
	if h.stopDrain != nil {
		close(h.stopDrain)
		<-h.drained
	}
	if h.loader != nil {
		// Ordering here is the whole point. The user-space channel has just
		// been drained by the goroutine above; this asks whether the *kernel*
		// ring still holds anything, and it has to be asked before Close below
		// detaches the programs and frees the ring along with the answer.
		if pending, err := h.loader.ringHasPendingRecords(MapEvents); err != nil {
			run.Error = appendErr(run.Error, fmt.Sprintf("checking for stranded records: %v", err))
		} else if pending {
			// A record that was reserved and submitted but never consumed is
			// not a drop: count_ringbuf_drop fires only where
			// bpf_ringbuf_reserve returned NULL, so ringbuf_drops reports zero
			// for this and always will. Nothing else in the pipeline would
			// notice either — the run would simply report fewer events than it
			// produced, which reads as a quiet workload rather than a lost one.
			//
			// Recorded as an Error rather than as a new field with a new rule.
			// Analyze already excludes any run whose Error is non-empty and
			// counts it in FailedRuns, so this reuses the validity machinery
			// that exists instead of adding a second one beside it.
			run.Error = appendErr(run.Error,
				"the kernel ring buffer still held unread records at teardown: this run observed "+
					"fewer events than the probes produced, and ringbuf_drops cannot see that loss")
		}

		// The drop counter is read before anything is detached, because
		// detaching frees the map it lives in.
		if n, err := h.loader.ReadCounter(context.Background(), MapRingbufDrops); err == nil {
			run.RingbufDrops = n
		} else {
			run.Error = appendErr(run.Error, fmt.Sprintf("ReadCounter: %v", err))
		}
		if err := h.loader.Close(); err != nil {
			run.Error = appendErr(run.Error, fmt.Sprintf("Close: %v", err))
		}
	}
	run.Events = h.byType
	run.EventsTotal = h.total
	run.DecodeErrors = h.decodeErrors
}

// setUpArm builds the arm's telemetry configuration and times the parts of it
// ALLSEER pays for once.
//
// Load and attach are timed and reported separately, and deliberately never
// added to the workload's wall clock. A governed session pays them once at
// startup; folding a fixed cost into a per-build ratio would make the measured
// overhead a function of how long the build happened to be.
// forceWakeupForArm is the ring buffer notification policy an arm loads with.
//
// False for every arm but the forced-wakeup one, and false is what the object
// already declares, so applyForceWakeup writes nothing and the loaded programs
// are the ones the acceptance session measured. A pure function rather than a
// branch inside setUpArm because it is the entire definition of the new arm,
// and a definition that can only be checked by loading BPF as root can only be
// checked on one machine.
func forceWakeupForArm(arm string) bool {
	return arm == benchstat.ArmTrackedForceWake
}

// armTracksCgroup reports whether an arm registers the workload's cgroup in the
// filter map, which is what turns a probe that returns after a lookup into one
// that reports an event.
//
// ArmAttachedUntracked is the deliberate false: it attaches everything and
// registers nothing, which is what separates the cost of a tracepoint firing
// from the cost of a record being produced.
func armTracksCgroup(arm string) bool {
	switch arm {
	case benchstat.ArmTracked, benchstat.ArmDecoded, benchstat.ArmTrackedForceWake:
		return true
	default:
		return false
	}
}

func setUpArm(t *testing.T, cfg benchConfig, cg *workloadCgroup, run *benchstat.Run) *armHarness {
	t.Helper()

	if cfg.arm == benchstat.ArmOff {
		// The true baseline: nothing is loaded, so there is nothing to time.
		return &armHarness{byType: map[string]uint64{}}
	}

	obj := objectOrSkip(t)
	ctx := context.Background()
	h := &armHarness{byType: map[string]uint64{}, ringSize: benchRingBufferSize}

	l := NewLoader(Config{
		ObjectPath:         obj,
		RingBufferSize:     h.ringSize,
		RingbufForceWakeup: forceWakeupForArm(cfg.arm),
	}, nil)
	start := time.Now()
	if err := l.Load(ctx, obj); err != nil {
		t.Fatalf("Load: %v", err)
	}
	run.LoadSeconds = time.Since(start).Seconds()
	h.loader = l

	records, err := l.RingBuffer(ctx, MapEvents)
	if err != nil {
		t.Fatalf("RingBuffer: %v", err)
	}
	h.records = records

	if cfg.arm != benchstat.ArmLoaded {
		h.programs = benchAllPrograms()
		start = time.Now()
		for _, p := range h.programs {
			if err := l.Attach(ctx, p); err != nil {
				t.Fatalf("Attach %s: %v", p, err)
			}
		}
		run.AttachSeconds = time.Since(start).Seconds()
	}

	// A2 is attached with an empty filter on purpose: every probe fires and
	// returns after one hash lookup, which is what separates the cost of a
	// tracepoint being attached from the cost of reporting an event.
	//
	// The workload's cgroup is tracked rather than this process's. Tracking
	// this process's would register whatever cgroup the session happens to run
	// in — under `sudo bash scripts/bench-overhead.sh` from a login shell that
	// is the whole session scope, containing the orchestrator, the shell, the
	// terminal and anything else the operator left running, plus this process
	// and its own ring-buffer drain. Every probe those fired would be charged
	// to a treatment arm and to nothing in the baseline, which is unrelated
	// work counted as ALLSEER overhead. Tracking one cgroup that holds exactly
	// the workload is what makes the headline a statement about the build.
	if armTracksCgroup(cfg.arm) {
		key, value := trackedKV(cg.id)
		if err := l.UpdateMap(ctx, MapTrackedCgroups, key, value); err != nil {
			t.Fatalf("registering the workload cgroup %d (%s): %v", cg.id, cg.path, err)
		}
	}

	h.startDrain(cfg.arm == benchstat.ArmDecoded)
	return h
}

// startDrain consumes the ring buffer for the life of the run.
//
// A3 reads only the type field, straight out of the record at the offset the
// generated ABI publishes; A4 runs the whole decoder. That is the difference
// between the two arms, and keeping A3's accounting to a four-byte read is what
// stops it from quietly measuring part of A4.
func (h *armHarness) startDrain(decode bool) {
	if h.records == nil {
		return
	}
	h.stopDrain = make(chan struct{})
	h.drained = make(chan struct{})

	var dec Decoder
	if decode {
		dec = NewDecoder()
	}

	go func() {
		defer close(h.drained)
		for {
			select {
			case raw, ok := <-h.records:
				if !ok {
					return
				}
				h.count(raw, dec)
			case <-h.stopDrain:
				// Drain what is already queued before returning.
				//
				// A bare `return` here loses it. Go picks uniformly among the
				// ready cases of a select, so once stopDrain is closed the two
				// arms above are a coin flip on every iteration and the loop
				// leaves with records still in the channel — measured at ~98%
				// of whatever was queued. libbpfgo then finishes the job:
				// RingBuffer.Stop spawns `for range eventChan {}` to avoid
				// deadlocking its poll goroutine, so anything this loop did not
				// take is discarded there. Neither loss is a ring buffer drop,
				// because the kernel reserved and submitted those records
				// successfully, so ringbuf_drops cannot report it.
				//
				// The default case is what bounds this: it drains what is
				// present and stops, rather than waiting for records that are
				// not coming. Nothing here can block, and all of it runs after
				// WallSeconds has been computed.
				for {
					select {
					case raw, ok := <-h.records:
						if !ok {
							return
						}
						h.count(raw, dec)
					default:
						return
					}
				}
			}
		}
	}()
}

// count folds one raw record into the run's tallies.
//
// Extracted so the steady-state path and the drain-on-stop path above cannot
// disagree about what counting a record means — which is exactly the kind of
// difference that would make the two produce different totals for the same
// stream.
func (h *armHarness) count(raw []byte, dec Decoder) {
	h.total++
	if len(raw) >= abi.OffsetEventType+4 {
		typ := abi.EventType(nativeU32(raw[abi.OffsetEventType:]))
		h.byType[typ.String()]++
	}
	if dec != nil {
		if _, err := dec.Decode(raw); err != nil {
			h.decodeErrors++
		}
	}
}

// ringHasPendingRecords reports whether a ring buffer map still holds records
// user space has not consumed.
//
// A method on BPFLoader declared in a test file: the harness is in package
// telemetry, so it can reach l.module and l.mu without any of this becoming
// production API. Nothing outside a benchmark needs to ask the question.
//
// # Why poll(2) and not the ring buffer's own machinery
//
// libbpfgo drives the ring with libbpf's ring_buffer__poll, which processes a
// ring only for a file descriptor epoll reported ready, and it binds neither
// ring_buffer__consume nor ring__avail_data_size nor ring_buffer__epoll_fd. So
// there is no supported way to ask its consumer how far behind it is.
//
// The map's own file descriptor answers directly. A BPF ring buffer map
// implements ->poll as "readable if consumer_pos != producer_pos", and poll(2)
// invokes that callback on every call rather than consulting a readiness list
// maintained by wakeups. That distinction is the reason this works where epoll
// would not: it reports pending data whether or not anything ever woke the
// consumer.
//
// ppoll rather than poll because SYS_POLL does not exist on arm64, and a zero
// timespec because the question is about this instant and the caller is on a
// teardown path.
func (l *BPFLoader) ringHasPendingRecords(mapName string) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if err := l.readyLocked(); err != nil {
		return false, err
	}
	m, err := l.module.GetMap(mapName)
	if err != nil {
		return false, fmt.Errorf("telemetry: map %q: %w", mapName, err)
	}

	fds := []pollFD{{Fd: int32(m.FileDescriptor()), Events: pollIn}}
	ts := syscall.Timespec{}
	for {
		n, _, errno := syscall.Syscall6(syscall.SYS_PPOLL,
			uintptr(unsafe.Pointer(&fds[0])), uintptr(len(fds)),
			uintptr(unsafe.Pointer(&ts)), 0, 0, 0)
		if errno == syscall.EINTR {
			continue
		}
		if errno != 0 {
			return false, fmt.Errorf("telemetry: polling map %q: %w", mapName, errno)
		}
		return n > 0 && fds[0].Revents&pollIn != 0, nil
	}
}

// pollFD is struct pollfd. Declared here rather than pulled from
// golang.org/x/sys/unix because this is the only caller in the tree and the
// module has no dependency on x/sys today.
type pollFD struct {
	Fd      int32
	Events  int16
	Revents int16
}

const pollIn = 0x0001 // POLLIN

// --- the workloads --------------------------------------------------------------

// measureWorkload runs the workload and records what it cost.
func measureWorkload(t *testing.T, cfg benchConfig, cg *workloadCgroup, run *benchstat.Run) {
	t.Helper()

	switch cfg.workload {
	case benchstat.WorkloadColdBuild:
		measureColdBuild(t, cfg, cg, run)
	case benchstat.WorkloadOpenatStorm:
		measureOpenatStorm(t, cfg, cg, run)
	default:
		t.Fatalf("%s=%q is not a workload this runner knows", envWorkload, cfg.workload)
	}
}

// measureColdBuild is the primary workload: `go build ./...` against a GOCACHE
// that the orchestrator created empty for this run.
//
// The cache is the orchestrator's to create and remove. This runner never
// touches the developer's, and never calls `go clean -cache` — which would
// impose minutes of rebuild penalty on every subsequent command the developer
// ran, in exchange for exactly what an empty GOCACHE gives for free.
//
// GOMODCACHE is passed through from the invoking user rather than defaulted,
// because a root process with no GOMODCACHE would resolve modules against
// /root/go/pkg/mod, find it empty, and turn a compile benchmark into a download
// benchmark.
func measureColdBuild(t *testing.T, cfg benchConfig, cg *workloadCgroup, run *benchstat.Run) {
	t.Helper()

	// Refused rather than annotated, and refused before the build starts.
	//
	// This check used to be `if entries, err := os.ReadDir(...); err == nil &&
	// len(entries) > 0`, which recorded a note and built anyway — and, in the
	// half that mattered, took any error from ReadDir as permission to proceed.
	// A missing cache directory, an unreadable one, or a path that turned out
	// to be a file all skipped the body and left the run indistinguishable from
	// a verified cold one.
	//
	// It is indistinguishable downstream too. A warm run emits the same schema,
	// the same fields and the same event counts as a cold run; only its wall
	// clock is far too low, and a low wall clock on a treatment arm reads as
	// low overhead. Failing here costs one run out of a hundred and fifteen.
	// Proceeding costs the session, in the direction of a pass.
	if err := benchstat.VerifyColdCache(cfg.goCache); err != nil {
		t.Fatalf("%v\n\tthe orchestrator creates a fresh empty GOCACHE for every cold-build run; "+
			"a hand-run arm must set %s to a directory it created empty", err, envGoCache)
	}

	cmd := exec.Command("go", "build", "./...")
	cmd.Dir = cfg.repoRoot
	cmd.Env = append(os.Environ(),
		"GOCACHE="+cfg.goCache,
		"GOFLAGS=-mod=readonly",
	)
	if cfg.goModCache != "" {
		cmd.Env = append(cmd.Env, "GOMODCACHE="+cfg.goModCache)
	}
	timeCommand(t, cmd, cg, run)
}

// measureOpenatStorm is the adversarial secondary workload.
//
// A tight loop of openat on a path that does not exist, which is the shape
// TestRuntimeOpenProbeCountsDropsAndStillDeletesScratch already uses. It bounds
// the worst case — a process doing nothing but the syscall the probes hook —
// and it gates nothing. Reporting it beside the build is what answers "is there
// a workload where this is much worse" without letting that workload decide a
// milestone about builds.
//
// Run in a subprocess so that its cost is measured the same way the build's is,
// through the same rusage of the same child.
func measureOpenatStorm(t *testing.T, cfg benchConfig, cg *workloadCgroup, run *benchstat.Run) {
	t.Helper()

	self, err := os.Executable()
	if err != nil {
		t.Fatalf("locating the test binary: %v", err)
	}
	cmd := exec.Command(self, "-test.run=TestBenchmarkOpenatStormChild", "-test.v=false")
	cmd.Env = append(os.Environ(),
		envStormChild+"="+strconv.Itoa(cfg.stormOps),
		envArm+"=", // the child must not recurse into an arm
	)
	timeCommand(t, cmd, cg, run)
}

const envStormChild = "ALLSEER_BENCH_STORM_CHILD"

// TestBenchmarkOpenatStormChild is the storm subprocess, not a test.
func TestBenchmarkOpenatStormChild(t *testing.T) {
	ops := os.Getenv(envStormChild)
	if ops == "" {
		t.Skip("not the storm child")
	}
	n, err := strconv.Atoi(ops)
	if err != nil {
		t.Fatalf("%s=%q: %v", envStormChild, ops, err)
	}

	// A path under a directory that exists, so the failure is ENOENT on the
	// leaf rather than on a component — the shape a build's file probing
	// actually produces, and the one the openat probe pays full price for.
	//
	// Not t.TempDir: this process ends in os.Exit, which runs no cleanup, and a
	// session leaving one root-owned directory per storm run behind in /tmp is
	// litter the next session would have to step over.
	dir, err := os.MkdirTemp("", "allseer-bench-storm-*")
	if err != nil {
		t.Fatalf("creating the storm directory: %v", err)
	}
	absent := filepath.Join(dir, "allseer-bench-absent")
	for range n {
		if fd := rawOpenat(absent, syscall.O_RDONLY, 0); fd >= 0 {
			syscall.Close(fd)
		}
	}
	os.RemoveAll(dir)
	os.Exit(0)
}

// timeCommand runs a child and records wall clock and its rusage.
//
// CLOCK_MONOTONIC for the wall clock, so a clock adjustment mid-run cannot
// produce a negative or wildly long build. The rusage is the child's own rather
// than this process's cumulative children, so a runner that somehow ran two
// children could not add them together by accident.
func timeCommand(t *testing.T, cmd *exec.Cmd, cg *workloadCgroup, run *benchstat.Run) {
	t.Helper()

	cmd.Stdout = nil
	cmd.Stderr = nil

	// CLONE_INTO_CGROUP rather than a write to cgroup.procs after the fork.
	// The child is created inside the cgroup, so there is no window in which
	// it is running outside the tracked set — a migration would leave the
	// process start, and whatever the go driver did first, systematically
	// unobserved on exactly the arms the measurement is about.
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: cg.fd}

	// Host state is sampled on both sides of the measured interval and never
	// inside it. Both calls are outside the time.Now()/time.Since() bracket
	// below, so WallSeconds still covers exactly what it covered before: the
	// workload subprocess and nothing else. Each sample is four small procfs
	// reads costing a few hundred microseconds, against a workload measured in
	// tens of seconds, and it is charged identically to every arm.
	//
	// Sampled here, in the one function both workloads run through, rather than
	// in each of them, so a workload added later cannot forget to do it.
	hostBefore := benchstat.SampleHost(procRoot)

	start := time.Now()
	err := cmd.Run()
	run.WallSeconds = time.Since(start).Seconds()

	run.Host = benchstat.HostStateBetween(hostBefore, benchstat.SampleHost(procRoot))

	if cmd.ProcessState != nil {
		run.ExitCode = cmd.ProcessState.ExitCode()
		if ru, ok := cmd.ProcessState.SysUsage().(*syscall.Rusage); ok {
			run.UserSeconds = timevalSeconds(ru.Utime)
			run.SysSeconds = timevalSeconds(ru.Stime)
			run.MaxRSSKB = ru.Maxrss
			run.VoluntaryCtxSwitch = ru.Nvcsw
			run.InvoluntaryCtxSw = ru.Nivcsw
		}
	}
	if err != nil {
		run.Error = appendErr(run.Error, err.Error())
	}
}

func timevalSeconds(tv syscall.Timeval) float64 {
	return float64(tv.Sec) + float64(tv.Usec)/1e6
}

// --- the workload's cgroup --------------------------------------------------------

// workloadCgroup is a cgroup v2 directory holding exactly the process whose
// wall clock is being measured, and nothing else.
//
// Which cgroup is tracked is what decides the meaning of the headline number.
// The obvious choice — track the cgroup this process is already in — registers
// whatever the session happens to run under, and under `sudo bash
// scripts/bench-overhead.sh` from a login shell that is the entire session
// scope: the orchestrator, the shell, the terminal, anything else the operator
// left running, and this process together with the ring-buffer drain it runs to
// consume its own events. Every probe those fired would be charged to A3 and A4
// and to nothing in A0, so the measured difference would include work that has
// nothing to do with the build. One cgroup per run, holding one workload, is
// what makes the comparison a statement about instrumenting that workload.
//
// Created on every arm including A0, so the placement is a constant of the
// experiment rather than something that arrives with the treatment.
type workloadCgroup struct {
	// path is the directory in the unified hierarchy.
	path string

	// id is the directory's inode number, which is what
	// bpf_get_current_cgroup_id() reports for a process inside it and therefore
	// what the tracked_cgroups filter is keyed on.
	id uint64

	// fd is held open for CLONE_INTO_CGROUP and closed by remove.
	fd int
}

func newWorkloadCgroup(t *testing.T) *workloadCgroup {
	t.Helper()

	root, err := requireCgroupV2()
	if err != nil {
		t.Skipf("no cgroup2 hierarchy: %v", err)
	}

	name := fmt.Sprintf("allseer-bench-%d", os.Getpid())

	var lastErr error
	for _, parent := range workloadCgroupParents(root) {
		dir := filepath.Join(parent, name)
		if err := os.Mkdir(dir, 0o755); err != nil && !os.IsExist(err) {
			lastErr = err
			continue
		}
		fd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
		if err != nil {
			os.Remove(dir)
			lastErr = err
			continue
		}
		// Fstat on the fd rather than Stat on the path, so the ID belongs to
		// the same directory the child will be cloned into even if something
		// replaced the path in between.
		var st syscall.Stat_t
		if err := syscall.Fstat(fd, &st); err != nil {
			syscall.Close(fd)
			os.Remove(dir)
			lastErr = err
			continue
		}
		return &workloadCgroup{path: dir, id: st.Ino, fd: fd}
	}
	t.Fatalf("creating a cgroup for the workload under %s: %v", root, lastErr)
	return nil
}

// workloadCgroupParents is where to try creating the workload's cgroup, best
// first.
//
// This process's own cgroup is preferred so the workload keeps whatever
// resource settings the session would have given it and only its identity
// changes. The hierarchy root is the fallback, for a delegated subtree that
// refuses a child.
func workloadCgroupParents(root string) []string {
	var parents []string
	if b, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			// The unified hierarchy is the "0::<path>" line.
			if after, ok := strings.CutPrefix(line, "0::"); ok {
				parents = append(parents, filepath.Join(root, after))
				break
			}
		}
	}
	return append(parents, root)
}

// remove closes the cgroup fd and deletes the directory.
//
// rmdir refuses a cgroup that still holds a process, and the build's compile
// and link children are reaped by the go driver rather than by this process, so
// a bounded retry covers the gap between the driver exiting and the kernel
// accounting its last child. A cgroup that still will not go is reported and
// left behind: removing it is tidiness, and failing a completed run over
// tidiness would discard a minute of good measurement.
func (c *workloadCgroup) remove(t *testing.T) {
	t.Helper()
	if c == nil {
		return
	}
	if c.fd >= 0 {
		syscall.Close(c.fd)
		c.fd = -1
	}
	var err error
	for range 50 {
		if err = os.Remove(c.path); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Logf("could not remove the workload cgroup %s: %v", c.path, err)
}

// --- recording -------------------------------------------------------------------

// appendRun appends one JSON line, opened O_APPEND so a session that dies
// halfway leaves every run it finished.
func appendRun(t *testing.T, path string, run benchstat.Run) {
	t.Helper()

	b, err := json.Marshal(run)
	if err != nil {
		t.Fatalf("marshalling the run: %v", err)
	}
	// O_CREATE creates a file, not a missing parent directory, and losing a
	// completed run to a missing directory costs a minute of measurement.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("creating the directory for %s: %v", path, err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatalf("opening %s: %v", path, err)
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		t.Fatalf("writing the run: %v", err)
	}
}

func appendErr(existing, add string) string {
	if existing == "" {
		return add
	}
	return existing + "; " + add
}

// --- environment capture ----------------------------------------------------------

// procRoot is where the per-run host state is read from.
//
// A constant rather than benchstat.SampleHost's own default, because
// benchstat takes it as a parameter so that its parsing can be tested against
// a fixture tree on a machine with no procfs.
const procRoot = "/proc"

// benchRingBufferSize is the ring the benchmark runs with.
//
// The value configs/allseerd.example.yaml ships, so the measurement describes
// the configuration an operator would actually deploy rather than a tuned one.
const benchRingBufferSize = 8 << 20

// benchAllPrograms is every program in the object, in a fixed order.
//
// Assembled from the loader's own constants rather than from a list written
// here, so a probe added without being added to this list would be a compile
// error at the constant rather than a silently unmeasured program.
func benchAllPrograms() []string {
	progs := []string{
		ProgProcExec, ProgProcExit,
		ProgOpenatEnter, ProgOpenatExit,
		ProgConnectEnter, ProgConnectExit,
	}
	return append(progs, ProgPrivPairs()...)
}

// nativeU32 reads a little-endian u32; both supported targets are
// little-endian, which is the assumption the generated ABI is built on.
func nativeU32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// captureEnvironment records what another machine needs in order to decide
// whether this session's numbers mean anything on theirs.
//
// Every field that cannot be read is recorded as "unavailable" rather than left
// empty, because "we could not read the governor" and "this host has no
// governor" are different facts and only one of them is a reason to distrust
// the numbers. On the host this was written for, the governor is genuinely
// unavailable: it is a VM with no cpufreq sysfs, which is itself the single
// largest confounder in any result it produces.
func captureEnvironment(t *testing.T, cfg benchConfig, h *armHarness, cg *workloadCgroup) *benchstat.Environment {
	t.Helper()

	env := &benchstat.Environment{
		CapturedAt:     time.Now().UTC().Format(time.RFC3339),
		KernelRelease:  firstLine(readFileOr("/proc/sys/kernel/osrelease", "unavailable")),
		BTFAvailable:   fileExists("/sys/kernel/btf/vmlinux"),
		Virtualization: commandOutput("systemd-detect-virt"),
		CPUModel:       cpuModel(),
		CPUCores:       runtime.NumCPU(),
		Governor: firstLine(readFileOr(
			"/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor", "unavailable")),
		TurboState:     turboState(),
		GoVersion:      runtime.Version(),
		ClangVersion:   firstLine(commandOutput("clang", "--version")),
		LibbpfVersion:  firstLine(commandOutput("pkg-config", "--modversion", "libbpf")),
		AllseerCommit:  firstLine(commandOutputIn(cfg.repoRoot, "git", "rev-parse", "HEAD")),
		ABIVersion:     abi.ABIVersion,
		RecordSize:     abi.RecordSize,
		GOCACHE:        cfg.goCache,
		GOMODCACHE:     cfg.goModCache,
		GOMAXPROCS:     runtime.GOMAXPROCS(0),
		RingBufferSize: benchRingBufferSize,
		LoadAvgBefore:  firstLine(readFileOr("/proc/loadavg", "unavailable")),
		Seed:           cfg.seed,
		Replicates:     cfg.replicates,
	}
	env.MemTotalKB, env.MemFreeKB = meminfo()
	if h != nil {
		env.AttachedPrograms = h.programs
	}
	if cg != nil {
		env.WorkloadCgroup = cg.path
		env.WorkloadCgroupID = cg.id
	}
	if obj := os.Getenv("ALLSEER_BENCH_OBJECT"); obj != "" {
		env.ObjectSHA256 = fileSHA256(obj)
	} else if cfg.repoRoot != "" {
		env.ObjectSHA256 = fileSHA256(filepath.Join(cfg.repoRoot, "bpf", "allseer.bpf.o"))
	}
	// Read after the workload, so the pair brackets the run rather than
	// describing only its start.
	env.LoadAvgAfter = firstLine(readFileOr("/proc/loadavg", "unavailable"))
	return env
}

func readFileOr(path, fallback string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return fallback
	}
	if s := strings.TrimSpace(string(b)); s != "" {
		return s
	}
	return fallback
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

func commandOutput(name string, args ...string) string { return commandOutputIn("", name, args...) }

func commandOutputIn(dir, name string, args ...string) string {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return "unavailable"
	}
	if s := strings.TrimSpace(string(out)); s != "" {
		return s
	}
	return "unavailable"
}

func cpuModel() string {
	b, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return "unavailable"
	}
	for _, line := range strings.Split(string(b), "\n") {
		if name, val, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(name) == "model name" {
			return strings.TrimSpace(val)
		}
	}
	return "unavailable"
}

// turboState reads intel_pstate's no_turbo, inverted into a statement about
// turbo rather than about its negation.
func turboState() string {
	v := readFileOr("/sys/devices/system/cpu/intel_pstate/no_turbo", "")
	switch v {
	case "0":
		return "enabled"
	case "1":
		return "disabled"
	}
	return "unavailable"
}

func meminfo() (total, free int64) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields := strings.Fields(val)
		if len(fields) == 0 {
			continue
		}
		n, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil {
			continue
		}
		switch key {
		case "MemTotal":
			total = n
		case "MemAvailable":
			free = n
		}
	}
	return total, free
}

// fileSHA256 identifies the exact object the measurement ran against, so a
// result cannot be attributed to a build of the probes that produced it.
func fileSHA256(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "unavailable"
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
