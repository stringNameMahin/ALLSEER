// Package benchstat reads the run records scripts/bench-overhead.sh produces
// and decides whether the probe-overhead target was met.
//
// It is deliberately separate from the code that takes the measurements. The
// arm runner needs root, a kernel, a compiled object and roughly two hours; this
// package needs a file. Splitting them means the statistics — the part most
// likely to be wrong in a way nobody notices — are unit-testable against known
// answers on any machine, which is the same argument internal/telemetry/abigen
// makes for keeping generation separable from the thing generated.
//
// By the same argument the package also holds the two decisions the harness
// makes before a run rather than after it: which order a replicate runs its
// arms in, and whether a run's GOCACHE is cold enough to measure. Both are in
// schedule.go, and both are here because both previously lived where nothing
// could test them and both were silently wrong.
//
// # What it is deciding
//
// M5's stated target is "under 5% wall clock, measured rather than assumed".
// The second half is what shapes this package. A point estimate below 5% is not
// a measurement that the overhead is below 5%; it is a measurement that could
// be below 5%. So the acceptance test is on the upper bound of a confidence
// interval, and an interval too wide to decide produces INCONCLUSIVE rather
// than a pass. That is the only direction that fails safely: an underpowered
// experiment is told to collect more samples instead of being rewarded for
// its own imprecision.
package benchstat

// Schema is the value every run record carries in its `schema` field.
//
// A version string rather than an implicit format, for the reason
// bpf/include/allseer_event.h gives about its own: a reader that cannot tell
// which layout it was handed will decode an old file into a confident wrong
// answer rather than an error.
const Schema = "allseer.dev/bench/v1"

// Arm names. These are the five configurations the design defines, and they are
// a wire contract between the runner and this package.
const (
	// ArmOff is the true baseline: no BPF object loaded, nothing attached.
	ArmOff = "A0"

	// ArmLoaded has the object loaded, its maps created and its ring buffer
	// allocated and polled, with zero programs attached. It is the control:
	// whatever it costs is what the harness itself costs, and the headline
	// number is only believable if this arm is indistinguishable from ArmOff.
	ArmLoaded = "A1"

	// ArmAttachedUntracked has all programs attached with an empty
	// tracked_cgroups, so every probe fires and returns after one hash lookup.
	// It separates the cost of a tracepoint being attached at all from the cost
	// of reporting an event.
	ArmAttachedUntracked = "A2"

	// ArmTracked is the headline configuration: all programs attached, the
	// workload's cgroup tracked, records drained and counted.
	ArmTracked = "A3"

	// ArmDecoded is ArmTracked plus a full EventDecoder.Decode on every record,
	// which is the floor cost of the consumer M6 will build.
	ArmDecoded = "A4"

	// ArmTrackedForceWake is ArmTracked with the ring buffer's consumer
	// notification forced on every record instead of only when the consumer has
	// caught up. Everything else — the programs, the filter, the record, the
	// reserve, the ring, the drain, the workload — is ArmTracked's.
	//
	// A diagnostic arm, and it gates nothing. It exists to split the cost
	// ArmTracked pays into producing records and notifying the consumer about
	// them, which the W3 acceptance session measured together: +21.01% for
	// ArmTracked against ArmOff, of which +0.19% was already paid by
	// ArmAttachedUntracked, and no way to tell which half of emitting the rest
	// belonged to.
	//
	// It forces wakeups rather than suppressing them because suppression is not
	// a valid experiment against this drain. An arm using BPF_RB_NO_WAKEUP was
	// built and abandoned: libbpf's ring_buffer__poll processes a ring only for
	// a file descriptor epoll reported ready, and a ringbuf fd becomes ready
	// only through the wakeup that flag suppresses, so a representative run
	// stranded 161 successfully submitted records in the ring at teardown with
	// ringbuf_drops correctly reporting zero. Forcing wakeups can only deliver
	// more of them, so this arm has no such failure mode.
	ArmTrackedForceWake = "A3F"
)

// Arms lists the five arms the milestone is defined in terms of, in the order a
// report should present them.
//
// ArmTrackedForceWake is deliberately absent. This slice is what an acceptance
// session schedules when it is not told otherwise, and adding a sixth arm to it
// would change the permutation every replicate of every seed produces — so a
// session recorded before the diagnostic arm existed could no longer be
// reproduced from its own seed. The instrument must not move the experiment it
// was built to explain.
func Arms() []string {
	return []string{ArmOff, ArmLoaded, ArmAttachedUntracked, ArmTracked, ArmDecoded}
}

// KnownArms lists every arm this package can schedule and report, including the
// diagnostic ones Arms omits.
//
// Two functions rather than one because the two questions differ: "what does an
// acceptance session run" is Arms, and "is this a real arm name" is this. Only
// the second should grow when an instrument is added, and ArmOrder validates
// against this so a diagnostic arm can be scheduled by naming it explicitly
// without ever being scheduled by default.
func KnownArms() []string {
	return append(Arms(), ArmTrackedForceWake)
}

// Workload names.
const (
	// WorkloadColdBuild is the primary workload: `go build ./...` against a
	// GOCACHE that was empty when the run started.
	WorkloadColdBuild = "cold-build"

	// WorkloadOpenatStorm is the adversarial secondary workload. It is reported
	// separately and gates nothing: it exists to answer "is there a workload
	// where this is much worse", not to decide the milestone.
	WorkloadOpenatStorm = "openat-storm"
)

// Run is one execution of one arm against one workload.
//
// One JSON object per line, appended as the session proceeds, so a session that
// dies after ninety minutes still leaves every run it completed.
type Run struct {
	Schema    string `json:"schema"`
	SessionID string `json:"session_id"`

	// Replicate is the pairing key. Every arm runs once per replicate, and a
	// comparison pairs two arms by this number — which is what makes the
	// comparison paired rather than a difference of two independent means.
	Replicate int `json:"replicate"`

	// Sequence is the run's position within the session, from 1. It records the
	// interleaving actually used, so a reader can check that the arms were not
	// run in blocks after the fact.
	Sequence int `json:"sequence"`

	Arm      string `json:"arm"`
	Workload string `json:"workload"`

	// WarmUp marks a run excluded from analysis by a rule fixed before the
	// session started. Excluding it afterwards, on the evidence of its own
	// value, would be choosing the data to fit the answer.
	WarmUp bool `json:"warmup"`

	// --- the workload's cost ------------------------------------------------

	WallSeconds float64 `json:"wall_seconds"`
	UserSeconds float64 `json:"user_seconds"`
	SysSeconds  float64 `json:"sys_seconds"`

	MaxRSSKB           int64 `json:"max_rss_kb"`
	VoluntaryCtxSwitch int64 `json:"voluntary_ctx_switches"`
	InvoluntaryCtxSw   int64 `json:"involuntary_ctx_switches"`

	// --- ALLSEER's own cost, kept out of the workload's ----------------------

	// LoadSeconds and AttachSeconds are the one-off startup cost. They are
	// recorded and reported, and deliberately not added to WallSeconds: a
	// governed session pays them once, and folding a fixed cost into a
	// per-build ratio would make the overhead depend on how long the build was.
	LoadSeconds   float64 `json:"load_seconds"`
	AttachSeconds float64 `json:"attach_seconds"`

	// --- what the probes saw -------------------------------------------------

	Events      map[string]uint64 `json:"events,omitempty"`
	EventsTotal uint64            `json:"events_total"`

	// RingbufDrops is read from the kernel counter. A non-zero value on a
	// tracked arm invalidates that run's timing rather than merely annotating
	// it: a build whose records were dropped did less work than one whose were
	// not, so its wall clock understates the cost being measured.
	RingbufDrops uint64 `json:"ringbuf_drops"`

	DecodeErrors uint64 `json:"decode_errors"`

	// --- outcome --------------------------------------------------------------

	ExitCode int    `json:"exit_code"`
	Error    string `json:"error,omitempty"`

	// Host is the machine's state around this run: sampled immediately before
	// the workload started and immediately after it exited, both outside the
	// measured interval.
	//
	// Per run rather than per session, which Env is. Env describes a host that
	// does not change during a session — its kernel, its CPU model, the object
	// under test — and is attached to the first record only. This describes a
	// host that demonstrably does change during a session, and a session that
	// carried one host reading for a hundred and fifteen runs could not show
	// which of them had been measured on which machine.
	//
	// Optional, and omitted when empty. Records written before this field
	// existed decode with Host nil and analyse exactly as they did: nothing in
	// Analyze reads it, and no verdict depends on it. It is evidence for
	// whoever has to explain a result, not an input to one.
	Host *HostState `json:"host,omitempty"`

	// Env is attached to the first record of a session and omitted from the
	// rest. It is what lets another machine decide whether this session's
	// numbers mean anything on theirs.
	Env *Environment `json:"env,omitempty"`
}

// HostState is what the machine did while one run's workload ran.
//
// Cumulative figures are differences across the run; instantaneous ones are
// recorded as the before/after pair. See hoststate.go for what each source is
// worth on a VirtualBox guest, and for the three signals — CPU frequency,
// governor and turbo — that genuinely cannot be read from inside one.
//
// Every field is additive and optional. Nothing in this package's analysis
// reads any of them, by design: the goal is evidence, not another gate.
type HostState struct {
	// LoadAvgBefore and LoadAvgAfter are /proc/loadavg verbatim, in the same
	// form Environment records it so the two are directly comparable.
	LoadAvgBefore string `json:"load_avg_before,omitempty"`
	LoadAvgAfter  string `json:"load_avg_after,omitempty"`

	MemAvailableKBBefore int64 `json:"mem_available_kb_before,omitempty"`
	MemAvailableKBAfter  int64 `json:"mem_available_kb_after,omitempty"`

	// CPUBusySeconds and CPUIdleSeconds are what the whole machine spent during
	// the run, summed over every CPU. Against the run's own UserSeconds plus
	// SysSeconds they answer whether anything else was running; see
	// Run.OtherCPUSeconds.
	CPUBusySeconds float64 `json:"cpu_busy_seconds,omitempty"`
	CPUIdleSeconds float64 `json:"cpu_idle_seconds,omitempty"`

	// CPUStealSeconds is time the hypervisor took. It is structurally zero on
	// the VirtualBox guest this was written for, which exposes no
	// paravirtualised steal clock, and is recorded anyway because "this
	// hypervisor cannot account steal" and "no time was stolen" are different
	// facts about a slow run.
	CPUStealSeconds float64 `json:"cpu_steal_seconds"`

	// PSICPUStallSeconds is how long at least one runnable task waited for a
	// CPU during the run, from /proc/pressure/cpu.
	PSICPUStallSeconds float64 `json:"psi_cpu_stall_seconds,omitempty"`

	// NumCPU is the CPU count /proc/stat accounted over, recorded per run so a
	// vCPU count that changed mid-session is visible rather than assumed
	// constant from the session's one Environment block.
	NumCPU int `json:"num_cpu,omitempty"`

	// InterruptDeltas is how far each recorded /proc/interrupts counter
	// advanced during the run, summed across CPUs. See InterruptsOfInterest for
	// which rows are kept and why.
	//
	// IWI is the one this was added for: bpf_ringbuf_commit wakes the consumer
	// through an irq_work, so a tracked arm that notifies on every record
	// should show an IWI delta close to its event count, and an arm that
	// notifies less should show less. Evidence for a mechanism, not a
	// measurement of cost, and nothing in the analysis reads it.
	InterruptDeltas map[string]int64 `json:"interrupt_deltas,omitempty"`

	// Unavailable names procfs sources that could not be read, comma
	// separated, for the reason Environment gives about its own gaps.
	Unavailable string `json:"unavailable,omitempty"`
}

// Environment is what a reader needs to interpret a session.
//
// Every field is recorded even when it cannot be determined, with the string
// "unavailable" rather than an empty value, because "we could not read the
// governor" and "there is no governor" are different facts about a host and
// only one of them is a reason to distrust the numbers.
type Environment struct {
	CapturedAt string `json:"captured_at"`

	KernelRelease  string `json:"kernel_release"`
	BTFAvailable   bool   `json:"btf_available"`
	Virtualization string `json:"virtualization"`

	CPUModel   string `json:"cpu_model"`
	CPUCores   int    `json:"cpu_cores"`
	Governor   string `json:"cpu_governor"`
	TurboState string `json:"cpu_turbo"`

	MemTotalKB int64 `json:"mem_total_kb"`
	MemFreeKB  int64 `json:"mem_free_kb"`

	GoVersion     string `json:"go_version"`
	ClangVersion  string `json:"clang_version"`
	LibbpfVersion string `json:"libbpf_version"`

	AllseerCommit string `json:"allseer_commit"`
	ObjectSHA256  string `json:"object_sha256"`
	ABIVersion    uint32 `json:"abi_version"`
	RecordSize    int    `json:"record_size"`

	AttachedPrograms []string `json:"attached_programs"`

	// WorkloadCgroup and WorkloadCgroupID identify the cgroup the measured
	// process ran in, which on a tracked arm is also the only cgroup in the
	// filter map. Recorded because a reader checking whether the headline
	// describes the build alone has no other way to tell what was instrumented.
	WorkloadCgroup   string `json:"workload_cgroup"`
	WorkloadCgroupID uint64 `json:"workload_cgroup_id"`

	GOCACHE    string `json:"gocache"`
	GOMODCACHE string `json:"gomodcache"`
	GOMAXPROCS int    `json:"gomaxprocs"`

	RingBufferSize int `json:"ring_buffer_size"`

	LoadAvgBefore string `json:"load_avg_before"`
	LoadAvgAfter  string `json:"load_avg_after"`

	// Seed is what makes the arm ordering reproducible. Two sessions with the
	// same seed and replicate count run the arms in the same order.
	Seed int64 `json:"seed"`

	Replicates int `json:"replicates"`
}
