// Package telemetry collects kernel-level ground truth about governed
// processes.
//
// Every downstream conclusion is only as trustworthy as the observations
// feeding it. Kernel instrumentation via eBPF is what separates this system
// from wrapper- or API-based approaches: an agent can lie about what it did,
// and can bypass any library-level hook, but it cannot execute a syscall the
// kernel does not see.
//
// Notes that shape the design:
//
//   - eBPF is Linux-only and needs privilege. The collector sits behind
//     event.Source so the rest of the system can be developed and tested on any
//     platform against a replay source.
//   - The kernel side is compiled from C (bpf/*.bpf.c) and loaded with
//     libbpfgo. Probes emit a flat record and return; all enrichment happens in
//     user space, where being slow is safe.
//   - CO-RE via BTF is required, so one build runs across kernel versions
//     without recompiling per host.
//
// Files requiring libbpfgo are guarded by `//go:build linux && ebpf`, which
// keeps the portable interface layer buildable everywhere.
package telemetry

import (
	"context"
	"time"

	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// Collector attaches probes and produces events. It extends event.Source with
// the lifecycle operations only a live kernel collector needs.
type Collector interface {
	event.Source

	// AttachSession begins collecting for a process tree. Attribution is by
	// cgroup where available and PID ancestry otherwise, because cgroup IDs
	// survive PID reuse and PIDs do not.
	AttachSession(ctx context.Context, sessionID string, rootPID int32) error

	// DetachSession stops collecting for a session.
	DetachSession(ctx context.Context, sessionID string) error

	// Probes reports which probes are loaded, so the daemon can warn when an
	// envelope grants a capability nothing is watching.
	Probes() []ProbeInfo
}

// ProbeInfo describes a loaded probe.
type ProbeInfo struct {
	Name string `json:"name"`

	// Type is the eBPF program type: "tracepoint", "kprobe", "fentry", "lsm".
	Type string `json:"type"`

	// AttachPoint is the kernel hook, e.g. "syscalls/sys_enter_openat".
	AttachPoint string `json:"attach_point"`

	// Capabilities lists the kinds this probe can observe, which is what lets
	// the daemon compute coverage against an envelope.
	Capabilities []capability.Kind `json:"capabilities"`

	// Attached reports whether attachment succeeded. A probe that failed to
	// attach is a blind spot and must be surfaced loudly, not logged at debug
	// level.
	Attached bool `json:"attached"`

	// Error explains attachment failure.
	Error string `json:"error,omitempty"`
}

// Loader manages eBPF object lifecycle: load, attach, detach, unload.
//
// Behind an interface so libbpfgo can be swapped without touching the
// collector, and so tests can exercise collector logic without a kernel.
type Loader interface {
	// Load reads a compiled eBPF object and prepares its programs.
	Load(ctx context.Context, objectPath string) error

	// Attach attaches a named program to its hook.
	Attach(ctx context.Context, programName string) error

	// DetachAll detaches every attached program.
	DetachAll(ctx context.Context) error

	// RingBuffer returns the raw record stream for a named map.
	RingBuffer(ctx context.Context, mapName string) (<-chan []byte, error)

	// UpdateMap writes a key/value into a BPF map. This is the user-to-kernel
	// channel: the filter map telling probes which cgroups to watch is
	// populated this way, so filtering happens in the kernel rather than
	// costing a userspace round trip per event.
	UpdateMap(ctx context.Context, mapName string, key, value []byte) error

	// DeleteMap removes a key from a BPF map.
	//
	// The other half of UpdateMap, and the only way to say "stop watching this
	// cgroup". The filter map's contract is that presence is the entire signal
	// — bpf/allseer.bpf.c tests the lookup for NULL and never dereferences what
	// it returns — so a session that ends cannot be un-watched by writing a
	// zero value over its entry. There is nothing a value could say. The key
	// has to go.
	//
	// The alternative to having this at all would be for the collector to keep
	// tracking a dead session in the kernel and discard its events in user
	// space, which is the exact cost the filter map exists to avoid: "an
	// untracked process should cost a lookup and a return, not a ring buffer
	// reservation, a wakeup, a decode and a discard".
	DeleteMap(ctx context.Context, mapName string, key []byte) error

	// ReadCounter returns a single-entry per-CPU counter map's value, summed
	// across CPUs.
	//
	// The kernel-to-user channel for what the ring buffer could not carry.
	// Records lost to a full ring are invisible in the stream by construction:
	// the loss is the absence of a record, so no amount of reading the ring
	// reveals it, and RingBuffer reports on exactly the wrong population.
	// bpf/allseer.bpf.c counts each loss where it happens and this is how the
	// count is read.
	//
	// Nothing here resets it. The counter is monotonic for the lifetime of the
	// loaded object because both users of it need that: SourceStats
	// .DroppedEvents is cumulative by definition, and the per-record delta
	// Event.Dropped wants is current minus last-observed — a subtraction any
	// reader can do, and one a reader that reset the counter would break for
	// every other reader.
	ReadCounter(ctx context.Context, mapName string) (uint64, error)

	Close() error
}

// Decoder converts raw ring buffer bytes into typed events.
//
// Isolated because it is the boundary where kernel and user space must agree
// byte for byte on struct layout. A mismatch produces plausible garbage rather
// than a clean error, so this code deserves to be generated from a shared
// definition and fuzzed against malformed input.
type Decoder interface {
	// Decode parses one raw record.
	Decode(raw []byte) (*event.Event, error)

	// EventSize returns the expected record size, used to catch layout drift
	// between the loaded object and this binary at startup rather than at the
	// first event.
	EventSize() int
}

// Enricher adds user-space context to a decoded event.
//
// Enrichment turns cheap kernel records into matchable observations: resolving
// paths, correlating IPs to hostnames, hashing binaries, unwrapping
// interpreters. It runs off the kernel's critical path but is still on the
// decision path, so every enricher needs a bounded cost and a defined behavior
// when it cannot resolve something.
type Enricher interface {
	// Enrich augments the event in place.
	//
	// An error means enrichment failed, which downstream must treat as
	// VerdictIndeterminate rather than a benign absence of data. Failing to
	// resolve a path is not the same as the path being safe.
	Enrich(ctx context.Context, e *event.Event) error

	// Name identifies the enricher for metrics and configuration.
	Name() string
}

// ProcessTracker maintains the supervised process tree.
//
// Attribution is harder than it looks: an agent spawns a shell, which spawns a
// compiler, which spawns a linker. All of it belongs to the session, and PID
// reuse means naive tracking will eventually attribute a stranger's syscall to
// a governed session, or miss a governed one.
type ProcessTracker interface {
	// Track registers a process as belonging to a session.
	Track(sessionID string, pid int32, startTime uint64) error

	// Untrack removes a process on exit.
	Untrack(pid int32, startTime uint64) error

	// SessionFor returns the session owning a process, if any.
	SessionFor(pid int32, startTime uint64) (sessionID string, ok bool)

	// Descendants returns all tracked processes in a session.
	Descendants(sessionID string) []int32

	// Depth returns a process's generation distance from the session root.
	Depth(pid int32, startTime uint64) int
}

// DNSCorrelator maps observed IP addresses back to the hostnames they were
// resolved from.
//
// It exists because of a mismatch: envelopes are written in hostnames ("may
// reach proxy.golang.org") while the kernel observes IP addresses. Correlation
// works by watching DNS responses and caching answers.
//
// It is best-effort and must be treated as such. DNS over HTTPS, hardcoded IPs,
// and cache expiry all defeat it. An uncorrelated connection has to raise
// scrutiny rather than being assumed to match a granted host, or the easiest
// way to evade a network grant is to skip DNS.
type DNSCorrelator interface {
	// Observe records a DNS answer.
	Observe(hostname string, addrs []string, ttl time.Duration)

	// Lookup returns the hostname an IP was resolved from.
	Lookup(addr string) (hostname string, ok bool)
}

// Config configures the collector.
type Config struct {
	// ObjectPath is the compiled eBPF object file.
	ObjectPath string `json:"object_path" yaml:"object_path"`

	// RingBufferSize must be a power-of-two multiple of the page size. Larger
	// buffers tolerate consumer stalls at the cost of locked memory.
	RingBufferSize int `json:"ring_buffer_size" yaml:"ring_buffer_size"`

	// EventChannelSize bounds the user-space buffer between decode and the
	// pipeline.
	EventChannelSize int `json:"event_channel_size" yaml:"event_channel_size"`

	// EnabledProbes selects which probes to attach; empty means all. Narrowing
	// it is the main lever for reducing overhead, at the cost of blind spots.
	EnabledProbes []string `json:"enabled_probes" yaml:"enabled_probes"`

	// EnableBinaryHashing computes SHA-256 of executed binaries. Expensive on
	// large or cold binaries, so off by default.
	EnableBinaryHashing bool `json:"enable_binary_hashing" yaml:"enable_binary_hashing"`

	// EnableDNSCorrelation attaches DNS probes for hostname recovery.
	EnableDNSCorrelation bool `json:"enable_dns_correlation" yaml:"enable_dns_correlation"`

	// FailClosedOnDrop halts the session when ring buffer records are lost. A
	// gap in telemetry means the system can no longer make sound statements
	// about what the agent did. Correct, and disruptive.
	FailClosedOnDrop bool `json:"fail_closed_on_drop" yaml:"fail_closed_on_drop"`
}

// Done: the replay source lives in internal/telemetry/replay. It reads recorded
// JSONL streams behind event.Source, reproducing sequence gaps and Dropped
// counters verbatim so fail-closed paths are exercisable without a kernel. Seed
// fixtures are in test/testdata/replay.

// Done: Loader is implemented in loader_linux.go as BPFLoader, over libbpfgo,
// behind `//go:build linux && ebpf`. Load establishes the two things that must
// be true before any event is believed — a cgroup2 hierarchy exists, and the
// object's record layout matches Decoder.EventSize, read from the object's BTF
// — and refuses to open anything if either fails, which is the only point at
// which a mismatch costs nothing. RingBuffer returns raw records and decodes
// none of them; UpdateMap and DeleteMap are how tracked_cgroups is populated
// and unpopulated, with key and value widths checked against the loaded map
// because nothing else can check them. DetachAll and Close are idempotent. The
// loader owns no session state and makes no decision: that is Collector, and it
// does not exist yet.
// `make test-ebpf` runs its tests; the ones that load BPF skip unless root.
// Done: ring buffer loss is counted in the kernel and readable from Go.
// bpf/allseer.bpf.c increments the per-CPU `ringbuf_drops` map at the one place
// a record is lost — a bpf_ringbuf_reserve that returned NULL — and
// Loader.ReadCounter sums it. Before this, Config.FailClosedOnDrop and
// pkg/event.Event.Dropped were both written against a signal that did not
// exist, which is worse than an absent control because it reads as a present
// one. Three things stay distinct and are worth naming here because they are
// easy to conflate: an event the cgroup filter rejected is not a drop, a record
// that failed to decode is not a drop, and only a reservation that failed is.
// What is still missing is the consumer: nothing turns the counter into
// SourceStats.DroppedEvents or into Event.Dropped, because that is Collector's
// and Collector does not exist.

// TODO(telemetry): write the last of the four eBPF programs as a tracepoint
// pair: sys_enter_connect and sys_exit_connect. Tracepoints before kprobes: a
// stable ABI is worth more than coverage while the design moves. The pairing it
// needs is settled — see the Done entry below — so what is left is the payload:
// reading a sockaddr out of user memory, deciding what an AF_UNIX connect means
// against a catalog that lists `connect` under both net.connect and
// ipc.unixsocket, and declaring a `connect_scratch` map of its own shape under
// the protocol allseer_maps.h now writes down.
// Done, for the first of the four: sched_process_exec is implemented in
// bpf/allseer.bpf.c as the program `proc_exec`, under
// SEC("tracepoint/sched/sched_process_exec"). It emits ALLSEER_EVT_PROC_EXEC
// carrying struct allseer_exec_payload, reserving the record in the `events`
// ring buffer and filling it in place — the record is larger than the eBPF
// stack, so that is the only shape it can be written in. The hook is the
// scheduler's rather than the syscall's: an exec that failed never reaches it
// and one that succeeded never returns, which is why `ret` is 0 and why comm
// already names the new image. Identity is struct allseer_proc and nothing
// else. Every kernel read is CO-RE-relocated — the tracepoint's __data_loc
// field and the task_struct walks alike — so no offset from the build kernel is
// compiled in; the ring buffer helpers set the floor at 5.8.
// Not carried, and stated here rather than left to be discovered: argv. The
// tracepoint does not expose it, `argc` is written 0, and reaching the arguments
// means task->mm->arg_start or struct linux_binprm — both kernel-internal, and
// so both a trade against the stable-ABI reason for choosing a tracepoint in the
// first place. Selector.ArgPatterns is already documented as "a convenience for
// readable envelopes, not a security boundary", so the gap costs convenience and
// not a control.
// Done, for the second of the four: sched_process_exit is implemented in
// bpf/allseer.bpf.c as the program `proc_exit`, under
// SEC("tracepoint/sched/sched_process_exit"), emitting ALLSEER_EVT_PROC_EXIT.
// It is the pair to proc_exec and the reason it comes before the two syscall
// probes is that without it a governed process has a beginning and no end:
// ProcessTracker.Untrack is declared as "removes a process on exit" and had
// nothing to call it, and a (PID, StartTime) pair cannot be retired until
// something observes the death that frees the number. The two records agree on
// that pair by construction — exec does not replace the task_struct, so
// start_boottime is the same value read twice — and the runtime tests assert it
// rather than assuming it.
// It reads nothing at all from the tracepoint context. Identity comes from the
// same helpers and the same CO-RE walks proc_exec uses, so there is no context
// layout this probe can be wrong about.
// Two limits are stated at the probe and carried as TODOs in the C file rather
// than left to be discovered. The tracepoint fires per thread and the probe
// emits only on the thread group leader, which is one record per process with
// the right identity but fires early in the one case where a leader exits while
// its siblings run on; `group_dead` is the exact signal and reading it is a
// portability trade. And `ret` is written 0, because the header defines it as a
// syscall return and task->exit_code is an encoded wait status — carrying
// whether a governed agent's build failed needs a field of its own, which is a
// record-layout change.
// Done, for the third of the four, and for the mechanism the fourth will reuse:
// openat is implemented in bpf/allseer.bpf.c as a *pair* of programs,
// `openat_enter` under SEC("tracepoint/syscalls/sys_enter_openat") and
// `openat_exit` under SEC("tracepoint/syscalls/sys_exit_openat"), emitting one
// ALLSEER_EVT_FILE_OPEN between them. A syscall's arguments and its return are
// on opposite sides of the call: the entry has the path, the flags and the mode
// and no outcome; the exit has the outcome and no arguments. struct
// allseer_event needs both, and emitting at entry would mean writing something
// into `ret` — a field the header defines as "syscall return; negative is
// -errno" — before there is a return, which would make every failed open decode
// as Succeeded.
// The pairing is a scratch map, `openat_scratch`, and its contract is written
// down in bpf/include/allseer_maps.h rather than at the probe, because connect
// will declare a second map under the same protocol. The decisions, in short:
//   - the key is bpf_get_current_pid_tgid(), the thread, because a thread is
//     what enters a syscall and is inside at most one at a time. No two openats
//     from one thread can overlap, so the key needs no sequence number.
//   - a TID is reused, so the key alone is not enough. Every entry carries the
//     calling thread's start_boottime and the exit side compares it against the
//     thread it is running on. Without that check a thread killed inside openat
//     leaves an entry that a later, possibly *untracked*, holder of its TID
//     would complete — an untracked cgroup producing a governed event.
//   - BPF_MAP_TYPE_LRU_HASH, which is the opposite of the choice made for
//     tracked_cgroups and for the opposite reason. That map holds user-space
//     policy, where eviction silently un-governs a session; this one holds
//     kernel-owned ephemeral state, where a plain hash filled with orphans from
//     killed tasks would reject every insert forever and stop openat being
//     observed at all. Eviction costs one event; the alternative costs all of
//     them.
//   - the entry side decides and the exit side obeys. The cgroup lookup happens
//     once, at entry, and the ID it matched on is the one in the record — so a
//     task moved between cgroups mid-syscall cannot produce a record whose
//     attribution and whose reason for existing disagree. The event belongs to
//     the cgroup the task was in when it made the call.
//   - the exit side owns deletion and deletes on every path that found an entry:
//     the identity check failing, the reservation failing, and the record being
//     submitted alike.
//   - no entry, no event. An exit that finds nothing returns, and never
//     synthesises a record from the one field it holds.
// The path is captured with bpf_probe_read_user_str, because the pointer is a
// user-space address — proc_exec's kernel-side read is not a precedent for it —
// and is stored as the process supplied it. It is not joined to dirfd and not
// resolved: that is M6's, and internal/telemetry/resolve already refuses to fall
// back to an unresolved path, so a relative open arrives unevaluable rather than
// wrongly evaluated. Truncation behaves as proc_exec's filename does — a
// terminated prefix, which abi.CString cannot distinguish from a whole path, and
// which the TODO(event) in decode.go is the fix for.
// One gap is stated rather than left to be found: an open whose correlation is
// lost — to eviction, or to a scratch update that failed — produces no event and
// nothing counts it. It is not folded into ringbuf_drops, which is defined as
// counting reservation failures; the TODO at the foot of allseer_maps.h is what
// would close it, and it waits on Collector because a counter needs a consumer.
// Done: kernel-side cgroup filtering is implemented in bpf/allseer.bpf.c.
// proc_exec looks the current cgroup ID up in `tracked_cgroups` before it
// reserves anything, so an exec in an undeclared cgroup costs a hash lookup and
// a return rather than a reservation, a wakeup, a decode and a discard.
// Presence in the map is the whole test, as allseer_maps.h defines it: the
// returned pointer is checked against NULL and never dereferenced. Two
// consequences are worth stating here rather than leaving to be found. While no
// loader populates the map, the filter set is empty and this object reports
// nothing — the correct direction to fail in, but not an obvious one from the
// Go side. And the filter is per-probe rather than a property of the object, so
// every tracepoint added after this one has to perform the same lookup or it
// silently reports on cgroups nobody declared. proc_exit, the first probe added
// after it, does perform the lookup and does it first, and
// TestRuntimeUntrackedCgroupProducesNoExitEvent is what proves it rather than
// the reviewer's eye. The same now goes for count_ringbuf_drop, which is a
// second per-probe obligation of exactly the same shape.
// Done, in its first half: the Go view of the ABI is generated from
// bpf/include/allseer_event.h by internal/telemetry/abigen into
// internal/telemetry/abi. Sizes, offsets, the event-type enum, the struct
// mirrors, and the byte-level decode functions are all derived; nothing about
// the layout is written down twice. TestGeneratedFileIsNotStale fails when the
// header and the generated file disagree, and `make gen` regenerates.
// Done, in its second half: Decoder.Decode and EventSize are implemented in
// decode.go as EventDecoder, over internal/telemetry/abi. Each
// allseer_event_type maps to a capability.Kind and the Kind's domain comes from
// the M1 catalog, never from a second table. ALLSEER_EVT_FILE_OPEN is the one
// type whose kind the payload decides — the open flags separate fs.read,
// fs.write, and fs.create, which is the mapping docs/dataflow.md already traces.
// Two declared types are refused rather than guessed at: ALLSEER_EVT_UNKNOWN,
// which states no operation, and ALLSEER_EVT_PRIV_CHANGE, whose `operation`
// field has no enumerators in the header and so cannot be told apart from four
// other privilege kinds the shipped rule set treats differently.
// The abi package deliberately stops at the ABI shape: it imports neither
// pkg/event nor pkg/capability, because deciding what a record *means* is a
// judgment and the generated layer must stay free of judgments it would have to
// regenerate.
// TODO(telemetry): add an `enum allseer_priv_op` to the header so
// ALLSEER_EVT_PRIV_CHANGE becomes decodable. A C edit, and one for the Linux
// host, alongside the version field already open above.
// TODO(telemetry): decide the path resolution strategy. Full dentry walking in
// the kernel is expensive and bounded by the verifier's loop limits; resolving
// in user space races with rename. Neither is clean.
// TODO(telemetry): implement the synthetic event generator sharing the replay
// format, for benchmarks and for scenarios awkward to record.
// TODO(telemetry): benchmark probe overhead against a realistic build. Target
// under 5% wall clock, measured rather than assumed.
// TODO(telemetry): evaluate LSM BPF hooks for synchronous blocking. Tracepoints
// observe after the fact and can only detect; real prevention needs an LSM hook
// or seccomp-unotify, and that choice decides what ActionBlock can honestly
// mean.
