// SPDX-License-Identifier: GPL-2.0
/* ALLSEER eBPF object.
 *
 * One object, not one per probe. telemetry.Config carries a single ObjectPath,
 * and maps are per-object: two objects loaded separately get two ring buffers
 * and two filter sets, and sharing one between them means pinning it and
 * agreeing on a bpffs path. Probes are added to this file as they are written.
 *
 * At this point the file declares five maps and six programs: sched_process_exec
 * and sched_process_exit, which each produce a record on their own, and two
 * syscall pairs — sys_enter_openat / sys_exit_openat and sys_enter_connect /
 * sys_exit_connect — which each produce one record between them. The maps are
 * what the probes emit into, are filtered by, and — for the syscall pairs —
 * hold half-built events in between.
 *
 * allseer_event.h is included for a reason that outlives the absence of probes:
 * it is the record ABI, internal/telemetry/abigen derives the Go decoder by
 * parsing it, and until now no C compiler had ever been asked to read it. A
 * generator's idea of a C header and a compiler's are not the same thing.
 * Compiling it here for the BPF target is the cheapest way to keep them from
 * diverging, and the include costs nothing in the object: BTF carries only
 * types something references.
 */

/* vmlinux.h is generated from the running kernel's BTF, not written here, and
 * this kernel's BTF produces empty forward declarations inside anonymous
 * unions that clang's -Wmissing-declarations objects to. The Makefile compiles
 * with -Wall -Werror and that is worth keeping, so the suppression is scoped to
 * this one include rather than removed from the flags: warnings about ALLSEER's
 * own C are still errors. It cannot be fixed at the source, because the source
 * is whatever kernel the object is built on. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-declarations"
#include "vmlinux.h"
#pragma clang diagnostic pop

#include <bpf/bpf_core_read.h>
/* bpf_ntohs, for the one field on the wire that is not in the machine's own byte
 * order. A sockaddr's port is big-endian by definition and struct
 * allseer_net_payload declares `dport` as __u16 rather than __be16, so the probe
 * is the side that converts — see connect_enter, and decode.go on what the
 * alternative reading costs. */
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "allseer_event.h"
#include "allseer_maps.h"

/* The record stream. Probes reserve into this and user space drains it by name
 * through telemetry.Loader.RingBuffer.
 *
 * A ring buffer rather than a perf buffer: it preserves ordering across CPUs,
 * which a per-CPU perf ring does not, and pkg/event.Event.Sequence is defined
 * as giving "a total order when timestamps collide". It also allows reserving
 * space and writing the record in place, which this record shape requires
 * rather than merely prefers — struct allseer_event is 856 bytes against a
 * 512-byte eBPF stack, so a probe cannot build one on the stack and copy it
 * out. internal/telemetry/abi asserts that size relationship precisely so this
 * conclusion is revisited if the record ever shrinks past it.
 *
 * A ring buffer map takes no key or value type; max_entries is its size in
 * bytes. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, ALLSEER_RINGBUF_BYTES);
} events SEC(".maps");

/* The set of cgroups worth reporting on, whose membership user space controls
 * through telemetry.Loader.UpdateMap and telemetry.Loader.DeleteMap.
 *
 * proc_exec below consults it, and it is the first thing that probe does. What
 * the map is for is stated in the Loader contract: filtering happens in the
 * kernel "rather than costing a userspace round trip per event". An untracked
 * process costs a lookup and a return, not a ring buffer reservation, a wakeup,
 * a decode and a discard.
 *
 * Both ends now exist. telemetry.BPFLoader adds a cgroup with UpdateMap and
 * removes one with DeleteMap, and removal is a delete rather than a zeroed
 * value because presence is the entire signal — the lookup below is tested for
 * NULL and never dereferenced, so there is nothing a value could say. Those two
 * calls are the whole of how a session becomes governed and stops being
 * governed.
 *
 * What an empty map means is worth being explicit about, because it is the
 * state this object is in until user space says otherwise: no cgroup has been
 * declared governed, so every event misses the filter and nothing is reported.
 * That is the direction to fail in. Reporting on a cgroup nobody asked about
 * would be surveillance the system has no mandate for, and the opposite default
 * — report everything until told otherwise — is the one that cannot be undone
 * after the fact. Silence here is a filter with no members, not a probe that is
 * failing to fire, and telemetry.Loader.ReadCounter is what distinguishes a
 * host that observed nothing from one that lost what it observed.
 *
 * BPF_MAP_TYPE_HASH and not BPF_MAP_TYPE_LRU_HASH. An LRU map evicts under
 * pressure, and an evicted entry here does not degrade anything visibly — it
 * silently stops a governed session from being observed, which reads
 * downstream as an agent that did nothing. Membership is decided by user space
 * and must only change when user space says so, so a full map has to fail the
 * insert loudly rather than quietly make room. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, ALLSEER_MAX_TRACKED_CGROUPS);
	__type(key, allseer_cgroup_id_t);
	__type(value, allseer_tracked_t);
} tracked_cgroups SEC(".maps");

/* The count of records the ring buffer could not accept, read from user space
 * through telemetry.Loader.ReadCounter.
 *
 * Declared next to `events` because the two are one mechanism rather than two:
 * that map carries what was observed and this one carries what was observed and
 * lost, and a reader holding the first without the second cannot tell a quiet
 * host from a blind one. allseer_maps.h states what an increment means and, at
 * more length, the two things that look like drops and are not.
 *
 * Nothing in this object reads it. It is write-only from the kernel side by
 * design: a probe that changed its behaviour based on how much it had already
 * lost would be making a governance decision on the hot path, in the one place
 * that cannot log why. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, ALLSEER_DROP_SLOTS);
	__type(key, allseer_drop_key_t);
	__type(value, allseer_drop_count_t);
} ringbuf_drops SEC(".maps");

/* The half-built openat events, held between one thread's sys_enter_openat and
 * its sys_exit_openat.
 *
 * Nothing in user space reads or writes it during operation, unlike the three
 * maps above: it is kernel-internal state, and telemetry.MapOpenatScratch exists
 * so the runtime tests can look at it rather than because the loader needs it.
 *
 * allseer_maps.h holds the whole contract — why the key is a thread and not a
 * process, why a thread cannot have two of these at once, why PID reuse needs a
 * start-time stamp on top of the key, why this one is an LRU where
 * tracked_cgroups is deliberately not, and every failure path with its answer.
 * It is written there rather than here because connect will declare a second map
 * under the same protocol.
 *
 * BPF_MAP_TYPE_LRU_HASH and not a per-CPU array, which is the tempting cheap
 * answer and is wrong twice over. A task can be preempted inside openat and
 * resume on another CPU, so the exit is not guaranteed to run where the entry
 * did; and two tasks on one CPU can both be inside openat, so a single per-CPU
 * slot would have them overwrite each other. The state belongs to a thread, so
 * it has to be keyed by one. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, ALLSEER_MAX_OPEN_SCRATCH);
	__type(key, allseer_syscall_key_t);
	__type(value, struct allseer_open_scratch);
} openat_scratch SEC(".maps");

/* The half-built connect events, held between one thread's sys_enter_connect
 * and its sys_exit_connect.
 *
 * A second map rather than a second mechanism. allseer_maps.h settled the
 * protocol when openat needed it and said this map would exist: "connect will
 * want the same mechanism and will not share this map", because the value shape
 * differs and because "one LRU shared by both means a burst of opens evicts
 * pending connects, so the noisiest syscall on the host decides which of the
 * quieter one's events survive".
 *
 * That separation is also the whole of how connect state is told apart from
 * openat state. There is no discriminator in the value and none is needed: an
 * entry written by connect_enter can only ever be read by connect_exit, because
 * no other program names this map. A shared map would have needed a syscall tag
 * and a check on it; two maps make the distinction structural, and a program
 * that looked in the wrong one would not compile.
 *
 * Everything else is identical to openat_scratch by construction — the same
 * allseer_syscall_key_t, the same LRU, the same capacity argument, the same
 * identity stamp — and allseer_maps.h holds the reasoning for all of it. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, ALLSEER_MAX_CONNECT_SCRATCH);
	__type(key, allseer_syscall_key_t);
	__type(value, struct allseer_connect_scratch);
} connect_scratch SEC(".maps");

/* Required before any program in this object can load. Declared with the maps
 * because it belongs to the object rather than to any one probe, and because
 * the helpers the probes will need — bpf_probe_read_kernel and the task
 * accessors among them — are GPL-only and refuse to verify without it. */
char LICENSE[] SEC("license") = "GPL";

/* The record ABI version this object was compiled against.
 *
 * The value of ALLSEER_ABI_VERSION, placed where a loader can read it out of
 * the file before a single program reaches the kernel. That is the whole
 * purpose: allseer_event.h explains that the version field in each record "is
 * the backstop, not the mechanism: it reports the mismatch one event at a time,
 * after the probes are already running, which is later than the loader could
 * have known". This declaration is the mechanism, and
 * telemetry.checkABIVersion is what reads it.
 *
 * `const` and not `const volatile`. Both land in .rodata and both are frozen by
 * libbpf after load, but `const volatile` is the libbpf idiom for a global the
 * *loader* fills in before load — a tunable — and this is the opposite of a
 * tunable. It is a fact about the compiled object, and a loader that could
 * write it could only ever write over the mismatch it exists to detect.
 *
 * Nothing in this object reads it, and nothing should. A probe comparing this
 * against a version from somewhere else would be re-deciding, on the hot path
 * and with nowhere to log it, a question the loader already refused to start
 * on.
 *
 * External linkage rather than static, because a static that nothing references
 * is a variable the compiler is free to discard, and a version the object drops
 * for being unused reads to the loader exactly like a version it never had. The
 * symbol is what carries the value's offset within .rodata: BTF names the
 * variable and its size, but its DATASEC offset is zero in an unlinked object
 * and is fixed up from .rel.BTF, so the ELF symbol table is where the loader
 * looks. internal/telemetry/rodata.go records that in more detail. */
const __u32 allseer_abi_version = ALLSEER_ABI_VERSION;

/* --- Helpers ----------------------------------------------------------------
 */

/* count_ringbuf_drop records that one record was lost.
 *
 * Called from the one place this object loses a record it meant to emit: a
 * bpf_ringbuf_reserve that returned NULL. It is deliberately not called
 * anywhere else, and in particular not where the cgroup filter rejects an
 * event — allseer_maps.h says why at the map, and the short form is that a
 * filtered event is not a lost one.
 *
 * __sync_fetch_and_add rather than a plain `*slot += 1`. The slot belongs to
 * this CPU, so there is no other CPU to race, but a tracepoint program can be
 * interrupted on its own CPU — by an NMI-driven perf program among others — and
 * a read-modify-write split across that interrupt loses a count silently. The
 * atomic is uncontended by construction and it runs only on the path where a
 * record has already been lost, so its cost is charged to the case that is
 * already the expensive one.
 *
 * A lookup that fails returns without counting. It cannot fail: an array map is
 * preallocated and the index is a constant inside max_entries. The check is
 * there because the verifier requires it, and returning is the only honest
 * thing to do with a count there is nowhere to put. */
static __always_inline void count_ringbuf_drop(void)
{
	allseer_drop_key_t key = ALLSEER_DROP_KEY_RINGBUF;
	allseer_drop_count_t *slot;

	slot = bpf_map_lookup_elem(&ringbuf_drops, &key);
	if (!slot)
		return;

	__sync_fetch_and_add(slot, 1);
}

/* --- Probes -----------------------------------------------------------------
 *
 * Tracepoints before kprobes, as internal/telemetry states:
 * "a stable ABI is worth more than coverage while the design moves". A
 * tracepoint's argument layout is published in
 * /sys/kernel/tracing/events/<group>/<event>/format and is not rearranged by a
 * kernel release the way an inlined function's arguments are.
 */

/* sched_process_exec: a process has replaced its image.
 *
 * The hook rather than the syscall. sys_enter_execve fires on the attempt, with
 * arguments still in user memory and the outcome unknown; sched_process_exec
 * fires from the kernel's exec path after the new image is installed, so it
 * reports what actually ran. That ordering is why struct allseer_event.ret is
 * written 0 below and not left to a syscall return that does not exist here: an
 * exec that failed never reaches this tracepoint, and one that succeeded never
 * returns. resultOf in internal/telemetry/decode.go reads ret >= 0 as
 * Succeeded, which is the true statement for every record this probe emits.
 *
 * It also fires *after* the new comm is installed, which is what makes
 * bpf_get_current_comm here report the binary that is now running rather than
 * the shell that called it.
 *
 * What this tracepoint carries, from its format file, is the whole of what can
 * be filled in from it:
 *
 *   __data_loc filename  the path exec resolved   -> exec payload `filename`
 *   pid                  the execing thread group -> proc.pid, from the helper
 *   old_pid              the pre-exec tgid        -> not carried; see below
 *
 * old_pid is dropped rather than stored. It differs from pid only when a thread
 * other than the group leader execs and the group leader's identity is
 * discarded, and struct allseer_proc has no field whose documented meaning is
 * "the tgid this process used to have". Putting it in ppid would be a lie about
 * ancestry, which is the one thing ProcessTracker attributes sessions by.
 *
 * argv is not carried, because this tracepoint does not carry it. The exec
 * payload has room for ALLSEER_ARGV_MAX arguments and argc is written 0, which
 * internal/telemetry/decode.go already reads as "no arguments in this record"
 * rather than "a process invoked with none" only by accident — the two are
 * indistinguishable downstream, and that is the honest cost of this hook. The
 * arguments exist at this point only in the new process's user stack, reachable
 * through task->mm->arg_start, or in struct linux_binprm, reachable only from a
 * BTF raw tracepoint or a kprobe. Both are kernel-internal structures and both
 * are a decision about what evidence is worth an unbounded user-memory read on
 * the exec path; neither belongs inside the issue that writes the first probe.
 * Selector.ArgPatterns is documented as "a convenience for readable envelopes,
 * not a security boundary", so the gap costs convenience and not a control.
 *
 * Filtered before anything is reserved. See the lookup at the top of the
 * function: an exec in a cgroup nobody declared governed costs one hash lookup
 * and a return, which is the whole point of the map living in the kernel.
 *
 * CO-RE: every kernel struct read here goes through a relocation rather than a
 * literal offset. vmlinux.h applies preserve_access_index to every record it
 * declares, so the direct read of ctx->__data_loc_filename is relocated on
 * load, and the task_struct walks use BPF_CORE_READ explicitly. Nothing in this
 * function encodes an offset from the kernel it was compiled against.
 */
SEC("tracepoint/sched/sched_process_exec")
int proc_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct task_struct *task;
	struct allseer_event *e;
	allseer_cgroup_id_t cgroup_id;
	__u64 pid_tgid, uid_gid;
	__u32 filename_off;

	/* The filter, and the first thing this probe does.
	 *
	 * Presence in the map is the entire test, because that is the entire
	 * contract: allseer_maps.h declares the value as `allseer_tracked_t` and
	 * says of it that "presence in the map is the entire signal: a lookup that
	 * returns non-NULL means this cgroup is governed". So the returned pointer
	 * is tested against NULL and never dereferenced. Reading the byte it
	 * points at and treating a zero as untracked would invent a second, unstated
	 * meaning for a value user space has never been told to set — and would
	 * turn a memset in a future loader into a silent, total loss of telemetry.
	 * The header says the byte is one byte only "so that adding a field is a
	 * visible ABI change on both sides instead of a silent reinterpretation of
	 * padding"; giving the existing byte a meaning here would be exactly that
	 * silent reinterpretation.
	 *
	 * The key type is the typedef rather than a bare __u64, so the width the
	 * map was declared with and the width looked up in it are the same token.
	 * libbpf checks key_size at load, but only against what this file already
	 * says twice.
	 *
	 * Attribution is by cgroup and not by PID, for the reason allseer_maps.h
	 * gives: "a filter keyed by PID would have to be updated on every fork the
	 * agent performs, from user space, racing the child's first syscall". The
	 * cost of that choice is that a governed process outside a tracked cgroup
	 * is invisible from here — Collector.AttachSession's "PID ancestry
	 * otherwise" branch cannot see what the kernel already dropped — so placing
	 * the session in a cgroup is a requirement on the loader and not an
	 * optimisation. pkg/capability records the other end of the same fact:
	 * priv.namespace is "how a process escapes the attribution the collector
	 * depends on: a new cgroup or PID namespace puts work outside the probes'
	 * filter map". Nothing here closes that; it becomes reachable the moment a
	 * filter exists, and the probe that would observe it does not.
	 *
	 * Cgroup ID 0 gets no special case, because the repository gives it no
	 * special meaning: it is looked up like any other key and misses unless
	 * user space put it there. That matters most in the environment where
	 * bpf_get_current_cgroup_id() cannot answer — a kernel without cgroup v2 —
	 * where every exec misses and this object observes nothing. Special-casing
	 * 0 to pass the filter would convert that into reporting *everything*,
	 * which is the wrong direction to fail in and would hide the misconfigured
	 * host rather than surface it. Detecting it belongs to the loader, which is
	 * the only side that can refuse to start. */
	cgroup_id = bpf_get_current_cgroup_id();
	if (!bpf_map_lookup_elem(&tracked_cgroups, &cgroup_id))
		return 0;

	/* Reserved, not built and copied. struct allseer_event is 856 bytes and
	 * the eBPF stack is 512, so this is the only shape the record can be
	 * written in. A failed reservation means the ring is full and user space
	 * is behind: returning drops this record, which is the loss
	 * pkg/event.Event.Dropped exists to report and telemetry.Config
	 * .FailClosedOnDrop exists to act on.
	 *
	 * The record cannot be saved from in here — there is nowhere to put it and
	 * no waiting on the exec path — but the fact of it can be, and that is the
	 * whole difference between a hole in the stream and a hole nobody knows
	 * about. Counting is all this branch can do and all it does. */
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_ringbuf_drop();
		return 0;
	}

	/* Reserved space is not zeroed — it is whatever the ring held before —
	 * so every byte of the record is written, including the two named pads
	 * and the whole payload union. The union is cleared once rather than
	 * field by field because the exec member is the largest one and so is the
	 * union: an unwritten tail here is old ring contents handed to a decoder,
	 * and the argv block below is deliberately left empty, which is only
	 * true if something zeroed it. */
	e->timestamp = bpf_ktime_get_ns();
	e->type = ALLSEER_EVT_PROC_EXEC;
	e->ret = 0;
	e->version = ALLSEER_ABI_VERSION;
	e->_pad = 0;

	pid_tgid = bpf_get_current_pid_tgid();
	uid_gid = bpf_get_current_uid_gid();
	task = (struct task_struct *)bpf_get_current_task();

	/* The identity struct the header already declares, populated in the units
	 * it declares them in. pid is the thread group ID and tid the thread, as
	 * the kernel means them and as event.Process documents them; ppid is the
	 * parent's tgid, because a parent is identified by its process and not by
	 * whichever of its threads happened to fork. start_boottime paired with
	 * pid is what event.Process.StartTime is for — "the pair (PID, StartTime)
	 * is unique for a boot; PID alone is not". */
	/* The value the filter already matched on, not a second call. The record
	 * and the filter decision must agree about which cgroup this was. */
	e->proc.cgroup_id = cgroup_id;
	e->proc.start_time = BPF_CORE_READ(task, start_boottime);
	e->proc.pid = (__u32)(pid_tgid >> 32);
	e->proc.tid = (__u32)pid_tgid;
	e->proc.ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->proc.uid = (__u32)uid_gid;
	e->proc.gid = (__u32)(uid_gid >> 32);
	e->proc._pad = 0;
	bpf_get_current_comm(&e->proc.comm, sizeof(e->proc.comm));

	__builtin_memset(&e->payload, 0, sizeof(e->payload));

	/* __data_loc is the tracepoint ABI's variable-length encoding: the low 16
	 * bits are the string's offset from the start of this record, the high 16
	 * its length. The length is not used — the destination is fixed size and
	 * the copy has to stop at ALLSEER_PATH_MAX regardless, which is the
	 * truncation the header warns about and abi.CString reports.
	 *
	 * bpf_probe_read_kernel_str NUL-terminates within the destination even
	 * when it truncates, so a path longer than the field arrives as a
	 * terminated prefix. That is worth stating because it is the one case the
	 * decoder's ErrTruncatedString cannot catch: it detects an array with no
	 * NUL in it, and this helper never produces one. Carrying truncation on
	 * the wire is the open TODO(event) in internal/telemetry/decode.go and it
	 * is a record-layout change, not a probe change.
	 *
	 * On failure the field keeps the zero the memset above left, so an empty
	 * filename means the read failed rather than the process having no path.
	 * The event is still submitted: an exec happened, the identity of the
	 * process that performed it is known, and dropping the record would hide
	 * a real execution because one field of it could not be read. */
	filename_off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_kernel_str(&e->payload.exec.filename,
				  sizeof(e->payload.exec.filename),
				  (void *)ctx + filename_off);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* sched_process_exit: a task is leaving.
 *
 * The pair to proc_exec above, and the reason it is worth having is not that an
 * exit is interesting on its own — pkg/capability rates process.exit
 * SeverityInfo — but that without it a governed process has a beginning and no
 * end. telemetry.ProcessTracker.Untrack is declared as "removes a process on
 * exit" and has nothing to call it; internal/session/dispatch.go names PID reuse
 * as what a tracker keyed on (PID, StartTime) exists to prevent, and a pair
 * cannot be retired until something observes the death that frees the number.
 *
 * Nothing is read from the tracepoint context. That is not a shortcut, it is the
 * whole of what this probe needs: identity comes from the same helpers and the
 * same CO-RE task_struct walks proc_exec already uses, and comm, pid and prio in
 * the context are either duplicated by a helper or not carried by the record at
 * all. A probe that reads no context field cannot be broken by a context layout
 * this object was not compiled against, which is the stable-ABI argument for
 * tracepoints taken to its conclusion.
 *
 * # One event per process, not one per thread
 *
 * This tracepoint fires for every thread. A record per thread would report a
 * ten-thread process exiting ten times, and a tracker acting on those would
 * untrack a live process nine times before it died.
 *
 * The filter is pid == tid — the thread group leader — read from the one helper
 * proc_exec already uses for both halves. It is the leader that carries the
 * process's identity: `pid` in struct allseer_proc is documented as the thread
 * group ID, and start_boottime read from the leader is the same value proc_exec
 * recorded for the same process, which is what makes (pid, start_time) match
 * across the two events.
 *
 * The narrow case this gets wrong is worth stating rather than leaving to be
 * found. A group leader that exits while its siblings keep running — a bare
 * pthread_exit from main — becomes a zombie without ending the process, and this
 * probe reports an exit for a process that is still alive. The kernel does
 * distinguish the two: this tracepoint carries `group_dead`, true only on the
 * last thread of the group, which is the precise signal. It is not read here for
 * one reason, and it is a portability reason rather than a preference: the field
 * is a recent addition to the context, so reading it means either requiring a
 * kernel that has it or carrying a bpf_core_field_exists branch and a fallback —
 * and the fallback would be this comparison anyway. See the TODO at the foot of
 * this file.
 *
 * # What is not carried
 *
 * The exit status. `ret` is written 0, and the header defines that field as
 * "syscall return; negative is -errno" — a definition a process exit does not
 * fit. task->exit_code is an encoded wait status, a shifted exit code or a
 * signal number in the low bits, and putting it in `ret` unshifted would make
 * exit(1) decode as ReturnCode 256 and Succeeded true, because
 * internal/telemetry/decode.go reads ret >= 0 as success. Writing 0 says the
 * one thing that is true of every record here — the task exited — and says
 * nothing that is false. Carrying the status honestly needs a field of its own,
 * which is a record-layout change; see the TODO at the foot of this file.
 *
 * No payload member is designated for an exit and none is written.
 * internal/telemetry/decode.go states the same thing from the other side: "No
 * union member is designated for an exit, so none is read. The process identity
 * and the return are the whole record, and both are already decoded."
 */
SEC("tracepoint/sched/sched_process_exit")
int proc_exit(struct trace_event_raw_sched_process_exit *ctx)
{
	struct task_struct *task;
	struct allseer_event *e;
	allseer_cgroup_id_t cgroup_id;
	__u64 pid_tgid, uid_gid;

	/* The filter, and the first thing this probe does — the same obligation
	 * proc_exec carries and for the same reason. internal/telemetry states it
	 * as a standing requirement on every probe added after the first: "the
	 * filter is per-probe rather than a property of the object, so every
	 * tracepoint added after this one has to perform the same lookup or it
	 * silently reports on cgroups nobody declared."
	 *
	 * First, ahead of the cheaper thread-leader comparison below, deliberately.
	 * Ordering the comparison first would skip a hash lookup for every
	 * non-leader thread, which is a real saving on a threaded process — and it
	 * would also mean that "no untracked cgroup is ever observed" could no
	 * longer be checked by reading the top of each probe. The invariant is
	 * worth more than the lookup.
	 *
	 * The task is still in its cgroup here: this tracepoint fires from do_exit
	 * before the task is dissociated from it, so bpf_get_current_cgroup_id()
	 * answers with the cgroup the process lived in. That ordering is a property
	 * of the kernel and not of this file, which is why the test that proves it
	 * is a runtime one. */
	cgroup_id = bpf_get_current_cgroup_id();
	if (!bpf_map_lookup_elem(&tracked_cgroups, &cgroup_id))
		return 0;

	/* One record per process. See the comment above the function: every thread
	 * reaches this tracepoint and only the group leader carries the identity
	 * the record is about. */
	pid_tgid = bpf_get_current_pid_tgid();
	if ((__u32)(pid_tgid >> 32) != (__u32)pid_tgid)
		return 0;

	/* Reserved and filled in place, and counted when it cannot be. Identical to
	 * proc_exec, including the reason: the record is larger than the eBPF stack,
	 * and a reservation that fails is a lost record that only ringbuf_drops can
	 * make visible. */
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_ringbuf_drop();
		return 0;
	}

	e->timestamp = bpf_ktime_get_ns();
	e->type = ALLSEER_EVT_PROC_EXIT;
	e->ret = 0;
	e->version = ALLSEER_ABI_VERSION;
	e->_pad = 0;

	uid_gid = bpf_get_current_uid_gid();
	task = (struct task_struct *)bpf_get_current_task();

	/* The same fields, read the same way, in the same units as proc_exec. That
	 * is what makes the two records comparable: start_boottime does not change
	 * over a task's life and exec does not replace the task_struct, so the
	 * (pid, start_time) pair here is the pair the exec record carried for the
	 * same process — which is exactly the pair event.Process.StartTime is
	 * documented to make unique.
	 *
	 * pid and tid are equal by the filter above and both are written anyway,
	 * because struct allseer_proc declares both and a field left holding old
	 * ring contents is worse than a field holding a value that happens to be
	 * predictable.
	 *
	 * real_parent is read rather than parent: the tracepoint fires before
	 * exit_notify reparents the task, so this is still the process that forked
	 * it. */
	e->proc.cgroup_id = cgroup_id;
	e->proc.start_time = BPF_CORE_READ(task, start_boottime);
	e->proc.pid = (__u32)(pid_tgid >> 32);
	e->proc.tid = (__u32)pid_tgid;
	e->proc.ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->proc.uid = (__u32)uid_gid;
	e->proc.gid = (__u32)(uid_gid >> 32);
	e->proc._pad = 0;
	bpf_get_current_comm(&e->proc.comm, sizeof(e->proc.comm));

	/* Zeroed even though nothing reads it. Reserved space is whatever the ring
	 * held before, so skipping this would submit a record carrying 776 bytes of
	 * the previous event — a path, an argv, a peer address — under a type that
	 * declares no payload. The decoder ignores it today; a raw-record dump, a
	 * recorder, or a future payload member would not, and none of those should
	 * have to discover that exit records are not clean. */
	__builtin_memset(&e->payload, 0, sizeof(e->payload));

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* --- The openat pair ---------------------------------------------------------
 *
 * Two programs, one event. sys_enter_openat has the arguments and no return;
 * sys_exit_openat has the return and no arguments; struct allseer_event needs
 * both, so neither tracepoint can produce a record on its own and the pair is
 * joined through `openat_scratch`. The protocol — the key, the identity stamp,
 * the map type, the lifecycle, every failure path — is written down once in
 * allseer_maps.h, because sys_enter_connect will use the same one.
 *
 * The three rules those two programs implement, restated here because they are
 * what a reader of this file needs to be able to check by eye:
 *
 *   1. The entry side decides. It performs the tracked_cgroups lookup, captures
 *      the cgroup ID it matched on, and puts that value in the record. The exit
 *      side performs no filter lookup of its own. The presence of a scratch
 *      entry *is* the entry side's decision, carried forward.
 *   2. The exit side deletes. Every path that found an entry removes it, and no
 *      other program removes anything.
 *   3. No entry, no event. An exit that finds nothing returns. It never
 *      synthesises a record out of what it has, because what it has is a return
 *      value and no idea what syscall produced it.
 *
 * Rule 1 is what makes the cgroup question answerable. A task can be moved
 * between cgroups while it sits inside openat, so "which cgroup owns this
 * event" has two candidate answers and they can differ. The answer taken here is
 * **the cgroup the task was in when it made the call**, which is the one that
 * was governed at the moment the process asked for the file. It follows that a
 * task moved *into* a tracked cgroup mid-syscall produces no event — its entry
 * was filtered, so there is nothing to complete — and a task moved *out* of one
 * still produces the event it earned on the way in. Both are the same rule, and
 * the record's cgroup_id agrees with the lookup that admitted it in every case,
 * because it is a copy of it rather than a second reading.
 */

/* sys_enter_openat: a thread is asking to open a path.
 *
 * Emits nothing. That is the point of it: the record it would emit has a `ret`
 * field the header defines as "syscall return; negative is -errno", and at this
 * instant there is no return — the open has not been attempted. Writing 0 there
 * would make every failed open decode as Succeeded, and
 * internal/telemetry/decode.go is explicit that a failed action is a governance
 * signal in its own right: "the credential-egress fixture turns on it, where a
 * read of a key that failed with ENOENT must not be treated as a disclosure".
 * An event emitted here would say the opposite of that, for every open that
 * failed. So this side captures and stores, and openat_exit below emits.
 *
 * The tracepoint's arguments, from its format file, arrive in the generic
 * syscall context's args array:
 *
 *   args[0]  dfd        the directory fd a relative path is resolved against
 *   args[1]  filename   a pointer into *user* memory
 *   args[2]  flags      O_RDONLY/O_WRONLY/O_CREAT/...
 *   args[3]  mode       the creation mode
 *
 * dfd is captured nowhere, and that is a decision rather than an oversight. It
 * is only meaningful joined to the path, and joining them is path resolution —
 * which the repository has already placed in M6 and which
 * internal/telemetry/resolve is built around refusing to guess at: it "refuses
 * to fall back from ResolvedPath to Path precisely so that a pre-resolution path
 * can never reach selector matching". Carrying a dfd in a record that has no
 * field for one, or resolving it here against the verifier's loop limits, are
 * both ways of doing that job badly inside an issue that is not about it. An
 * open of a relative name therefore arrives unevaluable, which is the
 * fail-closed direction and is exactly what M6 exists to close.
 *
 * The path is read with bpf_probe_read_user_str and not the kernel variant. The
 * pointer is a user-space address: reading it as a kernel address either faults
 * and yields nothing, or on an architecture without a split address space reads
 * whatever kernel memory happens to live at that number and copies it into an
 * audit record. proc_exec's use of the kernel variant is not a precedent for
 * this one — its string is inside the tracepoint record, which is kernel memory.
 */
SEC("tracepoint/syscalls/sys_enter_openat")
int openat_enter(struct trace_event_raw_sys_enter *ctx)
{
	struct task_struct *task;
	struct allseer_open_scratch s;
	allseer_cgroup_id_t cgroup_id;
	allseer_syscall_key_t key;
	__u64 pid_tgid, uid_gid;

	/* The filter, first, and before the path is read out of user memory
	 * rather than after. Every probe in this object carries the same
	 * obligation — internal/telemetry states it as a standing requirement:
	 * "the filter is per-probe rather than a property of the object, so every
	 * tracepoint added after this one has to perform the same lookup or it
	 * silently reports on cgroups nobody declared."
	 *
	 * Here it also buys the most of anywhere it appears. openat is among the
	 * busiest syscalls on a Linux host, and an untracked one costs a hash
	 * lookup and a return instead of a 256-byte user-memory read and a map
	 * insert.
	 *
	 * The value this returns is never dereferenced, per the contract
	 * allseer_maps.h states for the map: "presence in the map is the entire
	 * signal". */
	cgroup_id = bpf_get_current_cgroup_id();
	if (!bpf_map_lookup_elem(&tracked_cgroups, &cgroup_id))
		return 0;

	/* Zeroed in full before anything is written into it. Two reasons, and both
	 * are load-bearing rather than defensive habit: the verifier refuses to
	 * copy stack memory into a map unless every byte of it has been written,
	 * and the path array below is filled by a helper that writes only as far as
	 * the string goes, so the tail is whatever this stack slot held before —
	 * which is another process's data, on its way into an audit record. */
	__builtin_memset(&s, 0, sizeof(s));

	/* The instant the call was made. Copied into the record verbatim by the
	 * exit side; allseer_maps.h says why it is this instant and not the one the
	 * syscall returned at. */
	s.timestamp = bpf_ktime_get_ns();

	pid_tgid = bpf_get_current_pid_tgid();
	uid_gid = bpf_get_current_uid_gid();
	task = (struct task_struct *)bpf_get_current_task();

	/* The identity stamp, and the one field here that is not part of the
	 * record. This is the *calling thread's* start_boottime, which is what
	 * makes a reused TID detectable at exit. */
	s.task_start_time = BPF_CORE_READ(task, start_boottime);

	/* struct allseer_proc, in the units the header declares and the same ones
	 * proc_exec and proc_exit use: pid is the thread group ID, tid the thread,
	 * ppid the parent's tgid.
	 *
	 * start_time is read from the group leader and not from the current task,
	 * which is the one place this probe differs from the two above it, and it
	 * differs because it has to. Those two report on a process at a moment when
	 * the current task is the process — exec installs a new image, exit is
	 * filtered to the group leader. openat is called by whichever thread wants
	 * a file, and a worker thread's start_boottime is its own, not its
	 * process's. Pairing that with proc.pid, which is the tgid, would produce a
	 * (PID, StartTime) that no other record in the stream carries — and
	 * event.Process.StartTime exists precisely so that pair identifies a
	 * process, with telemetry.ProcessTracker keyed on it. Reading the leader
	 * gives the same value proc_exec recorded for the same process, which is
	 * what lets a tracker find the session this open belongs to. */
	s.proc.cgroup_id = cgroup_id;
	s.proc.start_time = BPF_CORE_READ(task, group_leader, start_boottime);
	s.proc.pid = (__u32)(pid_tgid >> 32);
	s.proc.tid = (__u32)pid_tgid;
	s.proc.ppid = BPF_CORE_READ(task, real_parent, tgid);
	s.proc.uid = (__u32)uid_gid;
	s.proc.gid = (__u32)(uid_gid >> 32);
	s.proc._pad = 0;
	bpf_get_current_comm(&s.proc.comm, sizeof(s.proc.comm));

	/* The arguments, as supplied. Narrowed to __u32 because that is what
	 * struct allseer_file_payload declares; openat's flags and mode are an int
	 * and a mode_t, both 32-bit on every target this ABI supports, so the
	 * narrowing from the context's unsigned long discards only sign extension.
	 *
	 * mode is stored whatever the flags say. It is meaningful only when the
	 * flags permit creation, and the record reports what the process passed
	 * rather than substituting a zero it did not pass — the decoder is where
	 * flags decide meaning, and kindForOpenFlags already does exactly that. */
	s.flags = (__u32)ctx->args[2];
	s.mode = (__u32)ctx->args[3];

	/* The pathname, out of user memory, bounded by the destination.
	 *
	 * bpf_probe_read_user_str NUL-terminates within the destination even when
	 * it truncates, so a path longer than ALLSEER_PATH_MAX arrives as a
	 * terminated prefix and abi.CString reports it as whole. That is the same
	 * behaviour proc_exec's filename has and the same gap: the decoder's
	 * ErrTruncatedString detects an array with no NUL in it, which this helper
	 * never produces. Carrying truncation on the wire is the open TODO(event)
	 * in internal/telemetry/decode.go and is a record-layout change, not a
	 * probe change.
	 *
	 * The return is deliberately not checked. On failure — an unmapped or
	 * paged-out user address — the field keeps the zero the memset left, and
	 * the entry is stored regardless: the syscall happened, the process that
	 * made it is known, and refusing to report a real open because one field
	 * could not be read would hide the event entirely. An empty path means the
	 * read failed; it cannot mean a process opened nothing. */
	bpf_probe_read_user_str(&s.path, sizeof(s.path), (const char *)ctx->args[1]);

	/* BPF_ANY, so this thread's previous entry — if it has one, which means an
	 * exit it never reached — is replaced rather than kept. That is what makes
	 * an orphaned entry self-healing for a thread that is still alive.
	 *
	 * The return is not checked because there is nothing to do with it. An LRU
	 * hash does not fail for want of room; a failure here is ENOMEM, and the
	 * consequence is that the exit finds nothing and emits nothing, which is
	 * already the documented behaviour of a missing entry. Nothing is reserved
	 * yet, so no record has been lost and ringbuf_drops must not move: that
	 * counter is defined as counting reservation failures and nothing else. */
	key = pid_tgid;
	bpf_map_update_elem(&openat_scratch, &key, &s, BPF_ANY);
	return 0;
}

/* sys_exit_openat: the open has returned, and the record can be completed.
 *
 * This is the side that emits, and the only thing it contributes to the record
 * is `ret`. Everything else — the timestamp, the identity, the cgroup, the path,
 * the flags, the mode — is copied out of the scratch entry the entry side wrote,
 * unexamined and unrecomputed. That is rule 1 above: one decision, made once,
 * carried forward.
 *
 * It performs no tracked_cgroups lookup. Doing so would be a second, independent
 * governance decision on a task whose cgroup may have changed since the call was
 * made, and the two decisions can disagree — which is how a record ends up
 * carrying a cgroup_id that is not the one that admitted it. The absence of that
 * lookup is not a hole in the filter: an untracked caller's entry side stored
 * nothing, so there is no entry here to find, and the lookup below is what
 * enforces the filter on this side.
 */
SEC("tracepoint/syscalls/sys_exit_openat")
int openat_exit(struct trace_event_raw_sys_exit *ctx)
{
	struct allseer_open_scratch *s;
	struct task_struct *task;
	struct allseer_event *e;
	allseer_syscall_key_t key;

	/* No entry, no event, and no further work. This is where an untracked
	 * cgroup is rejected on this side — not by a filter lookup, but by the
	 * absence of the state a filter lookup on the other side would have
	 * produced. */
	key = bpf_get_current_pid_tgid();
	s = bpf_map_lookup_elem(&openat_scratch, &key);
	if (!s)
		return 0;

	/* The entry is keyed by a thread ID, and thread IDs are reused. This is the
	 * check that keeps a dead thread's entry from being completed by whatever
	 * thread inherits its number — see PID reuse in allseer_maps.h for the
	 * shape of the case, which ends in an untracked process producing a
	 * governed event.
	 *
	 * A mismatch deletes. The entry is provably stale: its thread is gone, and
	 * leaving it would let the next reuse of this TID try the same thing. */
	task = (struct task_struct *)bpf_get_current_task();
	if (BPF_CORE_READ(task, start_boottime) != s->task_start_time) {
		bpf_map_delete_elem(&openat_scratch, &key);
		return 0;
	}

	/* Reserved and filled in place, as everywhere in this object: the record is
	 * 856 bytes and the eBPF stack is 512.
	 *
	 * A failed reservation deletes the entry before returning. The scratch
	 * entry has served its purpose the moment this program has looked at it,
	 * and a path that returned early without deleting would leave an orphan for
	 * every record lost — which is exactly the moment the host is already
	 * struggling. Deleting here is what makes "the exit side owns deletion"
	 * true on every path rather than on the happy one. */
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_ringbuf_drop();
		bpf_map_delete_elem(&openat_scratch, &key);
		return 0;
	}

	e->timestamp = s->timestamp;
	e->type = ALLSEER_EVT_FILE_OPEN;

	/* The one field this side owns. The tracepoint's `ret` is a long because
	 * every syscall's return goes through this context; openat's is an int — a
	 * file descriptor or a negative errno — so narrowing to the __s32 the header
	 * declares is exact for every value openat can produce.
	 *
	 * Written as it is, negative and all. internal/telemetry/decode.go turns
	 * that into event.Result: "ret >= 0" is Succeeded, and a negative value is
	 * rendered as an errno name. A failed open is a governance signal, not an
	 * absence of one. */
	e->ret = (__s32)ctx->ret;
	e->version = ALLSEER_ABI_VERSION;
	e->_pad = 0;

	/* Identity as it was when the call was made, copied rather than re-read.
	 * Re-reading it here would mostly agree — it is the same task — and
	 * "mostly" is the problem: a reparented process's ppid changes underneath a
	 * blocking open, and the record would then describe an ancestry the process
	 * did not have when it acted. */
	e->proc = s->proc;

	/* Reserved space is not zeroed; it is whatever the ring held before. The
	 * union is cleared once rather than field by field, because the file
	 * payload is smaller than the union and an unwritten tail is the previous
	 * record's argv or peer address handed to a decoder. */
	__builtin_memset(&e->payload, 0, sizeof(e->payload));

	/* inode, device and bytes are left at the zero the memset gave them. The
	 * header defines them for the file payload, but openat's tracepoints carry
	 * none of them: the inode is not chosen until the path has been resolved
	 * inside the kernel, and there are no bytes yet on an open. Writing a
	 * plausible zero into a field the record cannot answer for would be a claim
	 * about a file this probe never saw. */
	e->payload.file.flags = s->flags;
	e->payload.file.mode = s->mode;
	bpf_probe_read_kernel(&e->payload.file.path, sizeof(e->payload.file.path), s->path);

	/* Deleted before the submit, and unconditionally. Once the bytes are in the
	 * reserved record the entry has nothing left to contribute, and this
	 * ordering means the only statement to make about the map afterwards is the
	 * simple one: after an exit that found an entry, there is no entry. */
	bpf_map_delete_elem(&openat_scratch, &key);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* --- The connect pair --------------------------------------------------------
 *
 * The second instance of the protocol openat established, and deliberately the
 * same shape: sys_enter_connect captures and stores, sys_exit_connect completes
 * and emits, and the three rules stated above the openat pair hold here
 * unchanged and unrestated —
 *
 *   1. the entry side decides, performing the one tracked_cgroups lookup and
 *      putting the ID it matched into the record;
 *   2. the exit side deletes, on every path that found an entry;
 *   3. no entry, no event.
 *
 * Rule 1 answers the cgroup question for connect exactly as it does for openat,
 * and connect makes the case it protects against far easier to reach: a connect
 * can block for minutes, so the window in which a task might be moved between
 * cgroups mid-syscall is not theoretical. The event belongs to the cgroup the
 * task was in when it made the call. A task moved *into* a tracked cgroup while
 * blocked in connect produces nothing, because its entry was filtered and there
 * is no state to complete; a task moved *out* still produces the event it earned
 * on the way in, carrying the cgroup_id that admitted it. Neither direction can
 * produce a record whose attribution and whose reason for existing disagree,
 * because the exit side never looks at the filter.
 */

/* Address families, in the vocabulary decode.go already uses.
 *
 * Defined here because vmlinux.h does not carry them: AF_* are uapi macros
 * rather than kernel types, so BTF has nothing to say about them. The numbers
 * are Linux's on both targets the ABI supports, and are the same three constants
 * internal/telemetry/decode.go declares for the reading side. AF_UNIX is named
 * even though the probe never compares against it, because the family it does
 * not special-case is the one a reader will ask about. */
#define ALLSEER_AF_UNIX   1
#define ALLSEER_AF_INET   2
#define ALLSEER_AF_INET6  10

/* The smallest sockaddr each family can be described by, which is also what the
 * kernel itself demands before it will look at one.
 *
 * For AF_INET that is the whole of struct sockaddr_in: inet_dgram_connect and
 * __inet_stream_connect both reject an addr_len below sizeof(struct
 * sockaddr_in) with EINVAL. For AF_INET6 it is *not* the whole struct — the
 * trailing sin6_scope_id is optional and the kernel's minimum is
 * SIN6_LEN_RFC2133, the 24 bytes up to and including sin6_addr. Requiring the
 * full 28 here would silently skip the destination of every connect made with
 * the shorter form, which is a legal and used call.
 *
 * Matching the kernel's own minimum buys a property worth having: an address
 * this probe captured is an address the kernel also considered well-formed. */
#define ALLSEER_SOCKADDR_IN_MIN   sizeof(struct sockaddr_in)
#define ALLSEER_SOCKADDR_IN6_MIN  (__builtin_offsetof(struct sockaddr_in6, sin6_addr) + \
				   sizeof(struct in6_addr))

/* capture_peer_address reads connect's destination out of user memory.
 *
 * On entry the scratch value has already been zeroed, and every path that
 * cannot produce an address simply leaves it that way: family AF_UNSPEC, no
 * port, no address. Nothing here reports a failure to its caller, because there
 * is nothing the caller would do with one — allseer_maps.h states the decision,
 * and it is openat's: the record is stored and emitted regardless, since "a
 * connect happened and the process that made it is known; dropping the record
 * because one field could not be read would hide a real connection attempt".
 *
 * bpf_probe_read_user, never the kernel variant. The pointer is a user-space
 * address supplied by the process being watched; reading it as a kernel address
 * either faults and yields nothing or, on an architecture without a split
 * address space, copies whatever kernel memory lives at that number into an
 * audit record. This is the same rule openat's path read follows.
 *
 * Two reads rather than one, and the first is two bytes. The family has to be
 * known before the size of the thing to read is known, and reading the larger
 * structure speculatively would fault on a caller that passed a correctly-sized
 * smaller one — turning a well-formed AF_INET connect into an unreadable
 * sockaddr. Reading the family first costs one extra helper call on a syscall
 * that is about to do far more work than that.
 *
 * addrlen is signed here, and every comparison against it casts the size it is
 * compared with. connect's third argument is an int and a process may pass a
 * negative one; left unsigned, -1 becomes 4294967295, clears every minimum, and
 * the probe reads a sockaddr the kernel is about to reject with EINVAL. The
 * property this function is written to keep — an address it captured is one the
 * kernel also considered well-formed — would be false for exactly that call.
 */
static __always_inline void capture_peer_address(struct allseer_connect_scratch *s,
						 const void *uaddr, __s32 addrlen)
{
	struct sockaddr_in6 v6;
	struct sockaddr_in v4;
	__u16 family;

	/* A null pointer or a length that cannot even hold a family. connect
	 * itself will fail with EFAULT or EINVAL, and the record will carry that
	 * return alongside a destination it does not claim to know. */
	if (!uaddr || addrlen < (__s32)sizeof(family))
		return;
	if (bpf_probe_read_user(&family, sizeof(family), uaddr))
		return;

	switch (family) {
	case ALLSEER_AF_INET:
		if (addrlen < (__s32)ALLSEER_SOCKADDR_IN_MIN)
			return;
		if (bpf_probe_read_user(&v4, sizeof(v4), uaddr))
			return;
		/* Set together, and only together. allseer_maps.h calls this the
		 * family rule: AF_INET is a promise that daddr holds the address
		 * the process passed, so it is made only where that is true. */
		s->family = ALLSEER_AF_INET;
		s->dport = bpf_ntohs(v4.sin_port);
		/* Four bytes, into the front of a sixteen-byte field, because the
		 * record header says so: "v4 addresses occupy the first 4 bytes".
		 * Copied in wire order rather than byte-swapped — that order is
		 * what netip.AddrFrom4 reads, and reversing it here would turn
		 * 10.0.0.1 into 1.0.0.10 on the way out. */
		__builtin_memcpy(s->daddr, &v4.sin_addr, sizeof(v4.sin_addr));
		return;

	case ALLSEER_AF_INET6:
		if (addrlen < (__s32)ALLSEER_SOCKADDR_IN6_MIN)
			return;
		/* Exactly the kernel's minimum, not sizeof(v6). A caller that
		 * passed 24 bytes has no sin6_scope_id to read, and asking for it
		 * would fault on a sockaddr the kernel accepts. The bytes beyond
		 * what is read keep the zero the memset left; nothing reads them,
		 * because the record has no field for a scope ID. */
		if (bpf_probe_read_user(&v6, ALLSEER_SOCKADDR_IN6_MIN, uaddr))
			return;
		s->family = ALLSEER_AF_INET6;
		s->dport = bpf_ntohs(v6.sin6_port);
		__builtin_memcpy(s->daddr, &v6.sin6_addr, sizeof(v6.sin6_addr));
		return;

	default:
		/* A family that carries no address of this shape — AF_UNIX above
		 * all, but also netlink, packet, bluetooth and the rest. The
		 * family is reported and the address is not, which is not an
		 * exception to the family rule but an application of it: these
		 * families promise nothing about daddr and decode.go renders them
		 * without one. AF_UNSPEC arrives here too and is written back as
		 * itself, which is the zero the field already held.
		 *
		 * The socket path an AF_UNIX connect names is deliberately not
		 * captured. struct allseer_net_payload has no field for it, the
		 * 108-byte sun_path does not fit in a 16-byte address, and
		 * decode.go states the reading side of the same fact: "a socket
		 * path is not an address and does not fit in the field". */
		s->family = family;
		return;
	}
}

/* sys_enter_connect: a thread is asking to connect a socket to an address.
 *
 * Emits nothing, for the reason openat_enter does not: `ret` has no value yet,
 * and connect's is worth more than most. A connect that fails with
 * ECONNREFUSED, EHOSTUNREACH or EPERM is a different governance fact from one
 * that succeeded — the difference between an agent that reached an endpoint and
 * one that tried to.
 *
 * The tracepoint's arguments, from its format file:
 *
 *   args[0]  fd        the socket descriptor
 *   args[1]  uservaddr a pointer into *user* memory
 *   args[2]  addrlen   how much of it the caller says is valid
 *
 * args[0] is captured nowhere, and the consequence is the largest limitation of
 * this probe: the descriptor is the only route to the socket, and the socket is
 * the only route to the protocol, the socket type and the local address. Three
 * of struct allseer_net_payload's nine fields are therefore left zero, and
 * allseer_maps.h names each one and why. Reaching them means walking
 * task->files->fdt to a struct file, which is a kernel-internal structure and
 * the same trade proc_exec already refused for argv.
 */
SEC("tracepoint/syscalls/sys_enter_connect")
int connect_enter(struct trace_event_raw_sys_enter *ctx)
{
	struct task_struct *task;
	struct allseer_connect_scratch s;
	allseer_cgroup_id_t cgroup_id;
	allseer_syscall_key_t key;
	__u64 pid_tgid, uid_gid;

	/* The filter, first, and before a byte of user memory is read. The
	 * standing per-probe obligation internal/telemetry states, and the
	 * governance decision this event will carry: the ID matched here is the
	 * one that ends up in the record. */
	cgroup_id = bpf_get_current_cgroup_id();
	if (!bpf_map_lookup_elem(&tracked_cgroups, &cgroup_id))
		return 0;

	/* Zeroed in full: the verifier requires every byte of stack copied into a
	 * map to have been written, and capture_peer_address relies on the zero
	 * as its "nothing to report" state. */
	__builtin_memset(&s, 0, sizeof(s));

	s.timestamp = bpf_ktime_get_ns();

	pid_tgid = bpf_get_current_pid_tgid();
	uid_gid = bpf_get_current_uid_gid();
	task = (struct task_struct *)bpf_get_current_task();

	/* The identity stamp, checked at exit against the thread running there.
	 * The calling thread's own start time, not the group leader's — see the
	 * PID reuse section of allseer_maps.h. */
	s.task_start_time = BPF_CORE_READ(task, start_boottime);

	/* struct allseer_proc, read exactly as openat_enter reads it, including
	 * start_time coming from the group leader so that (PID, StartTime) is the
	 * pair proc_exec and proc_exit report for the same process. A connect made
	 * by a worker thread must be attributable to the process that owns it. */
	s.proc.cgroup_id = cgroup_id;
	s.proc.start_time = BPF_CORE_READ(task, group_leader, start_boottime);
	s.proc.pid = (__u32)(pid_tgid >> 32);
	s.proc.tid = (__u32)pid_tgid;
	s.proc.ppid = BPF_CORE_READ(task, real_parent, tgid);
	s.proc.uid = (__u32)uid_gid;
	s.proc.gid = (__u32)(uid_gid >> 32);
	s.proc._pad = 0;
	bpf_get_current_comm(&s.proc.comm, sizeof(s.proc.comm));

	capture_peer_address(&s, (const void *)ctx->args[1], (__s32)ctx->args[2]);

	/* BPF_ANY, and the return unchecked, for the reasons openat_enter gives:
	 * a thread's previous entry is replaced rather than kept, an LRU insert
	 * does not fail for want of room, and a failure here means the exit finds
	 * nothing and emits nothing — which is already the documented behaviour of
	 * a missing entry. Nothing has been reserved, so ringbuf_drops must not
	 * move. */
	key = pid_tgid;
	bpf_map_update_elem(&connect_scratch, &key, &s, BPF_ANY);
	return 0;
}

/* sys_exit_connect: the connect has returned, and the record can be completed.
 *
 * Contributes `ret` and nothing else, exactly as openat_exit does. It performs
 * no tracked_cgroups lookup: the presence of a scratch entry is the entry side's
 * decision carried forward, and a second lookup on a task whose cgroup may have
 * changed during a call that can block for minutes is precisely how a record
 * ends up carrying a cgroup_id that is not the one that admitted it.
 *
 * # What `ret` means here, and one case it cannot express
 *
 * connect returns 0 on success and a negative errno on failure, which is the
 * convention struct allseer_event.ret already declares and the one
 * internal/telemetry/decode.go already reads: resultOf treats ret >= 0 as
 * Succeeded and renders a negative value as an errno name. Nothing new is
 * invented for connect.
 *
 * The case worth naming is EINPROGRESS. A connect on a non-blocking socket
 * returns -EINPROGRESS immediately and the connection is completed later, out of
 * sight of this tracepoint; the record says Succeeded false with errno
 * EINPROGRESS, which is a true statement about the syscall and a misleading one
 * about the connection if read as "no connection was made". The record cannot
 * say more, because the fact that would resolve it — whether the handshake later
 * completed — happens in the network stack rather than in any syscall this
 * object hooks. A downstream reader must treat EINPROGRESS as "attempted, and
 * this stream does not know the outcome" rather than as a failure.
 */
SEC("tracepoint/syscalls/sys_exit_connect")
int connect_exit(struct trace_event_raw_sys_exit *ctx)
{
	struct allseer_connect_scratch *s;
	struct task_struct *task;
	struct allseer_event *e;
	allseer_syscall_key_t key;

	/* No entry, no event, and no fabrication. This is where an untracked
	 * cgroup is rejected on this side: not by a filter lookup, but by the
	 * absence of the state a filter lookup on the other side would have
	 * produced. */
	key = bpf_get_current_pid_tgid();
	s = bpf_map_lookup_elem(&connect_scratch, &key);
	if (!s)
		return 0;

	/* The PID-reuse guard. A mismatch means the entry belongs to a thread
	 * that is gone and whose TID this one inherited; it is deleted rather
	 * than completed. */
	task = (struct task_struct *)bpf_get_current_task();
	if (BPF_CORE_READ(task, start_boottime) != s->task_start_time) {
		bpf_map_delete_elem(&connect_scratch, &key);
		return 0;
	}

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_ringbuf_drop();
		bpf_map_delete_elem(&connect_scratch, &key);
		return 0;
	}

	e->timestamp = s->timestamp;
	e->type = ALLSEER_EVT_NET_CONNECT;
	e->ret = (__s32)ctx->ret;
	e->version = ALLSEER_ABI_VERSION;
	e->_pad = 0;
	e->proc = s->proc;

	__builtin_memset(&e->payload, 0, sizeof(e->payload));

	/* Three fields written and six left at the zero the memset gave them.
	 * allseer_maps.h lists the six and why each is unreachable from these two
	 * tracepoints; the short form is that saddr, sport, protocol and sock_type
	 * are properties of the socket rather than of the call, and `bytes` is
	 * read by decode.go for ALLSEER_EVT_NET_SEND alone.
	 *
	 * The address is copied whole. For AF_INET only the first four bytes carry
	 * anything and the rest were never written, which is what the record
	 * header means by "v4 addresses occupy the first 4 bytes"; copying sixteen
	 * either way keeps this side free of a second place that knows how wide a
	 * family is. */
	e->payload.net.family = s->family;
	e->payload.net.dport = s->dport;
	__builtin_memcpy(e->payload.net.daddr, s->daddr, sizeof(e->payload.net.daddr));

	bpf_map_delete_elem(&connect_scratch, &key);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* --- BTF anchor -------------------------------------------------------------
 *
 * Not read by anything in the kernel. It exists so that `struct allseer_event`
 * reaches the object's BTF, where the loader reads its size before it attaches
 * a probe.
 *
 * The file preamble above already explains why BTF alone would not carry it:
 * "BTF carries only types something references", and a local variable in one
 * program is not a reference BTF records. So without this declaration the
 * record type is absent from the compiled object, and telemetry's startup check
 * — the one internal/telemetry/abi describes as reading the object "through BTF
 * before it attaches anything", because that is "the only point at which a
 * mismatch costs nothing" — has nothing to compare against and must refuse to
 * start.
 *
 * A pointer rather than an instance: it costs 8 bytes of .bss instead of 856,
 * and BTF describes the pointee either way. libbpf turns that .bss into a small
 * internal map alongside the two declared here, which is expected rather than a
 * third map of ALLSEER's own.
 *
 * This is half of the TODO in allseer_event.h, which asks for the ABI version
 * to be exposed the same way. The size is the half a struct declaration can
 * give for free; the version needed a read-only global carrying a value, and
 * `allseer_abi_version` above is now that global. The two are complementary and
 * neither subsumes the other: this anchor catches a layout that changed size,
 * and the version catches one that kept its size and changed meaning. */
struct allseer_event *_allseer_record_btf_anchor;

/* --- Open items -------------------------------------------------------------
 *
 * TODO(bpf): carry a task's exit status. proc_exit writes ret = 0 because the
 * header defines `ret` as "syscall return; negative is -errno" and a process
 * exit is not a syscall return: task->exit_code is an encoded wait status, and
 * writing it into that field would make exit(1) decode as ReturnCode 256 with
 * Succeeded true. Whether a governed agent's build failed is a governance fact
 * worth having, so this wants a field of its own — a __s32 exit_status, or an
 * exit payload member — which is a record-layout change and so belongs with the
 * other open ABI edits rather than inside a probe issue.
 *
 * TODO(bpf): use `group_dead` to decide when a process has exited. proc_exit
 * emits on the thread group leader, which is one record per process and the
 * right identity, but fires early in the one case where the leader exits and
 * its siblings keep running. The tracepoint context carries `group_dead`, true
 * only on the last thread of the group, which answers the question exactly.
 * Reading it needs a bpf_core_field_exists guard and a fallback for kernels
 * whose context predates the field — and the fallback is the comparison already
 * written — so it is a portability decision with a measurable cost, not a
 * one-line fix.
 */
