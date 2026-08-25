// SPDX-License-Identifier: GPL-2.0
/* ALLSEER eBPF object.
 *
 * One object, not one per probe. telemetry.Config carries a single ObjectPath,
 * and maps are per-object: two objects loaded separately get two ring buffers
 * and two filter sets, and sharing one between them means pinning it and
 * agreeing on a bpffs path. Probes are added to this file as they are written.
 *
 * At this point the file declares the maps and one probe: sched_process_exec.
 * The maps are what the probes emit into and are filtered by; the loader that
 * populates and drains them is a separate issue again, so nothing in user space
 * reads what this probe writes yet. That is deliberate ordering rather than an
 * oversight — a probe whose record shape is wrong is cheapest to find before
 * there is a consumer to blame it on, and the object, its programs and its maps
 * are all inspectable with bpftool without a line of Go.
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

/* The set of cgroups worth reporting on, written from user space through
 * telemetry.Loader.UpdateMap.
 *
 * The map exists here and no probe consults it. That stays true with the exec
 * probe below written: consulting it is the filtering issue, and the map is
 * empty until the loader exists to populate it, so a lookup added now would
 * reject every event on a machine where nothing has been declared governed —
 * which is a probe that reports nothing, tested against a filter that has never
 * had a member. What the map is for is stated in the Loader contract: filtering
 * happens in the kernel "rather than costing a userspace round trip per event".
 * An untracked process should cost a lookup and a return, not a ring buffer
 * reservation, a wakeup, a decode and a discard. Until that lands, this object
 * reports every exec on the host, which is the reason the filtering issue is
 * the next one and not a later one.
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

/* Required before any program in this object can load. Declared with the maps
 * because it belongs to the object rather than to any one probe, and because
 * the helpers the probes will need — bpf_probe_read_kernel and the task
 * accessors among them — are GPL-only and refuse to verify without it. */
char LICENSE[] SEC("license") = "GPL";

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
 * One probe so far. Tracepoints before kprobes, as internal/telemetry states:
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
 * give for free; the version needs a read-only global carrying a value, and
 * that remains open. */
struct allseer_event *_allseer_record_btf_anchor;
