/* ALLSEER BPF map contracts.
 *
 * Deliberately a separate header from allseer_event.h. That file is the record
 * ABI and is parsed by internal/telemetry/abigen, which resolves the ring
 * buffer record by finding the one struct nothing else embeds; a map key or
 * value declared there would become a second root and the generator would
 * refuse the file outright. Keeping map types here means the record header
 * stays exactly what the generator expects it to be.
 *
 * What lives here is still an ABI, for the same reason that one is. Maps are
 * addressed by name and written as raw bytes: telemetry.Loader names them
 * ("RingBuffer returns the raw record stream for a named map", "UpdateMap
 * writes a key/value into a BPF map"), and UpdateMap's key and value are
 * []byte. Neither the name nor the byte layout is checked by a compiler that
 * sees both sides, so both are written down here once and referred to rather
 * than restated.
 *
 * Map names, which user space passes as strings:
 *
 *   events           the record stream            telemetry.Loader.RingBuffer
 *   tracked_cgroups  the kernel-side filter set   telemetry.Loader.UpdateMap
 *   ringbuf_drops    records lost to a full ring  telemetry.Loader.ReadCounter
 *   openat_scratch   openat enter->exit state     kernel-internal; see below
 *
 * Names are capped at 15 characters plus a NUL by BPF_OBJ_NAME_LEN. Anything
 * longer is silently truncated by libbpf and then fails to be found by the name
 * user space asked for, so "tracked_cgroups", at exactly 15, is at the limit.
 */

#ifndef __ALLSEER_MAPS_H
#define __ALLSEER_MAPS_H

/* struct allseer_proc, which the scratch value below embeds verbatim.
 *
 * The dependency is one-way and stays that way: allseer_event.h includes
 * nothing from here, so internal/telemetry/abigen still parses that file alone
 * and still finds exactly one struct nothing else embeds. Embedding the
 * identity struct rather than restating its fields is the point — the scratch
 * entry holds the *record's* identity, captured once, and a second declaration
 * of the same fields would be a second thing to keep in step. */
#include "allseer_event.h"

/* Capacity of the `events` ring buffer, in bytes. Must be a power of two and a
 * multiple of the page size; the kernel rejects the map at creation otherwise.
 *
 * 4 MiB holds roughly 4,900 records at the current 856-byte size. That is a
 * burst tolerance, not a queue depth: the reader is expected to keep up, and
 * the buffer only has to cover the moments it does not. It is the compiled-in
 * default and the loader is expected to override it from
 * telemetry.Config.RingBufferSize before load, which is the only point at which
 * a ring buffer can be resized.
 *
 * Sizing this is a real tradeoff and not a free one — the memory is locked, and
 * a larger buffer converts dropped records into latency rather than removing
 * the loss. Records lost here are the hole pkg/event.Event.Dropped reports, and
 * telemetry.Config.FailClosedOnDrop is what an operator does about it. */
#define ALLSEER_RINGBUF_BYTES  (1 << 22)

/* Capacity of `tracked_cgroups`. One entry per governed cgroup, and sessions
 * are counted in the low tens, so this is deliberately generous: the failure
 * mode of running out is a governed process that no probe reports on, which is
 * a blind spot rather than a slowdown. */
#define ALLSEER_MAX_TRACKED_CGROUPS  1024

/* Key of `tracked_cgroups`: a cgroup ID, the same 64-bit value every record
 * carries in struct allseer_proc.cgroup_id, where the record header calls it
 * the "primary attribution key; survives PID reuse".
 *
 * Cgroup rather than PID because the two answer different questions. A PID
 * identifies a process until it exits and something else is given the number;
 * a cgroup ID identifies the tree an agent was placed in, for as long as that
 * tree exists. A filter keyed by PID would have to be updated on every fork the
 * agent performs, from user space, racing the child's first syscall. */
typedef __u64 allseer_cgroup_id_t;

/* Value of `tracked_cgroups`. Presence in the map is the entire signal: a
 * lookup that returns non-NULL means this cgroup is governed.
 *
 * There is nothing useful to carry alongside it. The session a cgroup belongs
 * to is a Go string, resolved in user space from the cgroup_id the record
 * already carries, so putting an identifier here would duplicate a mapping that
 * only user space can complete. It is one byte rather than a struct so that
 * adding a field is a visible ABI change on both sides instead of a silent
 * reinterpretation of padding. */
typedef __u8 allseer_tracked_t;

/* Capacity of `ringbuf_drops`. One slot, because there is one thing to count.
 *
 * The map exists because a lost record is invisible by construction: the loss
 * *is* the absence of a record, so no amount of reading `events` can reveal it.
 * bpf_ringbuf_reserve returns NULL when the ring is full, the probe has nowhere
 * to put what it saw and no way to wait, and it returns. Until this map, that
 * was the end of the story on both sides of the boundary.
 *
 * Two things in user space were already written against a signal that did not
 * exist. pkg/event.Event.Dropped is "ring buffer records lost before this one.
 * Non-zero means the stream has a hole, and any 'the agent never did X'
 * conclusion drawn across that hole is unsound", and
 * telemetry.Config.FailClosedOnDrop "halts the session when ring buffer records
 * are lost". A fail-closed switch with nothing wired to it is worse than no
 * switch at all: it reads as a control, and the condition it claims to catch is
 * exactly the one that makes a silent host indistinguishable from a clean one.
 */
#define ALLSEER_DROP_SLOTS  1

/* The only index `ringbuf_drops` has. Named rather than written as 0 at each
 * end, because a key that means "the ring buffer" is a fact about the map and
 * the two sides have to agree on it the same way they agree on the map's name.
 */
#define ALLSEER_DROP_KEY_RINGBUF  0

/* Key of `ringbuf_drops`: an array index, and not a fact about anything. */
typedef __u32 allseer_drop_key_t;

/* Value of `ringbuf_drops`: how many records this CPU could not reserve space
 * for, since the object was loaded.
 *
 * BPF_MAP_TYPE_PERCPU_ARRAY rather than a single shared cell. Drops do not
 * arrive one at a time — the ring fills once and then every CPU that reaches a
 * reservation fails at the same moment — so a shared counter would put every
 * CPU on the system onto one cache line precisely when the machine is already
 * behind. Per-CPU slots have no such moment, and summing them in user space is
 * a loop over a handful of words.
 *
 * What it counts, exactly, and what it does not:
 *
 *   counted      a probe wanted to emit a record and bpf_ringbuf_reserve
 *                returned NULL. One increment per lost record.
 *   not counted  an event `tracked_cgroups` rejected. That event was never
 *                going to be reported, and its absence is the filter working
 *                rather than telemetry failing.
 *   not counted  a record that reached user space and would not decode. That
 *                is a disagreement about bytes, not a loss of them, and
 *                telemetry.SourceStats keeps it apart as DecodeErrors.
 *
 * Monotonic for the lifetime of the loaded object, and never reset from user
 * space. The cumulative form is what SourceStats.DroppedEvents is defined as —
 * "Rising DroppedEvents is a correctness problem, not a performance one" — and
 * the per-record delta Event.Dropped wants is current minus last-observed,
 * which any reader can compute and which a reader that reset the counter would
 * destroy for every other reader. */
typedef __u64 allseer_drop_count_t;

/* --- Syscall enter/exit correlation ------------------------------------------
 *
 * The two probes written before this one hook the scheduler, where one
 * tracepoint carries everything a record needs. A syscall does not work that
 * way: sys_enter_openat carries the arguments and no return, sys_exit_openat
 * carries the return and no arguments, and struct allseer_event demands both —
 * the header defines `ret` as "syscall return; negative is -errno", and
 * internal/telemetry/decode.go reads `ret >= 0` as Succeeded. A record emitted
 * at entry would have to write *something* into that field, and every available
 * something is a claim about an outcome that has not happened yet. So the two
 * halves are paired through a scratch map, which internal/telemetry already
 * anticipated: "each needs the two paired through a per-task scratch map before
 * it can fill the `ret` field the header defines. That pairing is one design and
 * both probes use it, so it should be settled once."
 *
 * This block settles it. What is written here is the protocol; `openat_scratch`
 * below is its first instance, and sys_enter_connect is expected to declare a
 * second map of its own shape under the same rules.
 *
 * # The key: the thread, not the process
 *
 * allseer_syscall_key_t is bpf_get_current_pid_tgid() unmodified — the thread
 * group ID in the high 32 bits and the thread ID in the low 32 — because that
 * is the identity of the thing that makes a syscall. A process does not enter a
 * syscall; a thread does, and every thread of a process can be inside openat at
 * the same moment. A key of just the tgid would make those calls collide, and
 * the last one to enter would decide what all of their exits reported.
 *
 * The key is exact rather than approximate, and the reason is a property of the
 * kernel rather than an assumption about workloads: **a thread is inside at most
 * one syscall at a time**. There is no interleaving to represent. A signal that
 * arrives during openat is delivered after the syscall returns, so its handler
 * cannot nest another openat inside this one; a syscall restarted after a signal
 * (ERESTARTSYS) re-enters, which fires sys_enter again and overwrites the entry
 * with identical arguments. So the question "what happens if two openat calls
 * from the same thread overlap" has no case behind it: they cannot.
 *
 * # PID reuse, and why the key alone is not enough
 *
 * A thread ID is reused after the thread dies, and a scratch entry can outlive
 * the thread that wrote it — a task killed inside openat never reaches
 * sys_exit_openat. So the key can be matched by a thread that never wrote it.
 *
 * That is not hypothetical and it is not harmless. The dangerous shape is: a
 * tracked thread enters openat and is killed; its TID is later reused by a
 * thread in an *untracked* cgroup; that thread's openat entry is filtered and
 * writes nothing, and its exit finds the dead thread's entry. Without a guard
 * that would emit an event that never happened, carrying a path from one process
 * and a return from another, attributed to a cgroup the second process was never
 * in — an untracked cgroup producing a governed event, which is the one thing
 * the filter exists to make impossible.
 *
 * So every scratch value carries `task_start_time`, the calling thread's
 * start_boottime, and the exit side compares it against the thread it is running
 * on. A reused TID belongs to a task created later and so carries a different
 * start time; a mismatch means the entry is not this thread's, and the exit side
 * deletes it and emits nothing. This is the same disambiguator event.Process
 * .StartTime is documented for — "the pair (PID, StartTime) is unique for a
 * boot; PID alone is not" — applied one level down, to the thread.
 *
 * # Bounding, and what happens when the exit never comes
 *
 * BPF_MAP_TYPE_LRU_HASH, and the choice is the opposite of the one made for
 * tracked_cgroups directly above — deliberately, because the two maps fail in
 * opposite directions.
 *
 * tracked_cgroups holds policy that user space owns: an evicted entry there
 * silently stops a governed session from being observed, so it must be a plain
 * hash whose insert fails loudly rather than quietly making room. This map holds
 * kernel-owned ephemeral state whose entries are supposed to be short-lived, and
 * its bad state is the reverse. A plain hash that filled with orphans — entries
 * from threads killed mid-syscall, which no cleanup path can reach because there
 * is no tracepoint for "a syscall that never returned" — would reject every
 * subsequent insert forever. Every openat on the host would then go unreported,
 * permanently, from a condition nothing observes. An LRU cannot reach that
 * state: the least recently used entry gives way, insertion always succeeds, and
 * the orphans are precisely the entries least recently used.
 *
 * The cost of eviction is one lost open event, and it is stated rather than
 * hidden: an evicted entry means the exit finds nothing and emits nothing, which
 * is indistinguishable downstream from an openat that never happened. That is a
 * real gap, and it is bounded by capacity rather than by luck — see the TODO at
 * the foot of this file for what would make it visible.
 *
 * # One map per syscall, not one shared map
 *
 * connect will want the same mechanism and will not share this map. Two reasons,
 * and the second is the load-bearing one:
 *
 *   - the value differs. openat needs a path; connect needs a sockaddr. A shared
 *     value would be a union plus a discriminator the exit side has to check,
 *     and the second member cannot be designed honestly before the probe that
 *     fills it exists.
 *   - eviction would cross syscalls. One LRU shared by both means a burst of
 *     opens evicts pending connects, so the noisiest syscall on the host decides
 *     which of the quieter one's events survive. Separate maps make each
 *     syscall's pressure its own.
 *
 * What is shared is this protocol and allseer_syscall_key_t, which is the part
 * that has to be identical for the two probes to be reasoned about together.
 */
typedef __u64 allseer_syscall_key_t;

/* Capacity of `openat_scratch`, in entries.
 *
 * An entry exists only between one thread's sys_enter_openat and its
 * sys_exit_openat, so the live population is the number of tracked threads
 * blocked in openat at one instant — normally a handful, since openat on a warm
 * page cache returns in microseconds. The number is not sized for that. It is
 * sized for the orphans: entries from threads killed inside the syscall, which
 * accumulate at a rate nothing bounds and are only ever reclaimed by eviction.
 *
 * 4096 entries at 336 bytes is about 1.3 MiB, preallocated and locked, next to
 * the 4 MiB the ring buffer already holds. Generous enough that eviction under
 * ordinary load is not a thing that happens, small enough to be a rounding error
 * against the ring.
 *
 * Running out is not a failure mode here, which is the whole reason for the LRU:
 * it converts "no further opens can be correlated, forever" into "the oldest
 * pending open loses its correlation". */
#define ALLSEER_MAX_OPEN_SCRATCH  4096

/* Value of `openat_scratch`: everything the final record needs except `ret`.
 *
 * The split is the design, not an implementation detail. The entry side captures
 * the whole event — time, identity, cgroup, arguments — and the exit side
 * contributes exactly one field, the syscall return, and emits. Nothing about
 * the event is decided twice.
 *
 * That is what keeps attribution coherent. Every field below is read at the same
 * instant, the instant the process asked for the file, and `cgroup_id` inside
 * `proc` is the same value the entry side looked up in tracked_cgroups. The
 * governance decision and the attribution in the record it produced are then the
 * same fact rather than two lookups that could disagree — which they can, since
 * a task may be moved between cgroups while it is inside the syscall. Deciding
 * again at exit would produce a record whose cgroup_id and whose reason for
 * existing came from different cgroups.
 *
 * Field by field:
 *
 *   timestamp        bpf_ktime_get_ns() at sys_enter, copied into the record.
 *                    The instant the call was made, not the instant it finished:
 *                    it is the same instant every other field here was read, and
 *                    it is the one a "read the key, then connect out" sequence
 *                    should be ordered by. The cost is that records can reach the
 *                    ring in an order their timestamps do not agree with, by at
 *                    most the duration of one syscall.
 *   task_start_time  the calling thread's start_boottime. The identity stamp,
 *                    checked at exit against the thread running there. Not the
 *                    same value as proc.start_time and not interchangeable with
 *                    it; see below.
 *   proc             struct allseer_proc exactly as the record carries it.
 *                    proc.start_time is the thread *group leader's*
 *                    start_boottime, because proc.pid is the thread group ID and
 *                    the pair has to be the one proc_exec and proc_exit report
 *                    for the same process. A worker thread's own start time
 *                    paired with its process's PID would name nothing a
 *                    ProcessTracker keyed on that pair could find.
 *   flags            openat's third argument, as supplied.
 *   mode             openat's fourth argument, as supplied. Meaningful only when
 *                    flags permit creation; otherwise it is whatever the caller
 *                    happened to pass, and the record reports that rather than
 *                    inventing a zero.
 *   path             openat's second argument, read out of user memory with
 *                    bpf_probe_read_user_str and NUL-padded to the full array.
 *                    Not resolved, not made absolute, not joined to dirfd: the
 *                    pathname as the process wrote it. Resolution is M6's and
 *                    internal/telemetry/resolve already refuses to fall back to
 *                    an unresolved path, so an open of a relative name is
 *                    unevaluable rather than wrongly evaluated.
 */
struct allseer_open_scratch {
    __u64 timestamp;
    __u64 task_start_time;
    struct allseer_proc proc;
    __u32 flags;
    __u32 mode;
    char  path[ALLSEER_PATH_MAX];
};

/* The lifecycle of an entry, stated in one place because it is spread across two
 * programs that cannot see each other:
 *
 *   created   sys_enter_openat, after tracked_cgroups admits the caller and
 *             never before it. An untracked caller writes nothing at all, so an
 *             untracked cgroup cannot leave state for an exit to find.
 *   updated   BPF_ANY, so a thread's next openat replaces its own previous
 *             entry. That is what makes an orphan self-healing for any thread
 *             that is still alive: the stale entry is gone the next time that
 *             thread opens anything.
 *   deleted   sys_exit_openat, on every path that found an entry — the identity
 *             check failing, the ring buffer reservation failing, and the record
 *             being submitted alike. The exit side owns deletion and is the only
 *             side that deletes.
 *   evicted   by the LRU, when the map is at capacity and something has to give.
 *
 * And the failure paths, each with one answer:
 *
 *   the update fails            no entry exists, so the exit emits nothing and
 *                               the open goes unreported. An LRU insert does not
 *                               fail for want of room, so this means ENOMEM.
 *   the path read fails         the entry is stored anyway with an empty path.
 *                               The syscall happened and the process that made
 *                               it is known; dropping the record because one
 *                               field could not be read would hide a real open.
 *                               An empty path is a read that failed, not a
 *                               process that opened nothing.
 *   the path is longer than
 *   ALLSEER_PATH_MAX            it arrives truncated and NUL-terminated, which
 *                               is what bpf_probe_read_user_str does, and is the
 *                               same behaviour proc_exec's filename already has.
 *                               abi.CString sees a terminated array and reports
 *                               no truncation, so the decoder's
 *                               ErrTruncatedString does not fire and cannot:
 *                               carrying truncation on the wire is the open
 *                               TODO(event) in internal/telemetry/decode.go and
 *                               is a record-layout change.
 *   the exit lookup misses      no event. Not a synthesised one with a zero
 *                               path, not one with a guessed return: the record
 *                               would be a claim about a syscall this object
 *                               did not observe the start of.
 *   the identity check fails    no event, and the entry is deleted. See PID
 *                               reuse above.
 *   the reservation fails       no event, the entry is deleted, and
 *                               ringbuf_drops is incremented — the record was
 *                               fully formed and lost, which is exactly what
 *                               that counter is for.
 */

#endif /* __ALLSEER_MAPS_H */

/* TODO(bpf): count correlations lost to eviction and to a failed scratch update.
 * An open that was governed and produced no event is invisible from user space
 * in exactly the way a dropped record used to be, and the argument for
 * ringbuf_drops applies unchanged: the loss is the absence of a record, so no
 * amount of reading `events` reveals it. It must not be folded into
 * ringbuf_drops, which is defined as counting reservation failures and nothing
 * else — a second per-CPU counter map of the same shape, with its own key
 * constants, is the shape of the fix. It is left out of the openat issue because
 * the counter needs a consumer to be worth anything, and the consumer is
 * Collector. */
