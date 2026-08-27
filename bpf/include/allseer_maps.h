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
 *   connect_scratch  connect enter->exit state    kernel-internal; see below
 *
 * Names are capped at 15 characters plus a NUL by BPF_OBJ_NAME_LEN. Anything
 * longer is silently truncated by libbpf and then fails to be found by the name
 * user space asked for, so "tracked_cgroups" and "connect_scratch", both at
 * exactly 15, are at the limit.
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

/* Capacity of `connect_scratch`, in entries.
 *
 * The same number as openat's, and for the same reason rather than for
 * symmetry's sake: it is sized for orphans, not for the live population.
 *
 * The live population differs between the two syscalls in a way worth stating.
 * openat on a warm page cache returns in microseconds, so entries barely exist;
 * connect to an unreachable host blocks until the SYN retries give up, which is
 * on the order of two minutes. A tracked process that opens many connections to
 * something that is not answering therefore holds far more entries at once than
 * any openat workload does. 4096 still covers that by a wide margin — it is
 * 4096 threads simultaneously blocked in connect — and at 96 bytes the whole map
 * is about 384 KiB, a quarter of what openat's costs.
 *
 * Running out is not a failure mode, for the reason the protocol above gives:
 * the LRU converts "no further connects can be correlated, forever" into "the
 * oldest pending connect loses its correlation". */
#define ALLSEER_MAX_CONNECT_SCRATCH  4096

/* Value of `connect_scratch`: everything the final record needs except `ret`.
 *
 * The same split as openat's, the same prologue, and the same rule — the entry
 * side captures the whole event and the exit side contributes the syscall
 * return and emits. The first three fields are byte-for-byte the ones
 * struct allseer_open_scratch begins with, and the static assertion below is
 * what keeps that true rather than merely intended.
 *
 * # What connect can be asked for, and what it can answer
 *
 * connect(2) takes a socket descriptor, a user-space sockaddr and its length.
 * Of the nine fields struct allseer_net_payload declares, exactly three are
 * derivable from those arguments:
 *
 *   family     the sockaddr's sa_family
 *   daddr      the address inside the sockaddr, for the families that have one
 *   dport      the port inside the sockaddr, converted to host byte order
 *
 * The other six are not, and are left at the zero the exit side's memset gives
 * them. This is a limitation of the hook, not an omission, and each one is
 * worth naming because a reader of a record must not mistake a zero for an
 * observation:
 *
 *   saddr, sport   the local address is not an argument to connect, and for a
 *                  TCP socket that has not been bound it does not exist yet at
 *                  sys_enter — the kernel chooses it while the syscall runs.
 *                  Recovering it would mean walking the descriptor to its
 *                  struct socket through task->files, which is a kernel-internal
 *                  structure and exactly the trade proc_exec already refused for
 *                  argv: "both a decision about what evidence is worth an
 *                  unbounded read on the exec path; neither belongs inside the
 *                  issue that writes the first probe".
 *   protocol       likewise. IPPROTO_TCP versus IPPROTO_UDP is a property of
 *                  the socket, not of the call, and reaching it needs the same
 *                  walk. internal/telemetry/decode.go renders protocol 0 as the
 *                  empty string and says why that is survivable: "the matcher
 *                  already treats an empty protocol as unevaluable against a
 *                  grant that constrains protocols". Unevaluable is the
 *                  fail-closed direction; a guessed "tcp" would not be.
 *   sock_type      the same walk again, and the decoder already renders 0 as
 *                  empty. Nothing in the validator reads it.
 *   bytes          connect transfers nothing. decode.go reads the field for
 *                  ALLSEER_EVT_NET_SEND alone.
 *
 * The one that has no honest representation is saddr. A zeroed 16-byte address
 * under AF_INET decodes to "0.0.0.0" and under AF_INET6 to "::" — the wildcard,
 * not an absence — because struct allseer_net_payload has no way to say "this
 * field was never filled" and addressString has no rendering for it. The
 * remaining fields all have one: protocol and sock_type render empty, and
 * family renders AF_UNSPEC. See the TODO at the foot of this file.
 *
 * Field by field:
 *
 *   timestamp        bpf_ktime_get_ns() at sys_enter, copied into the record —
 *                    the same decision openat made, for the same reason, and it
 *                    matters more here. A connect can block for minutes, so the
 *                    gap between this instant and the moment the record reaches
 *                    the ring is bounded by the syscall's duration and that
 *                    bound is large. The instant recorded is the one the process
 *                    asked to connect, which is the instant a "read the key,
 *                    then connect out" sequence should be ordered by.
 *   task_start_time  the calling thread's start_boottime. The identity stamp the
 *                    protocol above requires, checked at exit against the thread
 *                    running there.
 *   proc             struct allseer_proc exactly as the record carries it,
 *                    including the cgroup_id the entry side matched on.
 *   family           the sockaddr's family, subject to the rule below.
 *   dport            the port, in host byte order. The header declares dport as
 *                    __u16 and not __be16, and decode.go states the consequence
 *                    of getting this wrong: "the alternative reading turns 443
 *                    into 47873 and nothing downstream would notice". The probe
 *                    is the side that converts.
 *   daddr            the address bytes in wire order, which is the order
 *                    netip.AddrFrom4 and AddrFrom16 read them in. v4 occupies
 *                    the first four bytes, as the record header declares.
 *
 * # The family rule
 *
 * `family` is set to AF_INET or AF_INET6 **only when the address that family
 * describes was captured**. Every other outcome leaves it at AF_UNSPEC or at
 * the family the process actually passed, and leaves daddr and dport zero.
 *
 * The rule exists because those two families are the only ones for which
 * addressString renders daddr at all. Setting family to AF_INET without a
 * captured address would publish "0.0.0.0" as a destination, which is both a
 * legal address to connect to and a plausible-looking lie. Under this rule a
 * record naming AF_INET or AF_INET6 always carries the address the process
 * passed, and a record that could not determine one says AF_UNSPEC and renders
 * an empty destination — which decode.go documents as the unevaluable case.
 *
 * Families that carry no address of this shape are reported as themselves, and
 * that is not an exception to the rule but the same rule: they promise nothing
 * about daddr, and the decoder already renders them without one. AF_UNIX is the
 * case that matters — "a socket path is not an address and does not fit in the
 * field" — and an unrecognised family renders as AddressFamily(N), which is the
 * decoder's stated policy of showing a reader what it did not expect.
 */
struct allseer_connect_scratch {
    __u64 timestamp;
    __u64 task_start_time;
    struct allseer_proc proc;
    __u8  daddr[16];
    __u16 family;
    __u16 dport;
    __u32 _pad;
};

/* Capacity of `priv_scratch`, in entries.
 *
 * Far smaller than the other two, and the reason is the workload rather than a
 * different appetite for risk. openat and connect are called constantly; the
 * eleven credential syscalls behind this map are called a handful of times in
 * the life of a process that changes identity at all, and never by one that
 * does not. A tracked cgroup running an ordinary build reaches this map zero
 * times.
 *
 * The live population is the number of tracked threads inside a credential
 * syscall at one instant, and none of them blocks: setuid and its relatives
 * take a lock and return, capset validates and returns, unshare allocates.
 * There is no equivalent of connect's two-minute SYN timeout to size for. So
 * this number, like the other two, is sized for the orphans — entries from
 * threads killed inside the syscall — and 1024 at 184 bytes is about 188 KiB.
 *
 * Running out is not a failure mode here either, for the reason the protocol
 * above gives: the LRU converts "no further privilege changes can be
 * correlated, forever" into "the oldest pending one loses its correlation". */
#define ALLSEER_MAX_PRIV_SCRATCH  1024

/* Value of `priv_scratch`: the before snapshot and what names the operation.
 *
 * The same prologue and the same split as the other two — the entry side
 * captures, the exit side contributes `ret` and emits — with one field the
 * others have no need of and one deliberate omission.
 *
 * # What it holds, and what it does not
 *
 * It holds `before`, which is 96 of its 184 bytes and is unavoidable: the
 * pre-change credential state exists only until the syscall commits, so a probe
 * that did not capture it at entry could never recover it. It does *not* hold
 * `after`, and it does not hold a built struct allseer_priv_payload. The after
 * snapshot is read at exit, straight into the reserved ring buffer record,
 * because at that instant it is simply the state of the task the exit program is
 * already running on. Copying the whole 208-byte payload through this map would
 * double the map's footprint to store a half of it that is not yet knowable.
 *
 * Field by field:
 *
 *   timestamp        bpf_ktime_get_ns() at sys_enter, copied into the record.
 *                    The instant the call was made, as it is for openat and
 *                    connect, and for the same reason: it is the instant every
 *                    other field here was read, so a record's timestamp and its
 *                    `before` snapshot describe the same moment.
 *   task_start_time  the calling thread's start_boottime. The identity stamp the
 *                    protocol above requires.
 *   proc             struct allseer_proc exactly as the record carries it. Note
 *                    that proc.uid and proc.gid are the *real* ids from
 *                    bpf_get_current_uid_gid, which is what every other probe
 *                    reports, while `before` carries all four views of each —
 *                    so proc.uid and before.uid_real are the same number by
 *                    construction and a record cannot disagree with itself.
 *   before           the pre-change snapshot, read from task->cred before the
 *                    kernel has touched it.
 *   operation        the enum allseer_priv_op value for the syscall that wrote
 *                    this entry. Its second job is described below.
 *   ns_flags         unshare's flags argument or setns's nstype, both CLONE_*.
 *                    Zero for every other operation.
 *   fields_present   the bits the entry side established. The exit side ORs its
 *                    own in; neither side sets a bit the other owns.
 *
 * # Why `operation` is also a discriminator
 *
 * One map serves eleven syscalls, where openat and connect were given one each.
 * That is a deliberate departure and the argument above for splitting them does
 * not carry here: the two reasons stated are that the values differ and that
 * eviction would let a noisy syscall decide which of a quiet one's events
 * survive. These eleven share one value shape exactly, and none of them is
 * noisy — they are the rarest syscalls this object hooks, so there is no
 * pressure for eviction to redistribute.
 *
 * What a shared map does need is the thing that section names: "A shared map
 * would have needed a syscall tag and a check on it". `operation` is that tag,
 * and the exit programs check it. Each exit program knows which syscall it is
 * attached to, so it compares the entry's operation against its own and treats a
 * mismatch exactly as it treats a stale identity stamp — delete, emit nothing.
 *
 * The window that check closes is narrow and real. A thread inside
 * unshare when the exit programs are attached leaves an entry no unshare_exit
 * will ever collect, because none was attached when the syscall returned. The
 * next credential syscall that thread makes has its own enter, which replaces
 * the entry, so the orphan is normally harmless — but between the two, an exit
 * program for a *different* syscall firing on that thread would find an entry
 * whose operation is not its own. Without the tag it would emit an unshare
 * event carrying some other syscall's return.
 */
struct allseer_priv_scratch {
    __u64 timestamp;
    __u64 task_start_time;
    struct allseer_proc proc;
    struct allseer_priv_state before;
    __u32 operation;
    __u32 ns_flags;
    __u32 fields_present;
    __u32 _pad;
};

/* The shared prologue, enforced rather than described.
 *
 * The protocol above says the two scratch values begin the same way; these are
 * what make that a fact a compiler checks. A field inserted into either struct's
 * head, or a reordering of one and not the other, stops the build instead of
 * quietly giving the two probes different ideas of where identity lives. */
_Static_assert(__builtin_offsetof(struct allseer_connect_scratch, timestamp) ==
               __builtin_offsetof(struct allseer_open_scratch, timestamp),
               "scratch prologue: timestamp must sit at the same offset in both");
_Static_assert(__builtin_offsetof(struct allseer_connect_scratch, task_start_time) ==
               __builtin_offsetof(struct allseer_open_scratch, task_start_time),
               "scratch prologue: task_start_time must sit at the same offset in both");
_Static_assert(__builtin_offsetof(struct allseer_connect_scratch, proc) ==
               __builtin_offsetof(struct allseer_open_scratch, proc),
               "scratch prologue: proc must sit at the same offset in both");
_Static_assert(__builtin_offsetof(struct allseer_priv_scratch, timestamp) ==
               __builtin_offsetof(struct allseer_open_scratch, timestamp),
               "scratch prologue: timestamp must sit at the same offset in all three");
_Static_assert(__builtin_offsetof(struct allseer_priv_scratch, task_start_time) ==
               __builtin_offsetof(struct allseer_open_scratch, task_start_time),
               "scratch prologue: task_start_time must sit at the same offset in all three");
_Static_assert(__builtin_offsetof(struct allseer_priv_scratch, proc) ==
               __builtin_offsetof(struct allseer_open_scratch, proc),
               "scratch prologue: proc must sit at the same offset in all three");

/* The before snapshot in the scratch value and the one in the record are the
 * same type, so a field added to one is added to both. Asserted anyway, because
 * the exit side copies it with a struct assignment and a silent divergence here
 * would be a partially-filled snapshot rather than a compile error. */
_Static_assert(sizeof(((struct allseer_priv_scratch *)0)->before) ==
               sizeof(((struct allseer_priv_payload *)0)->before),
               "priv scratch: the before snapshot must be the record's own type");

/* The lifecycle of a `connect_scratch` entry is the openat one unchanged, and
 * is not restated here: created at sys_enter_connect after tracked_cgroups
 * admits the caller and never before it, replaced with BPF_ANY, deleted by
 * sys_exit_connect on every path that found an entry, evicted by the LRU under
 * pressure. The failure paths are the same list too, with one substitution and
 * one addition:
 *
 *   the sockaddr read fails      the entry is stored anyway, with family
 *                                AF_UNSPEC and no address — the substitution for
 *                                openat's "the path read fails". A connect
 *                                happened and the process that made it is known;
 *                                dropping the record because one field could not
 *                                be read would hide a real connection attempt.
 *   the sockaddr is too short    the same, and it is not a rare case: a connect
 *                                with a length below what the family needs is
 *                                one the kernel itself rejects with EINVAL, so
 *                                the record pairs an unevaluable destination
 *                                with a return that explains why.
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
 * Collector. It now covers all three scratch maps on the same terms: connect,
 * and priv_scratch after it. The privilege case is the one where a lost
 * correlation costs the most and is hardest to notice — a credential change
 * whose exit found no entry produces no record, and a governed process that
 * appears never to have changed its credentials is indistinguishable from one
 * that did so unobserved. The deferral is unchanged, because the argument for it
 * is unchanged: a counter nothing reads is not a control.
 *
 * TODO(event): struct allseer_net_payload cannot say that an address field was
 * never filled. Every other field in it can — protocol and sock_type render as
 * the empty string, family renders as AF_UNSPEC — but saddr and daddr are 16
 * raw bytes, and 16 zero bytes under AF_INET are the wildcard 0.0.0.0, which is
 * a real address a process can connect to. connect records this as a live
 * problem rather than a theoretical one: it fills daddr and leaves saddr zero,
 * so every connect event decodes with SourceAddr "0.0.0.0" and nothing in the
 * record distinguishes that from an observation. The probe works around it for
 * daddr by refusing to claim AF_INET at all unless the address was captured,
 * which is only possible because family and address are set together; saddr has
 * no such lever. A `__u16 fields_present` bitmap on the payload, or separate
 * families for source and destination, would close it, and both are record
 * layout changes that belong with the other open ABI edits rather than inside a
 * probe issue. */
