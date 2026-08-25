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
 *
 * Names are capped at 15 characters plus a NUL by BPF_OBJ_NAME_LEN. Anything
 * longer is silently truncated by libbpf and then fails to be found by the name
 * user space asked for, so "tracked_cgroups", at exactly 15, is at the limit.
 */

#ifndef __ALLSEER_MAPS_H
#define __ALLSEER_MAPS_H

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

#endif /* __ALLSEER_MAPS_H */
