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

#endif /* __ALLSEER_MAPS_H */
