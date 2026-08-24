// SPDX-License-Identifier: GPL-2.0
/* ALLSEER eBPF object.
 *
 * One object, not one per probe. telemetry.Config carries a single ObjectPath,
 * and maps are per-object: two objects loaded separately get two ring buffers
 * and two filter sets, and sharing one between them means pinning it and
 * agreeing on a bpffs path. Probes are added to this file as they are written.
 *
 * At this point the file declares the maps and nothing else. That is the whole
 * of the current milestone issue: the maps are what the probes will emit into
 * and be filtered by, and the loader that populates and drains them is a
 * separate issue again. An object with maps and no programs is still a valid
 * object — libbpf will open and load it, and the maps are created in the kernel
 * exactly as they will be once probes reference them — which is what makes the
 * map layout checkable now rather than after the first probe is attached.
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
 * The map exists here; consulting it is the filtering issue, and there is
 * nothing yet to consult it. What it is for is stated in the Loader contract:
 * filtering happens in the kernel "rather than costing a userspace round trip
 * per event". An untracked process should cost a lookup and a return, not a
 * ring buffer reservation, a wakeup, a decode and a discard.
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

/* Required before any program in this object can load. Declared with the maps
 * because it belongs to the object rather than to any one probe, and because
 * the helpers the probes will need — bpf_probe_read_kernel and the task
 * accessors among them — are GPL-only and refuse to verify without it. */
char LICENSE[] SEC("license") = "GPL";
