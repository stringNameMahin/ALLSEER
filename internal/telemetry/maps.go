package telemetry

import "errors"

// Map names and loader errors. Portable so the collector and its tests
// build without libbpf.

// Map names, as bpf/include/allseer_maps.h publishes them. That header is the
// contract — "Maps are addressed by name and written as raw bytes ...  Neither
// the name nor the byte layout is checked by a compiler that sees both sides"
// — so the names are written down here once and referred to, rather than
// spelled out at each call site where a typo would become a runtime lookup
// failure.
const (
	// MapEvents is the record stream, drained by RingBuffer.
	MapEvents = "events"

	// MapTrackedCgroups is the kernel-side filter set, written by UpdateMap
	// and unwritten by DeleteMap.
	MapTrackedCgroups = "tracked_cgroups"

	// MapRingbufDrops counts records no probe could reserve space for, read by
	// ReadCounter. Per-CPU, one slot, monotonic; allseer_maps.h states exactly
	// what an increment does and does not mean.
	MapRingbufDrops = "ringbuf_drops"

	// MapOpenatScratch holds one half-built open event per thread that is
	// inside openat, between ProgOpenatEnter and ProgOpenatExit.
	//
	// No loader method touches it and none should. It is kernel-internal state
	// with a kernel-internal lifecycle — allseer_maps.h defines when an entry
	// is created, replaced, deleted and evicted, and every one of those is a
	// probe's doing. A user-space write into it would be a fabricated syscall
	// entry that the exit side would complete into a real-looking event.
	//
	// It is named here because allseer_maps.h publishes it in the same table as
	// the other three, and because the runtime tests assert on it: that entries
	// are gone after a completed open, and gone after one that failed. Those are
	// claims about the map, and a test cannot make them against a name that is
	// spelled out at its own call site and nowhere else.
	MapOpenatScratch = "openat_scratch"

	// MapConnectScratch holds one half-built connect event per thread that is
	// inside connect, between ProgConnectEnter and ProgConnectExit.
	//
	// The second instance of the scratch protocol, not a second mechanism:
	// same key, same map type, same lifecycle, and separate from
	// MapOpenatScratch only so that one syscall's pressure cannot evict the
	// other's pending state. allseer_maps.h argues both halves of that.
	//
	// Kernel-internal in exactly the way MapOpenatScratch is, and named here
	// for the same reason: the runtime tests assert on it. The name is fifteen
	// characters, which is the most BPF_OBJ_NAME_LEN allows.
	MapConnectScratch = "connect_scratch"

	// MapPrivScratch holds one half-built privilege event per thread that is
	// inside a credential syscall, between a ProgPriv*Enter and its matching
	// ProgPriv*Exit.
	//
	// The third instance of the scratch protocol and the first shared by more
	// than one syscall: eleven pairs write and read this one map, where openat
	// and connect were given one each. allseer_maps.h argues why that is right
	// here — the eleven have one value shape and none of them is hot, so
	// neither reason for splitting them applies — and what it costs, which is a
	// syscall tag the exit side has to check.
	//
	// Kernel-internal in exactly the way the other two are, and named here for
	// the same reason: the runtime tests assert that an entry exists between
	// the two halves and is gone after either outcome.
	MapPrivScratch = "priv_scratch"
)

// Errors reported by the loader.
//
// Separate sentinels because a caller deciding whether to retry, reload or give
// up needs to tell them apart, and because "the daemon started but observed
// nothing" is a failure mode this package is built to make impossible to reach
// quietly.
var (
	// ErrNotLoaded: an operation that needs a loaded object was called before
	// Load, or after Close.
	ErrNotLoaded = errors.New("telemetry: no BPF object is loaded")

	// ErrAlreadyLoaded: Load was called twice. Refused rather than made
	// idempotent: the second object would create a second ring buffer and a
	// second filter set, and every map in this design is per-object.
	ErrAlreadyLoaded = errors.New("telemetry: a BPF object is already loaded")

	// ErrClosed: the loader has been closed and cannot be reused.
	ErrClosed = errors.New("telemetry: loader is closed")

	// ErrAlreadyAttached: the same program was attached twice, which would
	// report every event twice.
	ErrAlreadyAttached = errors.New("telemetry: program is already attached")

	// ErrRingBufferExists: RingBuffer was called twice for one map. Two
	// consumers of one ring buffer split the records between them rather than
	// each seeing all of them, so a second reader is a silent gap in both.
	ErrRingBufferExists = errors.New("telemetry: a ring buffer reader already exists for this map")

	// ErrMapValueSize: a key or value handed to UpdateMap is not the width the
	// loaded map declares.
	//
	// Checked because nothing else can. UpdateMap's key and value are []byte
	// by contract, and allseer_maps.h says why that is dangerous: the byte
	// layout is "not checked by a compiler that sees both sides". A short key
	// would be read past by the kernel; a long one would be silently
	// truncated, and a truncated cgroup ID matches the wrong cgroup.
	ErrMapValueSize = errors.New("telemetry: key or value is not the size the map declares")

	// ErrMapKeyNotFound: DeleteMap was asked to remove a key the map does not
	// hold.
	//
	// Reported rather than swallowed, and given its own sentinel so that a
	// caller can swallow it deliberately. Removing an absent key is harmless
	// and a collector detaching a session it already detached will do it — but
	// "the entry was not there" and "the entry could not be removed" are
	// different findings about the filter map, and a DeleteMap that returned
	// nil for both would let a genuine failure to stop watching a cgroup read
	// as success.
	ErrMapKeyNotFound = errors.New("telemetry: the map holds no such key")

	// ErrNotACounter: ReadCounter was pointed at a map that is not the shape it
	// knows how to read.
	//
	// Checked for the same reason ErrMapValueSize is. The map is addressed by
	// name and the name is a string, so nothing but this can tell that the
	// caller reached a hash map, a ring buffer, or a counter of some other
	// width — and a per-CPU read against a map that is not per-CPU returns the
	// wrong number of bytes rather than an error, which would be summed into a
	// plausible drop count.
	ErrNotACounter = errors.New("telemetry: map is not a single-entry per-CPU counter")
)
