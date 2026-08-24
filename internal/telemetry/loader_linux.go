//go:build linux && ebpf

package telemetry

// The loader: eBPF object lifecycle over libbpfgo.
//
// This is the implementation the package doc names — "The kernel side is
// compiled from C (bpf/*.bpf.c) and loaded with libbpfgo" — behind the Loader
// interface, which exists "so libbpfgo can be swapped without touching the
// collector, and so tests can exercise collector logic without a kernel".
//
// # What it does not do
//
// It does not decode. Loader.RingBuffer is declared to return "the raw record
// stream", and that is what comes out of it: bytes, in the order the kernel
// wrote them, handed to whatever the caller chooses. Decoder is the only thing
// in this package that assigns meaning to those bytes, and putting a decode
// call in here would give the system two places where kernel bytes become Go
// values — which is the exact duplication internal/telemetry/abi exists to
// prevent.
//
// It also does not filter. That is in the kernel, in bpf/allseer.bpf.c, and the
// user-to-kernel half of it is UpdateMap. A loader that dropped events by
// cgroup after reading them would be paying the cost the map exists to avoid:
// "an untracked process should cost a lookup and a return, not a ring buffer
// reservation, a wakeup, a decode and a discard".
//
// It holds no session state, makes no policy decision, and knows nothing about
// capabilities. Collector owns all of that (M6).
//
// # Lifetime
//
// One BPFLoader owns one libbpf object. Load opens and loads it; Attach adds
// links; RingBuffer starts a poll goroutine per map; DetachAll drops the links
// but keeps the object loaded, so a session can be detached and re-attached
// without reloading; Close tears down everything and cannot be undone.
//
// Every method is safe to call concurrently. DetachAll and Close are idempotent,
// because a shutdown path that has to remember whether it already ran is a
// shutdown path that double-frees under a signal.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

// Map names, as bpf/include/allseer_maps.h publishes them. That header is the
// contract — "Maps are addressed by name and written as raw bytes ...  Neither
// the name nor the byte layout is checked by a compiler that sees both sides"
// — so the names are written down here once and referred to, rather than
// spelled out at each call site where a typo would become a runtime lookup
// failure.
const (
	// MapEvents is the record stream, drained by RingBuffer.
	MapEvents = "events"

	// MapTrackedCgroups is the kernel-side filter set, written by UpdateMap.
	MapTrackedCgroups = "tracked_cgroups"
)

// ProgProcExec is the sched_process_exec program in bpf/allseer.bpf.c, named
// for Attach. libbpf resolves the attach point from the program's SEC(), so the
// tracepoint is named in one place — the C file — and not restated here.
const ProgProcExec = "proc_exec"

const (
	// ringBufferPollMS is how long libbpf waits in epoll before checking
	// whether it has been asked to stop. It bounds shutdown latency and
	// nothing else: a record wakes the poll immediately.
	ringBufferPollMS = 300

	// rawEventChannelSize buffers records between the poll goroutine and the
	// consumer.
	//
	// Config.EventChannelSize is deliberately not used for this. It is
	// documented as bounding "the user-space buffer between decode and the
	// pipeline", which is the channel downstream of Decoder, not this one, and
	// borrowing it here would silently give one knob two meanings.
	//
	// Some buffering is required rather than merely nice: libbpfgo's poll
	// goroutine sends from inside the libbpf callback, so a full channel stalls
	// the drain of the kernel ring, and a stalled drain is how records are lost
	// — the loss pkg/event.Event.Dropped reports. That this is a compiled-in
	// constant and not configurable is a real gap; see the TODO at the end of
	// this file.
	rawEventChannelSize = 1024
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
)

// BPFLoader implements Loader over libbpfgo.
type BPFLoader struct {
	cfg     Config
	decoder Decoder

	mu       sync.Mutex
	module   *bpf.Module
	links    map[string]*bpf.BPFLink
	ringBufs map[string]*bpf.RingBuffer
	closed   bool
}

var _ Loader = (*BPFLoader)(nil)

// NewLoader returns a loader for the given configuration.
//
// The decoder is taken rather than constructed so the startup layout check
// compares the object against the decoder that will actually read it. Passing
// nil uses this build's decoder, which is the same thing said differently, but
// a caller that has swapped the decoder should not get the check silently
// applied to a different one.
func NewLoader(cfg Config, decoder Decoder) *BPFLoader {
	if decoder == nil {
		decoder = NewDecoder()
	}
	return &BPFLoader{
		cfg:      cfg,
		decoder:  decoder,
		links:    make(map[string]*bpf.BPFLink),
		ringBufs: make(map[string]*bpf.RingBuffer),
	}
}

// Load reads a compiled eBPF object and prepares its programs.
//
// The order is deliberate and is the point of doing this here rather than in
// the collector. Both preconditions are established before anything reaches the
// kernel, because both describe a daemon that would otherwise run, attach
// cleanly, and observe nothing:
//
//  1. A cgroup2 hierarchy exists. The probes filter on
//     bpf_get_current_cgroup_id(), and without the unified hierarchy that value
//     names nothing user space can put in the filter map.
//
//  2. The object's record layout matches this binary's decoder, read out of the
//     object's BTF. internal/telemetry/abi calls the loader "the only point at
//     which a mismatch costs nothing — no probes are running and no events have
//     been believed".
//
// The context is honoured at entry only. libbpf's open and load are synchronous
// C calls with no cancellation, and returning early while they run would leave
// an object nobody owns.
func (l *BPFLoader) Load(ctx context.Context, objectPath string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	switch {
	case l.closed:
		return ErrClosed
	case l.module != nil:
		return ErrAlreadyLoaded
	}

	if _, err := requireCgroupV2(); err != nil {
		return err
	}
	if err := checkRecordLayout(objectPath, l.decoder.EventSize()); err != nil {
		return err
	}
	if err := validateRingBufferSize(l.cfg.RingBufferSize); err != nil {
		return err
	}

	module, err := bpf.NewModuleFromFile(objectPath)
	if err != nil {
		return fmt.Errorf("telemetry: opening BPF object %s: %w", objectPath, err)
	}

	// Between open and load is the only window in which a map can be resized:
	// after load it exists in the kernel at whatever size it was created with.
	if err := resizeRingBuffer(module, l.cfg.RingBufferSize); err != nil {
		module.Close()
		return err
	}

	if err := module.BPFLoadObject(); err != nil {
		module.Close()
		return fmt.Errorf("telemetry: loading BPF object %s: %w", objectPath, err)
	}

	l.module = module
	return nil
}

// resizeRingBuffer applies Config.RingBufferSize to the events map.
//
// A zero size keeps ALLSEER_RINGBUF_BYTES, the value compiled into the object.
// That is the documented default rather than a silent fallback: allseer_maps.h
// calls it "the compiled-in default and the loader is expected to override it
// from telemetry.Config.RingBufferSize before load, which is the only point at
// which a ring buffer can be resized".
//
// The size is validated by Load before anything is opened; this applies it.
func resizeRingBuffer(module *bpf.Module, size int) error {
	if size == 0 {
		return nil
	}

	m, err := module.GetMap(MapEvents)
	if err != nil {
		return fmt.Errorf("telemetry: map %q: %w", MapEvents, err)
	}
	if err := m.SetMaxEntries(uint32(size)); err != nil {
		return fmt.Errorf("telemetry: sizing map %q to %d bytes: %w", MapEvents, size, err)
	}
	return nil
}

// Attach attaches a named program to its hook.
//
// The hook itself is not named here. libbpf derives it from the program's
// SEC(), so bpf/allseer.bpf.c stays the single place a probe's attach point is
// written down — which is what keeps ProbeInfo.AttachPoint describable from the
// object rather than from a table beside it.
func (l *BPFLoader) Attach(ctx context.Context, programName string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if err := l.readyLocked(); err != nil {
		return err
	}
	if _, ok := l.links[programName]; ok {
		return fmt.Errorf("%w: %s", ErrAlreadyAttached, programName)
	}

	prog, err := l.module.GetProgram(programName)
	if err != nil {
		return fmt.Errorf("telemetry: program %q: %w", programName, err)
	}
	link, err := prog.AttachGeneric()
	if err != nil {
		return fmt.Errorf("telemetry: attaching %q: %w", programName, err)
	}

	l.links[programName] = link
	return nil
}

// RingBuffer returns the raw record stream for a named map.
//
// Raw is the contract. Each element is one ring buffer record exactly as the
// probe wrote it, which Decoder.Decode refuses unless it is EventSize() bytes.
// Nothing here inspects, reorders, or drops them.
//
// The channel is closed when the loader stops polling — DetachAll or Close — so
// a consumer ranging over it terminates rather than blocking on a stream that
// will never produce again.
func (l *BPFLoader) RingBuffer(ctx context.Context, mapName string) (<-chan []byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if err := l.readyLocked(); err != nil {
		return nil, err
	}
	if _, ok := l.ringBufs[mapName]; ok {
		return nil, fmt.Errorf("%w: %s", ErrRingBufferExists, mapName)
	}

	records := make(chan []byte, rawEventChannelSize)
	rb, err := l.module.InitRingBuf(mapName, records)
	if err != nil {
		return nil, fmt.Errorf("telemetry: ring buffer %q: %w", mapName, err)
	}
	rb.Poll(ringBufferPollMS)

	l.ringBufs[mapName] = rb
	return records, nil
}

// UpdateMap writes a key/value into a BPF map.
//
// This is the user-to-kernel channel the Loader contract describes: it is how
// tracked_cgroups is populated, and so how kernel-side filtering is told what
// to let through. For that map the key is an allseer_cgroup_id_t — a
// little-endian __u64 on both supported targets — and the value is a single
// allseer_tracked_t byte whose content carries no meaning: allseer_maps.h says
// "presence in the map is the entire signal", and bpf/allseer.bpf.c tests the
// lookup for NULL without dereferencing it.
//
// The widths are checked against what the loaded map declares, because that is
// the one check available: the signature is []byte on both sides and no
// compiler sees them together.
func (l *BPFLoader) UpdateMap(ctx context.Context, mapName string, key, value []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if err := l.readyLocked(); err != nil {
		return err
	}

	m, err := l.module.GetMap(mapName)
	if err != nil {
		return fmt.Errorf("telemetry: map %q: %w", mapName, err)
	}
	if len(key) != m.KeySize() || len(value) != m.ValueSize() {
		return fmt.Errorf("%w: map %q takes a %d-byte key and a %d-byte value, got %d and %d",
			ErrMapValueSize, mapName, m.KeySize(), m.ValueSize(), len(key), len(value))
	}

	// The pointers are into Go byte slices holding no Go pointers, which is
	// what cgo permits to cross into C for the duration of the call.
	if err := m.Update(unsafe.Pointer(&key[0]), unsafe.Pointer(&value[0])); err != nil {
		return fmt.Errorf("telemetry: updating map %q: %w", mapName, err)
	}
	return nil
}

// DetachAll detaches every attached program and stops every ring buffer reader.
//
// The ring buffers go with the links deliberately. A reader left polling a map
// no probe writes to is not harmless: it is a channel that never closes and a
// consumer that never returns, which is how a shutdown hangs. The object stays
// loaded and the maps keep their contents, so Attach can be called again
// without reloading.
//
// Idempotent: with nothing attached it does nothing and reports no error.
func (l *BPFLoader) DetachAll(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.detachLocked()
}

func (l *BPFLoader) detachLocked() error {
	// Ring buffers first. Stopping a reader after its programs are gone is
	// fine; destroying the programs while a poll goroutine is mid-callback is
	// the ordering worth avoiding.
	for name, rb := range l.ringBufs {
		rb.Close()
		delete(l.ringBufs, name)
	}

	var errs []error
	for name, link := range l.links {
		if err := link.Destroy(); err != nil {
			errs = append(errs, fmt.Errorf("detaching %q: %w", name, err))
		}
		delete(l.links, name)
	}
	if len(errs) > 0 {
		return fmt.Errorf("telemetry: %w", errors.Join(errs...))
	}
	return nil
}

// Close detaches everything and releases the object.
//
// Idempotent, and safe on a loader that was never loaded. libbpfgo's
// Module.Close is neither — it calls bpf_object__close unconditionally — so the
// guard is here, where a daemon closing on a signal path it may reach twice can
// rely on it.
func (l *BPFLoader) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return nil
	}
	l.closed = true

	err := l.detachLocked()
	if l.module != nil {
		l.module.Close()
		l.module = nil
	}
	return err
}

// readyLocked reports whether the loader can serve an operation that needs a
// loaded object. Callers hold l.mu.
func (l *BPFLoader) readyLocked() error {
	switch {
	case l.closed:
		return ErrClosed
	case l.module == nil:
		return ErrNotLoaded
	}
	return nil
}

// TODO(telemetry): Config has no field for the raw record channel's capacity,
// so rawEventChannelSize is compiled in. EventChannelSize is not it — that one
// is documented as sitting between decode and the pipeline — and the two have
// different consequences when they fill: the downstream one backs up into the
// decoder, this one stalls the kernel ring drain and loses records. Adding the
// field belongs with the collector, which is what will have to react to the
// loss.
// TODO(telemetry): Config.EnabledProbes is not consulted here. The Loader
// interface attaches one named program at a time, so which ones to attach is a
// decision the caller already expresses by choosing what to call Attach with,
// and making Load honour the list too would put the same policy in two places.
// The collector is where it belongs, together with the ProbeInfo it has to
// report for probes it deliberately did not attach.
