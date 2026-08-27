// Package synth generates synthetic telemetry: event streams in the replay
// format, built with no kernel, no root, no libbpf and no compiled eBPF object.
//
// It is the third producer internal/telemetry/replay names — "a stream can be
// produced by the daemon's recorder, by the synthetic generator, or by hand" —
// and it exists for the two cases the other two serve badly. A benchmark needs
// ten thousand events of a stated shape, which nobody wants to hand-author and
// which a recording pins to one machine's timing. A scenario needs a stream
// that is awkward to record on purpose: ring buffer loss at a chosen point, a
// hundred failed opens of the same path, an exec tree deeper than any real
// build produces.
//
// # Not a second decoder
//
// The load-bearing decision here is that nothing in this package decides what
// an event *means*. A Spec describes the record a probe would have submitted —
// an allseer_event_type, a syscall return, the process identity, the one union
// member the header designates for that type — and the generator renders it as
// the 856 bytes struct allseer_event occupies and hands those bytes to the same
// telemetry.EventDecoder the live collector reads its ring buffer with:
//
//	Spec ─▶ 856-byte record ─▶ telemetry.EventDecoder ─▶ enrichment ─▶ resolve.Observe
//
// So an open's capability comes from its flags, an errno comes from a negative
// return, an address is rendered according to its family, a domain comes from
// the M1 catalog, and a record this build refuses is refused here too. A
// generator that assembled event.Event values directly would be a second
// decoder written beside the first, and the failure that produces is the one
// the header's preamble names: "plausible garbage that flows straight into
// governance decisions" — arriving, in that version, through the tool meant to
// produce test evidence. It would also drift silently, since nothing would fail
// when the two disagreed.
//
// The cost of the choice is real and small: the generator can only produce
// events a probe could produce. That is the point.
//
// # What is added after decode, and by whom
//
// decode.go leaves several fields of event.Event deliberately zero because
// filling them from one record would mean inventing. Every one of them is
// supplied here explicitly by the caller or derived deterministically, and none
// is guessed at:
//
//   - SessionID, Sequence and ID come from the generator. Sequence is a dense
//     per-session counter; ID follows the same "<session>/<sequence>" form the
//     replay source synthesizes, so a generated stream and a replayed one carry
//     the same identifiers.
//   - Dropped, and the sequence gap that must accompany it, come from
//     Spec.Dropped. The two are advanced together, so a generated stream cannot
//     claim loss its numbering contradicts.
//   - WallClock stays zero unless Config.BootWallClock states the boot wall
//     time. The boot-offset strategy is an open decision in pkg/event, which
//     records why: "a synthesized wall time reads as observed". A caller that
//     names the offset has measured it by declaration; the generator will not
//     pick one.
//   - Enrichment — a resolved path, a correlated hostname, the executable, the
//     ancestry depth, an interpreter, a binary hash, environment *names* — is
//     M6's and does not exist yet. Each field sits on the payload it belongs
//     to, so a spec cannot enrich a payload the event does not carry, and each
//     is carried verbatim.
//   - Syscall stays empty, because the record carries no syscall identifier.
//     See the TODO(telemetry) at the foot of decode.go: ALLSEER_EVT_FILE_OPEN
//     could be open, openat or openat2, and naming one would be a guess.
//
// Observation is not among them: it is produced by resolve.Observe from the
// enriched event, never hand-built, for the same reason the decoder does not
// build one. An observation written beside the payload it describes can
// contradict it, and the validator reads the observation.
//
// # Determinism
//
// Same specs, same config, same bytes. Timestamps are Config.StartTimestamp
// plus a fixed interval per step rather than a clock read, sequence numbers are
// a counter, and there is no randomness anywhere in the package. Two runs
// produce byte-identical streams, which is what lets a generated corpus be
// diffed and a benchmark be compared against itself.
//
// A Generator is stateful — it holds the clock and the counter — and is not
// safe for concurrent use. One generator per stream.
package synth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"time"

	"github.com/stringNameMahin/ALLSEER/internal/telemetry"
	"github.com/stringNameMahin/ALLSEER/internal/telemetry/abi"
	"github.com/stringNameMahin/ALLSEER/internal/telemetry/replay"
	"github.com/stringNameMahin/ALLSEER/internal/telemetry/resolve"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// Defaults for the generator's clock, in kernel-timestamp nanoseconds.
//
// The values are arbitrary and only their properties matter: a non-zero start,
// because a zero ktime is the value an unfilled field holds, and a non-zero
// interval, because the replay format requires timestamps to increase and
// nothing may deliver two events at the same instant.
const (
	DefaultStartTimestamp uint64 = 1_000_000 // 1 ms after boot
	DefaultInterval       uint64 = 1_000_000 // 1 ms between steps
)

// ErrNoSessionID is returned by New when the config names no session.
//
// Refused at construction rather than discovered downstream. pkg/event requires
// every event to be independently interpretable, session.Dispatcher rejects an
// event carrying no session_id with ErrEventUnidentified, and a generator that
// defaulted the field would be choosing an identity on the caller's behalf.
var ErrNoSessionID = errors.New("synth: a session ID is required")

// Config configures a generator.
type Config struct {
	// SessionID is stamped on every event. Required.
	SessionID string

	// Process is the identity used for a Spec that names none. It is the common
	// case — a stream is usually one process, or a few — and repeating the
	// identity on every spec would bury what each spec is actually about.
	Process Proc

	// StartTimestamp is the kernel timestamp of the first event, in
	// nanoseconds since boot. Zero uses DefaultStartTimestamp.
	StartTimestamp uint64

	// Interval is the kernel-timestamp distance between consecutive steps, in
	// nanoseconds. Zero uses DefaultInterval.
	//
	// A step is one event, or one event plus the records Spec.Dropped says were
	// lost before it: the lost records took time as well as sequence numbers,
	// and a gap that consumed neither would not look like loss.
	Interval uint64

	// BootWallClock is the wall time the machine booted. When set, each event's
	// WallClock is this plus its kernel timestamp. When zero — the default —
	// WallClock is left zero, exactly as the decoder leaves it.
	//
	// It exists because several downstream stages read the field: the validator
	// compares it against envelope expiry, session state advances its clock
	// from it, and the risk engine measures the distance between the halves of
	// a sequence with it. A scenario that needs any of those has to state an
	// offset, and stating it here makes it a declared input of the fixture
	// rather than an invented property of the events.
	BootWallClock time.Time
}

// decoder is the collector's own decoder, shared by every generator.
//
// Shared rather than held per generator because EventDecoder "holds no state"
// by its own contract — decoding one record must not depend on any record
// before it — and a generator that carried a private one would suggest
// otherwise.
var decoder = telemetry.NewDecoder()

// Generator produces synthetic events. Use New; the zero value is not usable.
type Generator struct {
	cfg Config

	// step counts clock and sequence advances rather than events, because
	// Spec.Dropped advances both by more than one. The first event is step 0,
	// so it lands exactly on StartTimestamp.
	step uint64
}

// New returns a generator over cfg.
func New(cfg Config) (*Generator, error) {
	if cfg.SessionID == "" {
		return nil, ErrNoSessionID
	}
	if cfg.StartTimestamp == 0 {
		cfg.StartTimestamp = DefaultStartTimestamp
	}
	if cfg.Interval == 0 {
		cfg.Interval = DefaultInterval
	}
	return &Generator{cfg: cfg}, nil
}

// Next builds the next event in the stream.
//
// It advances the clock and the sequence counter, so calling it is the only way
// to move the stream forward and the order of calls is the order of the stream.
// An error leaves the generator where it was: a spec the record layer or the
// decoder refuses produces no event and consumes no sequence number, so a
// caller that recovers from one does not end up with a hole it never asked for.
func (g *Generator) Next(s Spec) (event.Event, error) {
	// Dropped records are lost before this one, so the step they consume comes
	// first: this event carries the timestamp and the sequence number on the
	// far side of the hole.
	step := g.step + s.Dropped
	ts := g.cfg.StartTimestamp + step*g.cfg.Interval

	proc := s.Proc
	if proc == nil {
		proc = &g.cfg.Process
	}

	raw, err := record(s, proc, ts)
	if err != nil {
		return event.Event{}, err
	}

	e, err := decoder.Decode(raw)
	if err != nil {
		return event.Event{}, fmt.Errorf("synth: %w", err)
	}

	enrich(e, s, proc)

	// The observation comes from the resolver the pipeline uses, over the
	// enriched event. Building one here would be a second answer to a question
	// internal/telemetry/resolve already answers, and the validator reads the
	// observation rather than the payload.
	obs, err := resolve.Observe(e)
	if err != nil {
		return event.Event{}, fmt.Errorf("synth: resolving the generated event: %w", err)
	}
	e.Observation = obs

	seq := step + 1 // sequence is 1-based, as the committed fixtures are
	e.SessionID = g.cfg.SessionID
	e.Sequence = seq
	e.ID = g.cfg.SessionID + "/" + strconv.FormatUint(seq, 10)
	if !g.cfg.BootWallClock.IsZero() {
		e.WallClock = g.cfg.BootWallClock.Add(time.Duration(ts))
	}

	g.step = step + 1
	return *e, nil
}

// enrich applies the fields a user-space enricher would have added.
//
// Every one is carried verbatim from the spec. Nothing is derived, because
// deriving any of them is the M6 work this package stands in for and a guess
// here would read as a resolution that happened.
func enrich(e *event.Event, s Spec, proc *Proc) {
	e.Process.Executable = proc.Executable
	e.Process.AncestryDepth = proc.AncestryDepth
	e.Dropped = s.Dropped

	switch {
	case s.File != nil && e.File != nil:
		e.File.ResolvedPath = s.File.ResolvedPath
	case s.Net != nil && e.Network != nil:
		e.Network.Hostname = s.Net.Hostname
	case s.Exec != nil && e.Exec != nil:
		e.Exec.Interpreter = s.Exec.Interpreter
		e.Exec.BinaryHash = s.Exec.BinaryHash
		// Cloned rather than shared: a caller reusing one Spec across a stream
		// would otherwise have every event pointing at the same backing array,
		// and a later append would edit events already produced.
		e.Exec.EnvKeys = slices.Clone(s.Exec.EnvKeys)
	}
}

// Generate builds a whole stream in one call.
//
// The events are returned in the order the specs were given, which is the order
// they carry sequence numbers in. An error names the spec that failed, since a
// stream is usually built from a table and the index is what identifies the row.
func (g *Generator) Generate(specs ...Spec) ([]event.Event, error) {
	out := make([]event.Event, 0, len(specs))
	for i, s := range specs {
		e, err := g.Next(s)
		if err != nil {
			return nil, fmt.Errorf("synth: spec %d: %w", i, err)
		}
		out = append(out, e)
	}
	return out, nil
}

// WriteStream writes the specs to w in the replay format.
//
// One JSON-encoded event per line, and nothing else. The blank lines and //
// comments the replay reader accepts are a convenience for hand-written
// fixtures — "Neither appears in machine-produced streams" — and this is a
// machine-produced stream, so a caller that wants a fixture to explain itself
// adds the commentary itself rather than getting it from here.
func (g *Generator) WriteStream(w io.Writer, specs ...Spec) error {
	events, err := g.Generate(specs...)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(w)
	for i := range events {
		if err := enc.Encode(&events[i]); err != nil {
			return fmt.Errorf("synth: writing event %d: %w", i, err)
		}
	}
	return nil
}

// Source returns an event.Source delivering the generated stream.
//
// It is a *replay.Source over the generated bytes rather than a source of this
// package's own. Everything a source has to get right — single-use Start,
// idempotent Close, drop accounting, sequence gap detection, the closed channel
// that does not by itself mean success — is already decided there, and a second
// implementation would be a second set of answers for a consumer that must not
// be able to tell its sources apart.
//
// The stream is built eagerly, so an unsatisfiable spec is an error here rather
// than a silently short stream later. A caller wanting paced playback, a
// different buffer size, or the stream on disk should use WriteStream and
// construct the replay source itself.
func (g *Generator) Source(specs ...Spec) (*replay.Source, error) {
	var buf bytes.Buffer
	if err := g.WriteStream(&buf, specs...); err != nil {
		return nil, err
	}
	return replay.New(replay.Config{Reader: &buf}), nil
}

// Record renders one spec as the raw ring buffer record a probe would have
// submitted at the given kernel timestamp.
//
// Exposed for the half of the benchmark case that is about the decoder rather
// than about the pipeline: measuring Decode needs records, not events. It is a
// pure function of its arguments — no generator, no clock, no counter — so the
// same spec and timestamp always produce the same bytes, and the result is
// always exactly abi.RecordSize long.
//
// Spec.Dropped is ignored. Ring buffer loss is a fact about the reader that saw
// the hole, and struct allseer_event has no field for it.
func Record(s Spec, timestamp uint64) ([]byte, error) {
	proc := s.Proc
	if proc == nil {
		proc = &Proc{}
	}
	return record(s, proc, timestamp)
}

// EventSize is the size of the records Record produces, which is
// sizeof(struct allseer_event) for this build.
//
// The generated constant rather than a number written down again, so a header
// change moves this with it.
const EventSize = abi.RecordSize
