// Package audit writes governance decisions to durable storage.
//
// This is the concrete side of decision.Sink, which pkg/decision declares and
// deliberately does not implement: pkg/decision is the vocabulary every layer
// shares, and a file writer in it would drag os, buffering, and durability
// policy into the one package that is supposed to be pure contract.
//
// # Format
//
// Append-only JSON Lines, one decision.Decision per line. Fixed by
// docs/architecture.md as a communication decision — an audit record has to be
// greppable and consumable by external tooling without a library — and by
// config.AuditConfig.Format, which names "jsonl". The record is exactly what
// encoding/json produces for a Decision: this package adds no envelope, no
// wrapper, and no field of its own. A second decision schema, invented here so
// the writer could be tidier, would be a second thing to keep in agreement with
// the type and the JSON schema, and the two would drift.
//
// # What this package is not
//
// It does not judge. Attaching a sink changes no verdict, no score, no rule,
// and no action; it only records what the pipeline already decided. That is
// asserted in TestSinkChangesNoDecision rather than left as an intention.
//
// # Three contradictions in the shipped contracts, and how they are settled
//
// Each of these was recorded in STATUS.md before this package existed, and each
// had to be answered in words before it could be answered in code.
//
//  1. An unscored decision does not validate against the shipped schema.
//     decision.Decision.Risk is a value, not a pointer, so a decision from an
//     unscored pipeline or from any stage failure publishes "level": "" and
//     "factors": null. api/schema/decision.v1alpha1.schema.json requires level
//     to be one of five named levels and factors to be an array, and admits
//     neither. This writer serializes faithfully and does not resolve it. It
//     does not substitute "none" for the empty level, and it does not turn a
//     nil factor list into an empty array: an empty level is how a consumer
//     tells unscored from scored-none, and manufacturing a risk assessment to
//     satisfy a validator is the exact failure this project's treatment of
//     absent evidence exists to prevent. The disagreement is between the Go
//     type and the JSON schema, and closing it is a wire-format change that
//     must not ride along inside a feature.
//     TestUnscoredDecisionIsWrittenFaithfully pins the shape that actually
//     reaches disk, so whoever settles the schema has to come back here.
//
//  2. Nothing calls Flush. pipeline.EventPipeline.Run returns as soon as its
//     source closes and never flushes, so a sink that buffered in user space
//     would silently lose its last records on a clean shutdown. Rather than
//     invent a lifecycle the interfaces do not have — a background flusher, a
//     Close the interface does not declare, a Run that flushes — this sink does
//     not buffer across Emit calls. Every Emit performs one write. A record is
//     therefore in the operating system's hands the moment Emit returns, and
//     nothing is lost by never calling Flush. Flush remains meaningful and is
//     not a no-op: it fsyncs, which is what turns "written" into "survives a
//     machine crash". The scratch buffer this type holds is reused within a
//     single Emit and is empty between calls; it is an allocation optimization,
//     not a queue.
//
//  3. "Must not block" versus SyncWrites. decision.Sink's contract says an
//     implementation "must not block the pipeline; buffer or drop with a
//     counter instead", while config.AuditConfig.SyncWrites exists to force an
//     fsync per record, whose whole purpose is to block until the record is
//     durable. These are two sides of a trade the operator is the one entitled
//     to make, and the resolution taken here is that SyncWrites is that
//     operator's explicit choice and therefore permits the synchronous
//     durability operation the interface otherwise discourages. With SyncWrites
//     false — the default — Emit issues one write and never waits for a disk.
//     With it true, Emit additionally fsyncs and does block, visibly, because
//     that is what was asked for. Neither setting buffers or drops, so the
//     interface's suggested escape hatch is not implemented: dropping under
//     load is the backpressure policy, an open decision that cannot be settled
//     before M5 and M6 establish what the kernel side does under load. See
//     TODO(audit) at the bottom of this file.
package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/stringNameMahin/ALLSEER/internal/config"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
)

// FormatJSONL is the only audit format this build writes.
//
// config.AuditConfig documents "jsonl" or "cbor". CBOR is named and not
// implemented, and an unimplemented format is refused at Open rather than
// silently downgraded to this one — an operator who configured cbor and got
// JSONL would have an audit log in a format nothing they built expects, and
// would not find out until they tried to read it.
const FormatJSONL = "jsonl"

// FileMode is the permission the audit file is created with.
//
// Owner read/write only. The audit log records what an agent was caught doing,
// so an agent that can read it learns what is watched and an agent that can
// write it can rewrite the evidence. 0600 is the narrowest mode that still lets
// the daemon append.
//
// Applied at creation only. An existing file keeps whatever mode it has:
// silently chmod-ing a file the operator placed deliberately would be this
// package overriding a decision that was not its to make. Verifying the mode of
// an existing log is a startup check and belongs with the rest of the daemon's
// permission checks, not here.
const FileMode os.FileMode = 0o600

// Errors reported for a sink that cannot be used as configured.
var (
	// ErrNoPath means AuditConfig.Path was empty. Not defaulted: an audit log
	// written to a guessed location is an audit log nobody finds.
	ErrNoPath = errors.New("audit: path is required")

	// ErrUnsupportedFormat means AuditConfig.Format named something this build
	// does not write.
	ErrUnsupportedFormat = errors.New("audit: unsupported format")

	// ErrClosed means Emit or Flush was called after Close.
	ErrClosed = errors.New("audit: sink is closed")
)

// syncWriteCloser is the file behavior this sink needs.
//
// Named as an interface rather than taking *os.File so the failure paths can be
// tested. A write error on a real file requires a full disk or a revoked
// descriptor, neither of which a unit test can arrange portably, and an audit
// writer whose error handling is never exercised is an audit writer whose error
// handling is a guess.
type syncWriteCloser interface {
	io.Writer
	Sync() error
	Close() error
}

// JSONLSink is an append-only JSONL implementation of decision.Sink.
//
// Safe for concurrent use. The pipeline processes one session serially on one
// goroutine, so a sink serving a single pipeline would need no lock — but that
// is a guarantee about a pipeline, not about a sink. One audit file is a
// process-wide resource that several session pipelines are expected to share,
// and Flush and Close arrive from whichever goroutine is running shutdown. The
// lock is held across the encode and the write so two decisions can never
// interleave within a line.
type JSONLSink struct {
	mu sync.Mutex

	w      syncWriteCloser
	closed bool

	// buf is scratch for one record. Reused across Emit calls to keep the
	// serializer off the allocator on the hot path; empty between calls, so it
	// is not a queue and holds nothing that a missing Flush could lose.
	buf bytes.Buffer
	enc *json.Encoder

	syncWrites bool
	recordAll  bool

	path string

	written  uint64
	filtered uint64
	errors   uint64
}

var _ decision.Sink = (*JSONLSink)(nil)

// Stats reports what the sink has done. Counters, not health: a sink that is
// failing every write still returns, and Errors is how a caller notices.
type Stats struct {
	// Written is the number of decisions that reached the file.
	Written uint64 `json:"written"`

	// Filtered is the number suppressed by RecordAllEvents=false. Counted
	// rather than forgotten, so "the log is short" can be told apart from "the
	// session was quiet".
	Filtered uint64 `json:"filtered"`

	// Errors is the number of Emit and Flush calls that failed.
	Errors uint64 `json:"errors"`
}

// Open creates or appends to the audit file named by cfg.
//
// The file is opened O_APPEND and never O_TRUNC. Truncating an existing audit
// log on startup would destroy the record of the previous run, which is both
// the least recoverable data the daemon holds and precisely what an attacker
// who can restart the daemon would want.
func Open(cfg config.AuditConfig) (*JSONLSink, error) {
	if cfg.Path == "" {
		return nil, ErrNoPath
	}
	// "" is jsonl. config.Defaults() does not exist yet (TODO(config)), so a
	// zero AuditConfig is a shape callers really do hold, and refusing it would
	// make the only implemented format the one you have to name explicitly.
	if cfg.Format != "" && cfg.Format != FormatJSONL {
		return nil, fmt.Errorf("%w: %q; this build writes %q only",
			ErrUnsupportedFormat, cfg.Format, FormatJSONL)
	}

	f, err := os.OpenFile(cfg.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, FileMode)
	if err != nil {
		return nil, fmt.Errorf("audit: opening %s: %w", cfg.Path, err)
	}

	s := newSink(f, cfg)
	s.path = cfg.Path
	return s, nil
}

// newSink wires a sink over an already-open destination.
func newSink(w syncWriteCloser, cfg config.AuditConfig) *JSONLSink {
	s := &JSONLSink{
		w:          w,
		syncWrites: cfg.SyncWrites,
		recordAll:  cfg.RecordAllEvents,
	}
	s.enc = json.NewEncoder(&s.buf)
	return s
}

// Path reports the file this sink writes to, for diagnostics.
func (s *JSONLSink) Path() string { return s.path }

// Emit appends one decision as one line.
//
// The Decision is taken by value and only read. Its slices and maps are shared
// with the caller and are not modified, so a caller may keep using the value it
// passed — a sink that normalized a record in place would silently change what
// the rest of the pipeline sees.
//
// ctx is accepted for the interface and deliberately not honored as a
// cancellation signal. Shutdown cancels the context that is in flight, and a
// sink that refused to write on a cancelled context would drop exactly the
// records a shutdown is most likely to matter for. The write is bounded by one
// syscall, so there is nothing here that a cancellation would usefully abort.
func (s *JSONLSink) Emit(_ context.Context, d decision.Decision) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrClosed
	}
	if !s.recordAll && routine(d) {
		s.filtered++
		return nil
	}

	s.buf.Reset()
	// Encode appends the trailing newline itself, which is the whole line
	// discipline. Serialization goes to the scratch buffer rather than straight
	// to the file so that a record reaches the file in one write: with O_APPEND
	// that keeps a line whole, where an encoder writing directly could
	// interleave two decisions from two sessions sharing this sink.
	if err := s.enc.Encode(d); err != nil {
		s.errors++
		return fmt.Errorf("audit: encoding decision %s: %w", d.ID, err)
	}

	if _, err := s.w.Write(s.buf.Bytes()); err != nil {
		// A short or failed write may already have put a partial line on disk,
		// and there is no unwriting it. Reported rather than repaired: a reader
		// of a JSONL log can see a malformed final line, and a writer that
		// tried to patch over its own failure would produce a log that looks
		// intact and is not.
		s.errors++
		return fmt.Errorf("audit: writing decision %s: %w", d.ID, err)
	}

	if s.syncWrites {
		if err := s.w.Sync(); err != nil {
			s.errors++
			return fmt.Errorf("audit: syncing decision %s: %w", d.ID, err)
		}
	}

	s.written++
	return nil
}

// Flush makes everything written so far durable.
//
// One fsync, no buffer drain, because there is no buffer to drain — see the
// package doc on why this sink does not buffer across calls. Flush is therefore
// about surviving a machine crash rather than about not losing records at
// shutdown, and it is safe and meaningful to call on a sink that has emitted
// nothing.
//
// Redundant but harmless under SyncWrites, which has already synced every
// record. Callers should not have to know which mode they are in.
func (s *JSONLSink) Flush(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrClosed
	}
	if err := s.w.Sync(); err != nil {
		s.errors++
		return fmt.Errorf("audit: flushing %s: %w", s.path, err)
	}
	return nil
}

// Close syncs and releases the file.
//
// Not part of decision.Sink, which declares only Emit and Flush. It is on the
// concrete type because this one owns a file descriptor and something has to
// hand it back; adding it to the interface would oblige every sink — a stdout
// printer, a test recorder — to have a lifecycle it does not have.
//
// Idempotent, so it can be deferred beside an explicit call. Emit and Flush
// after Close report ErrClosed rather than silently discarding, since a
// discarded decision is the failure this whole package exists to prevent.
func (s *JSONLSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true

	syncErr := s.w.Sync()
	closeErr := s.w.Close()
	if syncErr != nil {
		s.errors++
		return fmt.Errorf("audit: syncing %s on close: %w", s.path, syncErr)
	}
	if closeErr != nil {
		s.errors++
		return fmt.Errorf("audit: closing %s: %w", s.path, closeErr)
	}
	return nil
}

// Stats reports the sink's counters. Safe from any goroutine.
func (s *JSONLSink) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Stats{Written: s.written, Filtered: s.filtered, Errors: s.errors}
}

// routine reports whether a decision is the uninteresting common case that
// RecordAllEvents=false suppresses.
//
// The question config.AuditConfig poses and does not answer is whether an allow
// is recorded. It is: routine means the envelope covered the operation *and*
// policy allowed it. Both halves are required, because they are separate
// findings — a within-envelope event can still be warned on by a risk-
// conditioned rule, and that rule firing is the whole reason the rule exists.
// Anything else, including every verdict that is not within_envelope and every
// indeterminate decision from a stage failure, is recorded whatever this
// setting says.
//
// The default is false — configs/allseerd.example.yaml sets record_all_events
// to false and calls the alternative expensive — so the shipped posture is
// violations only, and replay-based development turns it on.
func routine(d decision.Decision) bool {
	return d.Verdict == decision.VerdictWithinEnvelope && d.Action == ece.ActionAllow
}

// TODO(audit): rotation and retention, per config.AuditConfig.MaxSizeMB and
// RetentionDays. Deliberately not here: both are daemon lifecycle concerns (M7)
// and rotation in particular has to agree with whatever the tamper-evidence
// decision turns out to be, since a rotated file is a chain boundary.
// TODO(audit): the "cbor" format config.AuditConfig names. Refused at Open
// rather than stubbed, so the gap is loud.
// TODO(audit): hash chaining for tamper evidence, which TODO(decision) in
// pkg/decision raises and does not settle. It needs the threat-model answer
// first — the agent may run as the same user as the daemon in the single-user
// development case, and a chain that user can recompute proves nothing.
// TODO(audit): the drop-with-a-counter behavior decision.Sink's contract
// suggests. It cannot be written before the end-to-end backpressure policy
// exists, which is an open decision recorded in internal/pipeline, pkg/event,
// and docs/dataflow.md, and which M5 and M6 have to inform.
