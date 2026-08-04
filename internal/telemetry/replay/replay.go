// Package replay implements event.Source over a recorded event stream on disk.
//
// This is the seam that makes the deterministic core developable without a
// kernel, without root, and without Linux. The validator, risk engine, policy
// engine, and CLI all consume event.Source, and none of them can tell whether
// the events came from an eBPF ring buffer or from a file. That is what makes
// `allseerctl policy dry-run` possible, what makes the Phase 6 evaluation
// corpus replayable, and what lets a recorded session be re-decided against a
// candidate rule set before an operator trusts it.
//
// # Stream format
//
// JSON Lines: one JSON-encoded pkg/event.Event per line, UTF-8, LF or CRLF
// terminated. It is the wire form of Event, so a stream can be produced by the
// daemon's recorder, by the synthetic generator, or by hand.
//
//	{"id":"evt-1","session_id":"s1","sequence":1,"kernel_timestamp":1000, ...}
//	{"id":"evt-2","session_id":"s1","sequence":2,"kernel_timestamp":1200, ...}
//
// Two conveniences let hand-written fixtures explain themselves. Neither
// appears in machine-produced streams:
//
//   - Blank lines are skipped.
//   - Lines whose first non-whitespace characters are "//" are skipped.
//
// Everything else must parse. A malformed line means a corrupt recording, and
// by default it stops the stream rather than being skipped. See Config.
//
// # Reproduced verbatim
//
// Sequence and Dropped are read from the file as recorded and never recomputed.
// That is the whole reason fail-closed paths can be exercised here: a recording
// that lost ring buffer records carries the loss in its Dropped counters and
// sequence gaps, and replaying it has to reproduce the same gap rather than
// paper over it with fresh dense numbering. A replay that renumbered would make
// every fail-closed test vacuous.
//
// Ordering is file order, and file order is authoritative. The source never
// sorts by timestamp or sequence: a recording whose order is wrong is a
// recording bug, and reordering here would hide it while breaking the
// per-session ordering guarantee the pipeline depends on.
//
// # Filled in
//
// Only Event.ID, and only when the record omits it, using a deterministic
// "<session>/<sequence>" form. Every event must be independently interpretable,
// and a blank ID breaks that. Determinism matters because golden-file tests
// compare decision streams, where a random ID would be unstable.
//
// # Timing
//
// Playback defaults to as fast as the consumer can take events, which is what
// tests and batch analysis want. Config.Speed enables wall-clock pacing derived
// from KernelTimestamp deltas, for demos and for latency measurement where the
// arrival pattern matters.
package replay

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// DefaultBufferSize is the depth of the outbound event channel. Large enough
// that a briefly slow consumer does not serialize the reader against disk,
// small enough that backpressure still reaches the reader instead of buffering
// an entire corpus in memory.
const DefaultBufferSize = 256

// Config configures a replay source.
type Config struct {
	// Path is the JSONL stream to read. Ignored when Reader is set.
	Path string

	// Reader supplies the stream directly, for tests and for streams that are
	// not files. Takes precedence over Path. If it implements io.Closer, Close
	// closes it.
	Reader io.Reader

	// Speed is the wall-clock playback multiplier derived from KernelTimestamp
	// deltas. Zero or negative means as fast as possible, which is the default
	// and what tests want. 1.0 replays at the original rate, 2.0 at twice that.
	Speed float64

	// BufferSize is the outbound channel depth. Zero uses DefaultBufferSize.
	BufferSize int

	// SessionID overrides the SessionID on every record when non-empty. Useful
	// for feeding a recorded fixture into a freshly created session without
	// rewriting the file.
	SessionID string

	// SkipMalformed continues past lines that fail to parse, counting them in
	// SourceStats.DecodeErrors instead of ending the stream.
	//
	// It defaults to false. A malformed line means the recording is corrupt,
	// and a corrupt recording cannot support the conclusion that the agent did
	// not do something. Skipping quietly would make a truncated file look like
	// a complete session, the same class of failure as treating an unresolvable
	// path as safe. Set this only for corpora containing malformed records on
	// purpose, such as decoder fuzzing inputs.
	SkipMalformed bool
}

// Source replays a recorded event stream. It implements event.Source.
//
// A Source is single-use: Start may be called once, and once the stream is
// exhausted or Close has been called it cannot be restarted. Reuse would mean
// re-opening the file, and an interface that looks restartable but replays from
// a stale offset is worse than one that does not.
type Source struct {
	cfg Config

	events chan event.Event

	// startOnce and closeOnce keep Start single-shot and Close idempotent, the
	// latter being required by event.Source.
	startOnce sync.Once
	closeOnce sync.Once

	// cancel stops the reader goroutine. Set by Start.
	cancel context.CancelFunc

	// done closes when the reader goroutine has returned, so Close can wait for
	// it and callers can be sure Err is final.
	done chan struct{}

	// rc is the underlying stream, kept so Close can release it.
	rc io.Closer

	mu       sync.Mutex
	stats    event.SourceStats
	started  time.Time
	gaps     uint64
	lastSeq  uint64
	haveLast bool
	err      error

	// closed guards against a Start that follows a Close. Without it, the
	// reader goroutine would close channels Close had already closed.
	closed bool
}

var _ event.Source = (*Source)(nil)

// Open returns a replay source reading the given JSONL file at full speed.
func Open(path string) *Source {
	return New(Config{Path: path})
}

// New returns a replay source for the given configuration. The stream is not
// opened until Start is called, so constructing a Source cannot fail.
func New(cfg Config) *Source {
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = DefaultBufferSize
	}
	return &Source{
		cfg:    cfg,
		events: make(chan event.Event, cfg.BufferSize),
		done:   make(chan struct{}),
	}
}

// Events returns the event stream. The channel closes when the recording is
// exhausted, Close is called, or the reader stops on a malformed record.
//
// A closed channel alone does not mean the stream completed successfully. A
// fail-closed governance path must check Err after the channel closes.
func (s *Source) Events() <-chan event.Event { return s.events }

// Start opens the stream and begins delivering events. It returns as soon as
// the stream is open; delivery continues in the background until the recording
// is exhausted, ctx is cancelled, or Close is called.
//
// Returns an error if the stream cannot be opened, or if Start has already been
// called.
func (s *Source) Start(ctx context.Context) error {
	s.mu.Lock()
	alreadyClosed := s.closed
	s.mu.Unlock()
	if alreadyClosed {
		return errors.New("replay: Start after Close; a Source is single-use")
	}

	var err error
	called := false

	s.startOnce.Do(func() {
		called = true

		var r io.Reader
		switch {
		case s.cfg.Reader != nil:
			r = s.cfg.Reader
			if c, ok := s.cfg.Reader.(io.Closer); ok {
				s.rc = c
			}
		case s.cfg.Path != "":
			f, openErr := os.Open(s.cfg.Path)
			if openErr != nil {
				err = fmt.Errorf("replay: opening stream: %w", openErr)
				return
			}
			r = f
			s.rc = f
		default:
			err = errors.New("replay: config has neither Path nor Reader")
			return
		}

		runCtx, cancel := context.WithCancel(ctx)
		s.cancel = cancel

		s.mu.Lock()
		s.started = time.Now()
		s.mu.Unlock()

		go s.run(runCtx, r)
	})

	if !called && err == nil {
		return errors.New("replay: Start already called; a Source is single-use")
	}
	if err != nil {
		// Opening failed, so no reader goroutine will ever run. Release the
		// consumer instead of leaving it blocked on a channel nothing will
		// close. Routed through closeOnce so a later Close is a no-op rather
		// than a double close. rc is always nil here; it is only set after the
		// open succeeds.
		s.closeOnce.Do(func() {
			s.mu.Lock()
			s.closed = true
			s.mu.Unlock()
			close(s.events)
			close(s.done)
		})
	}
	return err
}

// Close stops delivery and releases the stream. Safe to call more than once,
// and safe to call before Start.
func (s *Source) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()

		if s.cancel != nil {
			s.cancel()
			<-s.done // the reader owns the channel and the file; let it finish
		} else {
			// Never started. Release anything Start would have released, so a
			// consumer that already selected on Events is not left blocked.
			close(s.events)
			close(s.done)
		}
		if s.rc != nil {
			_ = s.rc.Close()
		}
	})
	return nil
}

// Stats reports replay progress.
//
// DroppedEvents accumulates the Dropped field of every delivered event: the
// loss the original recording observed, not loss introduced by replay, which
// cannot happen. RingBufferUsage is always zero, since there is no ring buffer
// here and inventing a plausible number for one would be worse than reporting
// nothing.
func (s *Source) Stats() event.SourceStats {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := s.stats
	if !s.started.IsZero() {
		out.Uptime = time.Since(s.started)
	}
	return out
}

// Err returns the error that ended the stream, or nil if it ended normally or
// is still running.
//
// Context cancellation and Close are normal terminations and do not set an
// error. A malformed record with SkipMalformed unset does.
func (s *Source) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// SequenceGaps returns how many discontinuities were seen in the recorded
// Sequence numbering.
//
// A gap is direct evidence of ring buffer loss in the original capture. It is
// reported separately from the Dropped counters because the two are
// independent: a recording can carry Dropped counts with no gap when the loss
// was reported but numbering stayed dense, and a gap with no Dropped count
// means the loss went uncounted, which is the worse case. Across either kind of
// hole, "the agent never did X" is unsound.
func (s *Source) SequenceGaps() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gaps
}

// run reads the stream and delivers events until exhausted or cancelled. It
// owns the events channel and closes it on return.
func (s *Source) run(ctx context.Context, r io.Reader) {
	defer close(s.done)
	defer close(s.events)

	sc := bufio.NewScanner(r)

	// Kernel records carry bounded paths and argv, but an enriched record with
	// a long resolved path and full argv can exceed bufio's 64 KiB default.
	// Allow 1 MiB per line so a legitimate record is never reported as corrupt.
	const maxLine = 1 << 20
	sc.Buffer(make([]byte, 0, 64*1024), maxLine)

	var (
		lineNo    int
		delivered int
		baseKTS   uint64
		haveBase  bool
		wallStart = time.Now()
		paced     = s.cfg.Speed > 0
	)

	for sc.Scan() {
		lineNo++

		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		var e event.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			s.mu.Lock()
			s.stats.DecodeErrors++
			s.mu.Unlock()

			if s.cfg.SkipMalformed {
				continue
			}
			s.fail(fmt.Errorf("replay: line %d: %w", lineNo, err))
			return
		}

		if s.cfg.SessionID != "" {
			e.SessionID = s.cfg.SessionID
		}
		if e.ID == "" {
			e.ID = e.SessionID + "/" + strconv.FormatUint(e.Sequence, 10)
		}

		if paced {
			if !haveBase {
				baseKTS, haveBase = e.KernelTimestamp, true
			}
			if !s.wait(ctx, wallStart, baseKTS, e.KernelTimestamp) {
				return
			}
		}

		s.observe(&e)

		select {
		case s.events <- e:
			delivered++
		case <-ctx.Done():
			return
		}
	}

	if err := sc.Err(); err != nil {
		s.fail(fmt.Errorf("replay: reading stream after %d events: %w", delivered, err))
	}
}

// observe records per-event statistics, including sequence discontinuities.
func (s *Source) observe(e *event.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.stats.EventsReceived++
	s.stats.DroppedEvents += e.Dropped

	// Sequence is per-session and monotonic, so anything other than +1 from the
	// previous record is a hole. Sequence 0 counts as unnumbered rather than as
	// a gap, so hand-written fixtures that skip numbering do not report
	// spurious loss.
	if s.haveLast && e.Sequence != 0 && e.Sequence != s.lastSeq+1 {
		s.gaps++
	}
	if e.Sequence != 0 {
		s.lastSeq = e.Sequence
		s.haveLast = true
	}
}

// wait paces delivery against the original capture's timeline. Returns false if
// ctx was cancelled while waiting.
func (s *Source) wait(ctx context.Context, wallStart time.Time, baseKTS, kts uint64) bool {
	if kts < baseKTS {
		// Timestamps are monotonic, so this means the recording is out of
		// order. File order is authoritative, so deliver immediately rather
		// than sorting.
		return true
	}

	offset := time.Duration(float64(kts-baseKTS) / s.cfg.Speed)
	delay := time.Until(wallStart.Add(offset))
	if delay <= 0 {
		return true
	}

	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// fail records the error that ended the stream. The first error wins; later
// ones cannot occur because run returns immediately after calling this.
func (s *Source) fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err == nil {
		s.err = err
	}
}
