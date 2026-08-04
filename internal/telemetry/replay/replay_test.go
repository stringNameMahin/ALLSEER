package replay

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// drain collects every event the source delivers, failing the test if the
// stream does not finish promptly. A hang here is a real bug, since the
// pipeline would hang the same way, so it is surfaced as a failure rather than
// left to the package test timeout.
func drain(t *testing.T, s *Source) []event.Event {
	t.Helper()

	var got []event.Event
	timeout := time.After(5 * time.Second)
	for {
		select {
		case e, ok := <-s.Events():
			if !ok {
				return got
			}
			got = append(got, e)
		case <-timeout:
			t.Fatalf("timed out after %d events; the stream never closed", len(got))
			return nil
		}
	}
}

func startString(t *testing.T, cfg Config, stream string) *Source {
	t.Helper()

	cfg.Reader = strings.NewReader(stream)
	s := New(cfg)
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

const threeEvents = `
// A minimal stream: two reads inside the workspace, then a connect.
{"id":"e1","session_id":"s1","sequence":1,"kernel_timestamp":1000,"capability":"fs.read","domain":"filesystem","syscall":"openat"}
{"id":"e2","session_id":"s1","sequence":2,"kernel_timestamp":2000,"capability":"fs.read","domain":"filesystem","syscall":"openat"}
{"id":"e3","session_id":"s1","sequence":3,"kernel_timestamp":3000,"capability":"net.connect","domain":"network","syscall":"connect"}
`

func TestReplayDeliversEventsInFileOrder(t *testing.T) {
	s := startString(t, Config{}, threeEvents)
	got := drain(t, s)

	if len(got) != 3 {
		t.Fatalf("delivered %d events, want 3", len(got))
	}
	for i, want := range []string{"e1", "e2", "e3"} {
		if got[i].ID != want {
			t.Errorf("event %d: ID = %q, want %q", i, got[i].ID, want)
		}
		if got[i].Sequence != uint64(i+1) {
			t.Errorf("event %d: Sequence = %d, want %d", i, got[i].Sequence, i+1)
		}
	}
	if got[2].Capability != capability.KindNetConnect {
		t.Errorf("event 2: Capability = %q, want %q", got[2].Capability, capability.KindNetConnect)
	}
	if err := s.Err(); err != nil {
		t.Errorf("Err() = %v, want nil on a clean stream", err)
	}
}

// Blank lines and // comments let a hand-written fixture explain which escape
// or scenario it exercises. Machine-produced streams contain neither.
func TestReplaySkipsBlankLinesAndComments(t *testing.T) {
	const stream = `
// leading comment

{"id":"e1","session_id":"s1","sequence":1}
   // indented comment

{"id":"e2","session_id":"s1","sequence":2}
`
	s := startString(t, Config{}, stream)
	if got := drain(t, s); len(got) != 2 {
		t.Fatalf("delivered %d events, want 2", len(got))
	}
	if s.Stats().DecodeErrors != 0 {
		t.Errorf("DecodeErrors = %d, want 0; comments must not count as malformed",
			s.Stats().DecodeErrors)
	}
}

// Ordering is file order, full stop. A recording whose timestamps disagree with
// its order is a recording bug; sorting it here would hide the bug and break
// the pipeline's per-session ordering guarantee at the same time.
func TestReplayDoesNotReorderByTimestamp(t *testing.T) {
	const stream = `
{"id":"first","session_id":"s1","sequence":1,"kernel_timestamp":9000}
{"id":"second","session_id":"s1","sequence":2,"kernel_timestamp":1000}
`
	got := drain(t, startString(t, Config{}, stream))
	if len(got) != 2 {
		t.Fatalf("delivered %d events, want 2", len(got))
	}
	if got[0].ID != "first" || got[1].ID != "second" {
		t.Errorf("stream was reordered: got %q then %q", got[0].ID, got[1].ID)
	}
}

// Every event must be independently interpretable, so a record with no ID gets
// a deterministic one. Deterministic because golden-file decision tests compare
// full streams and a random ID would make them unstable.
func TestReplaySynthesizesMissingIDDeterministically(t *testing.T) {
	const stream = `{"session_id":"s1","sequence":7}`

	first := drain(t, startString(t, Config{}, stream))
	second := drain(t, startString(t, Config{}, stream))

	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("delivered %d and %d events, want 1 each", len(first), len(second))
	}
	if first[0].ID != "s1/7" {
		t.Errorf("synthesized ID = %q, want %q", first[0].ID, "s1/7")
	}
	if first[0].ID != second[0].ID {
		t.Errorf("synthesized IDs are not deterministic: %q then %q", first[0].ID, second[0].ID)
	}
}

func TestReplayPreservesExplicitID(t *testing.T) {
	got := drain(t, startString(t, Config{}, `{"id":"recorded-id","session_id":"s1","sequence":1}`))
	if got[0].ID != "recorded-id" {
		t.Errorf("ID = %q, want the recorded value preserved", got[0].ID)
	}
}

func TestReplaySessionIDOverride(t *testing.T) {
	s := startString(t, Config{SessionID: "live-session"}, threeEvents)
	for _, e := range drain(t, s) {
		if e.SessionID != "live-session" {
			t.Errorf("SessionID = %q, want the override applied", e.SessionID)
		}
	}
}

// A recording that lost ring buffer records carries that loss in its Dropped
// counters. Replay must reproduce it exactly, or every fail-closed test built
// on replay is vacuous.
func TestReplayReproducesDroppedCounters(t *testing.T) {
	const stream = `
{"id":"e1","session_id":"s1","sequence":1}
{"id":"e2","session_id":"s1","sequence":2,"dropped":17}
{"id":"e3","session_id":"s1","sequence":3,"dropped":3}
`
	s := startString(t, Config{}, stream)
	got := drain(t, s)

	if got[1].Dropped != 17 {
		t.Errorf("event 1 Dropped = %d, want 17 preserved on the event itself", got[1].Dropped)
	}
	if n := s.Stats().DroppedEvents; n != 20 {
		t.Errorf("Stats().DroppedEvents = %d, want 20", n)
	}
	if n := s.Stats().EventsReceived; n != 3 {
		t.Errorf("Stats().EventsReceived = %d, want 3", n)
	}
}

// A gap in Sequence is independent evidence of loss, and it must survive replay
// rather than being renumbered into a dense stream that looks complete.
func TestReplayReproducesSequenceGaps(t *testing.T) {
	const stream = `
{"id":"e1","session_id":"s1","sequence":1}
{"id":"e2","session_id":"s1","sequence":2}
// records 3 through 40 were lost in the ring buffer
{"id":"e3","session_id":"s1","sequence":41}
{"id":"e4","session_id":"s1","sequence":42}
`
	s := startString(t, Config{}, stream)
	got := drain(t, s)

	if got[2].Sequence != 41 {
		t.Errorf("Sequence = %d, want 41 preserved rather than renumbered", got[2].Sequence)
	}
	if n := s.SequenceGaps(); n != 1 {
		t.Errorf("SequenceGaps() = %d, want 1", n)
	}
}

// A recording carrying a gap with no Dropped count is the more worrying case:
// the loss went uncounted. The two signals are reported separately so that
// case is visible.
func TestReplayReportsGapWithoutDroppedCounter(t *testing.T) {
	const stream = `
{"id":"e1","session_id":"s1","sequence":1}
{"id":"e2","session_id":"s1","sequence":9}
`
	s := startString(t, Config{}, stream)
	drain(t, s)

	if s.SequenceGaps() != 1 {
		t.Errorf("SequenceGaps() = %d, want 1", s.SequenceGaps())
	}
	if n := s.Stats().DroppedEvents; n != 0 {
		t.Errorf("Stats().DroppedEvents = %d, want 0; the recording counted no loss", n)
	}
}

// Unnumbered fixtures are convenient to hand-write and must not report
// spurious loss.
func TestReplayUnnumberedStreamReportsNoGaps(t *testing.T) {
	const stream = `
{"id":"e1","session_id":"s1"}
{"id":"e2","session_id":"s1"}
{"id":"e3","session_id":"s1"}
`
	s := startString(t, Config{}, stream)
	if got := drain(t, s); len(got) != 3 {
		t.Fatalf("delivered %d events, want 3", len(got))
	}
	if n := s.SequenceGaps(); n != 0 {
		t.Errorf("SequenceGaps() = %d, want 0 for an unnumbered stream", n)
	}
}

// The default is fail-closed: a corrupt recording ends the stream with a
// reported error rather than being silently truncated into something that
// looks like a complete session.
func TestReplayMalformedRecordStopsStreamByDefault(t *testing.T) {
	const stream = `
{"id":"e1","session_id":"s1","sequence":1}
{"id":"e2", THIS IS NOT JSON
{"id":"e3","session_id":"s1","sequence":3}
`
	s := startString(t, Config{}, stream)
	got := drain(t, s)

	if len(got) != 1 {
		t.Fatalf("delivered %d events, want 1 before the malformed line", len(got))
	}
	err := s.Err()
	if err == nil {
		t.Fatal("Err() = nil; a malformed record must not end the stream silently")
	}
	if !strings.Contains(err.Error(), "line 3") {
		t.Errorf("Err() = %v, want the offending line number named", err)
	}
	if n := s.Stats().DecodeErrors; n != 1 {
		t.Errorf("Stats().DecodeErrors = %d, want 1", n)
	}
}

func TestReplaySkipMalformedContinues(t *testing.T) {
	const stream = `
{"id":"e1","session_id":"s1","sequence":1}
not json at all
{"id":"e3","session_id":"s1","sequence":3}
`
	s := startString(t, Config{SkipMalformed: true}, stream)
	got := drain(t, s)

	if len(got) != 2 {
		t.Fatalf("delivered %d events, want 2", len(got))
	}
	if s.Err() != nil {
		t.Errorf("Err() = %v, want nil with SkipMalformed set", s.Err())
	}
	if n := s.Stats().DecodeErrors; n != 1 {
		t.Errorf("Stats().DecodeErrors = %d, want 1; skipped is not the same as unnoticed", n)
	}
}

func TestReplayOpenMissingFile(t *testing.T) {
	s := Open(filepath.Join(t.TempDir(), "does-not-exist.jsonl"))
	if err := s.Start(context.Background()); err == nil {
		t.Fatal("Start on a missing file returned nil error")
	}
	// The consumer must be released rather than left blocked on a channel
	// nothing will ever close.
	if got := drain(t, s); len(got) != 0 {
		t.Errorf("delivered %d events from a failed open", len(got))
	}
	if err := s.Close(); err != nil {
		t.Errorf("Close after a failed Start: %v", err)
	}
}

func TestReplayCloseIsIdempotent(t *testing.T) {
	s := startString(t, Config{}, threeEvents)
	for i := 0; i < 3; i++ {
		if err := s.Close(); err != nil {
			t.Fatalf("Close #%d: %v", i+1, err)
		}
	}
}

func TestReplayCloseBeforeStart(t *testing.T) {
	s := New(Config{Reader: strings.NewReader(threeEvents)})
	if err := s.Close(); err != nil {
		t.Fatalf("Close before Start: %v", err)
	}
	if got := drain(t, s); len(got) != 0 {
		t.Errorf("delivered %d events after Close", len(got))
	}
	if err := s.Start(context.Background()); err == nil {
		t.Error("Start after Close returned nil error")
	}
}

func TestReplayStartTwice(t *testing.T) {
	s := startString(t, Config{}, threeEvents)
	if err := s.Start(context.Background()); err == nil {
		t.Error("second Start returned nil error; a Source is single-use")
	}
}

func TestReplayContextCancellationStopsStream(t *testing.T) {
	// One event of buffer, many events to read: the reader blocks on send, so
	// cancellation is observed mid-stream rather than after everything is
	// already buffered.
	var b strings.Builder
	for i := 1; i <= 500; i++ {
		b.WriteString(`{"session_id":"s1","sequence":`)
		b.WriteString(strings.TrimSpace(strings.Repeat(" ", 0)))
		b.WriteString(itoa(i))
		b.WriteString("}\n")
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := New(Config{Reader: strings.NewReader(b.String()), BufferSize: 1})
	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	<-s.Events() // take one, leave the reader blocked
	cancel()

	got := drain(t, s)
	if len(got) >= 500 {
		t.Errorf("delivered %d events after cancellation, want the stream cut short", len(got))
	}
	if err := s.Err(); err != nil {
		t.Errorf("Err() = %v, want nil; cancellation is a normal termination", err)
	}
}

// Paced playback derives delays from KernelTimestamp deltas. Asserted loosely:
// the point is that pacing happens at all, and a tight bound would make this
// flaky on a loaded CI machine.
func TestReplayPacedPlayback(t *testing.T) {
	// 60ms of kernel time at 2x should take roughly 30ms.
	const stream = `
{"id":"e1","session_id":"s1","sequence":1,"kernel_timestamp":0}
{"id":"e2","session_id":"s1","sequence":2,"kernel_timestamp":60000000}
`
	start := time.Now()
	s := startString(t, Config{Speed: 2.0, BufferSize: 1}, stream)
	drain(t, s)
	elapsed := time.Since(start)

	if elapsed < 15*time.Millisecond {
		t.Errorf("paced playback finished in %v; timestamps were not honored", elapsed)
	}
	if elapsed > 2*time.Second {
		t.Errorf("paced playback took %v, far beyond the expected ~30ms", elapsed)
	}
}

func TestReplayUnpacedIsFast(t *testing.T) {
	// The same stream with no pacing must not wait on timestamps at all.
	const stream = `
{"id":"e1","session_id":"s1","sequence":1,"kernel_timestamp":0}
{"id":"e2","session_id":"s1","sequence":2,"kernel_timestamp":5000000000}
`
	start := time.Now()
	drain(t, startString(t, Config{}, stream))

	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("unpaced playback took %v; it must not honor timestamps", elapsed)
	}
}

func TestReplayConfigWithNoSource(t *testing.T) {
	s := New(Config{})
	if err := s.Start(context.Background()); err == nil {
		t.Fatal("Start with neither Path nor Reader returned nil error")
	}
}

func TestReplayEmptyStream(t *testing.T) {
	s := startString(t, Config{}, "")
	if got := drain(t, s); len(got) != 0 {
		t.Errorf("delivered %d events from an empty stream", len(got))
	}
	if s.Err() != nil {
		t.Errorf("Err() = %v, want nil; an empty stream is valid", s.Err())
	}
}

// itoa avoids pulling strconv into the test for one call site.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
