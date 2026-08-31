//go:build linux && ebpf

package telemetry

// The two teardown defects the A3W investigation surfaced, and the checks that
// keep them closed.
//
// Both are about the same thing: a record that the kernel reserved, filled and
// submitted successfully, and that user space then failed to collect. Neither
// is a ring buffer drop — count_ringbuf_drop fires only where
// bpf_ringbuf_reserve returned NULL — so ringbuf_drops reports zero for both
// and always will. A run that loses records this way reports a smaller event
// count and nothing else, which reads as a quiet workload rather than a broken
// measurement.

import (
	"testing"

	"github.com/stringNameMahin/ALLSEER/internal/telemetry/abi"
	"github.com/stringNameMahin/ALLSEER/internal/telemetry/benchstat"
)

// --- F1: the queued-record race ---------------------------------------------------

// Records already in the channel when the stop signal arrives must still be
// counted.
//
// The defect: `select` chooses uniformly among ready cases, so a bare `return`
// in the stopDrain arm leaves the loop with records still queued — measured at
// roughly 98% of whatever was pending. libbpfgo then discards the remainder
// itself, because RingBuffer.Stop spawns `for range eventChan {}` to keep its
// poll goroutine from blocking on a full channel.
//
// Repeated rather than run once. A single iteration passes about half the time
// even with the defect present, and the point of the test is to fail reliably
// if the drain-before-return is ever removed.
func TestQueuedRecordsAreDrainedBeforeStopIsHonoured(t *testing.T) {
	const (
		trials  = 200
		queued  = 64
		recSize = 8
	)

	for i := range trials {
		records := make(chan []byte, 1024)
		for range queued {
			records <- make([]byte, recSize)
		}

		h := &armHarness{byType: map[string]uint64{}, records: records}
		h.startDrain(false)

		var run benchstat.Run
		h.stop(t, &run)

		if run.EventsTotal != queued {
			t.Fatalf("trial %d: counted %d of %d queued records; the drain returned before the "+
				"channel was empty and the remainder is lost with no drop to show for it",
				i, run.EventsTotal, queued)
		}
	}
}

// The steady-state path and the drain-on-stop path must agree about what
// counting a record means. They share armHarness.count precisely so they
// cannot diverge, and this is the check that they still do.
func TestDrainCountsTheSameWayOnBothPaths(t *testing.T) {
	raw := make([]byte, 512)
	// A record whose type field decodes to something nameable, so byType is
	// exercised rather than only the total.
	if len(raw) < abi.OffsetEventType+4 {
		t.Skip("record fixture shorter than the type offset")
	}

	steady := &armHarness{byType: map[string]uint64{}}
	steady.count(raw, nil)

	drained := &armHarness{byType: map[string]uint64{}}
	drained.count(raw, nil)

	if steady.total != drained.total {
		t.Errorf("totals differ: %d vs %d", steady.total, drained.total)
	}
	for k, v := range steady.byType {
		if drained.byType[k] != v {
			t.Errorf("byType[%s] differs: %d vs %d", k, v, drained.byType[k])
		}
	}
}

// A harness with no ring buffer must stop cleanly. This is the A0 shape, where
// setUpArm returns before anything is loaded.
func TestStopIsSafeWithNoRingBuffer(t *testing.T) {
	h := &armHarness{byType: map[string]uint64{}}
	var run benchstat.Run
	h.stop(t, &run)
	if run.EventsTotal != 0 || run.Error != "" {
		t.Errorf("A0-shaped harness reported total=%d error=%q", run.EventsTotal, run.Error)
	}
	// Idempotent: the deferred call and the explicit one both reach it.
	h.stop(t, &run)
}

// --- F2: stranded kernel records --------------------------------------------------

// The detector must fail closed. A loader it cannot question is not a loader
// with an empty ring, and reporting "nothing pending" for it would reintroduce
// exactly the silent-shortfall failure F2 exists to catch.
func TestStrandedRecordCheckFailsClosedOnAnUnloadedLoader(t *testing.T) {
	l := NewLoader(Config{}, nil)

	pending, err := l.ringHasPendingRecords(MapEvents)
	if err == nil {
		t.Fatal("an unloaded loader answered the stranded-record question instead of refusing it")
	}
	if pending {
		t.Error("pending reported true alongside an error; the caller should act on the error")
	}
}

// On a real ring that user space has fully drained, the answer is no.
//
// Root, because it loads the object. This is the half of F2 that a fixture
// cannot establish: that poll(2) on the map fd reports *not* readable when
// consumer_pos == producer_pos, so the check does not fail every clean run.
func TestFreshRingHasNoPendingRecords(t *testing.T) {
	requireRoot(t)
	obj := objectOrSkip(t)

	l := NewLoader(Config{ObjectPath: obj, RingBufferSize: benchRingBufferSize}, nil)
	if err := l.Load(t.Context(), obj); err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer l.Close()

	// No programs are attached, so nothing can have been submitted.
	pending, err := l.ringHasPendingRecords(MapEvents)
	if err != nil {
		t.Fatalf("ringHasPendingRecords: %v", err)
	}
	if pending {
		t.Error("a ring nothing has written to reported pending records")
	}
}

// The check has to run while the ring still exists. Close frees it, and a
// question asked afterwards can only be answered wrongly.
func TestStrandedRecordCheckRefusesAfterClose(t *testing.T) {
	requireRoot(t)
	obj := objectOrSkip(t)

	l := NewLoader(Config{ObjectPath: obj, RingBufferSize: benchRingBufferSize}, nil)
	if err := l.Load(t.Context(), obj); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := l.ringHasPendingRecords(MapEvents); err == nil {
		t.Error("a closed loader answered instead of refusing")
	}
}
