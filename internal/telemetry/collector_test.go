package telemetry_test

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stringNameMahin/ALLSEER/internal/telemetry"
	"github.com/stringNameMahin/ALLSEER/internal/telemetry/abi"
	"github.com/stringNameMahin/ALLSEER/internal/telemetry/synth"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// fakeLoader is a Loader with no kernel: records are pushed by the test and
// map writes are recorded.
type fakeLoader struct {
	mu        sync.Mutex
	raw       chan []byte
	tracked   map[uint64]bool
	refuse    map[string]bool
	drops     uint64
	closed    bool
	attached  []string
	closeOnce sync.Once
}

func newFakeLoader() *fakeLoader {
	return &fakeLoader{raw: make(chan []byte, 64), tracked: map[uint64]bool{}, refuse: map[string]bool{}}
}

func (f *fakeLoader) Load(context.Context, string) error { return nil }
func (f *fakeLoader) Attach(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.refuse[name] {
		return errors.New("refused by test")
	}
	f.attached = append(f.attached, name)
	return nil
}
func (f *fakeLoader) DetachAll(context.Context) error { return nil }
func (f *fakeLoader) RingBuffer(context.Context, string) (<-chan []byte, error) {
	return f.raw, nil
}
func (f *fakeLoader) UpdateMap(_ context.Context, _ string, key, _ []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tracked[binary.NativeEndian.Uint64(key)] = true
	return nil
}
func (f *fakeLoader) DeleteMap(_ context.Context, _ string, key []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := binary.NativeEndian.Uint64(key)
	if !f.tracked[id] {
		return telemetry.ErrMapKeyNotFound
	}
	delete(f.tracked, id)
	return nil
}
func (f *fakeLoader) ReadCounter(context.Context, string) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.drops, nil
}
func (f *fakeLoader) Close() error {
	f.closeOnce.Do(func() {
		f.mu.Lock()
		f.closed = true
		f.mu.Unlock()
		close(f.raw)
	})
	return nil
}

func (f *fakeLoader) push(t *testing.T, s synth.Spec) {
	t.Helper()
	rec, err := synth.Record(s, uint64(time.Now().UnixNano()))
	if err != nil {
		t.Fatal(err)
	}
	f.raw <- rec
}

func startCollector(t *testing.T, f *fakeLoader, chanSize int) *telemetry.LiveCollector {
	t.Helper()
	c, err := telemetry.NewLiveCollector(telemetry.Config{EventChannelSize: chanSize},
		telemetry.CollectorOptions{Loader: f, Enrichers: []telemetry.Enricher{}, DropPoll: 5 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func next(t *testing.T, c *telemetry.LiveCollector) event.Event {
	t.Helper()
	select {
	case e, ok := <-c.Events():
		if !ok {
			t.Fatal("event stream closed")
		}
		return e
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for an event")
	}
	return event.Event{}
}

func exec(pid, ppid int32, start, cg uint64, file string) synth.Spec {
	return synth.Spec{Type: abi.EvtProcExec, Proc: &synth.Proc{PID: pid, TID: pid, PPID: ppid, CgroupID: cg, StartTime: start, Comm: "x"},
		Exec: &synth.Exec{Filename: file}}
}

func open(pid int32, start, cg uint64, path string) synth.Spec {
	return synth.Spec{Type: abi.EvtFileOpen, Ret: 3, Proc: &synth.Proc{PID: pid, TID: pid, CgroupID: cg, StartTime: start, Comm: "x"},
		File: &synth.File{Path: path}}
}

func TestCollectorAttributesByCgroupAndSequences(t *testing.T) {
	f := newFakeLoader()
	c := startCollector(t, f, 16)
	ctx := context.Background()

	if err := c.AttachCgroup(ctx, "sess-a", 77, 500); err != nil {
		t.Fatal(err)
	}
	if !f.tracked[77] {
		t.Fatal("the cgroup was not written to the kernel filter map")
	}

	f.push(t, exec(500, 1, 10, 77, "/usr/bin/sh"))
	f.push(t, exec(501, 500, 11, 77, "/usr/bin/cat"))
	f.push(t, open(501, 11, 77, "/etc/hostname"))
	f.push(t, open(900, 1, 999, "/etc/shadow")) // stranger cgroup

	e1, e2, e3 := next(t, c), next(t, c), next(t, c)
	for i, e := range []event.Event{e1, e2, e3} {
		if e.SessionID != "sess-a" || e.Sequence != uint64(i+1) {
			t.Fatalf("event %d: session %q seq %d", i, e.SessionID, e.Sequence)
		}
		if e.ID != "sess-a/"+string(rune('1'+i)) {
			t.Fatalf("event %d: ID %q", i, e.ID)
		}
	}
	if e1.Process.AncestryDepth != 0 || e2.Process.AncestryDepth != 1 || e3.Process.AncestryDepth != 1 {
		t.Fatalf("depths = %d %d %d, want 0 1 1", e1.Process.AncestryDepth, e2.Process.AncestryDepth, e3.Process.AncestryDepth)
	}
	if e3.Observation.Kind != capability.KindFileRead {
		t.Fatalf("observation not resolved: %+v", e3.Observation)
	}

	// The stranger's record is counted, never delivered.
	deadline := time.Now().Add(time.Second)
	for c.CollectorStats().Unattributed == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := c.CollectorStats().Unattributed; got != 1 {
		t.Fatalf("Unattributed = %d, want 1", got)
	}
}

// A full consumer channel drops events, and the next delivered event of that
// session says how many were lost.
func TestCollectorOverflowIsCountedAndReported(t *testing.T) {
	f := newFakeLoader()
	c := startCollector(t, f, 1)
	if err := c.AttachCgroup(context.Background(), "s", 5, 0); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		f.push(t, open(10, 1, 5, "/a"))
	}
	deadline := time.Now().Add(2 * time.Second)
	for c.CollectorStats().Overflow < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := c.CollectorStats().Overflow; got != 3 {
		t.Fatalf("Overflow = %d, want 3", got)
	}
	first := next(t, c)
	if first.Dropped != 0 || first.Sequence != 1 {
		t.Fatalf("first event: seq %d dropped %d", first.Sequence, first.Dropped)
	}
	f.push(t, open(10, 1, 5, "/b"))
	e := next(t, c)
	if e.Dropped != 3 || e.Sequence != 5 {
		t.Fatalf("event after overflow: seq %d dropped %d, want seq 5 dropped 3", e.Sequence, e.Dropped)
	}
}

// Kernel ring losses are global, so every attached session is told.
func TestCollectorChargesKernelDropsToSessions(t *testing.T) {
	f := newFakeLoader()
	c := startCollector(t, f, 16)
	ctx := context.Background()
	_ = c.AttachCgroup(ctx, "a", 1, 0)
	_ = c.AttachCgroup(ctx, "b", 2, 0)

	f.mu.Lock()
	f.drops = 7
	f.mu.Unlock()
	deadline := time.Now().Add(2 * time.Second)
	for c.CollectorStats().KernelDrops < 7 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	f.push(t, open(10, 1, 1, "/a"))
	f.push(t, open(11, 1, 2, "/b"))
	if a, b := next(t, c), next(t, c); a.Dropped != 7 || b.Dropped != 7 {
		t.Fatalf("Dropped = %d and %d, want 7 for both sessions", a.Dropped, b.Dropped)
	}
	if st := c.Stats(); st.DroppedEvents != 7 {
		t.Fatalf("DroppedEvents = %d, want 7", st.DroppedEvents)
	}
}

func TestCollectorRefusesWithoutTheFloor(t *testing.T) {
	f := newFakeLoader()
	f.refuse[telemetry.ProgProcExit] = true
	c, err := telemetry.NewLiveCollector(telemetry.Config{}, telemetry.CollectorOptions{Loader: f})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(context.Background()); !errors.Is(err, telemetry.ErrTelemetryFloor) {
		t.Fatalf("Start without proc_exit = %v, want ErrTelemetryFloor", err)
	}
	if !f.closed {
		t.Fatal("the loader was left open after refusing to start")
	}
}

// A refused non-floor family is a reported gap, not a startup failure. The
// connect hook is refused too, since it alone would keep net.connect observable.
func TestCollectorReportsPartialCoverage(t *testing.T) {
	f := newFakeLoader()
	f.refuse[telemetry.ProgConnectExit] = true
	f.refuse[telemetry.ProgSocketConnect] = true
	c := startCollector(t, f, 4)
	cov := c.Coverage()
	for _, k := range cov.Observable {
		if k == capability.KindNetConnect {
			t.Fatal("net.connect reported observable with half its family attached and no hook")
		}
	}
	var found bool
	for _, p := range c.Probes() {
		if p.Name == telemetry.ProgConnectExit && !p.Attached && p.Error != "" {
			found = true
		}
	}
	if !found {
		t.Fatal("the refused probe is not reported with its error")
	}
}

func TestCollectorAttachRules(t *testing.T) {
	f := newFakeLoader()
	ctx := context.Background()
	c, _ := telemetry.NewLiveCollector(telemetry.Config{}, telemetry.CollectorOptions{Loader: f})
	if err := c.AttachCgroup(ctx, "s", 1, 0); !errors.Is(err, telemetry.ErrNotStarted) {
		t.Fatalf("attach before Start = %v", err)
	}
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.AttachCgroup(ctx, "s", 1, 0); err != nil {
		t.Fatal(err)
	}
	if err := c.AttachCgroup(ctx, "t", 1, 0); !errors.Is(err, telemetry.ErrSessionAttached) {
		t.Fatalf("second session on one cgroup = %v", err)
	}
	if err := c.DetachSession(ctx, "s"); err != nil {
		t.Fatal(err)
	}
	if f.tracked[1] {
		t.Fatal("detach left the cgroup in the kernel filter")
	}
	if err := c.DetachSession(ctx, "s"); !errors.Is(err, telemetry.ErrSessionUnknown) {
		t.Fatalf("second detach = %v", err)
	}
}

func TestCollectorCloseEndsTheStream(t *testing.T) {
	f := newFakeLoader()
	c := startCollector(t, f, 4)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, ok := <-c.Events(); ok {
		t.Fatal("stream still open after Close")
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close = %v", err)
	}
}
