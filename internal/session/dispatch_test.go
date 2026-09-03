package session

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/stringNameMahin/ALLSEER/internal/pipeline"
	"github.com/stringNameMahin/ALLSEER/internal/validator"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// What these tests are about is routing, and only routing. The stages have
// their own package, the decisions have a golden file, and the lifecycle has
// manager_test.go. What is unproven until here is that putting several sessions
// on one stream changes nothing about any of them -- which is the whole claim a
// dispatcher makes.

// --- which states accept events ----------------------------------------------

// AcceptsEvents is walked over the closed State enum for the same reason the
// transition table is: a state added to the enum must not quietly inherit a
// default. Here the default is "does not accept", which is the safe direction --
// a new state that should accept events fails this test loudly, while one that
// should not is already correct.
func TestAcceptsEventsCoversEveryState(t *testing.T) {
	want := map[State]bool{
		StatePending:          false,
		StateAwaitingApproval: false,
		StateReady:            false,
		StateActive:           true,
		StateSuspended:        true,
		StateCompleted:        false,
		StateTerminated:       false,
		StateFailed:           false,
	}

	for _, s := range AllStates() {
		w, ok := want[s]
		if !ok {
			t.Fatalf("state %q is in AllStates but this test does not classify it; "+
				"decide whether a session in that state may receive events", s)
		}
		if got := AcceptsEvents(s); got != w {
			t.Errorf("AcceptsEvents(%q) = %v, want %v", s, got, w)
		}
	}

	// The security-relevant half, asserted independently of the table above so
	// that editing one does not silently edit the other. A terminal session has
	// had its Summary captured; recording into it afterwards produces a record
	// that disagrees with the report already made from it.
	for _, s := range TerminalStates() {
		if AcceptsEvents(s) {
			t.Errorf("terminal state %q accepts events; its summary is already captured", s)
		}
	}
}

// --- the registry seam ---------------------------------------------------------

// Binding is the manager's entire contribution to dispatch, and the one thing
// it must not copy is State_.
func TestBindingSharesStateAndDescribesTheSession(t *testing.T) {
	c := newClock()
	m := NewManager(ManagerConfig{Now: c.now})
	ctx := context.Background()

	const id = "s-bind"
	if _, err := m.Create(ctx, CreateRequest{Envelope: testEnvelope(id)}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	b, ok := m.Binding(id)
	if !ok {
		t.Fatal("Binding returned nothing for a session that exists")
	}
	if b.SessionID != id {
		t.Errorf("SessionID = %q, want %q", b.SessionID, id)
	}
	if b.Lifecycle != StatePending {
		t.Errorf("Lifecycle = %q, want pending", b.Lifecycle)
	}
	if b.Envelope == nil || b.Envelope.SessionID != id {
		t.Error("Binding carries the wrong envelope")
	}
	if b.Mode == "" {
		t.Error("Binding carries no mode; a pipeline built from it would be refused")
	}

	// Same object, not a copy. A copy here is the failure mode that produces a
	// pipeline recording into nothing, and it is invisible until a summary
	// comes back empty.
	st, _ := m.State(id)
	if b.State != st {
		t.Error("Binding.State is not the same object State returns")
	}

	if _, ok := m.Binding("s-nonexistent"); ok {
		t.Error("Binding reported a session the manager does not hold")
	}

	// The lifecycle field tracks, rather than being a snapshot taken at Create.
	if err := m.Seal(ctx, id); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if err := m.Start(ctx, id, 99); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if b, _ := m.Binding(id); b.Lifecycle != StateActive {
		t.Errorf("Lifecycle after Start = %q, want active", b.Lifecycle)
	}
}

// --- construction ---------------------------------------------------------------

func TestNewDispatcherRefusals(t *testing.T) {
	m := NewManager(ManagerConfig{})
	factory := func(Binding) (EventProcessor, error) { return &countingProcessor{}, nil }

	if _, err := NewDispatcher(DispatchConfig{Factory: factory}); !errors.Is(err, ErrNoRegistry) {
		t.Errorf("no registry: err = %v, want ErrNoRegistry", err)
	}
	if _, err := NewDispatcher(DispatchConfig{Registry: m}); !errors.Is(err, ErrNoFactory) {
		t.Errorf("no factory: err = %v, want ErrNoFactory", err)
	}
	d, err := NewDispatcher(DispatchConfig{Registry: m, Factory: factory})
	if err != nil {
		t.Fatalf("valid config: %v", err)
	}
	if _, err := d.Dispatch(context.Background(), nil); !errors.Is(err, ErrNilEvent) {
		t.Errorf("nil event: err = %v, want ErrNilEvent", err)
	}
	if err := d.Run(context.Background(), nil); !errors.Is(err, ErrNoSource) {
		t.Errorf("nil source: err = %v, want ErrNoSource", err)
	}
}

// --- what cannot be routed -------------------------------------------------------

// The three refusals are separately counted because they are three different
// findings about a host, and none of them may be silent: an event nobody could
// attribute is not an event that did not happen.
func TestUnroutableEventsAreRefusedAndCounted(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name string
		// drive puts a session into the state under test and returns the
		// session ID the event should name. An empty return means the event
		// names no session at all.
		drive   func(t *testing.T, m *MemoryManager) string
		wantErr error
		count   func(DispatchStats) uint64
	}{
		{
			name:    "no session id",
			drive:   func(*testing.T, *MemoryManager) string { return "" },
			wantErr: ErrEventUnidentified,
			count:   func(s DispatchStats) uint64 { return s.Unidentified },
		},
		{
			name:    "unknown session",
			drive:   func(*testing.T, *MemoryManager) string { return "s-stranger" },
			wantErr: ErrUnattributed,
			count:   func(s DispatchStats) uint64 { return s.Unattributed },
		},
		{
			name: "created but never started",
			drive: func(t *testing.T, m *MemoryManager) string {
				const id = "s-pending"
				if _, err := m.Create(ctx, CreateRequest{Envelope: testEnvelope(id)}); err != nil {
					t.Fatalf("Create: %v", err)
				}
				return id
			},
			wantErr: ErrNotAccepting,
			count:   func(s DispatchStats) uint64 { return s.NotAccepting },
		},
		{
			name: "sealed and ready but not started",
			drive: func(t *testing.T, m *MemoryManager) string {
				const id = "s-ready"
				if _, err := m.Create(ctx, CreateRequest{Envelope: testEnvelope(id)}); err != nil {
					t.Fatalf("Create: %v", err)
				}
				if err := m.Seal(ctx, id); err != nil {
					t.Fatalf("Seal: %v", err)
				}
				return id
			},
			wantErr: ErrNotAccepting,
			count:   func(s DispatchStats) uint64 { return s.NotAccepting },
		},
		{
			name: "already ended",
			drive: func(t *testing.T, m *MemoryManager) string {
				const id = "s-ended"
				if _, err := m.Create(ctx, CreateRequest{Envelope: testEnvelope(id)}); err != nil {
					t.Fatalf("Create: %v", err)
				}
				if err := m.Seal(ctx, id); err != nil {
					t.Fatalf("Seal: %v", err)
				}
				if err := m.Start(ctx, id, 7); err != nil {
					t.Fatalf("Start: %v", err)
				}
				if err := m.End(ctx, id, Outcome{Reason: "agent exited"}); err != nil {
					t.Fatalf("End: %v", err)
				}
				return id
			},
			wantErr: ErrNotAccepting,
			count:   func(s DispatchStats) uint64 { return s.NotAccepting },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewManager(ManagerConfig{Now: newClock().now})
			p := &countingProcessor{}
			d, err := NewDispatcher(DispatchConfig{
				Registry: m,
				Factory:  func(Binding) (EventProcessor, error) { return p, nil },
			})
			if err != nil {
				t.Fatalf("NewDispatcher: %v", err)
			}

			id := tc.drive(t, m)
			dec, err := d.Dispatch(ctx, readEvent(id, "e-1", "/home/dev/project/main.go"))

			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if dec != nil {
				t.Error("a refused event produced a decision")
			}
			if p.calls != 0 {
				t.Errorf("the processor was called %d times for an unroutable event", p.calls)
			}

			s := d.Stats()
			if s.EventsObserved != 1 {
				t.Errorf("EventsObserved = %d, want 1; a refused event is still an observed one", s.EventsObserved)
			}
			if s.EventsRouted != 0 {
				t.Errorf("EventsRouted = %d, want 0", s.EventsRouted)
			}
			if got := tc.count(s); got != 1 {
				t.Errorf("the refusal counter for this case = %d, want 1", got)
			}
		})
	}
}

// A suspended session still accepts events. Refusing them would make
// suspension a hole in the record exactly when scrutiny is highest: an event
// arriving while the tree is supposed to be stopped is either legitimately in
// flight or evidence that it did not stop.
func TestSuspendedSessionsStillAcceptEvents(t *testing.T) {
	ctx := context.Background()
	m := NewManager(ManagerConfig{Now: newClock().now, Supervisor: &stubSupervisor{}})

	const id = "s-suspended"
	mustRunnable(t, m, id, testEnvelope(id))
	if err := m.Suspend(ctx, id, "awaiting approval"); err != nil {
		t.Fatalf("Suspend: %v", err)
	}

	p := &countingProcessor{}
	d, err := NewDispatcher(DispatchConfig{
		Registry: m,
		Factory:  func(Binding) (EventProcessor, error) { return p, nil },
	})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	if _, err := d.Dispatch(ctx, readEvent(id, "e-1", "/home/dev/project/main.go")); err != nil {
		t.Fatalf("Dispatch to a suspended session: %v", err)
	}
	if p.calls != 1 {
		t.Errorf("the processor was called %d times, want 1", p.calls)
	}
	if got := d.Stats().EventsRouted; got != 1 {
		t.Errorf("EventsRouted = %d, want 1", got)
	}
}

// --- the equivalence claim ---------------------------------------------------------

// The claim a dispatcher makes is that interleaving several sessions on one
// stream changes nothing about any of them. This is that claim, tested against
// the alternative it replaces: the same events run through one pipeline per
// session, which is what every caller does today.
//
// It is the strongest test in this file, because a routing bug that mixed two
// sessions' state would still produce plausible decisions -- just the wrong
// ones -- and only a comparison against the isolated runs shows it.
func TestInterleavedSessionsMatchIsolatedRuns(t *testing.T) {
	ctx := context.Background()

	// Two sessions with the same envelope shape and overlapping targets, which
	// is the arrangement most likely to expose shared state: the same path is
	// novel in one session and familiar in the other, and the budgets are
	// separate counts of the same thing.
	streams := map[string][]*event.Event{
		"s-one": {
			readEvent("s-one", "e-1", "/home/dev/project/main.go"),
			readEvent("s-one", "e-2", "/home/dev/project/go.mod"),
			readEvent("s-one", "e-3", "/etc/shadow"),
			readEvent("s-one", "e-4", "/home/dev/project/main.go"),
		},
		"s-two": {
			readEvent("s-two", "e-1", "/home/dev/project/main.go"),
			readEvent("s-two", "e-2", "/etc/shadow"),
			readEvent("s-two", "e-3", "/home/dev/project/internal/a.go"),
		},
	}

	isolated := make(map[string][]decision.Decision, len(streams))
	for id, events := range streams {
		isolated[id] = runIsolated(t, id, events)
	}

	// The interleaving is deliberately uneven -- two of one, one of the other,
	// then a tail -- so that no session's events are contiguous.
	order := []struct {
		session string
		index   int
	}{
		{"s-one", 0}, {"s-two", 0}, {"s-one", 1}, {"s-one", 2},
		{"s-two", 1}, {"s-two", 2}, {"s-one", 3},
	}

	c := newClock()
	m := NewManager(ManagerConfig{Now: c.now})
	for id := range streams {
		mustRunnable(t, m, id, budgetedEnvelope(id))
	}

	d, err := NewDispatcher(DispatchConfig{
		Registry: m,
		Factory:  pipelineFactory(c),
	})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	got := make(map[string][]decision.Decision, len(streams))
	for _, step := range order {
		dec, err := d.Dispatch(ctx, streams[step.session][step.index])
		if err != nil {
			t.Fatalf("Dispatch %s/%d: %v", step.session, step.index, err)
		}
		got[step.session] = append(got[step.session], *dec)
	}

	for id := range streams {
		if !reflect.DeepEqual(got[id], isolated[id]) {
			t.Errorf("session %s: interleaved dispatch produced different decisions from an isolated run\n"+
				"interleaved: %+v\nisolated:    %+v", id, got[id], isolated[id])
		}
	}

	s := d.Stats()
	if s.EventsRouted != uint64(len(order)) {
		t.Errorf("EventsRouted = %d, want %d", s.EventsRouted, len(order))
	}
	if s.SessionsSeen != 2 || s.SessionsLive != 2 {
		t.Errorf("SessionsSeen = %d, SessionsLive = %d, want 2 and 2", s.SessionsSeen, s.SessionsLive)
	}
	if s.Unattributed+s.Unidentified+s.NotAccepting+s.ProcessorErrors+s.FactoryErrors != 0 {
		t.Errorf("a clean run reported refusals: %+v", s)
	}
}

// The budget half of the same claim, stated on its own because it is the one a
// reader will want named: a grant with max_count 2 must survive two uses per
// session, not two uses across the host.
func TestGrantBudgetsAreNotChargedAcrossSessions(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	m := NewManager(ManagerConfig{Now: c.now})

	for _, id := range []string{"s-x", "s-y"} {
		mustRunnable(t, m, id, budgetedEnvelope(id))
	}

	d, err := NewDispatcher(DispatchConfig{Registry: m, Factory: pipelineFactory(c)})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	// Alternating, so a shared counter would be exhausted by the fourth event
	// and the last two of each session would fall out of the envelope.
	want := []decision.Verdict{
		decision.VerdictWithinEnvelope,
		decision.VerdictWithinEnvelope,
		decision.VerdictWithinEnvelope,
		decision.VerdictWithinEnvelope,
	}
	var got []decision.Verdict
	for i := 0; i < 2; i++ {
		for _, id := range []string{"s-x", "s-y"} {
			e := readEvent(id, fmt.Sprintf("e-%d", i), fmt.Sprintf("/home/dev/project/f%d.go", i))
			dec, err := d.Dispatch(ctx, e)
			if err != nil {
				t.Fatalf("Dispatch %s: %v", id, err)
			}
			got = append(got, dec.Verdict)
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("verdicts = %v, want %v; a max_count of 2 is two uses per session", got, want)
	}

	// And the third use in a session is over budget, which is what proves the
	// budget was doing anything at all above.
	dec, err := d.Dispatch(ctx, readEvent("s-x", "e-9", "/home/dev/project/f9.go"))
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if dec.Verdict == decision.VerdictWithinEnvelope {
		t.Errorf("the third use of a max_count 2 grant was within_envelope; the budget is not being charged")
	}
}

// --- containment ------------------------------------------------------------------

// One session's processor falling over must not end governance for the others.
// The same containment argument that puts panic recovery around each stage,
// one layer up.
func TestProcessorFailureIsContainedToItsSession(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	m := NewManager(ManagerConfig{Now: c.now})
	mustRunnable(t, m, "s-bad", testEnvelope("s-bad"))
	mustRunnable(t, m, "s-good", testEnvelope("s-good"))

	good := &countingProcessor{}
	d, err := NewDispatcher(DispatchConfig{
		Registry: m,
		Factory: func(b Binding) (EventProcessor, error) {
			if b.SessionID == "s-bad" {
				return &failingProcessor{err: errors.New("scorer exploded")}, nil
			}
			return good, nil
		},
	})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	src := &stubSource{events: []event.Event{
		*readEvent("s-bad", "e-1", "/home/dev/project/a.go"),
		*readEvent("s-good", "e-1", "/home/dev/project/b.go"),
		*readEvent("s-bad", "e-2", "/home/dev/project/c.go"),
		*readEvent("s-good", "e-2", "/home/dev/project/d.go"),
	}}
	src.fill()

	if err := d.Run(ctx, src); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if good.calls != 2 {
		t.Errorf("the healthy session was processed %d times, want 2; one session's failure ended the stream", good.calls)
	}
	s := d.Stats()
	if s.ProcessorErrors != 2 {
		t.Errorf("ProcessorErrors = %d, want 2", s.ProcessorErrors)
	}
	if s.EventsRouted != 2 {
		t.Errorf("EventsRouted = %d, want 2; only the healthy session produced decisions", s.EventsRouted)
	}
	if s.EventsObserved != 4 {
		t.Errorf("EventsObserved = %d, want 4; a failed event is still an observed one", s.EventsObserved)
	}
}

// A factory that fails is not a session written off forever. There is no
// negative cache, deliberately: a transient failure must not be permanent.
func TestFactoryFailureIsCountedAndRetried(t *testing.T) {
	ctx := context.Background()
	m := NewManager(ManagerConfig{Now: newClock().now})
	mustRunnable(t, m, "s-late", testEnvelope("s-late"))

	var attempts int
	p := &countingProcessor{}
	d, err := NewDispatcher(DispatchConfig{
		Registry: m,
		Factory: func(Binding) (EventProcessor, error) {
			attempts++
			if attempts < 3 {
				return nil, errors.New("policy rule set not loaded yet")
			}
			return p, nil
		},
	})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	for i := 0; i < 3; i++ {
		_, _ = d.Dispatch(ctx, readEvent("s-late", fmt.Sprintf("e-%d", i), "/home/dev/project/a.go"))
	}

	if attempts != 3 {
		t.Errorf("the factory was asked %d times, want 3; a failed build must not write the session off", attempts)
	}
	if p.calls != 1 {
		t.Errorf("the processor ran %d times, want 1", p.calls)
	}
	s := d.Stats()
	if s.FactoryErrors != 2 {
		t.Errorf("FactoryErrors = %d, want 2", s.FactoryErrors)
	}
	if s.EventsRouted != 1 {
		t.Errorf("EventsRouted = %d, want 1", s.EventsRouted)
	}

	// A factory that declines by returning nothing at all is refused rather
	// than cached, because a nil processor panics on the next event.
	nilFactory, err := NewDispatcher(DispatchConfig{
		Registry: m,
		Factory:  func(Binding) (EventProcessor, error) { return nil, nil },
	})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}
	if _, err := nilFactory.Dispatch(ctx, readEvent("s-late", "e-nil", "/home/dev/project/a.go")); err == nil {
		t.Error("a factory returning (nil, nil) was accepted")
	}
}

// --- the sink -----------------------------------------------------------------------

// The dispatcher owns the sink, so this is where a decision becomes an audit
// record on a multi-session stream. A sink failure is counted and never
// returned, for the reason the pipeline gives: a full disk must not become a
// governance outage.
func TestDecisionsReachTheSinkAndSinkFailuresDoNotStopRouting(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	m := NewManager(ManagerConfig{Now: c.now})
	mustRunnable(t, m, "s-sunk", budgetedEnvelope("s-sunk"))

	sink := &recordingSink{}
	d, err := NewDispatcher(DispatchConfig{Registry: m, Factory: pipelineFactory(c), Sink: sink})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	dec, err := d.Dispatch(ctx, readEvent("s-sunk", "e-1", "/home/dev/project/a.go"))
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if len(sink.got) != 1 {
		t.Fatalf("the sink received %d decisions, want 1", len(sink.got))
	}
	if sink.got[0].ID != dec.ID {
		t.Errorf("the sink received decision %q, the caller received %q", sink.got[0].ID, dec.ID)
	}

	sink.err = errors.New("disk full")
	if _, err := d.Dispatch(ctx, readEvent("s-sunk", "e-2", "/home/dev/project/b.go")); err != nil {
		t.Fatalf("a sink failure stopped routing: %v", err)
	}
	s := d.Stats()
	if s.SinkErrors != 1 {
		t.Errorf("SinkErrors = %d, want 1", s.SinkErrors)
	}
	if s.EventsRouted != 2 {
		t.Errorf("EventsRouted = %d, want 2; the decision was still made", s.EventsRouted)
	}
}

// --- processor lifetime --------------------------------------------------------------

func TestProcessorsAreDroppedWhenASessionStopsAccepting(t *testing.T) {
	ctx := context.Background()
	m := NewManager(ManagerConfig{Now: newClock().now})
	mustRunnable(t, m, "s-短", testEnvelope("s-短"))

	var built int
	d, err := NewDispatcher(DispatchConfig{
		Registry: m,
		Factory: func(Binding) (EventProcessor, error) {
			built++
			return &countingProcessor{}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	if _, err := d.Dispatch(ctx, readEvent("s-短", "e-1", "/home/dev/project/a.go")); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if built != 1 || d.Stats().SessionsLive != 1 {
		t.Fatalf("built = %d, live = %d, want 1 and 1", built, d.Stats().SessionsLive)
	}

	// Built once, not once per event.
	if _, err := d.Dispatch(ctx, readEvent("s-短", "e-2", "/home/dev/project/b.go")); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if built != 1 {
		t.Errorf("the factory was called %d times for one session; the processor is not cached", built)
	}

	if err := m.End(ctx, "s-短", Outcome{Reason: "done"}); err != nil {
		t.Fatalf("End: %v", err)
	}
	if _, err := d.Dispatch(ctx, readEvent("s-短", "e-3", "/home/dev/project/c.go")); !errors.Is(err, ErrNotAccepting) {
		t.Fatalf("err = %v, want ErrNotAccepting", err)
	}
	if live := d.Stats().SessionsLive; live != 0 {
		t.Errorf("SessionsLive = %d after the session ended, want 0", live)
	}

	// Release on a session the dispatcher never held is a no-op, not an
	// accounting error.
	d.Release("s-never")
	if live := d.Stats().SessionsLive; live != 0 {
		t.Errorf("SessionsLive = %d after releasing an unknown session, want 0", live)
	}
}

// --- Run --------------------------------------------------------------------------

func TestRunStopsOnSourceCloseAndOnCancellation(t *testing.T) {
	m := NewManager(ManagerConfig{Now: newClock().now})
	mustRunnable(t, m, "s-run", testEnvelope("s-run"))
	p := &countingProcessor{}
	newDispatcher := func() *Dispatcher {
		d, err := NewDispatcher(DispatchConfig{
			Registry: m,
			Factory:  func(Binding) (EventProcessor, error) { return p, nil },
		})
		if err != nil {
			t.Fatalf("NewDispatcher: %v", err)
		}
		return d
	}

	src := &stubSource{events: []event.Event{
		*readEvent("s-run", "e-1", "/home/dev/project/a.go"),
		*readEvent("s-run", "e-2", "/home/dev/project/b.go"),
	}}
	src.fill()
	if err := newDispatcher().Run(context.Background(), src); err != nil {
		t.Fatalf("Run over a closed source: %v", err)
	}
	if p.calls != 2 {
		t.Errorf("processed %d events, want 2", p.calls)
	}

	// Cancellation is one of exactly two things that end a run, and it is
	// reported rather than swallowed: a run that stopped early must not look
	// like a stream that finished.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	open := &stubSource{ch: make(chan event.Event)}
	if err := newDispatcher().Run(ctx, open); !errors.Is(err, context.Canceled) {
		t.Errorf("Run on a cancelled context = %v, want context.Canceled", err)
	}
}

// --- fixtures ------------------------------------------------------------------------

// mustRunnable drives a session to active, which is the state everything here
// starts from.
func mustRunnable(t *testing.T, m *MemoryManager, id string, env *ece.Envelope) {
	t.Helper()
	ctx := context.Background()
	if _, err := m.Create(ctx, CreateRequest{Envelope: env}); err != nil {
		t.Fatalf("Create %s: %v", id, err)
	}
	if err := m.Seal(ctx, id); err != nil {
		t.Fatalf("Seal %s: %v", id, err)
	}
	if err := m.Start(ctx, id, 1000); err != nil {
		t.Fatalf("Start %s: %v", id, err)
	}
}

// budgetedEnvelope is testEnvelope with a countable grant, so the equivalence
// tests exercise state that accumulates rather than state that does not.
func budgetedEnvelope(sessionID string) *ece.Envelope {
	env := testEnvelope(sessionID)
	env.Grants = []capability.Grant{{
		Kind:   capability.KindFileRead,
		Domain: capability.DomainFilesystem,
		Selector: capability.Selector{
			PathPatterns: []string{"/home/dev/project/**"},
			MaxCount:     2,
		},
	}}
	return env
}

// pipelineFactory builds a real pipeline per session, which is what a daemon
// will do. The stopped clock is shared so decision timestamps and latencies are
// identical across runs; without it the equivalence test would compare two
// wall clocks.
func pipelineFactory(c *clock) ProcessorFactory {
	return func(b Binding) (EventProcessor, error) {
		return pipeline.New(
			pipeline.Config{
				Session: pipeline.Session{
					ID:       b.SessionID,
					Envelope: b.Envelope,
					Mode:     b.Mode,
					State:    b.State,
				},
				Now: c.now,
			},
			validator.NewValidator(),
			allowEngine{},
		)
	}
}

// runIsolated is the alternative the dispatcher replaces: one session, one
// pipeline, one stream, exactly as manager_pipeline_test.go wires it.
func runIsolated(t *testing.T, id string, events []*event.Event) []decision.Decision {
	t.Helper()
	ctx := context.Background()
	c := newClock()
	m := NewManager(ManagerConfig{Now: c.now})
	mustRunnable(t, m, id, budgetedEnvelope(id))

	b, ok := m.Binding(id)
	if !ok {
		t.Fatalf("Binding %s", id)
	}
	p, err := pipelineFactory(c)(b)
	if err != nil {
		t.Fatalf("building the pipeline for %s: %v", id, err)
	}

	out := make([]decision.Decision, 0, len(events))
	for _, e := range events {
		d, err := p.Process(ctx, e)
		if err != nil {
			t.Fatalf("Process %s/%s: %v", id, e.ID, err)
		}
		out = append(out, *d)
	}
	return out
}

// countingProcessor stands in for a pipeline where the decisions are not the
// point. It returns a decision so routing has something to emit.
type countingProcessor struct{ calls int }

func (p *countingProcessor) Process(_ context.Context, e *event.Event) (*decision.Decision, error) {
	p.calls++
	return &decision.Decision{
		ID:        "d-" + e.ID,
		SessionID: e.SessionID,
		EventID:   e.ID,
		Verdict:   decision.VerdictWithinEnvelope,
	}, nil
}

// nopProcessor returns the same preallocated decision every time, so the
// benchmark below measures routing rather than the stub's own allocation.
type nopProcessor struct{ d decision.Decision }

func (p *nopProcessor) Process(context.Context, *event.Event) (*decision.Decision, error) {
	return &p.d, nil
}

type failingProcessor struct{ err error }

func (p *failingProcessor) Process(context.Context, *event.Event) (*decision.Decision, error) {
	return nil, p.err
}

type recordingSink struct {
	got []decision.Decision
	err error
}

func (s *recordingSink) Emit(_ context.Context, d decision.Decision) error {
	if s.err != nil {
		return s.err
	}
	s.got = append(s.got, d)
	return nil
}

func (s *recordingSink) Flush(context.Context) error { return nil }

// stubSource is an event.Source over a fixed slice. The replay source would do,
// but it needs a file, and what these tests are about is routing rather than
// decoding.
type stubSource struct {
	events []event.Event
	ch     chan event.Event
}

func (s *stubSource) fill() {
	s.ch = make(chan event.Event, len(s.events))
	for _, e := range s.events {
		s.ch <- e
	}
	close(s.ch)
}

func (s *stubSource) Events() <-chan event.Event  { return s.ch }
func (s *stubSource) Start(context.Context) error { return nil }
func (s *stubSource) Close() error                { return nil }
func (s *stubSource) Stats() event.SourceStats    { return event.SourceStats{} }

// --- benchmark ---------------------------------------------------------------------

// What routing costs on top of processing: one registry lookup under a read
// lock, one map read, and the emit check. Measured against a processor that
// returns a preallocated decision, so what is left is the routing itself -- the
// number to add to BenchmarkProcess in internal/pipeline to get the per-event
// cost on a multi-session stream.
func BenchmarkDispatch(b *testing.B) {
	ctx := context.Background()
	c := newClock()
	m := NewManager(ManagerConfig{Now: c.now})

	env := testEnvelope("s-bench")
	if _, err := m.Create(ctx, CreateRequest{Envelope: env}); err != nil {
		b.Fatalf("Create: %v", err)
	}
	if err := m.Seal(ctx, "s-bench"); err != nil {
		b.Fatalf("Seal: %v", err)
	}
	if err := m.Start(ctx, "s-bench", 1); err != nil {
		b.Fatalf("Start: %v", err)
	}

	d, err := NewDispatcher(DispatchConfig{
		Registry: m,
		Factory:  func(Binding) (EventProcessor, error) { return &nopProcessor{}, nil },
	})
	if err != nil {
		b.Fatalf("NewDispatcher: %v", err)
	}

	e := readEvent("s-bench", "e-1", "/home/dev/project/main.go")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := d.Dispatch(ctx, e); err != nil {
			b.Fatalf("Dispatch: %v", err)
		}
	}
}
