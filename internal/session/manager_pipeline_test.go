package session

import (
	"context"
	"testing"
	"time"

	"github.com/stringNameMahin/ALLSEER/internal/pipeline"
	"github.com/stringNameMahin/ALLSEER/internal/policy"
	"github.com/stringNameMahin/ALLSEER/internal/validator"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// The seam this manager exists for: it owns the session and its tracking state,
// and hands that state to a pipeline built by the caller.
//
// This is the one test that shows the two halves fit. It is deliberately small
// and does not re-test either of them -- the pipeline has its own package, the
// decisions have a golden file. What it pins is the wiring: that the state a
// pipeline records into is the state the manager reports on, that a session's
// summary at End reflects what the pipeline actually did, and that the manager
// does not own the pipeline.

// TestManagedSessionFeedsAPipeline runs the deterministic stages over a
// session the manager created.
func TestManagedSessionFeedsAPipeline(t *testing.T) {
	c := newClock()
	m := NewManager(ManagerConfig{Now: c.now})
	ctx := context.Background()

	const id = "s-wired"
	env := testEnvelope(id)
	if _, err := m.Create(ctx, CreateRequest{Envelope: env}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := m.Seal(ctx, id); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if err := m.Start(ctx, id, 4242); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// The manager hands out State_; the caller builds the pipeline. A manager
	// that constructed pipelines itself would be the "session registry with a
	// stage list attached" internal/pipeline refused to become, and this is
	// what that refusal looks like from the other side.
	st, ok := m.State(id)
	if !ok {
		t.Fatal("State returned nothing for a started session")
	}
	state, ok := st.(*MemoryState)
	if !ok {
		t.Fatalf("State returned %T, want *MemoryState", st)
	}

	sess, err := m.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	p, err := pipeline.New(
		pipeline.Config{
			Session: pipeline.Session{
				ID:       sess.ID,
				Envelope: sess.Envelope,
				Mode:     sess.Mode,
				State:    state,
			},
			Now: c.now,
		},
		validator.NewValidator(),
		allowEngine{},
	)
	if err != nil {
		t.Fatalf("building the pipeline: %v", err)
	}

	// One read inside the granted workspace, one outside it. Enough to show the
	// counters and the verdicts reach the session record; what the validator
	// concludes is its own package's business.
	events := []*event.Event{
		readEvent(id, "e-1", "/home/dev/project/main.go"),
		readEvent(id, "e-2", "/etc/shadow"),
	}
	var verdicts []decision.Verdict
	for _, e := range events {
		d, err := p.Process(ctx, e)
		if err != nil {
			t.Fatalf("Process %s: %v", e.ID, err)
		}
		verdicts = append(verdicts, d.Verdict)
	}

	if verdicts[0] != decision.VerdictWithinEnvelope {
		t.Errorf("e-1 verdict = %q, want within_envelope", verdicts[0])
	}
	if verdicts[1] == decision.VerdictWithinEnvelope {
		t.Errorf("e-2 verdict = %q; a read outside the workspace grant must not be within envelope", verdicts[1])
	}

	// The manager's state and the pipeline's state are one object. A copy
	// anywhere in that handoff would show up here as a session that observed
	// nothing.
	c.advance(2 * time.Second)
	if err := m.End(ctx, id, Outcome{Reason: "agent exited 0"}); err != nil {
		t.Fatalf("End: %v", err)
	}

	ended, err := m.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get after End: %v", err)
	}
	if ended.Summary.EventsObserved != 2 {
		t.Errorf("Summary.EventsObserved = %d, want 2", ended.Summary.EventsObserved)
	}
	if ended.Summary.DecisionsIssued != 2 {
		t.Errorf("Summary.DecisionsIssued = %d, want 2", ended.Summary.DecisionsIssued)
	}
	if got := ended.Summary.CapabilityUsage[capability.KindFileRead]; got != 2 {
		t.Errorf("CapabilityUsage[fs.read] = %d, want 2", got)
	}
	if ended.State != StateCompleted {
		t.Errorf("state = %s, want completed", ended.State)
	}
}

// Two sessions, two states, two pipelines, one manager. The registry property:
// nothing a session records may reach another session's counters, which is the
// whole reason a manager keeps them apart rather than the pipeline doing it.
func TestSessionsDoNotShareState(t *testing.T) {
	c := newClock()
	m := NewManager(ManagerConfig{Now: c.now})
	ctx := context.Background()

	for _, id := range []string{"s-a", "s-b"} {
		if _, err := m.Create(ctx, CreateRequest{Envelope: testEnvelope(id)}); err != nil {
			t.Fatalf("Create %s: %v", id, err)
		}
		if err := m.Seal(ctx, id); err != nil {
			t.Fatalf("Seal %s: %v", id, err)
		}
		if err := m.Start(ctx, id, 1); err != nil {
			t.Fatalf("Start %s: %v", id, err)
		}
	}

	a, _ := m.State("s-a")
	a.RecordEvent(readEvent("s-a", "e-1", "/home/dev/project/main.go"))
	a.RecordEvent(readEvent("s-a", "e-2", "/home/dev/project/go.mod"))

	b, _ := m.State("s-b")
	b.RecordEvent(readEvent("s-b", "e-1", "/home/dev/project/main.go"))

	for id, want := range map[string]uint64{"s-a": 2, "s-b": 1} {
		if err := m.End(ctx, id, Outcome{Reason: "done"}); err != nil {
			t.Fatalf("End %s: %v", id, err)
		}
		s, _ := m.Get(ctx, id)
		if s.Summary.EventsObserved != want {
			t.Errorf("%s observed %d events, want %d", id, s.Summary.EventsObserved, want)
		}
	}
}

// --- fixtures ---------------------------------------------------------------------

// allowEngine is a policy engine that allows everything.
//
// The decisions are not what this test is about -- internal/policy has its own
// tests and test/golden pins the composition -- and a real rule set here would
// make a wiring test fail whenever a rule changed.
type allowEngine struct{}

func (allowEngine) Evaluate(_ context.Context, _ policy.EvaluateRequest) (*policy.Outcome, error) {
	return &policy.Outcome{
		Action: ece.ActionAllow,
		RuleID: "test-allow-all",
		Reasoning: []decision.ReasoningStep{{
			Stage:      "policy",
			Conclusion: "allowed by the test engine",
		}},
	}, nil
}

func readEvent(sessionID, id, path string) *event.Event {
	return &event.Event{
		ID:         id,
		SessionID:  sessionID,
		Capability: capability.KindFileRead,
		Domain:     capability.DomainFilesystem,
		WallClock:  epoch,
		File:       &event.FilePayload{Path: path, ResolvedPath: path},
		Observation: capability.Observation{
			Kind:   capability.KindFileRead,
			Domain: capability.DomainFilesystem,
			Target: path,
		},
	}
}
