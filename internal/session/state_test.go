package session

import (
	"context"
	"fmt"
	"math"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/stringNameMahin/ALLSEER/internal/validator"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// --- helpers ----------------------------------------------------------------

// eventOf builds an event carrying a pre-resolved observation, which is the
// shape enrichment produces and a replay fixture records. Building it here
// rather than leaning on the resolver keeps these tests about accounting.
func eventOf(kind capability.Kind, target string) *event.Event {
	domain, _ := capability.DomainOf(kind)
	return &event.Event{
		ID:         fmt.Sprintf("e-%s-%s", kind, target),
		SessionID:  "s-1",
		Capability: kind,
		Domain:     domain,
		Observation: capability.Observation{
			Kind: kind, Domain: domain, Target: target,
		},
	}
}

func fileEvent(kind capability.Kind, path string) *event.Event {
	e := eventOf(kind, path)
	e.File = &event.FilePayload{Path: path, ResolvedPath: path}
	return e
}

func sentEvent(bytes int64) *event.Event {
	e := eventOf(capability.KindNetSend, "api.example.com:443")
	e.Network = &event.NetworkPayload{
		Protocol: "tcp", Hostname: "api.example.com", DestAddr: "10.0.0.1",
		DestPort: 443, BytesSent: bytes,
	}
	return e
}

func envelopeWith(c ece.Constraints, grants ...capability.Grant) *ece.Envelope {
	return &ece.Envelope{
		SchemaVersion: ece.SchemaVersion,
		ID:            "env-1",
		SessionID:     "s-1",
		Grants:        grants,
		Constraints:   c,
		DefaultAction: ece.ActionWarn,
		Sealed:        true,
	}
}

func pathGrant(kind capability.Kind, maxCount int, patterns ...string) capability.Grant {
	return capability.Grant{
		Kind:     kind,
		Domain:   capability.DomainFilesystem,
		Selector: capability.Selector{PathPatterns: patterns, MaxCount: maxCount},
	}
}

// verdictOf validates e against env with st and returns the verdict. The point
// of routing these tests through the real validator is that a counter is only
// correct if the check that consumes it agrees.
func verdictOf(t *testing.T, env *ece.Envelope, e *event.Event, st validator.SessionState) *validator.Result {
	t.Helper()
	res, err := validator.NewValidator().Validate(context.Background(),
		validator.ValidateRequest{Envelope: env, Event: e, State: st})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	return res
}

// runSession is the pipeline order this state is built for: validate, then
// record. Recording first would spend the budget on the event being judged.
//
// A grant use is charged only when the grant actually covered the operation. A
// grant_exceeded result still names the grant it ran out of, and charging that
// would let a refused operation keep spending a budget it was already denied.
func runSession(t *testing.T, env *ece.Envelope, st *MemoryState, events []*event.Event) []decision.Verdict {
	t.Helper()
	var out []decision.Verdict
	for _, e := range events {
		res := verdictOf(t, env, e, st)
		out = append(out, res.Verdict)
		if res.MatchedGrant != nil && res.Verdict == decision.VerdictWithinEnvelope {
			st.RecordGrantUse(res.MatchedGrantIndex)
		}
		st.RecordEvent(e)
	}
	return out
}

// --- initial and empty state ------------------------------------------------

func TestNewStateIsEmpty(t *testing.T) {
	st := NewState("s-1", envelopeWith(ece.Constraints{}, pathGrant(capability.KindFileWrite, 0, "/ws/**")))

	if st.SessionID() != "s-1" {
		t.Errorf("SessionID = %q, want %q", st.SessionID(), "s-1")
	}
	if got := st.FileWriteCount(); got != 0 {
		t.Errorf("FileWriteCount = %d, want 0", got)
	}
	if got := st.ProcessCount(); got != 0 {
		t.Errorf("ProcessCount = %d, want 0", got)
	}
	if got := st.NetworkBytesSent(); got != 0 {
		t.Errorf("NetworkBytesSent = %d, want 0", got)
	}
	if got := st.ElapsedSeconds(); got != 0 {
		t.Errorf("ElapsedSeconds = %v, want 0", got)
	}
	if got := st.GrantUseCount(0); got != 0 {
		t.Errorf("GrantUseCount(0) = %d, want 0", got)
	}
	if got := st.ViolationCount(); got != 0 {
		t.Errorf("ViolationCount = %d, want 0", got)
	}
	if st.SeenTargets(capability.KindFileWrite, "/ws/a.go") {
		t.Error("SeenTargets true on a fresh state")
	}
	if got := st.RecentEvents(10); got != nil {
		t.Errorf("RecentEvents = %v, want nil", got)
	}
	if !st.TelemetryComplete() {
		t.Error("TelemetryComplete false on a fresh state")
	}

	sum := st.Snapshot()
	if sum.EventsObserved != 0 || sum.DecisionsIssued != 0 || sum.PeakRiskScore != 0 {
		t.Errorf("Snapshot = %+v, want zeroed counters", sum)
	}
	if len(sum.CapabilityUsage) != 0 {
		t.Errorf("CapabilityUsage = %v, want empty", sum.CapabilityUsage)
	}
	if len(sum.TopViolations) != 0 {
		t.Errorf("TopViolations = %v, want empty", sum.TopViolations)
	}
	// The one non-zero field on a fresh state: a grant that has not been used
	// yet is, so far, unused. Reporting otherwise would require guessing.
	if want := []capability.Kind{capability.KindFileWrite}; !reflect.DeepEqual(sum.UnusedGrants, want) {
		t.Errorf("UnusedGrants = %v, want %v", sum.UnusedGrants, want)
	}
}

// A nil *MemoryState must behave exactly like the nil SessionState the
// validator already accepts: no history, not zero budget. The distinction is
// load-bearing — if nil meant "everything spent", a caller that forgot to build
// state would see every grant refused.
func TestNilStateMeansNoHistoryNotZeroBudget(t *testing.T) {
	var st *MemoryState

	if got := st.FileWriteCount(); got != 0 {
		t.Errorf("FileWriteCount = %d, want 0", got)
	}
	if got := st.GrantUseCount(0); got != 0 {
		t.Errorf("GrantUseCount = %d, want 0", got)
	}
	if st.SeenTargets(capability.KindFileRead, "/ws/a.go") {
		t.Error("SeenTargets true on nil state")
	}
	if got := st.Snapshot(); !reflect.DeepEqual(got, Summary{}) {
		t.Errorf("Snapshot = %+v, want zero Summary", got)
	}

	// Writes on a nil state are no-ops rather than panics: an accounting error
	// must not end governance.
	st.RecordEvent(fileEvent(capability.KindFileWrite, "/ws/a.go"))
	st.RecordDecision(&decision.Decision{Verdict: decision.VerdictOutsideEnvelope})
	st.RecordGrantUse(0)

	env := envelopeWith(ece.Constraints{MaxFileWrites: 1},
		pathGrant(capability.KindFileWrite, 1, "/ws/**"))

	// Both the nil concrete type and a nil interface must reach the same
	// verdict, which is what makes the two interchangeable at a call site.
	viaNilConcrete := verdictOf(t, env, fileEvent(capability.KindFileWrite, "/ws/a.go"), st)
	viaNilInterface := verdictOf(t, env, fileEvent(capability.KindFileWrite, "/ws/a.go"), nil)
	if viaNilConcrete.Verdict != decision.VerdictWithinEnvelope {
		t.Errorf("nil *MemoryState verdict = %s, want within_envelope", viaNilConcrete.Verdict)
	}
	if viaNilConcrete.Verdict != viaNilInterface.Verdict {
		t.Errorf("nil concrete %s != nil interface %s", viaNilConcrete.Verdict, viaNilInterface.Verdict)
	}
}

// Every reader, on a nil state, in one place. Enumerated rather than sampled
// because the guarantee is "no reader panics and none of them invents history",
// and a reader added without a guard would otherwise fail at whichever call
// site reached it first.
func TestNilStateAcrossEveryReader(t *testing.T) {
	var st *MemoryState

	checks := []struct {
		name string
		got  any
		want any
	}{
		{"SessionID", st.SessionID(), ""},
		{"GrantUseCount", st.GrantUseCount(0), 0},
		{"FileWriteCount", st.FileWriteCount(), 0},
		{"NetworkBytesSent", st.NetworkBytesSent(), int64(0)},
		{"ProcessCount", st.ProcessCount(), 0},
		{"ElapsedSeconds", st.ElapsedSeconds(), float64(0)},
		{"SeenTargets", st.SeenTargets(capability.KindFileRead, "/ws/a.go"), false},
		{"CapabilityCount", st.CapabilityCount(capability.KindFileRead), 0},
		{"TargetSeen", st.TargetSeen(capability.KindFileRead, "/ws/a.go"), false},
		{"ViolationCount", st.ViolationCount(), 0},
		{"SessionDurationSeconds", st.SessionDurationSeconds(), float64(0)},
		{"BlockedCount", st.BlockedCount(), 0},
		{"DroppedEvents", st.DroppedEvents(), uint64(0)},
		{"PeakRiskScore", st.PeakRiskScore(), float64(0)},
		{"SeenTargetsSaturated", st.SeenTargetsSaturated(), false},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("nil state %s = %v, want %v", c.name, c.got, c.want)
		}
	}

	// An absent stream is complete in the only sense available: nothing was
	// lost because nothing was collected. The session's Outcome is what
	// qualifies that, not this counter.
	if !st.TelemetryComplete() {
		t.Error("nil state TelemetryComplete = false, want true")
	}
	if got := st.RecentEvents(5); got != nil {
		t.Errorf("nil state RecentEvents = %v, want nil", targets(got))
	}
	if got := st.UnusedGrantIndexes(); got != nil {
		t.Errorf("nil state UnusedGrantIndexes = %v, want nil", got)
	}
	if got := st.Outcome("aborted"); got != (Outcome{Reason: "aborted", TelemetryComplete: true}) {
		t.Errorf("nil state Outcome = %+v", got)
	}
}

// --- the filesystem-modification definition ---------------------------------

// The architectural requirement this whole file exists to pin: the counter must
// count exactly the events the validator's budget check asks about. Driven from
// the closed Kind enum so a Kind added to one definition and not the other
// fails here rather than in production, where the symptom is a budget that
// never runs out.
func TestFileWriteCountCountsExactlyModifiesFilesystem(t *testing.T) {
	for _, k := range capability.AllKinds() {
		k := k
		t.Run(string(k), func(t *testing.T) {
			st := NewState("s-1", nil)
			st.RecordEvent(eventOf(k, "/ws/target"))

			want := 0
			if validator.ModifiesFilesystem(k) {
				want = 1
			}
			if got := st.FileWriteCount(); got != want {
				t.Errorf("FileWriteCount after one %s = %d, want %d", k, got, want)
			}

			wantProcs := 0
			if validator.SpawnsProcess(k) {
				wantProcs = 1
			}
			if got := st.ProcessCount(); got != wantProcs {
				t.Errorf("ProcessCount after one %s = %d, want %d", k, got, wantProcs)
			}
		})
	}
}

// The same agreement, asserted end to end rather than by construction: for each
// Kind, run a session with MaxFileWrites=1 and check that a second event of
// that Kind trips the constraint if and only if the Kind is a modification.
func TestWriteBudgetTripsForExactlyTheCountedKinds(t *testing.T) {
	for _, k := range capability.AllKinds() {
		if _, ok := capability.DomainOf(k); !ok {
			continue
		}
		k := k
		t.Run(string(k), func(t *testing.T) {
			// An unconstrained grant for the Kind, so nothing but the session
			// budget can produce a non-within verdict.
			env := envelopeWith(ece.Constraints{MaxFileWrites: 1},
				capability.Grant{Kind: k})
			st := NewState("s-1", env)

			verdicts := runSession(t, env, st, []*event.Event{
				eventOf(k, "/ws/a"), eventOf(k, "/ws/b"),
			})

			want := decision.VerdictWithinEnvelope
			if validator.ModifiesFilesystem(k) {
				want = decision.VerdictConstraintViolation
			}
			if verdicts[0] != decision.VerdictWithinEnvelope {
				t.Errorf("first %s = %s, want within_envelope", k, verdicts[0])
			}
			if verdicts[1] != want {
				t.Errorf("second %s = %s, want %s", k, verdicts[1], want)
			}
		})
	}
}

// A write whose path never resolved still charges the budget. Not charging it
// would make an unresolvable target the cheapest way to write for free, which
// is the mirror of the validator refusing to call an unevaluable denial
// "allowed".
func TestUnresolvedWriteStillCharges(t *testing.T) {
	st := NewState("s-1", nil)

	e := &event.Event{
		ID:         "e-unresolved",
		Capability: capability.KindFileWrite,
		Domain:     capability.DomainFilesystem,
		File:       &event.FilePayload{Path: "../escape/a.go"}, // no ResolvedPath
	}
	st.RecordEvent(e)

	if got := st.FileWriteCount(); got != 1 {
		t.Errorf("FileWriteCount = %d, want 1", got)
	}
	if got := st.CapabilityCount(capability.KindFileWrite); got != 1 {
		t.Errorf("CapabilityCount = %d, want 1", got)
	}
	// But nothing was learned about the target, so nothing is recorded as seen.
	if st.SeenTargets(capability.KindFileWrite, "") || st.SeenTargets(capability.KindFileWrite, "../escape/a.go") {
		t.Error("an unresolved target was recorded as seen")
	}
}

// --- grant counters and MaxCount --------------------------------------------

func TestRecordGrantUse(t *testing.T) {
	env := envelopeWith(ece.Constraints{},
		pathGrant(capability.KindFileRead, 0, "/ws/**"),
		pathGrant(capability.KindFileWrite, 0, "/ws/**"))
	st := NewState("s-1", env)

	st.RecordGrantUse(1)
	st.RecordGrantUse(1)
	st.RecordGrantUse(0)

	if got := st.GrantUseCount(0); got != 1 {
		t.Errorf("GrantUseCount(0) = %d, want 1", got)
	}
	if got := st.GrantUseCount(1); got != 2 {
		t.Errorf("GrantUseCount(1) = %d, want 2", got)
	}

	// Out of range in both directions is ignored, never fatal and never
	// misattributed to a neighbouring grant.
	st.RecordGrantUse(-1)
	st.RecordGrantUse(99)
	if got := st.GrantUseCount(0); got != 1 {
		t.Errorf("GrantUseCount(0) after stray writes = %d, want 1", got)
	}
	if got := st.GrantUseCount(99); got != 0 {
		t.Errorf("GrantUseCount(99) = %d, want 0", got)
	}
}

// MaxCount is inclusive: a grant of N permits exactly N uses, and the N+1th is
// refused. The boundary is the whole point of the record-after-validate order.
func TestMaxCountIsInclusive(t *testing.T) {
	const limit = 3

	env := envelopeWith(ece.Constraints{}, pathGrant(capability.KindFileWrite, limit, "/ws/**"))
	st := NewState("s-1", env)

	events := make([]*event.Event, limit+2)
	for i := range events {
		events[i] = fileEvent(capability.KindFileWrite, fmt.Sprintf("/ws/f%d.go", i))
	}
	verdicts := runSession(t, env, st, events)

	for i := 0; i < limit; i++ {
		if verdicts[i] != decision.VerdictWithinEnvelope {
			t.Errorf("use %d = %s, want within_envelope", i+1, verdicts[i])
		}
	}
	for i := limit; i < len(verdicts); i++ {
		if verdicts[i] != decision.VerdictGrantExceeded {
			t.Errorf("use %d = %s, want grant_exceeded", i+1, verdicts[i])
		}
	}
	// The refused uses are not charged, since the pipeline only records a use
	// for a result that matched a grant and stayed within it.
	if got := st.GrantUseCount(0); got != limit {
		t.Errorf("GrantUseCount = %d, want %d", got, limit)
	}
}

// Zero means unlimited, the same rule an empty selector list follows. A grant
// with no MaxCount must never run out.
func TestMaxCountZeroIsUnlimited(t *testing.T) {
	env := envelopeWith(ece.Constraints{}, pathGrant(capability.KindFileWrite, 0, "/ws/**"))
	st := NewState("s-1", env)

	events := make([]*event.Event, 50)
	for i := range events {
		events[i] = fileEvent(capability.KindFileWrite, fmt.Sprintf("/ws/f%d.go", i))
	}
	for i, v := range runSession(t, env, st, events) {
		if v != decision.VerdictWithinEnvelope {
			t.Fatalf("use %d = %s, want within_envelope", i+1, v)
		}
	}
	if got := st.GrantUseCount(0); got != 50 {
		t.Errorf("GrantUseCount = %d, want 50", got)
	}
}

// Two grants for the same Kind keep separate budgets, which only works if the
// index that won precedence is the index that gets charged.
func TestMaxCountIsPerGrantNotPerKind(t *testing.T) {
	env := envelopeWith(ece.Constraints{},
		pathGrant(capability.KindFileWrite, 1, "/ws/src/**"),
		pathGrant(capability.KindFileWrite, 1, "/ws/docs/**"))
	st := NewState("s-1", env)

	verdicts := runSession(t, env, st, []*event.Event{
		fileEvent(capability.KindFileWrite, "/ws/src/a.go"),
		fileEvent(capability.KindFileWrite, "/ws/docs/a.md"),
		fileEvent(capability.KindFileWrite, "/ws/src/b.go"),
	})

	want := []decision.Verdict{
		decision.VerdictWithinEnvelope,
		decision.VerdictWithinEnvelope,
		decision.VerdictGrantExceeded,
	}
	if !reflect.DeepEqual(verdicts, want) {
		t.Errorf("verdicts = %v, want %v", verdicts, want)
	}
	if st.GrantUseCount(0) != 1 || st.GrantUseCount(1) != 1 {
		t.Errorf("grant uses = (%d, %d), want (1, 1)", st.GrantUseCount(0), st.GrantUseCount(1))
	}
}

// --- session constraints -----------------------------------------------------

func TestFileWriteConstraintBoundary(t *testing.T) {
	const limit = 2

	env := envelopeWith(ece.Constraints{MaxFileWrites: limit},
		pathGrant(capability.KindFileWrite, 0, "/ws/**"))
	st := NewState("s-1", env)

	verdicts := runSession(t, env, st, []*event.Event{
		fileEvent(capability.KindFileWrite, "/ws/a.go"),
		fileEvent(capability.KindFileWrite, "/ws/b.go"),
		fileEvent(capability.KindFileWrite, "/ws/c.go"),
	})

	want := []decision.Verdict{
		decision.VerdictWithinEnvelope,
		decision.VerdictWithinEnvelope,
		decision.VerdictConstraintViolation,
	}
	if !reflect.DeepEqual(verdicts, want) {
		t.Errorf("verdicts = %v, want %v", verdicts, want)
	}
}

// An exhausted write budget must not start flagging reads. The per-event
// constraint check is scoped to the dimension the observation exercises, and
// the counters have to keep that true.
func TestExhaustedWriteBudgetDoesNotFlagReads(t *testing.T) {
	env := envelopeWith(ece.Constraints{MaxFileWrites: 1},
		pathGrant(capability.KindFileWrite, 0, "/ws/**"),
		pathGrant(capability.KindFileRead, 0, "/ws/**"))
	st := NewState("s-1", env)

	verdicts := runSession(t, env, st, []*event.Event{
		fileEvent(capability.KindFileWrite, "/ws/a.go"),
		fileEvent(capability.KindFileRead, "/ws/b.go"),
		fileEvent(capability.KindFileWrite, "/ws/c.go"),
		fileEvent(capability.KindFileRead, "/ws/d.go"),
	})

	want := []decision.Verdict{
		decision.VerdictWithinEnvelope,
		decision.VerdictWithinEnvelope,
		decision.VerdictConstraintViolation,
		decision.VerdictWithinEnvelope,
	}
	if !reflect.DeepEqual(verdicts, want) {
		t.Errorf("verdicts = %v, want %v", verdicts, want)
	}
}

func TestProcessConstraintBoundary(t *testing.T) {
	env := envelopeWith(ece.Constraints{MaxProcesses: 2},
		capability.Grant{Kind: capability.KindProcessExec})
	st := NewState("s-1", env)

	verdicts := runSession(t, env, st, []*event.Event{
		eventOf(capability.KindProcessExec, "/usr/bin/go"),
		eventOf(capability.KindProcessExec, "/usr/bin/gcc"),
		eventOf(capability.KindProcessExec, "/usr/bin/ld"),
	})

	if verdicts[2] != decision.VerdictConstraintViolation {
		t.Errorf("third exec = %s, want constraint_violation", verdicts[2])
	}
	if got := st.ProcessCount(); got != 3 {
		t.Errorf("ProcessCount = %d, want 3", got)
	}
}

func TestNetworkBytesConstraint(t *testing.T) {
	env := envelopeWith(ece.Constraints{MaxNetworkBytes: 1000},
		capability.Grant{Kind: capability.KindNetSend})
	st := NewState("s-1", env)

	verdicts := runSession(t, env, st, []*event.Event{
		sentEvent(400), sentEvent(400), sentEvent(400), sentEvent(400),
	})

	// 0, 400, 800 are all under the cap; the fourth event sees 1200 recorded.
	want := []decision.Verdict{
		decision.VerdictWithinEnvelope,
		decision.VerdictWithinEnvelope,
		decision.VerdictWithinEnvelope,
		decision.VerdictConstraintViolation,
	}
	if !reflect.DeepEqual(verdicts, want) {
		t.Errorf("verdicts = %v, want %v", verdicts, want)
	}
	if got := st.NetworkBytesSent(); got != 1600 {
		t.Errorf("NetworkBytesSent = %d, want 1600", got)
	}
}

// Every constraint is unlimited at zero. This is the same rule as MaxCount and
// as an empty selector list, and it is the one that would be silently wrong in
// the dangerous direction: a zero budget refuses everything.
func TestZeroConstraintsAreUnlimited(t *testing.T) {
	env := envelopeWith(ece.Constraints{}, // every limit unset
		pathGrant(capability.KindFileWrite, 0, "/ws/**"),
		capability.Grant{Kind: capability.KindProcessExec},
		capability.Grant{Kind: capability.KindNetSend})
	st := NewState("s-1", env)

	var events []*event.Event
	for i := 0; i < 20; i++ {
		events = append(events,
			fileEvent(capability.KindFileWrite, fmt.Sprintf("/ws/f%d.go", i)),
			eventOf(capability.KindProcessExec, "/usr/bin/go"),
			sentEvent(1<<20))
	}
	for i, v := range runSession(t, env, st, events) {
		if v != decision.VerdictWithinEnvelope {
			t.Fatalf("event %d = %s, want within_envelope under unset limits", i, v)
		}
	}

	// And ValidateSession agrees: nothing to report when nothing was limited.
	viols, err := validator.NewValidator().ValidateSession(context.Background(), env, st)
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	if len(viols) != 0 {
		t.Errorf("ValidateSession = %v, want none", viols)
	}
}

// ValidateSession uses a strict comparison where the per-event check uses an
// inclusive one, because it runs after the fact: a session that made exactly
// its budget did not exceed it.
func TestValidateSessionAtAndOverTheLimit(t *testing.T) {
	env := envelopeWith(ece.Constraints{MaxFileWrites: 2},
		pathGrant(capability.KindFileWrite, 0, "/ws/**"))

	for _, tc := range []struct {
		writes int
		want   int
	}{
		{writes: 1, want: 0},
		{writes: 2, want: 0}, // exactly the budget is not over it
		{writes: 3, want: 1},
	} {
		st := NewState("s-1", env)
		for i := 0; i < tc.writes; i++ {
			st.RecordEvent(fileEvent(capability.KindFileWrite, fmt.Sprintf("/ws/f%d.go", i)))
		}
		viols, err := validator.NewValidator().ValidateSession(context.Background(), env, st)
		if err != nil {
			t.Fatalf("ValidateSession: %v", err)
		}
		if len(viols) != tc.want {
			t.Errorf("%d writes: %d violations, want %d", tc.writes, len(viols), tc.want)
		}
	}
}

// --- elapsed time ------------------------------------------------------------

func TestElapsedFromStreamClock(t *testing.T) {
	base := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)

	// No StartedAt: the stream measures itself, so the host clock is irrelevant
	// and a recorded session replays to the same duration however long ago it
	// ran.
	st := NewStateWith(Config{
		SessionID: "s-1",
		Now:       func() time.Time { return base.Add(999 * time.Hour) },
	})

	if got := st.ElapsedSeconds(); got != 0 {
		t.Errorf("ElapsedSeconds before any event = %v, want 0", got)
	}

	first := fileEvent(capability.KindFileWrite, "/ws/a.go")
	first.WallClock = base
	st.RecordEvent(first)
	if got := st.ElapsedSeconds(); got != 0 {
		t.Errorf("ElapsedSeconds after one event = %v, want 0", got)
	}

	second := fileEvent(capability.KindFileWrite, "/ws/b.go")
	second.WallClock = base.Add(90 * time.Second)
	st.RecordEvent(second)
	if got := st.ElapsedSeconds(); got != 90 {
		t.Errorf("ElapsedSeconds = %v, want 90", got)
	}

	// A record whose wall clock went backwards must not shorten the session.
	// Wall clock is explicitly not the ordering key, and a duration that could
	// decrease would let an exhausted budget come back.
	late := fileEvent(capability.KindFileWrite, "/ws/c.go")
	late.WallClock = base.Add(10 * time.Second)
	st.RecordEvent(late)
	if got := st.ElapsedSeconds(); got != 90 {
		t.Errorf("ElapsedSeconds after a backwards record = %v, want 90", got)
	}
}

func TestElapsedFromHostClock(t *testing.T) {
	base := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	now := base

	st := NewStateWith(Config{
		SessionID: "s-1",
		StartedAt: base,
		Now:       func() time.Time { return now },
	})

	if got := st.ElapsedSeconds(); got != 0 {
		t.Errorf("ElapsedSeconds = %v, want 0", got)
	}

	// An idle session still accrues duration, which is what MaxDuration means
	// for a live agent that has stopped emitting events.
	now = base.Add(5 * time.Minute)
	if got := st.ElapsedSeconds(); got != 300 {
		t.Errorf("ElapsedSeconds = %v, want 300", got)
	}

	// A backwards host clock reports zero, not a negative session.
	now = base.Add(-time.Hour)
	if got := st.ElapsedSeconds(); got != 0 {
		t.Errorf("ElapsedSeconds under a backwards clock = %v, want 0", got)
	}
}

func TestDurationConstraintThroughValidator(t *testing.T) {
	base := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	env := envelopeWith(ece.Constraints{MaxDuration: time.Minute},
		pathGrant(capability.KindFileWrite, 0, "/ws/**"))
	st := NewStateWith(Config{SessionID: "s-1", Envelope: env})

	at := func(d time.Duration, name string) *event.Event {
		e := fileEvent(capability.KindFileWrite, "/ws/"+name)
		e.WallClock = base.Add(d)
		return e
	}

	verdicts := runSession(t, env, st, []*event.Event{
		at(0, "a.go"), at(30*time.Second, "b.go"), at(2*time.Minute, "c.go"),
	})

	// The third event is judged against the elapsed time the first two
	// established, which is 30s — under the limit. The fourth sees 120s.
	if verdicts[2] != decision.VerdictWithinEnvelope {
		t.Errorf("third = %s, want within_envelope", verdicts[2])
	}
	next := verdictOf(t, env, at(3*time.Minute, "d.go"), st)
	if next.Verdict != decision.VerdictConstraintViolation {
		t.Errorf("fourth = %s, want constraint_violation", next.Verdict)
	}
}

// --- history, novelty, and multiple events ----------------------------------

func TestSeenTargets(t *testing.T) {
	st := NewState("s-1", nil)

	if st.SeenTargets(capability.KindFileRead, "/ws/a.go") {
		t.Error("target seen before any event")
	}
	st.RecordEvent(fileEvent(capability.KindFileRead, "/ws/a.go"))

	if !st.SeenTargets(capability.KindFileRead, "/ws/a.go") {
		t.Error("target not seen after being recorded")
	}
	if !st.TargetSeen(capability.KindFileRead, "/ws/a.go") {
		t.Error("TargetSeen disagrees with SeenTargets")
	}
	// Novelty is per (Kind, target): reading a file is not writing it.
	if st.SeenTargets(capability.KindFileWrite, "/ws/a.go") {
		t.Error("a read marked the same path seen for writes")
	}
	if st.SeenTargets(capability.KindFileRead, "/ws/b.go") {
		t.Error("an unrelated target reported seen")
	}
	if st.SeenTargets(capability.KindFileRead, "") {
		t.Error("the empty target reported seen")
	}
}

// At the ceiling the set stops recording, and unrecorded targets keep reporting
// as novel. The failure direction is deliberate: reporting them as familiar
// would let a long session launder every subsequent access.
func TestSeenTargetsSaturatesTowardNovel(t *testing.T) {
	st := NewStateWith(Config{SessionID: "s-1", MaxSeenTargets: 2})

	for i := 0; i < 5; i++ {
		st.RecordEvent(fileEvent(capability.KindFileRead, fmt.Sprintf("/ws/f%d.go", i)))
	}

	if !st.SeenTargets(capability.KindFileRead, "/ws/f0.go") {
		t.Error("a target recorded before the ceiling was forgotten")
	}
	if st.SeenTargets(capability.KindFileRead, "/ws/f4.go") {
		t.Error("a target past the ceiling reported as seen")
	}
	if !st.SeenTargetsSaturated() {
		t.Error("SeenTargetsSaturated false after the ceiling was hit")
	}
	// Counters are unaffected: the ceiling bounds novelty, not accounting.
	if got := st.Snapshot().EventsObserved; got != 5 {
		t.Errorf("EventsObserved = %d, want 5", got)
	}
}

func TestRecentEventsIsChronologicalAndBounded(t *testing.T) {
	st := NewStateWith(Config{SessionID: "s-1", HistorySize: 3})

	for i := 0; i < 5; i++ {
		st.RecordEvent(fileEvent(capability.KindFileWrite, fmt.Sprintf("/ws/f%d.go", i)))
	}

	got := st.RecentEvents(10)
	if len(got) != 3 {
		t.Fatalf("RecentEvents returned %d events, want 3 (the ring size)", len(got))
	}
	for i, want := range []string{"/ws/f2.go", "/ws/f3.go", "/ws/f4.go"} {
		if got[i].Observation.Target != want {
			t.Errorf("RecentEvents[%d] = %q, want %q", i, got[i].Observation.Target, want)
		}
	}

	if two := st.RecentEvents(2); len(two) != 2 || two[0].Observation.Target != "/ws/f3.go" {
		t.Errorf("RecentEvents(2) = %v, want the last two in order", targets(two))
	}
	if st.RecentEvents(0) != nil || st.RecentEvents(-1) != nil {
		t.Error("RecentEvents with a non-positive n returned events")
	}
}

func TestHistoryCanBeDisabled(t *testing.T) {
	st := NewStateWith(Config{SessionID: "s-1", HistorySize: -1})
	st.RecordEvent(fileEvent(capability.KindFileWrite, "/ws/a.go"))

	if got := st.RecentEvents(10); got != nil {
		t.Errorf("RecentEvents = %v, want nil with history disabled", targets(got))
	}
	// Accounting continues regardless: history is a risk input, not the ledger.
	if got := st.FileWriteCount(); got != 1 {
		t.Errorf("FileWriteCount = %d, want 1", got)
	}
}

func targets(events []event.Event) []string {
	out := make([]string, 0, len(events))
	for i := range events {
		out = append(out, events[i].Observation.Target)
	}
	return out
}

func TestCapabilityCountAcrossManyEvents(t *testing.T) {
	st := NewState("s-1", nil)

	for i := 0; i < 7; i++ {
		st.RecordEvent(fileEvent(capability.KindFileRead, fmt.Sprintf("/ws/f%d.go", i)))
	}
	for i := 0; i < 3; i++ {
		st.RecordEvent(fileEvent(capability.KindFileWrite, fmt.Sprintf("/ws/f%d.go", i)))
	}

	if got := st.CapabilityCount(capability.KindFileRead); got != 7 {
		t.Errorf("fs.read count = %d, want 7", got)
	}
	if got := st.CapabilityCount(capability.KindFileWrite); got != 3 {
		t.Errorf("fs.write count = %d, want 3", got)
	}
	if got := st.CapabilityCount(capability.KindNetConnect); got != 0 {
		t.Errorf("net.connect count = %d, want 0", got)
	}
	if got := st.CapabilityCount("not.a.capability"); got != 0 {
		t.Errorf("unknown kind count = %d, want 0", got)
	}

	sum := st.Snapshot()
	if sum.EventsObserved != 10 {
		t.Errorf("EventsObserved = %d, want 10", sum.EventsObserved)
	}
	want := map[capability.Kind]int{capability.KindFileRead: 7, capability.KindFileWrite: 3}
	if !reflect.DeepEqual(sum.CapabilityUsage, want) {
		t.Errorf("CapabilityUsage = %v, want %v", sum.CapabilityUsage, want)
	}
}

func TestDroppedEventsAndTelemetryCompleteness(t *testing.T) {
	st := NewState("s-1", nil)

	st.RecordEvent(fileEvent(capability.KindFileRead, "/ws/a.go"))
	if !st.TelemetryComplete() {
		t.Error("TelemetryComplete false on a clean stream")
	}

	gap := fileEvent(capability.KindFileRead, "/ws/b.go")
	gap.Dropped = 24
	st.RecordEvent(gap)

	if got := st.DroppedEvents(); got != 24 {
		t.Errorf("DroppedEvents = %d, want 24", got)
	}
	if st.TelemetryComplete() {
		t.Error("TelemetryComplete true across a gap")
	}
	if out := st.Outcome("finished"); out.TelemetryComplete {
		t.Error("Outcome.TelemetryComplete true across a gap")
	}
}

// --- decisions ---------------------------------------------------------------

func TestRecordDecision(t *testing.T) {
	st := NewState("s-1", nil)

	st.RecordDecision(&decision.Decision{
		Verdict: decision.VerdictWithinEnvelope, Action: ece.ActionAllow,
		Risk: decision.RiskAssessment{Score: 12},
	})
	st.RecordDecision(&decision.Decision{
		Verdict: decision.VerdictOutsideEnvelope, Action: ece.ActionWarn,
		MatchedRule: "warn-unexpected", Risk: decision.RiskAssessment{Score: 55},
	})
	st.RecordDecision(&decision.Decision{
		Verdict: decision.VerdictExplicitlyDenied, Action: ece.ActionBlock,
		MatchedRule: "deny-credentials", Enforced: true,
		Risk: decision.RiskAssessment{Score: 30},
	})
	// A block that was never applied did not stop anything.
	st.RecordDecision(&decision.Decision{
		Verdict: decision.VerdictExplicitlyDenied, Action: ece.ActionBlock,
		MatchedRule: "deny-credentials", Enforced: false,
	})

	sum := st.Snapshot()
	if sum.DecisionsIssued != 4 {
		t.Errorf("DecisionsIssued = %d, want 4", sum.DecisionsIssued)
	}
	if got := st.ViolationCount(); got != 3 {
		t.Errorf("ViolationCount = %d, want 3", got)
	}
	if got := st.BlockedCount(); got != 1 {
		t.Errorf("BlockedCount = %d, want 1 (only the enforced block)", got)
	}
	if sum.PeakRiskScore != 55 {
		t.Errorf("PeakRiskScore = %v, want 55", sum.PeakRiskScore)
	}

	want := []string{
		"explicitly_denied ×2 (rule deny-credentials)",
		"outside_envelope ×1 (rule warn-unexpected)",
	}
	if !reflect.DeepEqual(sum.TopViolations, want) {
		t.Errorf("TopViolations = %v, want %v", sum.TopViolations, want)
	}
}

func TestSeenTargetsCanBeDisabled(t *testing.T) {
	st := NewStateWith(Config{SessionID: "s-1", MaxSeenTargets: -1})
	st.RecordEvent(fileEvent(capability.KindFileRead, "/ws/a.go"))

	if st.SeenTargets(capability.KindFileRead, "/ws/a.go") {
		t.Error("a target was recorded with the novelty set disabled")
	}
	// Disabled is not saturated: nothing was dropped at a ceiling, the feature
	// was switched off, and a risk factor reading the two the same way would
	// report a degraded signal where there is none.
	if st.SeenTargetsSaturated() {
		t.Error("SeenTargetsSaturated true with the set disabled")
	}
	if got := st.CapabilityCount(capability.KindFileRead); got != 1 {
		t.Errorf("CapabilityCount = %d, want 1", got)
	}
}

// A NaN score must not become an undisplaceable peak: every comparison against
// NaN is false, so a peak of NaN could never be raised or lowered again.
func TestPeakRiskIgnoresNaNAndNonPositive(t *testing.T) {
	st := NewState("s-1", nil)

	st.RecordDecision(&decision.Decision{
		Verdict: decision.VerdictOutsideEnvelope,
		Risk:    decision.RiskAssessment{Score: math.NaN()},
	})
	if got := st.PeakRiskScore(); got != 0 {
		t.Errorf("PeakRiskScore after NaN = %v, want 0", got)
	}

	st.RecordDecision(&decision.Decision{
		Verdict: decision.VerdictOutsideEnvelope, Risk: decision.RiskAssessment{Score: 42},
	})
	st.RecordDecision(&decision.Decision{
		Verdict: decision.VerdictOutsideEnvelope, Risk: decision.RiskAssessment{Score: math.NaN()},
	})
	st.RecordDecision(&decision.Decision{
		Verdict: decision.VerdictOutsideEnvelope, Risk: decision.RiskAssessment{Score: 10},
	})
	if got := st.PeakRiskScore(); got != 42 {
		t.Errorf("PeakRiskScore = %v, want 42", got)
	}
}

// The summary is read by a human in a few seconds, so the violation list is
// capped — and the cap must keep the most frequent, not the first seen.
func TestTopViolationsIsCappedAndRanked(t *testing.T) {
	st := NewState("s-1", nil)

	// Seven distinct rules, firing 1..7 times. Only the top five survive.
	for rule := 1; rule <= 7; rule++ {
		for i := 0; i < rule; i++ {
			st.RecordDecision(&decision.Decision{
				Verdict:     decision.VerdictOutsideEnvelope,
				MatchedRule: fmt.Sprintf("rule-%d", rule),
			})
		}
	}

	got := st.Snapshot().TopViolations
	want := []string{
		"outside_envelope ×7 (rule rule-7)",
		"outside_envelope ×6 (rule rule-6)",
		"outside_envelope ×5 (rule rule-5)",
		"outside_envelope ×4 (rule rule-4)",
		"outside_envelope ×3 (rule rule-3)",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("TopViolations = %v, want %v", got, want)
	}
}

// An unset verdict is a wiring bug, not a governance finding. Counting it would
// attach a violation to evidence the system never produced — the same rule the
// policy engine follows about a condition with no evidence behind it.
func TestUnsetVerdictIsNotAViolation(t *testing.T) {
	st := NewState("s-1", nil)
	st.RecordDecision(&decision.Decision{Action: ece.ActionAllow})

	if got := st.ViolationCount(); got != 0 {
		t.Errorf("ViolationCount = %d, want 0", got)
	}
	if got := st.Snapshot().DecisionsIssued; got != 1 {
		t.Errorf("DecisionsIssued = %d, want 1", got)
	}
}

// --- unused grants -----------------------------------------------------------

func TestUnusedGrants(t *testing.T) {
	optional := pathGrant(capability.KindFileDelete, 0, "/ws/tmp/**")
	optional.Optional = true

	env := envelopeWith(ece.Constraints{},
		pathGrant(capability.KindFileRead, 0, "/ws/**"),  // used
		pathGrant(capability.KindNetConnect, 0),          // never used
		optional,                                         // never used, but optional
		pathGrant(capability.KindFileWrite, 0, "/ws/**"), // never used
	)
	st := NewState("s-1", env)
	st.RecordGrantUse(0)

	if got, want := st.UnusedGrantIndexes(), []int{1, 3}; !reflect.DeepEqual(got, want) {
		t.Errorf("UnusedGrantIndexes = %v, want %v", got, want)
	}
	want := []capability.Kind{capability.KindNetConnect, capability.KindFileWrite}
	if got := st.Snapshot().UnusedGrants; !reflect.DeepEqual(got, want) {
		t.Errorf("UnusedGrants = %v, want %v", got, want)
	}
}

func TestUnusedGrantKindsAreDeduplicated(t *testing.T) {
	env := envelopeWith(ece.Constraints{},
		pathGrant(capability.KindFileWrite, 0, "/ws/src/**"),
		pathGrant(capability.KindFileWrite, 0, "/ws/docs/**"))
	st := NewState("s-1", env)

	if got, want := st.UnusedGrantIndexes(), []int{0, 1}; !reflect.DeepEqual(got, want) {
		t.Errorf("UnusedGrantIndexes = %v, want %v", got, want)
	}
	want := []capability.Kind{capability.KindFileWrite}
	if got := st.Snapshot().UnusedGrants; !reflect.DeepEqual(got, want) {
		t.Errorf("UnusedGrants = %v, want %v", got, want)
	}
}

// --- determinism -------------------------------------------------------------

// The same recording must produce the same summary every time, including the
// order of the violation list. A summary whose order depends on map iteration
// cannot be diffed between two runs of the same corpus, which is exactly what
// the evaluation harness does with it.
func TestSnapshotIsDeterministic(t *testing.T) {
	env := envelopeWith(ece.Constraints{MaxFileWrites: 3},
		pathGrant(capability.KindFileWrite, 2, "/ws/**"),
		pathGrant(capability.KindFileRead, 0, "/ws/**"),
		pathGrant(capability.KindNetConnect, 0))

	build := func() Summary {
		st := NewState("s-1", env)
		events := []*event.Event{
			fileEvent(capability.KindFileWrite, "/ws/a.go"),
			fileEvent(capability.KindFileRead, "/ws/b.go"),
			fileEvent(capability.KindFileWrite, "/ws/c.go"),
			fileEvent(capability.KindFileWrite, "/etc/passwd"),
			fileEvent(capability.KindFileRead, "/ws/b.go"),
		}
		for _, e := range events {
			res := verdictOf(t, env, e, st)
			if res.MatchedGrant != nil && res.Verdict == decision.VerdictWithinEnvelope {
				st.RecordGrantUse(res.MatchedGrantIndex)
			}
			st.RecordEvent(e)
			st.RecordDecision(&decision.Decision{
				Verdict: res.Verdict, Action: ece.ActionWarn, MatchedRule: "r-" + string(res.Verdict),
			})
		}
		return st.Snapshot()
	}

	first := build()
	for i := 0; i < 25; i++ {
		if got := build(); !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d produced %+v, want %+v", i, got, first)
		}
	}
	if len(first.TopViolations) == 0 {
		t.Fatal("the fixture produced no violations, so ordering was never exercised")
	}
}

// Snapshot must be a copy. A reporting path holding one while the session keeps
// running must not see it change underneath.
func TestSnapshotIsACopy(t *testing.T) {
	env := envelopeWith(ece.Constraints{},
		pathGrant(capability.KindFileWrite, 0, "/ws/**"),
		pathGrant(capability.KindNetConnect, 0))
	st := NewState("s-1", env)
	st.RecordEvent(fileEvent(capability.KindFileWrite, "/ws/a.go"))

	sum := st.Snapshot()
	sum.CapabilityUsage[capability.KindFileWrite] = 999
	sum.UnusedGrants[0] = capability.KindKernelBPFLoad
	sum.TopViolations = append(sum.TopViolations, "invented")

	fresh := st.Snapshot()
	if fresh.CapabilityUsage[capability.KindFileWrite] != 1 {
		t.Errorf("mutating a snapshot changed CapabilityUsage: %v", fresh.CapabilityUsage)
	}
	want := []capability.Kind{capability.KindFileWrite, capability.KindNetConnect}
	if !reflect.DeepEqual(fresh.UnusedGrants, want) {
		t.Errorf("mutating a snapshot changed UnusedGrants: %v, want %v", fresh.UnusedGrants, want)
	}
	if len(fresh.TopViolations) != 0 {
		t.Errorf("TopViolations = %v, want none", fresh.TopViolations)
	}
}

// --- concurrency --------------------------------------------------------------

// The guarantee the design actually provides: one writer, and counters that any
// goroutine may read while it works. Run under -race this fails if a counter is
// ever left unsynchronized; without -race it still pins that the values a
// reader observes are monotone and land on the final totals.
//
// It deliberately does not exercise SeenTargets, RecentEvents, or Snapshot
// concurrently. Those are owner-goroutine only by design, and a test that used
// them here would be asserting a guarantee the type does not make.
func TestConcurrentCounterReadsDuringSingleWriter(t *testing.T) {
	const writes = 2000

	env := envelopeWith(ece.Constraints{}, pathGrant(capability.KindFileWrite, 0, "/ws/**"))
	st := NewState("s-1", env)

	stop := make(chan struct{})
	var readers sync.WaitGroup

	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			var lastWrites int
			var lastGrant int
			for {
				select {
				case <-stop:
					return
				default:
				}
				w := st.FileWriteCount()
				g := st.GrantUseCount(0)
				if w < lastWrites {
					t.Errorf("FileWriteCount went backwards: %d then %d", lastWrites, w)
					return
				}
				if g < lastGrant {
					t.Errorf("GrantUseCount went backwards: %d then %d", lastGrant, g)
					return
				}
				lastWrites, lastGrant = w, g
				_ = st.NetworkBytesSent()
				_ = st.ProcessCount()
				_ = st.ViolationCount()
				_ = st.CapabilityCount(capability.KindFileWrite)
				_ = st.ElapsedSeconds()
			}
		}()
	}

	// The single writer.
	for i := 0; i < writes; i++ {
		st.RecordEvent(fileEvent(capability.KindFileWrite, fmt.Sprintf("/ws/f%d.go", i)))
		st.RecordGrantUse(0)
		st.RecordDecision(&decision.Decision{Verdict: decision.VerdictOutsideEnvelope})
	}

	close(stop)
	readers.Wait()

	if got := st.FileWriteCount(); got != writes {
		t.Errorf("FileWriteCount = %d, want %d", got, writes)
	}
	if got := st.GrantUseCount(0); got != writes {
		t.Errorf("GrantUseCount = %d, want %d", got, writes)
	}
	if got := st.ViolationCount(); got != writes {
		t.Errorf("ViolationCount = %d, want %d", got, writes)
	}
}

// --- interface conformance ----------------------------------------------------

// The claim in the package doc, asserted rather than assumed: one type feeds
// both readers, so the validator's counters and the risk engine's history
// cannot come to describe different sessions.
func TestOneStateSatisfiesBothReaders(t *testing.T) {
	st := NewState("s-1", nil)
	st.RecordEvent(fileEvent(capability.KindFileRead, "/ws/a.go"))

	var vs validator.SessionState = st
	if vs.SeenTargets(capability.KindFileRead, "/ws/a.go") != st.TargetSeen(capability.KindFileRead, "/ws/a.go") {
		t.Error("validator.SessionState and risk.History disagree about novelty")
	}
	if vs.ElapsedSeconds() != st.SessionDurationSeconds() {
		t.Error("validator.SessionState and risk.History disagree about duration")
	}
}

// --- benchmarks ---------------------------------------------------------------

func BenchmarkRecordEvent(b *testing.B) {
	env := envelopeWith(ece.Constraints{}, pathGrant(capability.KindFileWrite, 0, "/ws/**"))
	st := NewState("s-1", env)
	e := fileEvent(capability.KindFileWrite, "/ws/a.go")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		st.RecordEvent(e)
	}
}
