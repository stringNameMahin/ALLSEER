package pipeline

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stringNameMahin/ALLSEER/internal/policy"
	"github.com/stringNameMahin/ALLSEER/internal/session"
	"github.com/stringNameMahin/ALLSEER/internal/telemetry/replay"
	"github.com/stringNameMahin/ALLSEER/internal/validator"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// --- fixtures ----------------------------------------------------------------

var baseTime = time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)

// frozen returns a clock that never advances, so latency is zero and every
// decision is byte-comparable between runs.
func frozen() func() time.Time { return func() time.Time { return baseTime } }

func envelope(grants, denials []capability.Grant, c ece.Constraints) *ece.Envelope {
	return &ece.Envelope{
		SchemaVersion: ece.SchemaVersion,
		ID:            "env-1",
		SessionID:     "s-1",
		Grants:        grants,
		Denials:       denials,
		Constraints:   c,
		DefaultAction: ece.ActionRequestApproval,
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

func fileEvent(id string, kind capability.Kind, path string) *event.Event {
	domain, _ := capability.DomainOf(kind)
	return &event.Event{
		ID:         id,
		SessionID:  "s-1",
		Capability: kind,
		Domain:     domain,
		WallClock:  baseTime,
		File:       &event.FilePayload{Path: path, ResolvedPath: path},
		Observation: capability.Observation{
			Kind: kind, Domain: domain, Target: path,
		},
	}
}

// unresolvedEvent carries a path enrichment never resolved, which is the
// validator's unevaluable case rather than a pipeline failure.
func unresolvedEvent(id string) *event.Event {
	return &event.Event{
		ID:         id,
		SessionID:  "s-1",
		Capability: capability.KindFileWrite,
		Domain:     capability.DomainFilesystem,
		WallClock:  baseTime,
		File:       &event.FilePayload{Path: "../escape/a.go"},
	}
}

// simpleRules is a rule set small enough to reason about: deny wins, expected
// behavior is allowed, everything else falls through to the posture.
func simpleRules() *policy.RuleSet {
	return &policy.RuleSet{
		Name:          "test",
		DefaultAction: ece.ActionWarn,
		Rules: []policy.Rule{
			{
				ID: "denied", Description: "explicit denial", Priority: 100, Enabled: true,
				Match:  policy.Condition{Verdicts: []decision.Verdict{decision.VerdictExplicitlyDenied}},
				Action: ece.ActionBlock, Terminal: true,
			},
			{
				ID: "expected", Description: "within envelope", Priority: 50, Enabled: true,
				Match:  policy.Condition{Verdicts: []decision.Verdict{decision.VerdictWithinEnvelope}},
				Action: ece.ActionAllow,
			},
		},
	}
}

func engineFor(t *testing.T, rs *policy.RuleSet) *policy.RuleEngine {
	t.Helper()
	e, err := policy.NewEngine(rs)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

// build assembles a pipeline over the real validator and a real policy engine.
func build(t *testing.T, env *ece.Envelope, st State, rs *policy.RuleSet) *EventPipeline {
	t.Helper()
	p, err := New(Config{
		Session: Session{Envelope: env, Mode: policy.ModeMonitor, State: st},
		Now:     frozen(),
	}, validator.NewValidator(), engineFor(t, rs))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func process(t *testing.T, p *EventPipeline, e *event.Event) *ProcessingContext {
	t.Helper()
	pc, err := p.ProcessContext(context.Background(), e)
	if err != nil {
		t.Fatalf("ProcessContext: %v", err)
	}
	return pc
}

// --- 1. normal flow ----------------------------------------------------------

func TestNormalFlowThroughEveryStage(t *testing.T) {
	env := envelope([]capability.Grant{pathGrant(capability.KindFileWrite, 0, "/ws/**")}, nil, ece.Constraints{})
	st := session.NewState("s-1", env)
	p := build(t, env, st, simpleRules())

	pc := process(t, p, fileEvent("e-1", capability.KindFileWrite, "/ws/a.go"))

	if pc.Validation == nil || pc.Validation.Verdict != decision.VerdictWithinEnvelope {
		t.Fatalf("validation = %+v, want within_envelope", pc.Validation)
	}
	if pc.Outcome == nil || pc.Outcome.Action != ece.ActionAllow || pc.Outcome.RuleID != "expected" {
		t.Fatalf("outcome = %+v, want allow via rule 'expected'", pc.Outcome)
	}

	d := pc.Decision
	if d == nil {
		t.Fatal("no decision")
	}
	if d.ID != "d-e-1" || d.EventID != "e-1" || d.SessionID != "s-1" {
		t.Errorf("identity = %s/%s/%s", d.ID, d.EventID, d.SessionID)
	}
	if d.Verdict != decision.VerdictWithinEnvelope || d.Action != ece.ActionAllow || d.MatchedRule != "expected" {
		t.Errorf("decision = %s/%s/%s", d.Verdict, d.Action, d.MatchedRule)
	}
	if d.MatchedGrant == nil {
		t.Error("MatchedGrant not carried on a within-envelope decision")
	}
	if !d.Timestamp.Equal(baseTime) {
		t.Errorf("Timestamp = %v, want the event's wall clock %v", d.Timestamp, baseTime)
	}
	// Enforcement is M12. A decision that claimed otherwise would be the exact
	// dishonesty Decision.Enforced exists to prevent.
	if d.Enforced {
		t.Error("Enforced is true with no enforcer in the build")
	}
	// Risk was never assessed, and the record has to say so rather than let a
	// zero score read as an assessment.
	if d.Risk.Level != "" {
		t.Errorf("Risk.Level = %q, want empty for an unscored decision", d.Risk.Level)
	}
	if !hasReasoning(d, "risk", "not assessed") {
		t.Error("no reasoning step recording that risk did not run")
	}
	// The chain has to reach from validation through to the action.
	if !hasStage(d, "validator") || !hasStage(d, "policy") {
		t.Errorf("reasoning does not span validation and policy: %+v", d.Reasoning)
	}

	if got := st.Snapshot().EventsObserved; got != 1 {
		t.Errorf("EventsObserved = %d, want 1", got)
	}
	if got := st.GrantUseCount(0); got != 1 {
		t.Errorf("GrantUseCount = %d, want 1", got)
	}
}

func hasStage(d *decision.Decision, stage string) bool {
	for _, r := range d.Reasoning {
		if r.Stage == stage {
			return true
		}
	}
	return false
}

func hasReasoning(d *decision.Decision, stage, conclusion string) bool {
	for _, r := range d.Reasoning {
		if r.Stage == stage && strings.Contains(r.Conclusion, conclusion) {
			return true
		}
	}
	return false
}

// --- 2. denial ----------------------------------------------------------------

func TestDeniedEvent(t *testing.T) {
	env := envelope(
		[]capability.Grant{pathGrant(capability.KindFileWrite, 0, "/ws/**")},
		[]capability.Grant{pathGrant(capability.KindFileWrite, 0, "/ws/.github/**")},
		ece.Constraints{})
	st := session.NewState("s-1", env)
	p := build(t, env, st, simpleRules())

	pc := process(t, p, fileEvent("e-1", capability.KindFileWrite, "/ws/.github/ci.yml"))

	if pc.Validation.Verdict != decision.VerdictExplicitlyDenied {
		t.Fatalf("verdict = %s, want explicitly_denied", pc.Validation.Verdict)
	}
	if pc.Decision.Action != ece.ActionBlock || pc.Decision.MatchedRule != "denied" {
		t.Errorf("decision = %s via %s, want block via 'denied'", pc.Decision.Action, pc.Decision.MatchedRule)
	}
	if !pc.Outcome.Terminal {
		t.Error("Terminal not carried from the outcome")
	}
	// A denied operation never spends a grant, and the decision must not name
	// one: downstream reads MatchedGrant as "what covered this".
	if got := st.GrantUseCount(0); got != 0 {
		t.Errorf("GrantUseCount = %d, want 0 on a denied write", got)
	}
	if pc.Decision.MatchedGrant != nil {
		t.Error("a denied decision carries MatchedGrant")
	}
	// The write still happened, so it still counts against the write budget.
	if got := st.FileWriteCount(); got != 1 {
		t.Errorf("FileWriteCount = %d, want 1", got)
	}
	if got := st.ViolationCount(); got != 1 {
		t.Errorf("ViolationCount = %d, want 1", got)
	}
}

// --- 3. unevaluable ------------------------------------------------------------

// An event the validator cannot evaluate is a finding, not a pipeline failure.
// It travels the normal path and comes out indeterminate; nothing is charged,
// and nothing about the stage list went wrong.
func TestUnevaluableEventIsNotAStageFailure(t *testing.T) {
	env := envelope([]capability.Grant{pathGrant(capability.KindFileWrite, 0, "/ws/**")}, nil, ece.Constraints{})
	st := session.NewState("s-1", env)
	p := build(t, env, st, simpleRules())

	pc := process(t, p, unresolvedEvent("e-1"))

	if pc.Err != nil {
		t.Fatalf("Err = %v, want nil; an unresolvable target is the validator's answer, not a failure", pc.Err)
	}
	if pc.Validation.Verdict != decision.VerdictIndeterminate {
		t.Errorf("verdict = %s, want indeterminate", pc.Validation.Verdict)
	}
	if pc.Decision.Action != ece.ActionWarn {
		t.Errorf("action = %s, want the rule set default", pc.Decision.Action)
	}
	if got := st.GrantUseCount(0); got != 0 {
		t.Errorf("GrantUseCount = %d, want 0", got)
	}
	// Charged anyway: skipping it would make an unresolvable path the cheapest
	// way to spend a write budget for free.
	if got := st.FileWriteCount(); got != 1 {
		t.Errorf("FileWriteCount = %d, want 1", got)
	}
	if got := p.Stats().Errors; got != 0 {
		t.Errorf("Stats.Errors = %d, want 0", got)
	}
}

// --- 4 & 6. ordering -----------------------------------------------------------

// tracingState wraps a real state and logs every write, so the order of writes
// relative to stage execution can be asserted rather than assumed.
type tracingState struct {
	*session.MemoryState
	log *[]string
}

func (s tracingState) RecordEvent(e *event.Event) {
	*s.log = append(*s.log, "state:RecordEvent")
	s.MemoryState.RecordEvent(e)
}

func (s tracingState) RecordDecision(d *decision.Decision) {
	*s.log = append(*s.log, "state:RecordDecision")
	s.MemoryState.RecordDecision(d)
}

func (s tracingState) RecordGrantUse(i int) {
	*s.log = append(*s.log, "state:RecordGrantUse")
	s.MemoryState.RecordGrantUse(i)
}

// tracedStage logs a stage's execution, and optionally what it could see at
// that moment, then delegates to the real thing.
type tracedStage struct {
	inner Stage
	log   *[]string
	seen  func(pc *ProcessingContext)
}

func (s *tracedStage) Name() string { return s.inner.Name() }
func (s *tracedStage) Execute(ctx context.Context, pc *ProcessingContext) error {
	*s.log = append(*s.log, "stage:"+s.inner.Name())
	if s.seen != nil {
		s.seen(pc)
	}
	return s.inner.Execute(ctx, pc)
}

// noopStage is a placeholder for observing the context mid-list.
type noopStage struct{ name string }

func (s *noopStage) Name() string                                      { return s.name }
func (s *noopStage) Execute(context.Context, *ProcessingContext) error { return nil }

// The ordering guarantee, asserted end to end: every stage runs, and only then
// is anything written to session state. This is what keeps a budget inclusive
// and what keeps novelty observable to a future risk stage.
func TestStateIsWrittenOnlyAfterEveryStage(t *testing.T) {
	env := envelope([]capability.Grant{pathGrant(capability.KindFileWrite, 0, "/ws/**")}, nil, ece.Constraints{})
	var log []string
	st := tracingState{MemoryState: session.NewState("s-1", env), log: &log}

	// A mid-list observer standing in for the risk stage that will sit here.
	// If state were written before the stage list finished, it would already
	// see the event under judgment counted, and novelty would be dead.
	var seenWrites int
	observer := &tracedStage{inner: &noopStage{name: "observe"}, log: &log,
		seen: func(pc *ProcessingContext) { seenWrites = pc.State.FileWriteCount() }}

	p, err := NewBuilder(Config{
		Session: Session{Envelope: env, Mode: policy.ModeMonitor, State: st},
		Now:     frozen(),
	}).
		WithStage(&tracedStage{inner: NewValidateStage(validator.NewValidator()), log: &log}).
		WithStage(observer).
		WithStage(&tracedStage{inner: NewDecideStage(engineFor(t, simpleRules())), log: &log}).
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if _, err := p.Process(context.Background(), fileEvent("e-1", capability.KindFileWrite, "/ws/a.go")); err != nil {
		t.Fatalf("Process: %v", err)
	}

	want := []string{
		"stage:validate",
		"stage:observe",
		"stage:decide",
		"state:RecordGrantUse",
		"state:RecordEvent",
		"state:RecordDecision",
	}
	if !reflect.DeepEqual(log, want) {
		t.Errorf("order = %v\nwant %v", log, want)
	}
	if seenWrites != 0 {
		t.Errorf("a stage saw FileWriteCount = %d; the event under judgment was already counted", seenWrites)
	}
}

// --- 5. policy receives the validator result ------------------------------------

type spyEngine struct {
	got  policy.EvaluateRequest
	out  *policy.Outcome
	err  error
	runs int
}

func (e *spyEngine) Evaluate(_ context.Context, req policy.EvaluateRequest) (*policy.Outcome, error) {
	e.got = req
	e.runs++
	return e.out, e.err
}

func TestPolicyReceivesTheValidatorResult(t *testing.T) {
	env := envelope([]capability.Grant{pathGrant(capability.KindFileWrite, 0, "/ws/**")}, nil, ece.Constraints{})
	st := session.NewState("s-1", env)
	spy := &spyEngine{out: &policy.Outcome{Action: ece.ActionAllow, RuleID: "stub"}}

	p, err := New(Config{
		Session: Session{Envelope: env, Mode: policy.ModeEnforce, State: st},
		Now:     frozen(),
	}, validator.NewValidator(), spy)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	e := fileEvent("e-1", capability.KindFileWrite, "/ws/a.go")
	pc := process(t, p, e)

	if spy.runs != 1 {
		t.Fatalf("engine ran %d times, want 1", spy.runs)
	}
	if spy.got.Validation == nil {
		t.Fatal("policy received no validation result")
	}
	if spy.got.Validation != pc.Validation {
		t.Error("policy received a different result than the one on the context")
	}
	if spy.got.Validation.Verdict != decision.VerdictWithinEnvelope {
		t.Errorf("policy saw verdict %s", spy.got.Validation.Verdict)
	}
	if spy.got.Event != e || spy.got.Envelope != env {
		t.Error("policy received a different event or envelope")
	}
	if spy.got.Mode != policy.ModeEnforce {
		t.Errorf("policy saw mode %q, want the session's", spy.got.Mode)
	}
	// Nil, not a zero assessment. A fabricated score of zero would satisfy
	// every max_risk_score rule in a set.
	if spy.got.Risk != nil {
		t.Errorf("policy received a risk assessment (%+v) with no risk stage", spy.got.Risk)
	}
}

// The decide stage refuses to evaluate an event that was never validated,
// rather than letting it fall through to the rule set's default action, which
// would look exactly like a considered decision.
func TestDecideRefusesWithoutValidation(t *testing.T) {
	spy := &spyEngine{out: &policy.Outcome{Action: ece.ActionAllow, RuleID: "stub"}}
	err := NewDecideStage(spy).Execute(context.Background(), &ProcessingContext{})

	if err == nil {
		t.Fatal("decide accepted a context with no validation result")
	}
	if spy.runs != 0 {
		t.Error("the policy engine was called anyway")
	}
}

// --- 7. multiple events sharing one state ----------------------------------------

func TestMultipleEventsShareSessionState(t *testing.T) {
	env := envelope(
		[]capability.Grant{pathGrant(capability.KindFileWrite, 2, "/ws/**")},
		nil,
		ece.Constraints{MaxFileWrites: 3})
	st := session.NewState("s-1", env)
	p := build(t, env, st, simpleRules())

	var verdicts []decision.Verdict
	for i := 0; i < 5; i++ {
		pc := process(t, p, fileEvent(fmt.Sprintf("e-%d", i), capability.KindFileWrite, fmt.Sprintf("/ws/f%d.go", i)))
		verdicts = append(verdicts, pc.Validation.Verdict)
	}

	// MaxCount 2 is spent first (inclusive), so events 3+ are grant_exceeded.
	// The session write budget is never the reported cause here because the
	// grant-specific finding outranks it, which is the validator's rule and
	// must survive being run through the pipeline.
	want := []decision.Verdict{
		decision.VerdictWithinEnvelope,
		decision.VerdictWithinEnvelope,
		decision.VerdictGrantExceeded,
		decision.VerdictGrantExceeded,
		decision.VerdictGrantExceeded,
	}
	if !reflect.DeepEqual(verdicts, want) {
		t.Errorf("verdicts = %v\nwant %v", verdicts, want)
	}
	if got := st.GrantUseCount(0); got != 2 {
		t.Errorf("GrantUseCount = %d, want 2", got)
	}
	if got := st.FileWriteCount(); got != 5 {
		t.Errorf("FileWriteCount = %d, want 5", got)
	}
	if got := p.Stats().EventsProcessed; got != 5 {
		t.Errorf("Stats.EventsProcessed = %d, want 5", got)
	}
}

// --- 8. failure containment ------------------------------------------------------

type failingStage struct {
	name  string
	err   error
	panic bool
}

func (s *failingStage) Name() string { return s.name }
func (s *failingStage) Execute(context.Context, *ProcessingContext) error {
	if s.panic {
		panic("stage exploded")
	}
	return s.err
}

// A stage failure must not silently allow, must not charge a grant it never
// established, and must not stop the event being counted.
func TestStageFailureContainment(t *testing.T) {
	for _, tc := range []struct {
		name       string
		failFirst  bool
		panics     bool
		wantCharge int
	}{
		// Validation never ran, so there is nothing to charge.
		{name: "validate fails", failFirst: true, wantCharge: 0},
		// Validation succeeded and found coverage; a later failure does not
		// unmake that fact, so the grant is still charged.
		{name: "decide fails", failFirst: false, wantCharge: 1},
		{name: "decide panics", failFirst: false, panics: true, wantCharge: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := envelope([]capability.Grant{pathGrant(capability.KindFileWrite, 0, "/ws/**")}, nil, ece.Constraints{})
			st := session.NewState("s-1", env)

			b := NewBuilder(Config{
				Session: Session{Envelope: env, Mode: policy.ModeMonitor, State: st},
				Now:     frozen(),
			})
			if tc.failFirst {
				b = b.WithStage(&failingStage{name: "validate", err: errors.New("boom")})
			} else {
				b = b.WithStage(NewValidateStage(validator.NewValidator())).
					WithStage(&failingStage{name: "decide", err: errors.New("boom"), panic: tc.panics})
			}
			p, err := b.Build()
			if err != nil {
				t.Fatalf("Build: %v", err)
			}

			pc, err := p.(*EventPipeline).ProcessContext(context.Background(),
				fileEvent("e-1", capability.KindFileWrite, "/ws/a.go"))
			if err != nil {
				t.Fatalf("ProcessContext: %v", err)
			}

			if pc.Err == nil {
				t.Fatal("no failure recorded")
			}
			if pc.Decision == nil {
				t.Fatal("a stage failure produced no decision; the event is now indistinguishable from one that never happened")
			}
			if pc.Decision.Verdict != decision.VerdictIndeterminate {
				t.Errorf("verdict = %s, want indeterminate", pc.Decision.Verdict)
			}
			if pc.Decision.Action != ActionForFailure {
				t.Errorf("action = %s, want %s", pc.Decision.Action, ActionForFailure)
			}
			if pc.Decision.MatchedGrant != nil {
				t.Error("a failed run claims a grant covered the event")
			}
			if !hasReasoning(pc.Decision, "pipeline", "failed") {
				t.Errorf("reasoning does not name the failed stage: %+v", pc.Decision.Reasoning)
			}
			if tc.panics && !strings.Contains(pc.Err.Error(), "panicked") {
				t.Errorf("panic was not converted to a stage error: %v", pc.Err)
			}

			if got := st.GrantUseCount(0); got != tc.wantCharge {
				t.Errorf("GrantUseCount = %d, want %d", got, tc.wantCharge)
			}
			// Always counted. The kernel saw the write; a fault in our analysis
			// is not evidence the agent did less.
			if got := st.FileWriteCount(); got != 1 {
				t.Errorf("FileWriteCount = %d, want 1", got)
			}
			if got := st.Snapshot().DecisionsIssued; got != 1 {
				t.Errorf("DecisionsIssued = %d, want 1", got)
			}
			if got := p.Stats().Errors; got != 1 {
				t.Errorf("Stats.Errors = %d, want 1", got)
			}
		})
	}
}

// A pipeline whose stages never reach policy cannot say what should happen, and
// must say so rather than emit the zero Action.
func TestMissingOutcomeIsAFailure(t *testing.T) {
	env := envelope([]capability.Grant{pathGrant(capability.KindFileWrite, 0, "/ws/**")}, nil, ece.Constraints{})
	st := session.NewState("s-1", env)

	p, err := NewBuilder(Config{
		Session: Session{Envelope: env, Mode: policy.ModeMonitor, State: st},
		Now:     frozen(),
	}).WithStage(NewValidateStage(validator.NewValidator())).Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	pc, err := p.(*EventPipeline).ProcessContext(context.Background(),
		fileEvent("e-1", capability.KindFileWrite, "/ws/a.go"))
	if err != nil {
		t.Fatalf("ProcessContext: %v", err)
	}
	if !errors.Is(pc.Err, ErrNoOutcome) {
		t.Errorf("Err = %v, want ErrNoOutcome", pc.Err)
	}
	if pc.Decision.Action == "" {
		t.Error("decision carries the zero Action")
	}
}

// --- 9. determinism ---------------------------------------------------------------

// The same events through a fresh pipeline must produce identical decisions,
// every field included. A random decision ID or a host-clock timestamp would
// make two runs of one recording disagree, which breaks every regression test
// built on replay and the evaluation corpus with them.
func TestDeterministic(t *testing.T) {
	run := func() []decision.Decision {
		env := envelope(
			[]capability.Grant{pathGrant(capability.KindFileWrite, 1, "/ws/**")},
			[]capability.Grant{pathGrant(capability.KindFileWrite, 0, "/ws/.git/**")},
			ece.Constraints{MaxFileWrites: 2, WorkspaceRoot: "/ws"})
		st := session.NewState("s-1", env)
		p := build(t, env, st, simpleRules())

		events := []*event.Event{
			fileEvent("e-1", capability.KindFileWrite, "/ws/a.go"),
			fileEvent("e-2", capability.KindFileWrite, "/ws/.git/index"),
			fileEvent("e-3", capability.KindFileWrite, "/ws/b.go"),
			unresolvedEvent("e-4"),
			fileEvent("e-5", capability.KindFileWrite, "/etc/passwd"),
		}
		var out []decision.Decision
		for _, e := range events {
			out = append(out, *process(t, p, e).Decision)
		}
		return out
	}

	first := run()
	if len(first) != 5 {
		t.Fatalf("got %d decisions", len(first))
	}
	for i := 0; i < 25; i++ {
		if got := run(); !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d differed\n got %+v\nwant %+v", i, got, first)
		}
	}

	// The fixture has to actually exercise more than one outcome, or determinism
	// is being asserted over a constant.
	seen := map[decision.Verdict]bool{}
	for _, d := range first {
		seen[d.Verdict] = true
	}
	if len(seen) < 3 {
		t.Errorf("fixture produced only %d distinct verdicts: %v", len(seen), seen)
	}
}

// --- 10. equivalence with the hand-written orchestration ---------------------------

// referenceResult is the shape the old evaluateStream produced.
type referenceResult struct {
	EventID  string
	Verdict  decision.Verdict
	RuleID   string
	Action   ece.Action
	Terminal bool
}

// referenceLoop is the orchestration cmd/allseerctl/policy.go used to carry
// inline, reproduced verbatim: validate, evaluate, then charge the grant and
// record the event. It is kept here on purpose. The pipeline was written to
// replace it, and the only way to know it replaced it rather than quietly
// changed it is to keep the original and compare.
func referenceLoop(t *testing.T, events []event.Event, env *ece.Envelope, engine *policy.RuleEngine, mode policy.Mode) ([]referenceResult, *session.MemoryState) {
	t.Helper()

	val := validator.NewValidator()
	st := session.NewState(env.SessionID, env)
	var out []referenceResult

	for i := range events {
		e := events[i]
		res, err := val.Validate(context.Background(), validator.ValidateRequest{
			Envelope: env, Event: &e, State: st,
		})
		if err != nil {
			t.Fatalf("reference validate: %v", err)
		}
		outcome, err := engine.Evaluate(context.Background(), policy.EvaluateRequest{
			Event: &e, Validation: res, Envelope: env, Mode: mode,
		})
		if err != nil {
			t.Fatalf("reference evaluate: %v", err)
		}

		out = append(out, referenceResult{
			EventID: e.ID, Verdict: res.Verdict,
			RuleID: outcome.RuleID, Action: outcome.Action, Terminal: outcome.Terminal,
		})

		if res.MatchedGrant != nil && res.Verdict == decision.VerdictWithinEnvelope {
			st.RecordGrantUse(res.MatchedGrantIndex)
		}
		st.RecordEvent(&e)
	}
	return out, st
}

// gitEnvelope mirrors the envelope cmd/allseerctl's dry-run test uses against
// the same recording, so the two agree about what is being replayed.
func gitEnvelope() *ece.Envelope {
	ws := "/home/dev/project"
	env := envelope(
		[]capability.Grant{
			pathGrant(capability.KindFileRead, 0, ws+"/**"),
			pathGrant(capability.KindFileWrite, 0, ws+"/**"),
			pathGrant(capability.KindFileCreate, 0, ws+"/**"),
			pathGrant(capability.KindFileRename, 0, ws+"/**"),
			{Kind: capability.KindProcessExec, Domain: capability.DomainProcess,
				Selector: capability.Selector{Executables: []string{"/usr/bin/git"}}},
			{Kind: capability.KindProcessExit, Domain: capability.DomainProcess,
				Selector: capability.Selector{Executables: []string{"/usr/bin/git"}}},
		},
		[]capability.Grant{pathGrant(capability.KindFileWrite, 0, ws+"/.github/**")},
		ece.Constraints{WorkspaceRoot: ws})
	env.SessionID = "s-git"
	return env
}

func loadFixture(t *testing.T, name string) []event.Event {
	t.Helper()

	src := replay.New(replay.Config{Path: filepath.Join("..", "..", "test", "testdata", "replay", name)})
	if err := src.Start(context.Background()); err != nil {
		t.Fatalf("replay start: %v", err)
	}
	defer func() { _ = src.Close() }()

	var out []event.Event
	for e := range src.Events() {
		out = append(out, e)
	}
	if err := src.Err(); err != nil {
		t.Fatalf("replay: %v", err)
	}
	if len(out) == 0 {
		t.Fatalf("fixture %s produced no events", name)
	}
	return out
}

func defaultEngine(t *testing.T) *policy.RuleEngine {
	t.Helper()

	rs, err := policy.NewLoader().Load(context.Background(),
		filepath.Join("..", "..", "configs", "rules.default.yaml"))
	if err != nil {
		t.Fatalf("loading the shipped rule set: %v", err)
	}
	return engineFor(t, rs)
}

func TestPipelineReproducesTheHandWrittenOrchestration(t *testing.T) {
	for _, fixture := range []string{"git-operation.jsonl", "go-build.jsonl", "npm-install.jsonl"} {
		t.Run(fixture, func(t *testing.T) {
			events := loadFixture(t, fixture)
			env := gitEnvelope()
			mode := policy.ModeMonitor

			want, refState := referenceLoop(t, events, env, defaultEngine(t), mode)

			st := session.NewState(env.SessionID, env)
			p, err := New(Config{
				Session: Session{Envelope: env, Mode: mode, State: st},
				Now:     frozen(),
			}, validator.NewValidator(), defaultEngine(t))
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			var got []referenceResult
			for i := range events {
				e := events[i]
				pc := process(t, p, &e)
				if pc.Err != nil {
					t.Fatalf("%s: %v", e.ID, pc.Err)
				}
				got = append(got, referenceResult{
					EventID: e.ID, Verdict: pc.Validation.Verdict,
					RuleID: pc.Outcome.RuleID, Action: pc.Outcome.Action, Terminal: pc.Outcome.Terminal,
				})
			}

			if !reflect.DeepEqual(got, want) {
				t.Errorf("pipeline diverged from the hand-written orchestration\n got %+v\nwant %+v", got, want)
			}

			// The counters have to land in the same place too. A pipeline that
			// reached the same verdicts while charging different budgets would
			// diverge on the very next event.
			gotSum, refSum := st.Snapshot(), refState.Snapshot()
			if gotSum.EventsObserved != refSum.EventsObserved {
				t.Errorf("EventsObserved = %d, reference %d", gotSum.EventsObserved, refSum.EventsObserved)
			}
			if !reflect.DeepEqual(gotSum.CapabilityUsage, refSum.CapabilityUsage) {
				t.Errorf("CapabilityUsage diverged\n got %v\nwant %v", gotSum.CapabilityUsage, refSum.CapabilityUsage)
			}
			if !reflect.DeepEqual(gotSum.UnusedGrants, refSum.UnusedGrants) {
				t.Errorf("UnusedGrants diverged\n got %v\nwant %v", gotSum.UnusedGrants, refSum.UnusedGrants)
			}
			for i := range env.Grants {
				if a, b := st.GrantUseCount(i), refState.GrantUseCount(i); a != b {
					t.Errorf("grant %d charged %d times, reference charged %d", i, a, b)
				}
			}
			for _, c := range []struct {
				name string
				a, b int
			}{
				{"FileWriteCount", st.FileWriteCount(), refState.FileWriteCount()},
				{"ProcessCount", st.ProcessCount(), refState.ProcessCount()},
			} {
				if c.a != c.b {
					t.Errorf("%s = %d, reference %d", c.name, c.a, c.b)
				}
			}
			if a, b := st.NetworkBytesSent(), refState.NetworkBytesSent(); a != b {
				t.Errorf("NetworkBytesSent = %d, reference %d", a, b)
			}

			// The one intended divergence, asserted rather than glossed over:
			// the hand-written loop produced no decision.Decision at all — it
			// built the CLI's own result shape — so it never called
			// RecordDecision and its violation and decision counters stayed at
			// zero. The pipeline emits the record the daemon needs and counts
			// it. Anything beyond this in the diff would be a real regression,
			// which is why the comparison above is field by field rather than a
			// blanket DeepEqual that would absorb it.
			if refSum.DecisionsIssued != 0 {
				t.Errorf("the reference loop recorded %d decisions; it is not supposed to record any", refSum.DecisionsIssued)
			}
			if gotSum.DecisionsIssued != uint64(len(events)) {
				t.Errorf("DecisionsIssued = %d, want one per event (%d)", gotSum.DecisionsIssued, len(events))
			}
		})
	}
}

// --- Run, sinks, and construction ---------------------------------------------------

type stubSource struct{ ch chan event.Event }

func (s *stubSource) Events() <-chan event.Event  { return s.ch }
func (s *stubSource) Start(context.Context) error { return nil }
func (s *stubSource) Close() error                { return nil }
func (s *stubSource) Stats() event.SourceStats    { return event.SourceStats{} }

type recordingSink struct {
	emitted []decision.Decision
	err     error
}

func (s *recordingSink) Emit(_ context.Context, d decision.Decision) error {
	s.emitted = append(s.emitted, d)
	return s.err
}
func (s *recordingSink) Flush(context.Context) error { return nil }

func TestRunDrainsTheSourceAndEmits(t *testing.T) {
	env := envelope([]capability.Grant{pathGrant(capability.KindFileWrite, 0, "/ws/**")}, nil, ece.Constraints{})
	st := session.NewState("s-1", env)
	sink := &recordingSink{}

	p, err := New(Config{
		Session: Session{Envelope: env, Mode: policy.ModeMonitor, State: st},
		Sink:    sink,
		Now:     frozen(),
	}, validator.NewValidator(), engineFor(t, simpleRules()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	src := &stubSource{ch: make(chan event.Event, 3)}
	for i := 0; i < 3; i++ {
		src.ch <- *fileEvent(fmt.Sprintf("e-%d", i), capability.KindFileWrite, fmt.Sprintf("/ws/f%d.go", i))
	}
	close(src.ch)

	if err := p.Run(context.Background(), src); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(sink.emitted) != 3 {
		t.Errorf("sink received %d decisions, want 3", len(sink.emitted))
	}
	if got := st.Snapshot().EventsObserved; got != 3 {
		t.Errorf("EventsObserved = %d, want 3", got)
	}
	if got := p.Stats().DecisionsIssued; got != 3 {
		t.Errorf("DecisionsIssued = %d, want 3", got)
	}
}

// An audit sink that cannot write must not be able to stop governance. It is
// counted and the run continues.
func TestSinkFailureDoesNotStopTheRun(t *testing.T) {
	env := envelope([]capability.Grant{pathGrant(capability.KindFileWrite, 0, "/ws/**")}, nil, ece.Constraints{})
	st := session.NewState("s-1", env)
	sink := &recordingSink{err: errors.New("disk full")}

	p, err := New(Config{
		Session: Session{Envelope: env, Mode: policy.ModeMonitor, State: st},
		Sink:    sink, Now: frozen(),
	}, validator.NewValidator(), engineFor(t, simpleRules()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	src := &stubSource{ch: make(chan event.Event, 2)}
	src.ch <- *fileEvent("e-1", capability.KindFileWrite, "/ws/a.go")
	src.ch <- *fileEvent("e-2", capability.KindFileWrite, "/ws/b.go")
	close(src.ch)

	if err := p.Run(context.Background(), src); err != nil {
		t.Fatalf("Run returned %v; an audit failure must not stop the pipeline", err)
	}
	if got := st.Snapshot().EventsObserved; got != 2 {
		t.Errorf("EventsObserved = %d, want 2", got)
	}
	if got := p.Stats().Errors; got != 2 {
		t.Errorf("Stats.Errors = %d, want 2", got)
	}
}

func TestRunStopsOnContextCancel(t *testing.T) {
	env := envelope([]capability.Grant{pathGrant(capability.KindFileWrite, 0, "/ws/**")}, nil, ece.Constraints{})
	p := build(t, env, session.NewState("s-1", env), simpleRules())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	src := &stubSource{ch: make(chan event.Event)} // never delivers
	if err := p.Run(ctx, src); !errors.Is(err, context.Canceled) {
		t.Errorf("Run = %v, want context.Canceled", err)
	}
}

func TestBuilderRejections(t *testing.T) {
	env := envelope([]capability.Grant{pathGrant(capability.KindFileWrite, 0, "/ws/**")}, nil, ece.Constraints{})
	st := session.NewState("s-1", env)
	ok := Session{Envelope: env, Mode: policy.ModeMonitor, State: st}
	stage := NewValidateStage(validator.NewValidator())

	for _, tc := range []struct {
		name   string
		sess   Session
		stages []Stage
		conc   int
		want   string
	}{
		{name: "no envelope", sess: Session{Mode: policy.ModeMonitor, State: st}, stages: []Stage{stage}, want: "envelope is required"},
		{name: "no state", sess: Session{Envelope: env, Mode: policy.ModeMonitor}, stages: []Stage{stage}, want: "state is required"},
		{name: "no mode", sess: Session{Envelope: env, State: st}, stages: []Stage{stage}, want: "mode is required"},
		{name: "no stages", sess: ok, want: "at least one stage"},
		{name: "nil stage", sess: ok, stages: []Stage{nil}, want: "stage 0 is nil"},
		{name: "concurrency", sess: ok, stages: []Stage{stage}, conc: 4, want: "governs one session"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := NewBuilder(Config{Session: tc.sess})
			for _, s := range tc.stages {
				b = b.WithStage(s)
			}
			if tc.conc != 0 {
				b = b.WithConcurrency(tc.conc)
			}
			_, err := b.Build()
			if err == nil {
				t.Fatal("Build accepted it")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestSessionIDDefaultsToTheEnvelope(t *testing.T) {
	env := envelope([]capability.Grant{pathGrant(capability.KindFileWrite, 0, "/ws/**")}, nil, ece.Constraints{})
	p := build(t, env, session.NewState("s-1", env), simpleRules())

	pc := process(t, p, fileEvent("e-1", capability.KindFileWrite, "/ws/a.go"))
	if pc.Decision.SessionID != env.SessionID {
		t.Errorf("SessionID = %q, want %q", pc.Decision.SessionID, env.SessionID)
	}
}

func TestProcessRejectsANilEvent(t *testing.T) {
	env := envelope([]capability.Grant{pathGrant(capability.KindFileWrite, 0, "/ws/**")}, nil, ece.Constraints{})
	p := build(t, env, session.NewState("s-1", env), simpleRules())

	if _, err := p.Process(context.Background(), nil); !errors.Is(err, ErrNoEvent) {
		t.Errorf("err = %v, want ErrNoEvent", err)
	}
	if got := p.Stats().EventsProcessed; got != 0 {
		t.Errorf("a rejected call was counted: %d", got)
	}
}

func TestStatsBreakDownByStage(t *testing.T) {
	env := envelope([]capability.Grant{pathGrant(capability.KindFileWrite, 0, "/ws/**")}, nil, ece.Constraints{})
	st := session.NewState("s-1", env)

	// A clock that advances a fixed step per reading, so latency is non-zero
	// and still deterministic.
	var ticks int64
	clock := func() time.Time {
		ticks++
		return baseTime.Add(time.Duration(ticks) * time.Millisecond)
	}

	p, err := New(Config{
		Session: Session{Envelope: env, Mode: policy.ModeMonitor, State: st}, Now: clock,
	}, validator.NewValidator(), engineFor(t, simpleRules()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 0; i < 4; i++ {
		process(t, p, fileEvent(fmt.Sprintf("e-%d", i), capability.KindFileWrite, "/ws/a.go"))
	}

	s := p.Stats()
	if s.EventsProcessed != 4 || s.DecisionsIssued != 4 {
		t.Errorf("counts = %d/%d, want 4/4", s.EventsProcessed, s.DecisionsIssued)
	}
	if s.AvgLatency <= 0 || s.P99Latency <= 0 {
		t.Errorf("latency = avg %v, p99 %v; both should be measured", s.AvgLatency, s.P99Latency)
	}
	for _, name := range []string{"validate", "decide"} {
		if s.StageLatencies[name] <= 0 {
			t.Errorf("no latency recorded for stage %q: %v", name, s.StageLatencies)
		}
	}
	// Synchronous processing with no internal buffer, so this is a measured
	// zero rather than an unmeasured one.
	if s.QueueDepth != 0 {
		t.Errorf("QueueDepth = %d, want 0", s.QueueDepth)
	}
}

// What to do about a governance fault is deployment-specific — an unattended CI
// run has no human to ask — which is why ErrorHandler is an interface and the
// action is settable rather than fixed in the pipeline.
func TestCustomErrorHandler(t *testing.T) {
	env := envelope([]capability.Grant{pathGrant(capability.KindFileWrite, 0, "/ws/**")}, nil, ece.Constraints{})
	st := session.NewState("s-1", env)

	p, err := NewBuilder(Config{
		Session: Session{Envelope: env, Mode: policy.ModeEnforce, State: st}, Now: frozen(),
	}).
		WithStage(&failingStage{name: "validate", err: errors.New("boom")}).
		WithErrorHandler(NewErrorHandlerWithAction(ece.ActionBlock)).
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	d, err := p.Process(context.Background(), fileEvent("e-1", capability.KindFileWrite, "/ws/a.go"))
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if d.Action != ece.ActionBlock {
		t.Errorf("action = %s, want block from the configured handler", d.Action)
	}
	if d.Verdict != decision.VerdictIndeterminate {
		t.Errorf("verdict = %s; the handler chooses the action, never the verdict", d.Verdict)
	}
}

// A handler may decline to emit a record. The event is still counted: the
// counters describe what the kernel observed, and returning budget on a stage
// failure would make failing a stage the cheapest way to spend one.
type silentHandler struct{}

func (silentHandler) Handle(context.Context, *ProcessingContext, string, error) *decision.Decision {
	return nil
}

func TestHandlerMayEmitNoDecisionButTheEventIsStillCounted(t *testing.T) {
	env := envelope([]capability.Grant{pathGrant(capability.KindFileWrite, 0, "/ws/**")}, nil, ece.Constraints{})
	st := session.NewState("s-1", env)

	p, err := NewBuilder(Config{
		Session: Session{Envelope: env, Mode: policy.ModeMonitor, State: st}, Now: frozen(),
	}).
		WithStage(&failingStage{name: "validate", err: errors.New("boom")}).
		WithErrorHandler(silentHandler{}).
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	d, err := p.Process(context.Background(), fileEvent("e-1", capability.KindFileWrite, "/ws/a.go"))
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if d != nil {
		t.Errorf("decision = %+v, want none", d)
	}
	if got := st.FileWriteCount(); got != 1 {
		t.Errorf("FileWriteCount = %d, want 1", got)
	}
	if got := st.Snapshot().DecisionsIssued; got != 0 {
		t.Errorf("DecisionsIssued = %d, want 0", got)
	}
	if s := p.Stats(); s.EventsProcessed != 1 || s.DecisionsIssued != 0 {
		t.Errorf("stats = %d processed / %d issued, want 1/0", s.EventsProcessed, s.DecisionsIssued)
	}
}

// An event with neither an ID nor a wall clock still produces a stable,
// attributable record. Falling back to the host clock is the same rule the
// validator applies to expiry, and the identifier falls back to the session and
// sequence rather than to something random.
func TestIdentityAndTimestampFallbacks(t *testing.T) {
	env := envelope([]capability.Grant{pathGrant(capability.KindFileWrite, 0, "/ws/**")}, nil, ece.Constraints{})
	p := build(t, env, session.NewState("s-1", env), simpleRules())

	e := fileEvent("", capability.KindFileWrite, "/ws/a.go")
	e.WallClock = time.Time{}
	e.Sequence = 42

	d := process(t, p, e).Decision
	if d.ID != "d-s-1-42" {
		t.Errorf("ID = %q, want the session and sequence fallback", d.ID)
	}
	if !d.Timestamp.Equal(baseTime) {
		t.Errorf("Timestamp = %v, want the pipeline clock %v", d.Timestamp, baseTime)
	}
}

// The stages promise a non-nil result alongside a nil error. A stage that
// breaks that contract has to fail where it broke it, not one stage later as a
// nil dereference.
func TestStagesRejectBrokenEngineContracts(t *testing.T) {
	ctx := context.Background()
	pc := &ProcessingContext{Event: fileEvent("e-1", capability.KindFileWrite, "/ws/a.go")}

	for _, tc := range []struct {
		name  string
		stage Stage
		pc    *ProcessingContext
		want  string
	}{
		{"no validator", NewValidateStage(nil), pc, "no validator configured"},
		{"validator returns nil", NewValidateStage(nilValidator{}), pc, "returned no result"},
		{"no engine", NewDecideStage(nil), pc, "no policy engine configured"},
		{"engine returns nil", NewDecideStage(&spyEngine{}),
			&ProcessingContext{Event: pc.Event, Validation: &validator.Result{}}, "returned no outcome"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.stage.Execute(ctx, tc.pc)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

type nilValidator struct{}

func (nilValidator) Validate(context.Context, validator.ValidateRequest) (*validator.Result, error) {
	return nil, nil
}

func TestRunRejectsANilSource(t *testing.T) {
	env := envelope([]capability.Grant{pathGrant(capability.KindFileWrite, 0, "/ws/**")}, nil, ece.Constraints{})
	p := build(t, env, session.NewState("s-1", env), simpleRules())

	if err := p.Run(context.Background(), nil); !errors.Is(err, ErrNoSource) {
		t.Errorf("err = %v, want ErrNoSource", err)
	}
}

// --- benchmark -------------------------------------------------------------------

func BenchmarkProcess(b *testing.B) {
	env := envelope([]capability.Grant{pathGrant(capability.KindFileWrite, 0, "/ws/**")}, nil, ece.Constraints{})
	st := session.NewState("s-1", env)

	e, err := policy.NewEngine(simpleRules())
	if err != nil {
		b.Fatalf("NewEngine: %v", err)
	}
	p, err := New(Config{Session: Session{Envelope: env, Mode: policy.ModeMonitor, State: st}},
		validator.NewValidator(), e)
	if err != nil {
		b.Fatalf("New: %v", err)
	}

	ev := fileEvent("e-1", capability.KindFileWrite, "/ws/a.go")
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := p.Process(ctx, ev); err != nil {
			b.Fatal(err)
		}
	}
}
