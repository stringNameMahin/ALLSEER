package pipeline

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/stringNameMahin/ALLSEER/internal/policy"
	"github.com/stringNameMahin/ALLSEER/internal/risk"
	"github.com/stringNameMahin/ALLSEER/internal/session"
	"github.com/stringNameMahin/ALLSEER/internal/validator"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// This file covers the score stage: the composition validate → score → decide,
// and the two claims that only hold end to end. That the scorer reads the
// session history *before* the pipeline commits the event is one of them, and it
// is unobservable from either package alone. That a risk-conditioned policy rule
// can now fire is the other, and it is the whole reason this milestone exists.

// --- fixtures ---------------------------------------------------------------------

func f64(v float64) *float64 { return &v }

// riskRules is a rule set whose interesting rules are risk-conditioned, so
// "fired" and "did not fire" is a direct statement about whether risk evidence
// reached policy.
func riskRules() *policy.RuleSet {
	return &policy.RuleSet{
		Name:          "risk-test",
		DefaultAction: ece.ActionWarn,
		Rules: []policy.Rule{
			{
				ID: "elevated-departure", Description: "a departure scoring at least 50", Priority: 100, Enabled: true,
				Match: policy.Condition{
					Verdicts:     []decision.Verdict{decision.VerdictOutsideEnvelope, decision.VerdictGrantExceeded},
					MinRiskScore: f64(50),
				},
				Action: ece.ActionBlock,
			},
			{
				ID: "quiet-departure", Description: "a departure scoring under 50", Priority: 90, Enabled: true,
				Match: policy.Condition{
					Verdicts:     []decision.Verdict{decision.VerdictOutsideEnvelope, decision.VerdictGrantExceeded},
					MaxRiskScore: f64(50),
				},
				Action: ece.ActionAllow,
			},
			{
				ID: "expected", Description: "within envelope", Priority: 50, Enabled: true,
				Match:  policy.Condition{Verdicts: []decision.Verdict{decision.VerdictWithinEnvelope}},
				Action: ece.ActionAllow,
			},
		},
	}
}

// buildScored assembles the full pipeline: validate, score, decide.
func buildScored(t *testing.T, env *ece.Envelope, st State, rs *policy.RuleSet) *EventPipeline {
	t.Helper()
	p, err := NewWithRisk(Config{
		Session: Session{Envelope: env, Mode: policy.ModeMonitor, State: st},
		Now:     frozen(),
	}, validator.NewValidator(), risk.NewEngine(), engineFor(t, rs))
	if err != nil {
		t.Fatalf("NewWithRisk: %v", err)
	}
	return p
}

// shippedOracle loads configs/sensitivity.default.yaml — the list the project
// actually ships, not a fixture. The defaults are a security claim, and a claim
// exercised only against a test-local list is a claim nothing checks.
func shippedOracle(t *testing.T) *risk.PathOracle {
	t.Helper()
	o, err := risk.LoadPathOracle(filepath.Join("..", "..", "configs", "sensitivity.default.yaml"))
	if err != nil {
		t.Fatalf("loading the shipped sensitivity list: %v", err)
	}
	return o
}

func ratedEngine(t *testing.T) *risk.BaselineEngine {
	t.Helper()
	e, err := risk.NewEngineWithOracle(shippedOracle(t))
	if err != nil {
		t.Fatalf("NewEngineWithOracle: %v", err)
	}
	return e
}

// buildRated is buildScored with the shipped sensitivity list behind it.
func buildRated(t *testing.T, env *ece.Envelope, st State, rs *policy.RuleSet) *EventPipeline {
	t.Helper()
	p, err := NewWithRisk(Config{
		Session: Session{Envelope: env, Mode: policy.ModeMonitor, State: st},
		Now:     frozen(),
	}, validator.NewValidator(), ratedEngine(t), engineFor(t, rs))
	if err != nil {
		t.Fatalf("NewWithRisk: %v", err)
	}
	return p
}

// escapeEnvelope grants reads inside a workspace, so a read outside it is a
// grant_exceeded that is also a workspace escape — the highest-scoring shape the
// baseline model produces without an explicit denial.
func escapeEnvelope() *ece.Envelope {
	env := envelope(
		[]capability.Grant{pathGrant(capability.KindFileRead, 0, "/ws/**")},
		nil,
		ece.Constraints{WorkspaceRoot: "/ws"},
	)
	return env
}

// --- the composition ----------------------------------------------------------------

// Event → validate → score → decide, with each stage's output visible on the
// context and the finished Decision carrying the assessment.
func TestPipelineScoresBetweenValidateAndDecide(t *testing.T) {
	env := escapeEnvelope()
	st := session.NewState("s-1", env)
	p := buildScored(t, env, st, riskRules())

	pc := process(t, p, fileEvent("e-1", capability.KindFileRead, "/etc/hosts"))

	if pc.Err != nil {
		t.Fatalf("unexpected stage failure: %v", pc.Err)
	}
	if pc.Validation == nil {
		t.Fatal("no validation result")
	}
	if pc.Risk == nil {
		t.Fatal("no risk assessment; the score stage did not run")
	}

	// 25 grant_exceeded + 15 (the escape's high severity) + 10 escape + 5 novel.
	if pc.Risk.Score != 55 {
		t.Errorf("Score = %v, want 55 (factors %+v)", pc.Risk.Score, pc.Risk.Factors)
	}
	if pc.Risk.Level != decision.LevelHigh {
		t.Errorf("Level = %q, want %q", pc.Risk.Level, decision.LevelHigh)
	}
	if !decision.ValidLevel(pc.Risk.Level) {
		t.Errorf("Level %q is not a member of decision.AllLevels", pc.Risk.Level)
	}

	// The risk-conditioned rule fired, which is what this milestone is for.
	if pc.Outcome.RuleID != "elevated-departure" {
		t.Errorf("RuleID = %q, want the risk-conditioned rule to have fired", pc.Outcome.RuleID)
	}
	if pc.Outcome.Action != ece.ActionBlock {
		t.Errorf("Action = %q, want %q", pc.Outcome.Action, ece.ActionBlock)
	}

	// And the audit record carries the assessment rather than the "risk did not
	// run" admission it used to.
	d := pc.Decision
	if d.Risk.Level != pc.Risk.Level || d.Risk.Score != pc.Risk.Score {
		t.Errorf("Decision.Risk = %+v, want the assessment the stage produced", d.Risk)
	}
	if len(d.Risk.Factors) == 0 {
		t.Error("Decision.Risk carries no factors; a score with no decomposition cannot be defended")
	}
	for _, s := range d.Reasoning {
		if s.Stage == "risk" && s.Conclusion == "not assessed" {
			t.Error("the decision still claims risk did not run")
		}
	}

	// Stage latencies name the score stage, so a regression in it can be
	// attributed rather than guessed at.
	if _, ok := p.Stats().StageLatencies["score"]; !ok {
		t.Error("Stats does not break out the score stage")
	}
}

// The same event under the same rule set, scored and unscored. The unscored
// pipeline must keep behaving exactly as it did before this milestone: a rule
// with a risk condition does not fire on evidence that was never produced,
// including the max_risk_score rule that a fabricated zero would have satisfied.
func TestRiskConditionedRulesStayInertWithoutAScoreStage(t *testing.T) {
	env := escapeEnvelope()
	e := fileEvent("e-1", capability.KindFileRead, "/etc/hosts")

	unscored, err := New(Config{
		Session: Session{Envelope: env, Mode: policy.ModeMonitor, State: session.NewState("s-1", env)},
		Now:     frozen(),
	}, validator.NewValidator(), engineFor(t, riskRules()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	up := process(t, unscored, e)

	if up.Risk != nil {
		t.Fatalf("an unscored pipeline produced a risk assessment: %+v", up.Risk)
	}
	if up.Outcome.RuleID != policy.DefaultRuleID {
		t.Errorf("RuleID = %q, want the fall-through to the posture", up.Outcome.RuleID)
	}
	if up.Outcome.Action != ece.ActionWarn {
		t.Errorf("Action = %q, want the default action %q", up.Outcome.Action, ece.ActionWarn)
	}

	// The published record still says so in words as well as in the empty level,
	// so a reader need not know that "" is not a member of AllLevels.
	if up.Decision.Risk.Level != "" {
		t.Errorf("Decision.Risk.Level = %q, want the empty level that means unscored", up.Decision.Risk.Level)
	}
	var said bool
	for _, s := range up.Decision.Reasoning {
		if s.Stage == "risk" && s.Conclusion == "not assessed" {
			said = true
		}
	}
	if !said {
		t.Error("the unscored decision no longer states that risk did not run")
	}

	// Same event, scored: the rule that could not fire now does.
	scored := buildScored(t, env, session.NewState("s-1", env), riskRules())
	sp := process(t, scored, e)
	if sp.Outcome.RuleID == up.Outcome.RuleID {
		t.Errorf("scored and unscored reached the same rule %q; the score stage changed nothing", sp.Outcome.RuleID)
	}
	// The validator's own answer is identical either way. Risk informs the
	// action; it must never alter the classification.
	if sp.Validation.Verdict != up.Validation.Verdict {
		t.Errorf("verdict differs between scored (%q) and unscored (%q) runs",
			sp.Validation.Verdict, up.Validation.Verdict)
	}
	if !reflect.DeepEqual(sp.Validation.Violations, up.Validation.Violations) {
		t.Error("the violation list differs between scored and unscored runs")
	}
}

// --- ordering: history is read before the event is committed ---------------------------

// The claim the whole pipeline ordering exists to support, and the one neither
// package can demonstrate alone.
//
// The same departing event is processed twice against one session. On the first
// pass the target has never been seen, so the novelty factor fires; on the
// second the pipeline has committed the first event, so it does not. If commit
// ran before the score stage the first pass would already read as familiar and
// the factor could never fire at all — which is the failure this pins.
func TestRiskStageSeesHistoryBeforeCommit(t *testing.T) {
	env := escapeEnvelope()
	st := session.NewState("s-1", env)
	p := buildScored(t, env, st, riskRules())

	first := process(t, p, fileEvent("e-1", capability.KindFileRead, "/etc/hosts"))
	second := process(t, p, fileEvent("e-2", capability.KindFileRead, "/etc/hosts"))

	novel := func(pc *ProcessingContext) *decision.Factor {
		for i := range pc.Risk.Factors {
			if pc.Risk.Factors[i].Name == risk.FactorNovelTarget {
				return &pc.Risk.Factors[i]
			}
		}
		return nil
	}

	if novel(first) == nil {
		t.Error("the first touch of a target did not read as novel; history was committed before scoring")
	}
	if novel(second) != nil {
		t.Error("the second touch of the same target still read as novel; the event was never committed")
	}
	if second.Risk.Score >= first.Risk.Score {
		t.Errorf("second score %v is not below the first %v", second.Risk.Score, first.Risk.Score)
	}

	// The violation counter moves the same way, in the same direction, for the
	// same reason: the score stage reads the session as it stood before this
	// event.
	hist := func(pc *ProcessingContext) float64 {
		for _, f := range pc.Risk.Factors {
			if f.Name == risk.FactorViolationHistory {
				return f.Weight
			}
		}
		return 0
	}
	if hist(first) != 0 {
		t.Errorf("the first event saw %v prior violations; it is the session's first", hist(first))
	}
	if hist(second) != 1 {
		t.Errorf("the second event saw %v prior violations, want exactly the first event's one", hist(second))
	}

	// A within-envelope event reads no history at all, which is what keeps the
	// common path free — asserted through the observable consequence, that it
	// scores zero however noisy the session already is.
	clean := process(t, p, fileEvent("e-3", capability.KindFileRead, "/ws/a.go"))
	if clean.Risk.Score != 0 || clean.Risk.Level != decision.LevelNone {
		t.Errorf("a covered event scored %v (%q) in a session with two violations behind it",
			clean.Risk.Score, clean.Risk.Level)
	}
}

// --- the blind spot, pinned -----------------------------------------------------------------

// The pair that documents what an oracle buys, and what its absence costs.
//
// Without one, a private key and a system header are the same event to the
// scorer: both are reads outside the workspace, both produce the same verdict
// and the same violation severities, so both score identically. With the
// shipped list behind it, they separate — and they separate by exactly the
// difference between a critical grade and an info one, which is the whole
// mechanism, checkable by hand.
//
// The first half is still worth keeping as a test rather than deleting. An
// engine built by NewEngine is the one a caller gets by default and the one the
// unscored composition still uses, and "it cannot tell these apart" remains a
// true and load-bearing statement about it.
func TestSensitivityIsWhatSeparatesAKeyFromAHeader(t *testing.T) {
	env := escapeEnvelope()

	scoreOf := func(build func(*testing.T, *ece.Envelope, State, *policy.RuleSet) *EventPipeline, path string) *decision.RiskAssessment {
		p := build(t, env, session.NewState("s-1", env), riskRules())
		return process(t, p, fileEvent("e-1", capability.KindFileRead, path)).Risk
	}

	t.Run("without an oracle they are indistinguishable", func(t *testing.T) {
		key := scoreOf(buildScored, "/home/dev/.ssh/id_rsa")
		header := scoreOf(buildScored, "/usr/include/stdio.h")

		if key.Score != header.Score {
			t.Errorf("a private key scored %v and a system header %v; an engine with no "+
				"oracle has nothing to tell them apart with", key.Score, header.Score)
		}
		// And neither carries a sensitivity finding at all: nobody asked.
		for _, a := range []*decision.RiskAssessment{key, header} {
			for _, f := range a.Factors {
				if f.Name == risk.FactorSensitivePath {
					t.Errorf("an engine with no oracle produced a sensitivity factor: %+v", f)
				}
			}
		}
	})

	t.Run("with the shipped list they separate", func(t *testing.T) {
		key := scoreOf(buildRated, "/home/dev/.ssh/id_rsa")
		header := scoreOf(buildRated, "/usr/include/stdio.h")

		if key.Score-header.Score != 25 {
			t.Errorf("key %v, header %v; want the key higher by exactly the critical grade (25)",
				key.Score, header.Score)
		}
		// Both still bucket to "high" — 55 and 80 sit inside the same band, and
		// that is the honest reading of the level scale rather than a defect.
		// What the 25 points buy is crossing the threshold the shipped rule set
		// actually keys on, which is the separation that changes an outcome.
		const credentialRuleFloor = 70
		if header.Score >= credentialRuleFloor {
			t.Errorf("a system header scored %v, at or above the credential rule's floor", header.Score)
		}
		if key.Score < credentialRuleFloor {
			t.Errorf("a private key scored %v, below the credential rule's floor of %v",
				key.Score, credentialRuleFloor)
		}

		// The header is *rated*, not merely unlisted — which is the distinction
		// the sensitivity list exists to make and the reason it contributes an
		// info entry that scores nothing.
		hf := riskFactor(header, risk.FactorSensitivePath)
		if hf == nil {
			t.Fatal("the header carries no sensitivity finding")
		}
		if hf.Evidence[risk.EvidenceSensitivity] != string(capability.SeverityInfo) {
			t.Errorf("header sensitivity = %q, want it rated info rather than left unknown",
				hf.Evidence[risk.EvidenceSensitivity])
		}

		kf := riskFactor(key, risk.FactorSensitivePath)
		if kf == nil {
			t.Fatal("the key carries no sensitivity finding")
		}
		if kf.Evidence[risk.EvidenceSensitivity] != string(capability.SeverityCritical) {
			t.Errorf("key sensitivity = %q, want critical", kf.Evidence[risk.EvidenceSensitivity])
		}
		// The reason travels all the way to the audit record.
		if kf.Evidence[risk.EvidenceReason] == "" {
			t.Error("the score went up without the record saying why")
		}
	})
}

// riskFactor returns the named factor from an assessment, or nil.
func riskFactor(a *decision.RiskAssessment, name string) *decision.Factor {
	if a == nil {
		return nil
	}
	for i := range a.Factors {
		if a.Factors[i].Name == name {
			return &a.Factors[i]
		}
	}
	return nil
}

// The rule this whole milestone was aimed at. credential-access-high-risk ships
// in configs/rules.default.yaml wanting a filesystem departure at 70 or above
// with confidence 0.6 or better, and until the oracle existed nothing could
// reach it: the highest a filesystem departure could score was the workspace
// escape at 56, so the rule was named for a distinction the build could not
// draw and fired on nothing.
//
// End to end, against the shipped rule set and the shipped sensitivity list.
func TestCredentialAccessRuleFiresWithSensitivity(t *testing.T) {
	env := gitEnvelope()
	const key = "/home/dev/.ssh/id_rsa"

	run := func(engine RiskEngine) *ProcessingContext {
		st := session.NewState(env.SessionID, env)
		p, err := NewWithRisk(Config{
			Session: Session{Envelope: env, Mode: policy.ModeMonitor, State: st},
			Now:     frozen(),
		}, validator.NewValidator(), engine, defaultEngine(t))
		if err != nil {
			t.Fatalf("NewWithRisk: %v", err)
		}
		return process(t, p, fileEvent("e-1", capability.KindFileRead, key))
	}

	without := run(risk.NewEngine())
	with := run(ratedEngine(t))

	// Before: 25 grant_exceeded + 15 escape severity + 10 escape + 5 novel = 55,
	// short of the rule's 70, so the escape rule decides it and warns.
	if without.Risk.Score != 55 {
		t.Fatalf("unrated score = %v, want 55", without.Risk.Score)
	}
	if without.Outcome.RuleID != "workspace-escape-read" || without.Outcome.Action != ece.ActionWarn {
		t.Errorf("unrated: %q/%q, want workspace-escape-read/warn",
			without.Outcome.RuleID, without.Outcome.Action)
	}

	// After: the same 55 plus 25 for a critical resource is 80, which clears
	// both the score floor and the confidence floor.
	if with.Risk.Score != 80 {
		t.Errorf("rated score = %v, want 80 (factors %+v)", with.Risk.Score, with.Risk.Factors)
	}
	if with.Risk.Confidence < 0.6 {
		t.Errorf("confidence = %v, below the rule's floor of 0.6", with.Risk.Confidence)
	}
	if with.Outcome.RuleID != "credential-access-high-risk" {
		t.Fatalf("RuleID = %q, want credential-access-high-risk", with.Outcome.RuleID)
	}
	if with.Outcome.Action != ece.ActionRequestApproval {
		t.Errorf("Action = %q, want %q", with.Outcome.Action, ece.ActionRequestApproval)
	}

	// The validator's answer is untouched by any of it. Sensitivity informs the
	// action; it never alters the classification.
	if with.Validation.Verdict != without.Validation.Verdict {
		t.Errorf("verdict changed with the oracle: %q vs %q",
			with.Validation.Verdict, without.Validation.Verdict)
	}
	if !reflect.DeepEqual(with.Validation.Violations, without.Validation.Violations) {
		t.Error("the violation list changed with the oracle; sensitivity must not touch validation")
	}
}

// --- failure containment ------------------------------------------------------------------

type failingRisk struct{ err error }

func (f failingRisk) Score(context.Context, risk.ScoreRequest) (*decision.RiskAssessment, error) {
	return nil, f.err
}

type nilRisk struct{}

func (nilRisk) Score(context.Context, risk.ScoreRequest) (*decision.RiskAssessment, error) {
	return nil, nil
}

type panickingRisk struct{}

func (panickingRisk) Score(context.Context, risk.ScoreRequest) (*decision.RiskAssessment, error) {
	panic("a scorer mishandled a malformed path")
}

// A scoring failure must reach an explicit indeterminate decision and must never
// reach policy as a score. The event is still counted, because a fault in our
// analysis is not evidence the agent did less.
func TestScoreStageFailureIsContained(t *testing.T) {
	cases := []struct {
		name   string
		engine RiskEngine
	}{
		{"engine error", failingRisk{errors.New("boom")}},
		{"nil assessment with a nil error", nilRisk{}},
		{"panic", panickingRisk{}},
		{"no engine configured", nil},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := escapeEnvelope()
			st := session.NewState("s-1", env)
			p := buildScoredWith(t, env, st, riskRules(), c.engine)

			pc := process(t, p, fileEvent("e-1", capability.KindFileRead, "/etc/hosts"))

			if pc.Err == nil {
				t.Fatal("the failure was absorbed rather than reported")
			}
			if pc.FailedStage != "score" {
				t.Errorf("FailedStage = %q, want %q", pc.FailedStage, "score")
			}
			if pc.Risk != nil {
				t.Errorf("a failed score stage left an assessment behind: %+v", pc.Risk)
			}
			if pc.Outcome != nil {
				t.Error("policy ran after the score stage failed")
			}
			if pc.Decision == nil {
				t.Fatal("no decision was emitted for a failed stage")
			}
			if pc.Decision.Verdict != decision.VerdictIndeterminate {
				t.Errorf("Verdict = %q, want %q", pc.Decision.Verdict, decision.VerdictIndeterminate)
			}
			if pc.Decision.Action != ActionForFailure {
				t.Errorf("Action = %q, want %q", pc.Decision.Action, ActionForFailure)
			}
			// The event is counted anyway. Failing a stage must not be the
			// cheapest way to spend no budget.
			if got := st.Snapshot().EventsObserved; got != 1 {
				t.Errorf("EventsObserved = %d, want 1", got)
			}
		})
	}
}

func buildScoredWith(t *testing.T, env *ece.Envelope, st State, rs *policy.RuleSet, r RiskEngine) *EventPipeline {
	t.Helper()
	p, err := NewWithRisk(Config{
		Session: Session{Envelope: env, Mode: policy.ModeMonitor, State: st},
		Now:     frozen(),
	}, validator.NewValidator(), r, engineFor(t, rs))
	if err != nil {
		t.Fatalf("NewWithRisk: %v", err)
	}
	return p
}

// The score stage refuses to run against an absent verdict, the same rule the
// decide stage applies one stage later.
func TestScoreStageRefusesWithoutValidation(t *testing.T) {
	s := NewScoreStage(risk.NewEngine())
	err := s.Execute(context.Background(), &ProcessingContext{Event: &event.Event{ID: "e-1"}})
	if err == nil {
		t.Fatal("the score stage ran without a validation result")
	}
}

// --- the replay corpus --------------------------------------------------------------------

// scoredOutcome is the per-event shape the corpus comparison uses.
type scoredOutcome struct {
	EventID string
	Verdict decision.Verdict
	Rule    string
	Action  ece.Action
	Score   float64
	Level   decision.Level
}

// The regression the milestone has to survive: adding a stage between validate
// and decide must not change what the validator concluded about any event in the
// corpus, and must not change any action.
//
// What it does change is which rule produced that action, and only in one
// direction — an event that used to fall through to the posture now matches a
// rule whose risk condition it could not previously satisfy. That is the point
// of the milestone, so it is asserted event by event rather than tolerated.
func TestScoredPipelineOnTheReplayCorpus(t *testing.T) {
	// Every rule-ID change the corpus produces, named. The action beside each is
	// the action both runs reach, which is what makes these attributions rather
	// than behavior changes.
	wantRuleChanges := map[string]map[string]string{
		"git-operation.jsonl": {
			"gt-009": "workspace-escape-read",
		},
		"go-build.jsonl": {
			"gb-001": "medium-risk-departure",
			"gb-004": "workspace-escape-read",
			"gb-007": "medium-risk-departure",
			"gb-009": "medium-risk-departure",
			"gb-010": "medium-risk-departure",
			"gb-012": "medium-risk-departure",
			"gb-013": "medium-risk-departure",
		},
		"npm-install.jsonl": {
			"np-001": "medium-risk-departure",
			"np-002": "workspace-escape-read",
			"np-003": "medium-risk-departure",
			"np-005": "medium-risk-departure",
			"np-034": "medium-risk-departure",
		},
	}

	for fixture, wantChanges := range wantRuleChanges {
		t.Run(fixture, func(t *testing.T) {
			events := loadFixture(t, fixture)

			unscored := runCorpus(t, events, corpusUnscored)
			scored := runCorpus(t, events, corpusScored)

			if len(unscored) != len(scored) || len(scored) != len(events) {
				t.Fatalf("event counts diverged: %d unscored, %d scored, %d in the fixture",
					len(unscored), len(scored), len(events))
			}

			gotChanges := map[string]string{}
			for i := range scored {
				u, s := unscored[i], scored[i]

				if s.EventID != u.EventID {
					t.Fatalf("event %d: %q scored, %q unscored", i, s.EventID, u.EventID)
				}
				// Validation semantics are untouched. This is the regression
				// claim: the score stage reads the validator and never feeds it.
				if s.Verdict != u.Verdict {
					t.Errorf("%s: verdict %q scored, %q unscored", s.EventID, s.Verdict, u.Verdict)
				}
				// No action changes anywhere in the corpus.
				if s.Action != u.Action {
					t.Errorf("%s: action %q scored, %q unscored — a scored run changed what would happen",
						s.EventID, s.Action, u.Action)
				}
				if s.Rule != u.Rule {
					if u.Rule != policy.DefaultRuleID {
						t.Errorf("%s: rule moved from %q to %q; only fall-throughs may become attributed",
							s.EventID, u.Rule, s.Rule)
					}
					gotChanges[s.EventID] = s.Rule
				}

				// Every event is scored, and every score is in range and
				// bucketed to a declared level.
				if s.Score < risk.ScoreMin || s.Score > risk.ScoreMax {
					t.Errorf("%s: score %v is outside the declared bounds", s.EventID, s.Score)
				}
				if !decision.ValidLevel(s.Level) {
					t.Errorf("%s: level %q is not a member of decision.AllLevels", s.EventID, s.Level)
				}
				if s.Verdict == decision.VerdictWithinEnvelope && s.Score != 0 {
					t.Errorf("%s: a covered event scored %v; routine work must stay at zero",
						s.EventID, s.Score)
				}
				if s.Verdict != decision.VerdictWithinEnvelope && s.Score == 0 {
					t.Errorf("%s: a departure scored zero", s.EventID)
				}
			}

			if !reflect.DeepEqual(gotChanges, wantChanges) {
				t.Errorf("rule attributions changed\n got %v\nwant %v", gotChanges, wantChanges)
			}
		})
	}
}

// corpusMode selects which composition a corpus run uses.
type corpusMode int

const (
	corpusUnscored corpusMode = iota // validate → decide
	corpusScored                     // validate → score → decide, no oracle
	corpusRated                      // …with the shipped sensitivity list
)

func runCorpus(t *testing.T, events []event.Event, mode corpusMode) []scoredOutcome {
	t.Helper()

	env := gitEnvelope()
	st := session.NewState(env.SessionID, env)
	cfg := Config{
		Session: Session{Envelope: env, Mode: policy.ModeMonitor, State: st},
		Now:     frozen(),
	}

	var p *EventPipeline
	var err error
	switch mode {
	case corpusUnscored:
		p, err = New(cfg, validator.NewValidator(), defaultEngine(t))
	case corpusScored:
		p, err = NewWithRisk(cfg, validator.NewValidator(), risk.NewEngine(), defaultEngine(t))
	case corpusRated:
		p, err = NewWithRisk(cfg, validator.NewValidator(), ratedEngine(t), defaultEngine(t))
	}
	if err != nil {
		t.Fatalf("building pipeline: %v", err)
	}

	out := make([]scoredOutcome, 0, len(events))
	for i := range events {
		e := events[i]
		pc := process(t, p, &e)
		if pc.Err != nil {
			t.Fatalf("%s: %v", e.ID, pc.Err)
		}
		o := scoredOutcome{
			EventID: e.ID,
			Verdict: pc.Validation.Verdict,
			Rule:    pc.Outcome.RuleID,
			Action:  pc.Outcome.Action,
		}
		if pc.Risk != nil {
			o.Score, o.Level = pc.Risk.Score, pc.Risk.Level
		} else if mode != corpusUnscored {
			t.Fatalf("%s: the scored pipeline produced no assessment", e.ID)
		}
		out = append(out, o)
	}
	return out
}

// A recorded session replayed twice has to produce the same decisions, or replay
// stops being a regression test. Risk is the stage most likely to break that,
// since it reads a map-backed history and builds a factor list.
func TestScoredPipelineIsDeterministic(t *testing.T) {
	events := loadFixture(t, "npm-install.jsonl")

	first := runCorpus(t, events, corpusRated)
	for i := 0; i < 25; i++ {
		if got := runCorpus(t, events, corpusRated); !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d diverged\n got %+v\nwant %+v", i, got, first)
		}
	}
}

// Adding the sensitivity list must change the corpus in exactly one place, and
// that place must be the one the feature was built for.
//
// This is the regression the milestone has to survive twice over: the oracle
// reads only the resource, so no verdict may move, and no event the list has
// never heard of may move either. The single change is gt-009 — a read of
// ~/.ssh/id_rsa that used to warn as an ordinary workspace escape and now
// requests approval under the rule written for it. It is asserted as an exact
// map, so both an unlisted change and a lost one fail.
func TestSensitivityChangesExactlyOneEventInTheCorpus(t *testing.T) {
	wantChanges := map[string]map[string]outcomeChange{
		"git-operation.jsonl": {
			"gt-009": {
				fromRule: "workspace-escape-read", toRule: "credential-access-high-risk",
				fromAction: ece.ActionWarn, toAction: ece.ActionRequestApproval,
				fromScore: 56, toScore: 81,
			},
		},
		"go-build.jsonl":    {},
		"npm-install.jsonl": {},
	}

	for fixture, want := range wantChanges {
		t.Run(fixture, func(t *testing.T) {
			events := loadFixture(t, fixture)

			scored := runCorpus(t, events, corpusScored)
			rated := runCorpus(t, events, corpusRated)

			got := map[string]outcomeChange{}
			for i := range rated {
				s, r := scored[i], rated[i]

				if r.Verdict != s.Verdict {
					t.Errorf("%s: verdict %q rated, %q unrated — sensitivity must not reach validation",
						r.EventID, r.Verdict, s.Verdict)
				}
				if r.Score < s.Score {
					t.Errorf("%s: score fell from %v to %v; a sensitivity list may only raise",
						r.EventID, s.Score, r.Score)
				}
				if r == s {
					continue
				}
				got[r.EventID] = outcomeChange{
					fromRule: s.Rule, toRule: r.Rule,
					fromAction: s.Action, toAction: r.Action,
					fromScore: s.Score, toScore: r.Score,
				}
			}

			if !reflect.DeepEqual(got, want) {
				t.Errorf("sensitivity changed the corpus somewhere unexpected\n got %+v\nwant %+v", got, want)
			}
		})
	}
}

type outcomeChange struct {
	fromRule, toRule     string
	fromAction, toAction ece.Action
	fromScore, toScore   float64
}

// --- benchmark ------------------------------------------------------------------------------

// The rated hot path: the full pipeline with the shipped sensitivity list
// behind it, on an ordinary in-workspace write the list has never heard of.
// That is the event a real session is made of, so the cost of an oracle is the
// cost of its misses.
func BenchmarkProcessRated(b *testing.B) {
	env := envelope([]capability.Grant{pathGrant(capability.KindFileWrite, 0, "/ws/**")}, nil, ece.Constraints{})
	st := session.NewState("s-1", env)

	pe, err := policy.NewEngine(simpleRules())
	if err != nil {
		b.Fatalf("NewEngine: %v", err)
	}
	o, err := risk.LoadPathOracle(filepath.Join("..", "..", "configs", "sensitivity.default.yaml"))
	if err != nil {
		b.Fatalf("LoadPathOracle: %v", err)
	}
	re, err := risk.NewEngineWithOracle(o)
	if err != nil {
		b.Fatalf("NewEngineWithOracle: %v", err)
	}
	p, err := NewWithRisk(Config{
		Session: Session{Envelope: env, Mode: policy.ModeMonitor, State: st},
		Now:     frozen(),
	}, validator.NewValidator(), re, pe)
	if err != nil {
		b.Fatalf("NewWithRisk: %v", err)
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

// The scored hot path, against BenchmarkProcess's unscored 2.5 µs. The delta is
// what adding risk costs per governed syscall.
func BenchmarkProcessScored(b *testing.B) {
	env := envelope([]capability.Grant{pathGrant(capability.KindFileWrite, 0, "/ws/**")}, nil, ece.Constraints{})
	st := session.NewState("s-1", env)

	e, err := policy.NewEngine(simpleRules())
	if err != nil {
		b.Fatalf("NewEngine: %v", err)
	}
	p, err := NewWithRisk(Config{
		Session: Session{Envelope: env, Mode: policy.ModeMonitor, State: st},
		Now:     frozen(),
	}, validator.NewValidator(), risk.NewEngine(), e)
	if err != nil {
		b.Fatalf("NewWithRisk: %v", err)
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
