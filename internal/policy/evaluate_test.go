package policy

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/stringNameMahin/ALLSEER/internal/validator"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// --- helpers ----------------------------------------------------------------

func rule(id string, priority int, action ece.Action, match Condition) Rule {
	return Rule{ID: id, Priority: priority, Action: action, Match: match, Enabled: true}
}

func set(defaultAction ece.Action, rules ...Rule) *RuleSet {
	return &RuleSet{Name: "test", Version: "1", DefaultAction: defaultAction, Rules: rules}
}

func engine(t *testing.T, rs *RuleSet) *RuleEngine {
	t.Helper()
	e, err := NewEngine(rs)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

func fileEvent(kind capability.Kind, resolved string) *event.Event {
	return &event.Event{
		ID:         "e-1",
		Capability: kind,
		Domain:     capability.DomainFilesystem,
		File:       &event.FilePayload{ResolvedPath: resolved},
	}
}

func netEvent(host, addr string, port int) *event.Event {
	return &event.Event{
		ID:         "e-net",
		Capability: capability.KindNetConnect,
		Domain:     capability.DomainNetwork,
		Network: &event.NetworkPayload{
			Protocol: "tcp", Hostname: host, DestAddr: addr, DestPort: port,
		},
	}
}

func result(v decision.Verdict, violations ...validator.ViolationType) *validator.Result {
	r := &validator.Result{Verdict: v}
	for _, vt := range violations {
		r.Violations = append(r.Violations, validator.Violation{Type: vt})
	}
	return r
}

func risk(score, confidence float64, level decision.Level) *decision.RiskAssessment {
	return &decision.RiskAssessment{Score: score, Confidence: confidence, Level: level}
}

func f64(v float64) *float64 { return &v }

func evaluate(t *testing.T, e *RuleEngine, req EvaluateRequest) *Outcome {
	t.Helper()
	out, err := e.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if out == nil {
		t.Fatal("Evaluate returned no outcome and no error")
	}
	return out
}

// --- first-match-wins and ordering ------------------------------------------

func TestFirstMatchWins(t *testing.T) {
	e := engine(t, set(ece.ActionWarn,
		rule("low-priority-block", 10, ece.ActionBlock, Condition{
			Verdicts: []decision.Verdict{decision.VerdictOutsideEnvelope},
		}),
		rule("high-priority-allow", 900, ece.ActionAllow, Condition{
			Verdicts: []decision.Verdict{decision.VerdictOutsideEnvelope},
		}),
	))

	out := evaluate(t, e, EvaluateRequest{
		Event:      fileEvent(capability.KindFileRead, "/ws/main.go"),
		Validation: result(decision.VerdictOutsideEnvelope),
	})

	if out.RuleID != "high-priority-allow" || out.Action != ece.ActionAllow {
		t.Fatalf("got rule %q action %q, want the higher-priority rule to win outright", out.RuleID, out.Action)
	}
}

func TestEqualPriorityKeepsDeclarationOrder(t *testing.T) {
	e := engine(t, set(ece.ActionWarn,
		rule("first", 500, ece.ActionWarn, Condition{}),
		rule("second", 500, ece.ActionBlock, Condition{}),
	))

	out := evaluate(t, e, EvaluateRequest{
		Event:      fileEvent(capability.KindFileRead, "/ws/main.go"),
		Validation: result(decision.VerdictWithinEnvelope),
	})
	if out.RuleID != "first" {
		t.Errorf("rule %q won at equal priority, want the earlier declaration", out.RuleID)
	}

	// Rules() must report the order that decides outcomes, not the input order,
	// or an operator debugging a surprise reads a sequence the engine never
	// walked.
	ordered := e.Rules()
	if ordered[0].ID != "first" || ordered[1].ID != "second" {
		t.Errorf("Rules() = %q, %q, want evaluation order", ordered[0].ID, ordered[1].ID)
	}
}

func TestSortIsStableAcrossPriorities(t *testing.T) {
	e := engine(t, set(ece.ActionWarn,
		rule("c", 1, ece.ActionWarn, Condition{}),
		rule("a", 100, ece.ActionWarn, Condition{}),
		rule("d", 1, ece.ActionWarn, Condition{}),
		rule("b", 100, ece.ActionWarn, Condition{}),
	))

	var got []string
	for _, r := range e.Rules() {
		got = append(got, r.ID)
	}
	if want := "a b c d"; strings.Join(got, " ") != want {
		t.Errorf("evaluation order = %q, want %q", strings.Join(got, " "), want)
	}
}

func TestNoRuleMatchesFallsToDefault(t *testing.T) {
	e := engine(t, set(ece.ActionRequestApproval,
		rule("network-only", 100, ece.ActionBlock, Condition{
			Domains: []capability.Domain{capability.DomainNetwork},
		}),
	))

	out := evaluate(t, e, EvaluateRequest{
		Event:      fileEvent(capability.KindFileRead, "/ws/main.go"),
		Validation: result(decision.VerdictOutsideEnvelope),
	})
	if out.RuleID != DefaultRuleID || out.Action != ece.ActionRequestApproval {
		t.Fatalf("got rule %q action %q, want the default posture", out.RuleID, out.Action)
	}
	if len(out.Reasoning) == 0 {
		t.Error("default outcome carries no reasoning; the audit log would not say why")
	}
}

func TestDisabledRuleIsSkipped(t *testing.T) {
	disabled := rule("blocker", 900, ece.ActionBlock, Condition{})
	disabled.Enabled = false

	e := engine(t, set(ece.ActionAllow, disabled))
	out := evaluate(t, e, EvaluateRequest{
		Event:      fileEvent(capability.KindFileRead, "/ws/main.go"),
		Validation: result(decision.VerdictOutsideEnvelope),
	})
	if out.RuleID != DefaultRuleID {
		t.Errorf("disabled rule %q fired", out.RuleID)
	}
}

func TestTerminalIsCarried(t *testing.T) {
	r := rule("kernel", 1000, ece.ActionBlock, Condition{
		Domains: []capability.Domain{capability.DomainKernel},
	})
	r.Terminal = true

	e := engine(t, set(ece.ActionWarn, r))
	out := evaluate(t, e, EvaluateRequest{
		Event: &event.Event{
			ID: "e", Capability: capability.KindKernelBPFLoad, Domain: capability.DomainKernel,
		},
		Validation: result(decision.VerdictOutsideEnvelope),
	})
	if !out.Terminal {
		t.Error("terminal rule produced a non-terminal outcome")
	}
	if !strings.Contains(out.Reasoning[0].Detail, "terminal") {
		t.Errorf("reasoning %q does not mention that the session ends", out.Reasoning[0].Detail)
	}
}

// --- conditions -------------------------------------------------------------

func TestConditionMatching(t *testing.T) {
	sensitiveRead := fileEvent(capability.KindFileRead, "/home/dev/.ssh/id_rsa")
	connect := netEvent("api.github.com", "140.82.121.4", 443)

	cases := []struct {
		name  string
		match Condition
		req   EvaluateRequest
		want  bool
	}{
		{
			name:  "empty condition matches anything",
			match: Condition{},
			req:   EvaluateRequest{Event: sensitiveRead, Validation: result(decision.VerdictWithinEnvelope)},
			want:  true,
		},
		{
			name:  "verdict matches",
			match: Condition{Verdicts: []decision.Verdict{decision.VerdictExplicitlyDenied}},
			req:   EvaluateRequest{Event: sensitiveRead, Validation: result(decision.VerdictExplicitlyDenied)},
			want:  true,
		},
		{
			name:  "verdict near miss",
			match: Condition{Verdicts: []decision.Verdict{decision.VerdictExplicitlyDenied}},
			req:   EvaluateRequest{Event: sensitiveRead, Validation: result(decision.VerdictOutsideEnvelope)},
			want:  false,
		},
		{
			name: "values within a field are ORed",
			match: Condition{Verdicts: []decision.Verdict{
				decision.VerdictOutsideEnvelope, decision.VerdictGrantExceeded,
			}},
			req:  EvaluateRequest{Event: sensitiveRead, Validation: result(decision.VerdictGrantExceeded)},
			want: true,
		},
		{
			name: "fields are ANDed",
			match: Condition{
				Verdicts:     []decision.Verdict{decision.VerdictOutsideEnvelope},
				Capabilities: []capability.Kind{capability.KindNetConnect},
			},
			req:  EvaluateRequest{Event: sensitiveRead, Validation: result(decision.VerdictOutsideEnvelope)},
			want: false,
		},
		{
			name:  "domain comes from the catalog",
			match: Condition{Domains: []capability.Domain{capability.DomainFilesystem}},
			req:   EvaluateRequest{Event: sensitiveRead, Validation: result(decision.VerdictOutsideEnvelope)},
			want:  true,
		},
		{
			name:  "domain ignores a contradicting Event.Domain",
			match: Condition{Domains: []capability.Domain{capability.DomainNetwork}},
			req: EvaluateRequest{
				// A mis-decoded record claiming the wrong domain must not
				// redirect policy; the catalog places fs.read in filesystem.
				Event: &event.Event{
					ID: "e", Capability: capability.KindFileRead, Domain: capability.DomainNetwork,
					File: &event.FilePayload{ResolvedPath: "/ws/a"},
				},
				Validation: result(decision.VerdictOutsideEnvelope),
			},
			want: false,
		},
		{
			name:  "violation type matches any recorded violation",
			match: Condition{ViolationTypes: []validator.ViolationType{validator.ViolationWorkspaceEscape}},
			req: EvaluateRequest{
				Event: sensitiveRead,
				Validation: result(decision.VerdictOutsideEnvelope,
					validator.ViolationUngrantedCapability, validator.ViolationWorkspaceEscape),
			},
			want: true,
		},
		{
			name:  "violation type near miss",
			match: Condition{ViolationTypes: []validator.ViolationType{validator.ViolationWorkspaceEscape}},
			req: EvaluateRequest{
				Event:      sensitiveRead,
				Validation: result(decision.VerdictOutsideEnvelope, validator.ViolationUngrantedCapability),
			},
			want: false,
		},
		{
			name:  "path pattern matches the resolved path",
			match: Condition{PathPatterns: []string{"/home/*/.ssh/**"}},
			req:   EvaluateRequest{Event: sensitiveRead, Validation: result(decision.VerdictOutsideEnvelope)},
			want:  true,
		},
		{
			name:  "path pattern near miss",
			match: Condition{PathPatterns: []string{"/etc/**"}},
			req:   EvaluateRequest{Event: sensitiveRead, Validation: result(decision.VerdictOutsideEnvelope)},
			want:  false,
		},
		{
			name:  "invalid path pattern matches nothing",
			match: Condition{PathPatterns: []string{"/home/**/.ssh/**", "/home/**.ssh/**"}},
			req: EvaluateRequest{
				Event:      fileEvent(capability.KindFileRead, "/home/dev/x/.ssh/id_rsa"),
				Validation: result(decision.VerdictOutsideEnvelope),
			},
			want: true, // the first pattern is valid and covers it
		},
		{
			name:  "only an invalid path pattern is no match",
			match: Condition{PathPatterns: []string{"/home/**.ssh/**"}},
			req:   EvaluateRequest{Event: sensitiveRead, Validation: result(decision.VerdictOutsideEnvelope)},
			want:  false,
		},
		{
			name:  "host condition matches the correlated name",
			match: Condition{Hosts: []string{"*.github.com"}},
			req:   EvaluateRequest{Event: connect, Validation: result(decision.VerdictOutsideEnvelope)},
			want:  true,
		},
		{
			name:  "host condition matches the literal address",
			match: Condition{Hosts: []string{"140.82.0.0/16"}},
			req:   EvaluateRequest{Event: connect, Validation: result(decision.VerdictOutsideEnvelope)},
			want:  true,
		},
		{
			name:  "host condition near miss",
			match: Condition{Hosts: []string{"evil.example.com"}},
			req:   EvaluateRequest{Event: connect, Validation: result(decision.VerdictOutsideEnvelope)},
			want:  false,
		},
		{
			name:  "an unresolvable event matches no target condition",
			match: Condition{PathPatterns: []string{"/**"}},
			req: EvaluateRequest{
				Event:      &event.Event{ID: "e", Capability: capability.KindFileRead},
				Validation: result(decision.VerdictIndeterminate),
			},
			want: false,
		},
		{
			name:  "host condition against a bare IPv6 literal",
			match: Condition{Hosts: []string{"2001:db8::/32"}},
			req: EvaluateRequest{
				// No correlated name and no port, so the target is the address
				// alone — full of colons, and not a host:port.
				Event:      netEvent("", "2001:db8::1", 0),
				Validation: result(decision.VerdictOutsideEnvelope),
			},
			want: true,
		},
		{
			name:  "capability condition with no event",
			match: Condition{Capabilities: []capability.Kind{capability.KindFileRead}},
			req:   EvaluateRequest{Validation: result(decision.VerdictIndeterminate)},
			want:  false,
		},
		{
			name:  "path condition with no event",
			match: Condition{PathPatterns: []string{"/**"}},
			req:   EvaluateRequest{Validation: result(decision.VerdictIndeterminate)},
			want:  false,
		},
		{
			name:  "risk level matches",
			match: Condition{RiskLevels: []decision.Level{decision.LevelHigh, decision.LevelCritical}},
			req: EvaluateRequest{
				Event:      sensitiveRead,
				Validation: result(decision.VerdictOutsideEnvelope),
				Risk:       risk(80, 0.9, decision.LevelHigh),
			},
			want: true,
		},
		{
			name:  "risk level near miss",
			match: Condition{RiskLevels: []decision.Level{decision.LevelCritical}},
			req: EvaluateRequest{
				Event:      sensitiveRead,
				Validation: result(decision.VerdictOutsideEnvelope),
				Risk:       risk(80, 0.9, decision.LevelHigh),
			},
			want: false,
		},
		{
			name:  "score within an explicit band",
			match: Condition{MinRiskScore: f64(40), MaxRiskScore: f64(75)},
			req: EvaluateRequest{
				Event:      sensitiveRead,
				Validation: result(decision.VerdictOutsideEnvelope),
				Risk:       risk(60, 0.9, decision.LevelMedium),
			},
			want: true,
		},
		{
			name:  "task type matches the envelope",
			match: Condition{TaskTypes: []string{"dependency-upgrade"}},
			req: EvaluateRequest{
				Event:      sensitiveRead,
				Validation: result(decision.VerdictOutsideEnvelope),
				Envelope:   &ece.Envelope{Intent: ece.IntentRecord{TaskType: "dependency-upgrade"}},
			},
			want: true,
		},
		{
			name:  "task type without an envelope",
			match: Condition{TaskTypes: []string{"dependency-upgrade"}},
			req:   EvaluateRequest{Event: sensitiveRead, Validation: result(decision.VerdictOutsideEnvelope)},
			want:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := engine(t, set(ece.ActionAllow, rule("candidate", 100, ece.ActionBlock, tc.match)))
			out := evaluate(t, e, tc.req)

			fired := out.RuleID == "candidate"
			if fired != tc.want {
				t.Errorf("rule fired = %v, want %v (outcome rule %q)", fired, tc.want, out.RuleID)
			}
		})
	}
}

// --- risk conditions --------------------------------------------------------

// TestRiskConditionsRequireAnAssessment pins the no-evidence rule. It is the
// case most likely to be "fixed" by someone treating a missing assessment as a
// zero score, which would make every max_risk_score rule fire on events the
// risk engine never saw.
func TestRiskConditionsRequireAnAssessment(t *testing.T) {
	cases := []struct {
		name  string
		match Condition
	}{
		{"minimum score", Condition{MinRiskScore: f64(70)}},
		{"maximum score", Condition{MaxRiskScore: f64(60)}},
		{"confidence floor", Condition{MinConfidence: f64(0.5)}},
		{"level", Condition{RiskLevels: []decision.Level{decision.LevelLow}}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := engine(t, set(ece.ActionWarn, rule("risky", 100, ece.ActionBlock, tc.match)))
			out := evaluate(t, e, EvaluateRequest{
				Event:      fileEvent(capability.KindFileRead, "/ws/a"),
				Validation: result(decision.VerdictOutsideEnvelope),
				Risk:       nil,
			})
			if out.RuleID != DefaultRuleID {
				t.Errorf("rule %q fired with no risk assessment", out.RuleID)
			}
			if !strings.Contains(out.Reasoning[0].Detail, "risk not scored") {
				t.Errorf("reasoning %q does not record that risk was never scored", out.Reasoning[0].Detail)
			}
		})
	}
}

func TestRiskBandsPartitionAtTheBoundary(t *testing.T) {
	// The shape configs/rules.default.yaml uses: a high band and a low band
	// sharing a threshold. Exactly one must claim a score sitting on it.
	e := engine(t, set(ece.ActionAllow,
		rule("high", 690, ece.ActionRequestApproval, Condition{MinRiskScore: f64(50)}),
		rule("low", 680, ece.ActionWarn, Condition{MaxRiskScore: f64(50)}),
	))

	for _, tc := range []struct {
		score float64
		want  string
	}{
		{49.9, "low"},
		{50, "high"},
		{50.1, "high"},
	} {
		out := evaluate(t, e, EvaluateRequest{
			Event:      fileEvent(capability.KindFileRead, "/ws/a"),
			Validation: result(decision.VerdictIndeterminate),
			Risk:       risk(tc.score, 1, decision.LevelMedium),
		})
		if out.RuleID != tc.want {
			t.Errorf("score %.1f selected %q, want %q", tc.score, out.RuleID, tc.want)
		}
	}
}

func TestConfidenceFloorHoldsBackAShakyScore(t *testing.T) {
	e := engine(t, set(ece.ActionWarn,
		rule("high-risk-departure", 600, ece.ActionRequestApproval, Condition{
			MinRiskScore: f64(75), MinConfidence: f64(0.5),
		}),
	))

	out := evaluate(t, e, EvaluateRequest{
		Event:      fileEvent(capability.KindFileRead, "/ws/a"),
		Validation: result(decision.VerdictOutsideEnvelope),
		Risk:       risk(90, 0.2, decision.LevelHigh),
	})
	if out.RuleID != DefaultRuleID {
		t.Errorf("rule %q fired on a high score with low confidence", out.RuleID)
	}
}

// --- mode -------------------------------------------------------------------

func TestModeSelectsRulesAndNeverRewritesActions(t *testing.T) {
	strict := rule("ci-block", 100, ece.ActionBlock, Condition{})
	strict.Modes = []Mode{ModeEnforce}

	e := engine(t, set(ece.ActionWarn, strict))
	req := EvaluateRequest{
		Event:      fileEvent(capability.KindFileRead, "/ws/a"),
		Validation: result(decision.VerdictOutsideEnvelope),
	}

	req.Mode = ModeEnforce
	if out := evaluate(t, e, req); out.RuleID != "ci-block" {
		t.Errorf("enforce mode selected %q, want ci-block", out.RuleID)
	}

	req.Mode = ModeMonitor
	if out := evaluate(t, e, req); out.RuleID != DefaultRuleID {
		t.Errorf("monitor mode selected %q, want the rule to be ineligible", out.RuleID)
	}
}

// TestMonitorModeStillReportsBlock is the measurement property. Monitor mode
// must answer "what would this policy have done", so the action stays block and
// only its application is advisory — that is Decision.Enforced's job, not this
// engine's. If this test is ever "fixed" to expect allow, the false-positive
// measurement the project is built to produce becomes impossible.
func TestMonitorModeStillReportsBlock(t *testing.T) {
	e := engine(t, set(ece.ActionAllow,
		rule("kernel-surface-tampering", 1000, ece.ActionBlock, Condition{
			Domains: []capability.Domain{capability.DomainKernel},
		}),
	))

	out := evaluate(t, e, EvaluateRequest{
		Event: &event.Event{
			ID: "e", Capability: capability.KindKernelModuleLoad, Domain: capability.DomainKernel,
		},
		Validation: result(decision.VerdictOutsideEnvelope),
		Mode:       ModeMonitor,
	})
	if out.Action != ece.ActionBlock {
		t.Fatalf("monitor mode produced action %q, want block reported and left unenforced downstream", out.Action)
	}
}

// --- admission --------------------------------------------------------------

func TestNewEngineRejectsUnevaluableRuleSets(t *testing.T) {
	cases := []struct {
		name string
		rs   *RuleSet
		want string
	}{
		{"nil rule set", nil, "rule set is required"},
		{
			name: "no default action",
			rs:   &RuleSet{Name: "x"},
			want: "default action",
		},
		{
			name: "unknown default action",
			rs:   set("shrug"),
			want: "default action",
		},
		{
			name: "rule without an id",
			rs:   set(ece.ActionWarn, rule("", 10, ece.ActionBlock, Condition{})),
			want: "no id",
		},
		{
			name: "rule with an unknown action",
			rs:   set(ece.ActionWarn, rule("typo", 10, "blok", Condition{})),
			want: "action",
		},
		{
			name: "rule with an unknown mode",
			rs: set(ece.ActionWarn, func() Rule {
				r := rule("moded", 10, ece.ActionBlock, Condition{})
				r.Modes = []Mode{"paranoid"}
				return r
			}()),
			want: "mode",
		},
		{
			name: "duplicate rule ids",
			rs: set(ece.ActionWarn,
				rule("same", 20, ece.ActionBlock, Condition{}),
				rule("same", 10, ece.ActionWarn, Condition{}),
			),
			want: "duplicate rule id",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewEngine(tc.rs)
			if err == nil {
				t.Fatal("rule set was admitted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestEvaluateRequiresAValidationResult(t *testing.T) {
	e := engine(t, set(ece.ActionWarn))
	if _, err := e.Evaluate(context.Background(), EvaluateRequest{}); err == nil {
		t.Fatal("evaluated with no validation result; a missing verdict must never read as an allow")
	}
}

// --- reload -----------------------------------------------------------------

func TestReloadKeepsTheDefaultAction(t *testing.T) {
	e := engine(t, set(ece.ActionRequestApproval, rule("old", 10, ece.ActionAllow, Condition{})))

	if err := e.Reload(context.Background(), []Rule{rule("new", 10, ece.ActionBlock, Condition{})}); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := e.Rules(); len(got) != 1 || got[0].ID != "new" {
		t.Fatalf("Rules() = %v, want the replacement", got)
	}
	if e.DefaultAction() != ece.ActionRequestApproval {
		t.Errorf("default action = %q, want the posture to survive a rule reload", e.DefaultAction())
	}
}

func TestReloadRejectsBadRulesAndKeepsGoverning(t *testing.T) {
	e := engine(t, set(ece.ActionWarn, rule("good", 10, ece.ActionBlock, Condition{})))

	err := e.Reload(context.Background(), []Rule{rule("", 10, ece.ActionBlock, Condition{})})
	if err == nil {
		t.Fatal("a rule set with no id was accepted")
	}
	if got := e.Rules(); len(got) != 1 || got[0].ID != "good" {
		t.Errorf("Rules() = %v, want the previous rule set still in force", got)
	}
}

func TestReloadSetReplacesThePosture(t *testing.T) {
	e := engine(t, set(ece.ActionWarn, rule("a", 10, ece.ActionAllow, Condition{})))

	if err := e.ReloadSet(set(ece.ActionBlock, rule("b", 10, ece.ActionAllow, Condition{}))); err != nil {
		t.Fatalf("ReloadSet: %v", err)
	}
	if e.DefaultAction() != ece.ActionBlock {
		t.Errorf("default action = %q, want block", e.DefaultAction())
	}
	if err := e.ReloadSet(nil); err == nil {
		t.Error("ReloadSet(nil) was accepted")
	}
}

// TestConcurrentEvaluateAndReload asserts the snapshot property: an event is
// judged against one rule set or the other, never a mixture, and nothing races.
func TestConcurrentEvaluateAndReload(t *testing.T) {
	e := engine(t, set(ece.ActionWarn, rule("a", 10, ece.ActionAllow, Condition{})))
	req := EvaluateRequest{
		Event:      fileEvent(capability.KindFileRead, "/ws/a"),
		Validation: result(decision.VerdictWithinEnvelope),
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				out, err := e.Evaluate(context.Background(), req)
				if err != nil {
					t.Errorf("Evaluate: %v", err)
					return
				}
				if out.Action != ece.ActionAllow && out.Action != ece.ActionBlock {
					t.Errorf("action %q belongs to neither rule set", out.Action)
					return
				}
			}
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			action := ece.ActionAllow
			if i%2 == 0 {
				action = ece.ActionBlock
			}
			for j := 0; j < 50; j++ {
				if err := e.Reload(context.Background(), []Rule{rule("a", 10, action, Condition{})}); err != nil {
					t.Errorf("Reload: %v", err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
}

// --- determinism ------------------------------------------------------------

// TestEvaluationIsDeterministic guards the property an audit record depends on:
// the same request must credit the same rule every time, including across
// engines built from the same rules in a different order.
func TestEvaluationIsDeterministic(t *testing.T) {
	rules := []Rule{
		rule("net", 840, ece.ActionRequestApproval, Condition{
			Capabilities: []capability.Kind{capability.KindNetConnect},
			Verdicts:     []decision.Verdict{decision.VerdictOutsideEnvelope},
		}),
		rule("denied", 900, ece.ActionBlock, Condition{
			Verdicts: []decision.Verdict{decision.VerdictExplicitlyDenied},
		}),
		rule("catch-all", 100, ece.ActionWarn, Condition{}),
	}
	shuffled := []Rule{rules[2], rules[0], rules[1]}

	req := EvaluateRequest{
		Event:      netEvent("api.github.com", "140.82.121.4", 443),
		Validation: result(decision.VerdictOutsideEnvelope),
	}

	first := evaluate(t, engine(t, set(ece.ActionAllow, rules...)), req)
	for i := 0; i < 50; i++ {
		out := evaluate(t, engine(t, set(ece.ActionAllow, shuffled...)), req)
		if out.RuleID != first.RuleID || out.Action != first.Action {
			t.Fatalf("run %d selected %q/%q, want %q/%q — evaluation depends on input order",
				i, out.RuleID, out.Action, first.RuleID, first.Action)
		}
	}
	if first.RuleID != "net" {
		t.Errorf("selected %q, want net", first.RuleID)
	}
}

func BenchmarkEvaluate(b *testing.B) {
	var rules []Rule
	for i := 0; i < 16; i++ {
		rules = append(rules, Rule{
			ID: string(rune('a'+i)) + "-rule", Priority: 100 * i, Enabled: true,
			Action: ece.ActionWarn,
			Match: Condition{
				Verdicts:     []decision.Verdict{decision.VerdictExplicitlyDenied},
				Capabilities: []capability.Kind{capability.KindNetConnect},
			},
		})
	}
	e, err := NewEngine(set(ece.ActionAllow, rules...))
	if err != nil {
		b.Fatal(err)
	}
	req := EvaluateRequest{
		Event:      fileEvent(capability.KindFileRead, "/ws/main.go"),
		Validation: result(decision.VerdictWithinEnvelope),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := e.Evaluate(context.Background(), req); err != nil {
			b.Fatal(err)
		}
	}
}
