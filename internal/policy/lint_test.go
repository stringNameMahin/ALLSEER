package policy

import (
	"context"
	"strings"
	"testing"

	"github.com/stringNameMahin/ALLSEER/internal/validator"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
)

// --- helpers ----------------------------------------------------------------

// wantLint is the part of a LintIssue a case asserts. Messages are prose; the
// cases that turn on wording check it separately.
type wantLint struct {
	severity capability.Severity
	ruleID   string
}

func assertLint(t *testing.T, got []LintIssue, want []wantLint) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d issues, want %d:\n%s", len(got), len(want), formatLint(got))
	}
	for i := range want {
		if got[i].Severity != want[i].severity || got[i].RuleID != want[i].ruleID {
			t.Errorf("issue %d = %s on %q, want %s on %q",
				i, got[i].Severity, got[i].RuleID, want[i].severity, want[i].ruleID)
		}
		if got[i].Message == "" {
			t.Errorf("issue %d has no message", i)
		}
	}
}

func formatLint(issues []LintIssue) string {
	var b strings.Builder
	for _, i := range issues {
		b.WriteString("  " + string(i.Severity) + " " + i.RuleID + ": " + i.Message + "\n")
	}
	if b.Len() == 0 {
		return "  (none)\n"
	}
	return b.String()
}

func withMatch(id string, priority int, action ece.Action, c Condition) Rule {
	return rule(id, priority, action, c)
}

// --- the shipped rule set ---------------------------------------------------

// TestShippedRuleSetLintsClean is the case that decides whether this linter is
// usable. A linter that fires on the policy the project ships is one every
// operator learns to ignore on their first run.
func TestShippedRuleSetLintsClean(t *testing.T) {
	rs, err := NewLoader().Load(context.Background(), defaultRuleSetPath)
	if err != nil {
		t.Fatalf("load shipped rule set: %v", err)
	}

	if issues := NewLinter().Lint(rs); len(issues) != 0 {
		t.Errorf("the shipped rule set produced %d lint issues:\n%s", len(issues), formatLint(issues))
	}
}

// --- impossible conditions --------------------------------------------------

func TestLintImpossibleConditions(t *testing.T) {
	cases := []struct {
		name    string
		match   Condition
		wantMsg string
	}{
		{
			name:    "unknown verdict",
			match:   Condition{Verdicts: []decision.Verdict{"outside-envelope"}},
			wantMsg: "not one the validator produces",
		},
		{
			name:    "unknown capability",
			match:   Condition{Capabilities: []capability.Kind{"fs.wrte"}},
			wantMsg: "not in the catalog",
		},
		{
			name:    "unknown domain",
			match:   Condition{Domains: []capability.Domain{"file"}},
			wantMsg: "is not one of",
		},
		{
			name:    "unknown violation type",
			match:   Condition{ViolationTypes: []validator.ViolationType{"workspace-escape"}},
			wantMsg: "not one the validator reports",
		},
		{
			name:    "unknown risk level",
			match:   Condition{RiskLevels: []decision.Level{"severe"}},
			wantMsg: "is not one of",
		},
		{
			name:    "inverted risk band",
			match:   Condition{MinRiskScore: f64(80), MaxRiskScore: f64(40)},
			wantMsg: "is not below",
		},
		{
			name: "empty risk band at the boundary",
			// Minimum inclusive, maximum exclusive, so an equal pair admits
			// nothing at all.
			match:   Condition{MinRiskScore: f64(50), MaxRiskScore: f64(50)},
			wantMsg: "is not below",
		},
		{
			name:    "minimum above the scale",
			match:   Condition{MinRiskScore: f64(120)},
			wantMsg: "above the top of the scale",
		},
		{
			name:    "maximum at the bottom of the scale",
			match:   Condition{MaxRiskScore: f64(0)},
			wantMsg: "leaves no score below it",
		},
		{
			name:    "confidence above the scale",
			match:   Condition{MinConfidence: f64(1.5)},
			wantMsg: "above the top of the scale",
		},
		{
			name: "capability and domain contradict",
			match: Condition{
				Capabilities: []capability.Kind{capability.KindFileRead, capability.KindFileWrite},
				Domains:      []capability.Domain{capability.DomainNetwork},
			},
			wantMsg: "belongs to any domain",
		},
		{
			name:    "every path pattern unusable",
			match:   Condition{PathPatterns: []string{"relative/**", "/ws/**.go"}},
			wantMsg: "every pattern in path_patterns is unusable",
		},
		{
			name:    "every host pattern unusable",
			match:   Condition{Hosts: []string{"api.github.com:443", "*.*.evil.tld"}},
			wantMsg: "every pattern in hosts is unusable",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			issues := LintRuleSet(set(ece.ActionWarn, withMatch("candidate", 100, ece.ActionBlock, tc.match)))

			blocking := BlockingIssues(issues)
			if len(blocking) == 0 {
				t.Fatalf("no blocking issue for an impossible condition:\n%s", formatLint(issues))
			}
			var found bool
			for _, i := range blocking {
				if strings.Contains(i.Message, tc.wantMsg) {
					found = true
				}
				if i.RuleID != "candidate" {
					t.Errorf("issue attributed to %q, want candidate", i.RuleID)
				}
			}
			if !found {
				t.Errorf("no issue mentions %q:\n%s", tc.wantMsg, formatLint(blocking))
			}
		})
	}
}

// TestLintUnknownCapabilityIsReportedOnce keeps one defect from producing two
// findings: an unknown capability cannot be checked against a domain, and
// saying so twice buries the actionable line.
func TestLintUnknownCapabilityIsReportedOnce(t *testing.T) {
	issues := LintRuleSet(set(ece.ActionWarn,
		withMatch("bad", 100, ece.ActionBlock, Condition{
			Capabilities: []capability.Kind{"fs.wrte"},
			Domains:      []capability.Domain{capability.DomainNetwork},
		}),
	))

	assertLint(t, issues, []wantLint{{capability.SeverityCritical, "bad"}})
	if !strings.Contains(issues[0].Message, "not in the catalog") {
		t.Errorf("message %q is not the unknown-capability finding", issues[0].Message)
	}
}

// TestLintPartiallyUnusablePatternList pins the severity split that follows
// from OR-within-a-list: one dead pattern weakens a rule, all of them kill it.
func TestLintPartiallyUnusablePatternList(t *testing.T) {
	issues := LintRuleSet(set(ece.ActionWarn,
		withMatch("paths", 100, ece.ActionBlock, Condition{
			PathPatterns: []string{"/ws/**", "relative/**"},
		}),
	))

	assertLint(t, issues, []wantLint{{capability.SeverityMedium, "paths"}})
	if len(BlockingIssues(issues)) != 0 {
		t.Error("a rule with one working pattern was blocked")
	}
	if !strings.Contains(issues[0].Message, "path_patterns[1]") {
		t.Errorf("message %q does not point at the dead pattern", issues[0].Message)
	}
}

// --- reachability -----------------------------------------------------------

func TestLintReachability(t *testing.T) {
	cases := []struct {
		name  string
		rules []Rule
		want  []wantLint
	}{
		{
			name: "a broader earlier rule shadows a narrower later one",
			rules: []Rule{
				withMatch("broad", 900, ece.ActionWarn, Condition{
					Verdicts: []decision.Verdict{decision.VerdictOutsideEnvelope, decision.VerdictGrantExceeded},
				}),
				withMatch("narrow", 800, ece.ActionBlock, Condition{
					Verdicts: []decision.Verdict{decision.VerdictOutsideEnvelope},
				}),
			},
			// Different actions: the operator wrote a block that never happens.
			want: []wantLint{{capability.SeverityHigh, "narrow"}},
		},
		{
			name: "same action is redundancy rather than surprise",
			rules: []Rule{
				withMatch("broad", 900, ece.ActionWarn, Condition{
					Verdicts: []decision.Verdict{decision.VerdictOutsideEnvelope, decision.VerdictGrantExceeded},
				}),
				withMatch("narrow", 800, ece.ActionWarn, Condition{
					Verdicts: []decision.Verdict{decision.VerdictOutsideEnvelope},
				}),
			},
			want: []wantLint{{capability.SeverityLow, "narrow"}},
		},
		{
			name: "an extra dimension makes the later rule narrower, not unreachable",
			rules: []Rule{
				withMatch("first", 900, ece.ActionWarn, Condition{
					Verdicts: []decision.Verdict{decision.VerdictOutsideEnvelope},
					Domains:  []capability.Domain{capability.DomainNetwork},
				}),
				withMatch("second", 800, ece.ActionBlock, Condition{
					Verdicts: []decision.Verdict{decision.VerdictOutsideEnvelope},
				}),
			},
			// "first" constrains the domain and "second" does not, so a
			// filesystem event still reaches "second".
			want: nil,
		},
		{
			name: "priority decides, not declaration order",
			rules: []Rule{
				withMatch("narrow", 100, ece.ActionBlock, Condition{
					Verdicts: []decision.Verdict{decision.VerdictOutsideEnvelope},
				}),
				withMatch("broad", 900, ece.ActionWarn, Condition{}),
			},
			want: []wantLint{
				{capability.SeverityHigh, "narrow"},
				// The catch-all also displaces the default action.
				{capability.SeverityMedium, "broad"},
			},
		},
		{
			name: "a disabled earlier rule shadows nothing",
			rules: []Rule{
				func() Rule {
					r := withMatch("off", 900, ece.ActionWarn, Condition{})
					r.Enabled = false
					return r
				}(),
				withMatch("live", 800, ece.ActionBlock, Condition{
					Verdicts: []decision.Verdict{decision.VerdictOutsideEnvelope},
				}),
			},
			want: nil,
		},
		{
			name: "a mode-restricted earlier rule does not shadow an unrestricted one",
			rules: []Rule{
				func() Rule {
					r := withMatch("ci-only", 900, ece.ActionBlock, Condition{})
					r.Modes = []Mode{ModeEnforce}
					return r
				}(),
				withMatch("always", 800, ece.ActionWarn, Condition{
					Verdicts: []decision.Verdict{decision.VerdictOutsideEnvelope},
				}),
			},
			want: nil,
		},
		{
			name: "an unrestricted earlier rule shadows a mode-restricted one",
			rules: []Rule{
				withMatch("always", 900, ece.ActionWarn, Condition{
					Verdicts: []decision.Verdict{decision.VerdictOutsideEnvelope},
				}),
				func() Rule {
					r := withMatch("ci-only", 800, ece.ActionBlock, Condition{
						Verdicts: []decision.Verdict{decision.VerdictOutsideEnvelope},
					})
					r.Modes = []Mode{ModeEnforce}
					return r
				}(),
			},
			want: []wantLint{{capability.SeverityHigh, "ci-only"}},
		},
		{
			name: "a wider mode restriction shadows a narrower one",
			rules: []Rule{
				func() Rule {
					r := withMatch("staged", 900, ece.ActionWarn, Condition{
						Verdicts: []decision.Verdict{decision.VerdictOutsideEnvelope},
					})
					r.Modes = []Mode{ModeInteractive, ModeEnforce}
					return r
				}(),
				func() Rule {
					r := withMatch("ci", 800, ece.ActionBlock, Condition{
						Verdicts: []decision.Verdict{decision.VerdictOutsideEnvelope},
					})
					r.Modes = []Mode{ModeEnforce}
					return r
				}(),
			},
			want: []wantLint{{capability.SeverityHigh, "ci"}},
		},
		{
			name: "rules restricted to different modes never meet",
			rules: []Rule{
				func() Rule {
					r := withMatch("ci", 900, ece.ActionBlock, Condition{})
					r.Modes = []Mode{ModeEnforce}
					return r
				}(),
				func() Rule {
					r := withMatch("desktop", 800, ece.ActionWarn, Condition{})
					r.Modes = []Mode{ModeMonitor}
					return r
				}(),
			},
			want: nil,
		},
		{
			name: "a wider risk band shadows a narrower one inside it",
			rules: []Rule{
				withMatch("wide", 900, ece.ActionWarn, Condition{
					MinRiskScore: f64(40), MaxRiskScore: f64(90),
				}),
				withMatch("inside", 800, ece.ActionBlock, Condition{
					MinRiskScore: f64(50), MaxRiskScore: f64(80),
				}),
			},
			want: []wantLint{{capability.SeverityHigh, "inside"}},
		},
		{
			name: "an overlapping risk band is not subsumed",
			rules: []Rule{
				withMatch("lower", 900, ece.ActionWarn, Condition{
					MinRiskScore: f64(40), MaxRiskScore: f64(70),
				}),
				withMatch("upper", 800, ece.ActionBlock, Condition{
					MinRiskScore: f64(60), MaxRiskScore: f64(90),
				}),
			},
			want: nil,
		},
		{
			name: "an unconditioned rule shadows a risk-conditioned one",
			rules: []Rule{
				withMatch("any", 900, ece.ActionWarn, Condition{
					Verdicts: []decision.Verdict{decision.VerdictIndeterminate},
				}),
				withMatch("scored", 800, ece.ActionBlock, Condition{
					Verdicts:     []decision.Verdict{decision.VerdictIndeterminate},
					MinRiskScore: f64(50),
				}),
			},
			// The risk condition only narrows: it additionally requires a
			// scored assessment.
			want: []wantLint{{capability.SeverityHigh, "scored"}},
		},
		{
			name: "a risk-conditioned rule does not shadow an unconditioned one",
			rules: []Rule{
				withMatch("scored", 900, ece.ActionBlock, Condition{
					Verdicts:     []decision.Verdict{decision.VerdictIndeterminate},
					MinRiskScore: f64(50),
				}),
				withMatch("any", 800, ece.ActionWarn, Condition{
					Verdicts: []decision.Verdict{decision.VerdictIndeterminate},
				}),
			},
			want: nil,
		},
		{
			name: "different path patterns are not compared as globs",
			rules: []Rule{
				withMatch("subtree", 900, ece.ActionWarn, Condition{
					PathPatterns: []string{"/ws/**"},
				}),
				withMatch("file", 800, ece.ActionBlock, Condition{
					PathPatterns: []string{"/ws/src/main.go"},
				}),
			},
			// Deliberately silent. "/ws/**" does cover "/ws/src/main.go", but
			// deciding glob containment in general is a different problem, and
			// a wrong answer here is a false accusation.
			want: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertLint(t, LintRuleSet(set(ece.ActionWarn, tc.rules...)), tc.want)
		})
	}
}

// --- default action ---------------------------------------------------------

func TestLintUnreachableDefaultAction(t *testing.T) {
	issues := LintRuleSet(set(ece.ActionBlock,
		withMatch("catch-all", 10, ece.ActionAllow, Condition{}),
	))

	assertLint(t, issues, []wantLint{{capability.SeverityMedium, "catch-all"}})
	if !strings.Contains(issues[0].Message, `default_action "block" can never apply`) {
		t.Errorf("message %q does not name the displaced default action", issues[0].Message)
	}
	if len(BlockingIssues(issues)) != 0 {
		t.Error("a catch-all rule blocked admission; it is legal policy")
	}
}

// TestLintDoesNotJudgeAStrongDefaultAction records a rule deliberately NOT
// implemented. A rule set that defaults to block and warns on specific cases is
// an allowlist posture, and its rules are exemptions rather than decoration.
// Nothing distinguishes that from a permissive mistake without knowing what the
// operator meant, so the linter says nothing.
func TestLintDoesNotJudgeAStrongDefaultAction(t *testing.T) {
	issues := LintRuleSet(set(ece.ActionBlock,
		withMatch("known-good-build", 100, ece.ActionAllow, Condition{
			Verdicts: []decision.Verdict{decision.VerdictWithinEnvelope},
		}),
		withMatch("noisy-reads", 90, ece.ActionWarn, Condition{
			Verdicts:     []decision.Verdict{decision.VerdictGrantExceeded},
			Capabilities: []capability.Kind{capability.KindFileRead},
		}),
	))

	if len(issues) != 0 {
		t.Errorf("an allowlist-posture rule set was flagged:\n%s", formatLint(issues))
	}
}

// --- restraint --------------------------------------------------------------

// TestLintStaysQuietOnValidRuleSets is the false-positive guard. Every case
// here is legitimate policy that an earlier draft of a linter like this one
// would plausibly have complained about.
func TestLintStaysQuietOnValidRuleSets(t *testing.T) {
	cases := []struct {
		name  string
		rules []Rule
	}{
		{
			name: "adjacent risk bands sharing a threshold",
			rules: []Rule{
				withMatch("high", 690, ece.ActionRequestApproval, Condition{MinRiskScore: f64(50)}),
				withMatch("low", 680, ece.ActionWarn, Condition{MaxRiskScore: f64(50)}),
			},
		},
		{
			name: "a zero minimum, meaning only when risk was scored at all",
			rules: []Rule{
				withMatch("scored", 100, ece.ActionWarn, Condition{MinRiskScore: f64(0)}),
			},
		},
		{
			name: "a disabled rule kept for documentation",
			rules: []Rule{
				func() Rule {
					r := withMatch("documented", 100, ece.ActionBlock, Condition{
						// Deliberately impossible content: a disabled rule is
						// inert by design, and reporting it would report the
						// feature rather than a defect.
						Capabilities: []capability.Kind{"fs.not-a-kind"},
					})
					r.Enabled = false
					return r
				}(),
			},
		},
		{
			name: "a catch-all as the last rule still displaces the default, but nothing else",
			rules: []Rule{
				withMatch("specific", 900, ece.ActionBlock, Condition{
					Verdicts: []decision.Verdict{decision.VerdictExplicitlyDenied},
				}),
			},
		},
		{
			name: "capability and domain that agree",
			rules: []Rule{
				withMatch("fs", 100, ece.ActionWarn, Condition{
					Capabilities: []capability.Kind{capability.KindFileRead},
					Domains:      []capability.Domain{capability.DomainFilesystem},
				}),
			},
		},
		{
			name: "one capability in the named domain is enough",
			rules: []Rule{
				withMatch("mixed", 100, ece.ActionWarn, Condition{
					Capabilities: []capability.Kind{capability.KindFileRead, capability.KindNetConnect},
					Domains:      []capability.Domain{capability.DomainNetwork},
				}),
			},
		},
		{
			name: "valid path and host patterns",
			rules: []Rule{
				withMatch("targets", 100, ece.ActionWarn, Condition{
					PathPatterns: []string{"/home/*/.ssh/**", "/etc/**"},
					Hosts:        []string{"*.github.com", "10.0.0.0/8", "203.0.113.5"},
				}),
			},
		},
		{
			name: "an unknown task type, which cannot be validated",
			rules: []Rule{
				withMatch("task", 100, ece.ActionWarn, Condition{TaskTypes: []string{"anything-goes"}}),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if issues := LintRuleSet(set(ece.ActionWarn, tc.rules...)); len(issues) != 0 {
				t.Errorf("valid policy produced issues:\n%s", formatLint(issues))
			}
		})
	}
}

// --- contract ---------------------------------------------------------------

func TestLintNeverAltersEvaluation(t *testing.T) {
	rs := set(ece.ActionWarn,
		withMatch("dead", 900, ece.ActionBlock, Condition{Verdicts: []decision.Verdict{"typo"}}),
		withMatch("live", 800, ece.ActionAllow, Condition{
			Verdicts: []decision.Verdict{decision.VerdictWithinEnvelope},
		}),
	)

	before := evaluate(t, engine(t, rs), EvaluateRequest{
		Event:      fileEvent(capability.KindFileRead, "/ws/a"),
		Validation: result(decision.VerdictWithinEnvelope),
	})

	if issues := LintRuleSet(rs); len(BlockingIssues(issues)) == 0 {
		t.Fatal("the dead rule was not reported")
	}

	after := evaluate(t, engine(t, rs), EvaluateRequest{
		Event:      fileEvent(capability.KindFileRead, "/ws/a"),
		Validation: result(decision.VerdictWithinEnvelope),
	})
	if before.RuleID != after.RuleID || before.Action != after.Action {
		t.Errorf("evaluation changed around a lint: %q/%q then %q/%q",
			before.RuleID, before.Action, after.RuleID, after.Action)
	}
	// And the rule set that lints badly still runs exactly as written.
	if after.RuleID != "live" {
		t.Errorf("selected %q, want live", after.RuleID)
	}
}

func TestLintNilAndEmpty(t *testing.T) {
	if issues := NewLinter().Lint(nil); issues != nil {
		t.Errorf("Lint(nil) = %v, want nil", issues)
	}
	if issues := LintRuleSet(set(ece.ActionWarn)); len(issues) != 0 {
		t.Errorf("an empty rule set produced issues:\n%s", formatLint(issues))
	}
	if got := BlockingIssues(nil); got != nil {
		t.Errorf("BlockingIssues(nil) = %v, want nil", got)
	}
}

func TestRiskConditioned(t *testing.T) {
	cases := []struct {
		name  string
		match Condition
		want  bool
	}{
		{"no risk condition", Condition{Verdicts: []decision.Verdict{decision.VerdictWithinEnvelope}}, false},
		{"minimum score", Condition{MinRiskScore: f64(10)}, true},
		{"maximum score", Condition{MaxRiskScore: f64(10)}, true},
		{"confidence", Condition{MinConfidence: f64(0.5)}, true},
		{"level", Condition{RiskLevels: []decision.Level{decision.LevelHigh}}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := RiskConditioned(withMatch("r", 1, ece.ActionWarn, tc.match)); got != tc.want {
				t.Errorf("RiskConditioned = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestVocabularyHelpersCoverTheEnums guards the membership functions the linter
// depends on. A verdict or violation type missing from them would be reported
// as unknown, which turns a working rule into a blocking lint error -- the worst
// possible false positive.
func TestVocabularyHelpersCoverTheEnums(t *testing.T) {
	for _, v := range decision.AllVerdicts() {
		if !decision.ValidVerdict(v) {
			t.Errorf("verdict %q is listed but not valid", v)
		}
	}
	for _, l := range decision.AllLevels() {
		if !decision.ValidLevel(l) {
			t.Errorf("level %q is listed but not valid", l)
		}
	}
	for _, vt := range validator.AllViolationTypes() {
		if !validator.ValidViolationType(vt) {
			t.Errorf("violation type %q is listed but not valid", vt)
		}
	}

	// The verdicts the shipped rule set names must all be real, which is the
	// property the linter is asserting on everyone else's behalf.
	rs, err := NewLoader().Load(context.Background(), defaultRuleSetPath)
	if err != nil {
		t.Fatalf("load shipped rule set: %v", err)
	}
	for _, r := range rs.Rules {
		for _, v := range r.Match.Verdicts {
			if !decision.ValidVerdict(v) {
				t.Errorf("rule %q names unknown verdict %q", r.ID, v)
			}
		}
	}
}
