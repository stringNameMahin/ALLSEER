package policy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// defaultRuleSetPath is the shipped policy. It is loaded by a test rather than
// only by the daemon, because a rule set nothing parses is documentation.
const defaultRuleSetPath = "../../configs/rules.default.yaml"

// --- helpers ----------------------------------------------------------------

// minimal is a well-formed rule set as a literal, so a case can change exactly
// one thing and show what that one thing costs.
const minimal = `
name: test
version: "1"
description: A minimal rule set.
default_action: warn
rules:
  - id: denied
    description: Explicit denials are blocked.
    priority: 900
    enabled: true
    match:
      verdicts: [explicitly_denied]
    action: block
`

func loadString(t *testing.T, yamlText string) (*RuleSet, error) {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(path, []byte(yamlText), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return NewLoader().Load(context.Background(), path)
}

// --- the shipped rule set ---------------------------------------------------

// TestLoadDefaultRuleSet is the drift guard between the file an operator edits
// and the engine that evaluates it. Every action, mode, and rule ID in the
// shipped policy has to be one this build understands, and the only way to know
// that is to load it.
func TestLoadDefaultRuleSet(t *testing.T) {
	rs, err := NewLoader().Load(context.Background(), defaultRuleSetPath)
	if err != nil {
		t.Fatalf("load shipped rule set: %v", err)
	}

	if rs.Name != "default" {
		t.Errorf("name = %q, want default", rs.Name)
	}
	if rs.DefaultAction != ece.ActionWarn {
		t.Errorf("default action = %q, want warn", rs.DefaultAction)
	}
	if len(rs.Rules) < 10 {
		t.Fatalf("loaded %d rules; the shipped set is substantially larger, so something parsed away", len(rs.Rules))
	}

	// It must be admissible, not merely parseable.
	e, err := NewEngine(rs)
	if err != nil {
		t.Fatalf("shipped rule set is not admissible: %v", err)
	}

	// And it must be evaluation-ready: every rule enabled, described, and
	// carrying an action, since a rule that reaches production without one of
	// those is either inert or unexplainable in an audit log.
	for _, r := range e.Rules() {
		if !r.Enabled {
			t.Errorf("rule %q is disabled in the shipped set; ship it enabled or remove it", r.ID)
		}
		if strings.TrimSpace(r.Description) == "" {
			t.Errorf("rule %q has no description; a decision citing it would not explain itself", r.ID)
		}
		if r.Priority <= 0 {
			t.Errorf("rule %q has priority %d; the shipped set orders explicitly", r.ID, r.Priority)
		}
	}
}

// TestDefaultRuleSetDecidesTheCasesItNames walks the shipped policy through the
// engine for the situations its own rule descriptions claim to cover. It pins
// the file's intent against the evaluator, which is what "validate the default
// rule set" has to mean if it is to mean anything.
func TestDefaultRuleSetDecidesTheCasesItNames(t *testing.T) {
	rs, err := NewLoader().Load(context.Background(), defaultRuleSetPath)
	if err != nil {
		t.Fatalf("load shipped rule set: %v", err)
	}
	e := engine(t, rs)

	cases := []struct {
		name       string
		req        EvaluateRequest
		wantRule   string
		wantAction ece.Action
	}{
		{
			name: "kernel tampering is blocked outright",
			req: EvaluateRequest{
				Event: &event.Event{
					ID: "e-kernel", Capability: capability.KindKernelBPFLoad,
					Domain: capability.DomainKernel,
				},
				// Verdict is irrelevant: the rule matches on domain alone,
				// because an envelope granting this would itself be the bug.
				Validation: result(decision.VerdictWithinEnvelope),
			},
			wantRule:   "kernel-surface-tampering",
			wantAction: ece.ActionBlock,
		},
		{
			name: "an explicit denial is blocked",
			req: EvaluateRequest{
				Event:      fileEvent(capability.KindFileRead, "/home/dev/.ssh/id_rsa"),
				Validation: result(decision.VerdictExplicitlyDenied),
			},
			wantRule:   "envelope-explicit-denial",
			wantAction: ece.ActionBlock,
		},
		{
			name: "unexpected egress asks a human",
			req: EvaluateRequest{
				Event:      netEvent("evil.example.com", "203.0.113.5", 443),
				Validation: result(decision.VerdictOutsideEnvelope),
			},
			wantRule:   "unexpected-network-egress",
			wantAction: ece.ActionRequestApproval,
		},
		{
			name: "an ungranted delete asks a human",
			req: EvaluateRequest{
				Event:      fileEvent(capability.KindFileDelete, "/ws/src/main.go"),
				Validation: result(decision.VerdictOutsideEnvelope),
			},
			wantRule:   "ungranted-delete",
			wantAction: ece.ActionRequestApproval,
		},
		{
			name: "a session budget breach asks a human",
			req: EvaluateRequest{
				Event:      fileEvent(capability.KindFileWrite, "/ws/src/main.go"),
				Validation: result(decision.VerdictConstraintViolation),
			},
			wantRule:   "session-constraint-exceeded",
			wantAction: ece.ActionRequestApproval,
		},
		{
			name: "expected behavior is allowed and stays quiet",
			req: EvaluateRequest{
				Event:      fileEvent(capability.KindFileWrite, "/ws/src/main.go"),
				Validation: result(decision.VerdictWithinEnvelope),
			},
			wantRule:   "within-envelope",
			wantAction: ece.ActionAllow,
		},
		{
			name: "an unscored departure falls through to the posture",
			req: EvaluateRequest{
				// Every escalation rule below unexpected-network-egress that
				// could cover this is risk-conditioned, and internal/risk does
				// not exist yet. The honest outcome is the default.
				Event:      fileEvent(capability.KindFileRead, "/etc/passwd"),
				Validation: result(decision.VerdictOutsideEnvelope),
			},
			wantRule:   DefaultRuleID,
			wantAction: ece.ActionWarn,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := evaluate(t, e, tc.req)
			if out.RuleID != tc.wantRule || out.Action != tc.wantAction {
				t.Errorf("got %q/%q, want %q/%q", out.RuleID, out.Action, tc.wantRule, tc.wantAction)
			}
		})
	}
}

// --- strictness -------------------------------------------------------------

func TestLoadRejects(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "malformed YAML",
			yaml: "name: test\n  version: oops\n",
			want: "parse rule set",
		},
		{
			name: "unknown top-level field",
			yaml: strings.Replace(minimal, "name: test", "name: test\nmode: enforce", 1),
			want: "field mode not found",
		},
		{
			name: "misspelled condition key",
			// The case the whole loader exists for: this parses, and the rule
			// it produces has no verdict constraint at all.
			yaml: strings.Replace(minimal, "verdicts:", "violaton_types:", 1),
			want: "not found",
		},
		{
			name: "unknown rule field",
			yaml: strings.Replace(minimal, "    action: block", "    action: block\n    severity: high", 1),
			want: "not found",
		},
		{
			name: "rule without enabled",
			yaml: strings.Replace(minimal, "    enabled: true\n", "", 1),
			want: "does not set enabled",
		},
		{
			name: "rule with neither an id nor enabled",
			// Reported by position, since there is no name to report it by.
			yaml: strings.Replace(
				strings.Replace(minimal, "  - id: denied\n    description:", "  - description:", 1),
				"    enabled: true\n", "", 1),
			want: `rule "#0"`,
		},
		{
			name: "rule without an id",
			yaml: strings.Replace(minimal, "  - id: denied\n    description:", "  - description:", 1),
			want: "no id",
		},
		{
			name: "unknown action",
			yaml: strings.Replace(minimal, "action: block", "action: destroy", 1),
			want: "action",
		},
		{
			name: "missing action",
			yaml: strings.Replace(minimal, "    action: block\n", "", 1),
			want: "action",
		},
		{
			name: "missing default action",
			yaml: strings.Replace(minimal, "default_action: warn\n", "", 1),
			want: "default action",
		},
		{
			name: "unknown default action",
			yaml: strings.Replace(minimal, "default_action: warn", "default_action: ignore", 1),
			want: "default action",
		},
		{
			name: "unknown mode",
			yaml: strings.Replace(minimal, "    action: block", "    action: block\n    modes: [paranoid]", 1),
			want: "mode",
		},
		{
			name: "duplicate rule ids",
			yaml: minimal + `
  - id: denied
    description: A second rule claiming the same audit key.
    priority: 100
    enabled: true
    action: warn
`,
			want: "duplicate rule id",
		},
		{
			name: "a second document",
			yaml: minimal + "\n---\nname: shadow\ndefault_action: allow\nrules: []\n",
			want: "more than one YAML document",
		},
		{
			name: "wrong type for a condition",
			yaml: strings.Replace(minimal, "verdicts: [explicitly_denied]", "verdicts: 7", 1),
			want: "parse rule set",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rs, err := loadString(t, tc.yaml)
			if err == nil {
				t.Fatalf("rule set was accepted: %+v", rs)
			}
			if rs != nil {
				t.Errorf("a rejected load returned a rule set: %+v", rs)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestLoadAcceptsAWellFormedRuleSet(t *testing.T) {
	rs, err := loadString(t, minimal)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if rs.Name != "test" || rs.Version != "1" || rs.DefaultAction != ece.ActionWarn {
		t.Errorf("header decoded as %+v", *rs)
	}
	if len(rs.Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(rs.Rules))
	}

	r := rs.Rules[0]
	if r.ID != "denied" || r.Action != ece.ActionBlock || r.Priority != 900 || !r.Enabled {
		t.Errorf("rule decoded as %+v", r)
	}
	if len(r.Match.Verdicts) != 1 || r.Match.Verdicts[0] != decision.VerdictExplicitlyDenied {
		t.Errorf("condition decoded as %+v", r.Match)
	}

	// The contract that makes the loader useful: what loads, runs.
	if _, err := NewEngine(rs); err != nil {
		t.Errorf("a loaded rule set was refused by the engine: %v", err)
	}
}

// TestLoadPreservesEnabledFalse pins the other half of the enabled rule: the
// field must be *written*, not necessarily true. A rule kept in the file for
// documentation while switched off is a legitimate thing to have.
func TestLoadPreservesEnabledFalse(t *testing.T) {
	rs, err := loadString(t, strings.Replace(minimal, "enabled: true", "enabled: false", 1))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if rs.Rules[0].Enabled {
		t.Fatal("enabled: false decoded as enabled")
	}

	// And it must actually stay out of evaluation.
	out := evaluate(t, engine(t, rs), EvaluateRequest{
		Event:      fileEvent(capability.KindFileRead, "/ws/a"),
		Validation: result(decision.VerdictExplicitlyDenied),
	})
	if out.RuleID != DefaultRuleID {
		t.Errorf("disabled rule %q fired", out.RuleID)
	}
}

func TestLoadEmptyAndMissingFiles(t *testing.T) {
	t.Run("empty file", func(t *testing.T) {
		_, err := loadString(t, "")
		if !errors.Is(err, ErrNoRules) {
			t.Fatalf("error = %v, want ErrNoRules", err)
		}
	})

	t.Run("comments only", func(t *testing.T) {
		_, err := loadString(t, "# a rule set that says nothing\n")
		if !errors.Is(err, ErrNoRules) {
			t.Fatalf("error = %v, want ErrNoRules", err)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := NewLoader().Load(context.Background(), filepath.Join(t.TempDir(), "absent.yaml"))
		if err == nil {
			t.Fatal("a missing rule set loaded")
		}
		if !strings.Contains(err.Error(), "open rule set") {
			t.Errorf("error %q does not say the file could not be opened", err)
		}
	})
}

// TestErrorsNameTheSource keeps a multi-file deployment debuggable: an operator
// with a default set and an override needs to know which one was rejected.
func TestErrorsNameTheSource(t *testing.T) {
	_, err := loadString(t, strings.Replace(minimal, "action: block", "action: destroy", 1))
	if err == nil {
		t.Fatal("invalid rule set was accepted")
	}
	if !strings.Contains(err.Error(), "rules.yaml") {
		t.Errorf("error %q does not name the file it came from", err)
	}
}

func TestWatchReportsNoSupport(t *testing.T) {
	ch, err := NewLoader().Watch(context.Background(), defaultRuleSetPath)
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	if ch != nil {
		t.Error("Watch returned a channel; nothing delivers to it yet")
	}
}
