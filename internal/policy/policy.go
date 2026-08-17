// Package policy turns a validated, scored observation into an action.
//
// Policy is the last stage before enforcement and the only one an operator is
// expected to edit routinely. Everything upstream produces facts: what
// happened, whether it was expected, how risky it looks. Policy supplies the
// judgment about what to do with them.
//
// Keeping that judgment in one module matters for two reasons. Deployments
// differ legitimately, since a CI runner should block what a developer laptop
// merely warns about, and the mapping from evidence to action is what an
// auditor needs to inspect. Scattering it across the validator and risk engine
// would make both untunable and the system's behavior unexplainable.
//
// Policy evaluation must be pure: same inputs, same action, every time.
package policy

import (
	"context"

	"github.com/stringNameMahin/ALLSEER/internal/validator"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// Engine evaluates policy to select an action.
type Engine interface {
	// Evaluate selects the action for a validated, scored event.
	Evaluate(ctx context.Context, req EvaluateRequest) (*Outcome, error)

	// Reload swaps in a new rule set without restarting. Rules change more
	// often than code, and an operator tightening policy mid-incident should
	// not have to drop an active session to do it.
	Reload(ctx context.Context, rules []Rule) error

	// Rules returns the active rule set for inspection.
	Rules() []Rule
}

// EvaluateRequest is the input to policy evaluation.
type EvaluateRequest struct {
	Event      *event.Event
	Validation *validator.Result
	Risk       *decision.RiskAssessment
	Envelope   *ece.Envelope

	// Mode is the enforcement posture for this session.
	Mode Mode
}

// Outcome is the result of policy evaluation.
type Outcome struct {
	Action ece.Action

	// RuleID identifies the rule that fired, or "default" when none matched.
	RuleID string

	// Reasoning explains the selection, carried into the Decision.
	Reasoning []decision.ReasoningStep

	// Terminal reports whether the session should end after this action. Some
	// findings are severe enough that continuing is inappropriate even if the
	// individual operation is blocked.
	Terminal bool
}

// Mode is the enforcement posture.
//
// It is an operational safety valve, and the progression matters: a system like
// this has to earn the right to block. Running in Monitor first surfaces false
// positives while they cost nothing but attention.
type Mode string

const (
	// ModeMonitor observes and records but never intervenes. Every decision is
	// advisory, with Decision.Enforced false. The right starting mode for any
	// new deployment or envelope profile.
	ModeMonitor Mode = "monitor"

	// ModeWarn surfaces violations to the user in real time but still does not
	// intervene.
	ModeWarn Mode = "warn"

	// ModeInteractive suspends the agent and asks for approval on risky
	// actions. The intended default for developer workstations.
	ModeInteractive Mode = "interactive"

	// ModeEnforce blocks autonomously without prompting. For CI and unattended
	// runs, where there is no human to ask.
	ModeEnforce Mode = "enforce"
)

// Rule is a single policy statement.
//
// Rules are declarative and ordered. Evaluation stops at the first match, so
// ordering is significant, and Priority makes that ordering explicit rather
// than dependent on file layout.
type Rule struct {
	// ID appears in every decision the rule produces, so a surprising outcome
	// can be traced to its source.
	ID string `json:"id" yaml:"id"`

	Description string `json:"description" yaml:"description"`

	// Priority orders evaluation. Higher priorities are evaluated first.
	Priority int `json:"priority" yaml:"priority"`

	// Match holds the conditions under which this rule applies. All populated
	// conditions must hold; they are ANDed.
	Match Condition `json:"match" yaml:"match"`

	Action ece.Action `json:"action" yaml:"action"`

	// Terminal ends the session when this rule fires.
	Terminal bool `json:"terminal,omitempty" yaml:"terminal,omitempty"`

	// Modes restricts the rule to specific enforcement modes. Empty means all.
	Modes []Mode `json:"modes,omitempty" yaml:"modes,omitempty"`

	// Enabled allows a rule to be kept for documentation while inactive.
	Enabled bool `json:"enabled" yaml:"enabled"`
}

// Condition specifies when a rule matches.
//
// Populated fields are ANDed; within a field, values are ORed. That keeps rules
// readable without a query language, which is worth the reduced expressiveness:
// policy operators cannot read confidently is policy that gets misconfigured.
type Condition struct {
	Verdicts       []decision.Verdict        `json:"verdicts,omitempty" yaml:"verdicts,omitempty"`
	Capabilities   []capability.Kind         `json:"capabilities,omitempty" yaml:"capabilities,omitempty"`
	Domains        []capability.Domain       `json:"domains,omitempty" yaml:"domains,omitempty"`
	ViolationTypes []validator.ViolationType `json:"violation_types,omitempty" yaml:"violation_types,omitempty"`

	MinRiskScore *float64         `json:"min_risk_score,omitempty" yaml:"min_risk_score,omitempty"`
	MaxRiskScore *float64         `json:"max_risk_score,omitempty" yaml:"max_risk_score,omitempty"`
	RiskLevels   []decision.Level `json:"risk_levels,omitempty" yaml:"risk_levels,omitempty"`

	PathPatterns []string `json:"path_patterns,omitempty" yaml:"path_patterns,omitempty"`
	Hosts        []string `json:"hosts,omitempty" yaml:"hosts,omitempty"`

	// MinConfidence keeps a shaky high score from triggering an aggressive rule.
	MinConfidence *float64 `json:"min_confidence,omitempty" yaml:"min_confidence,omitempty"`

	// TaskTypes matches the envelope's task classification.
	TaskTypes []string `json:"task_types,omitempty" yaml:"task_types,omitempty"`
}

// RuleSet is a named, versioned collection of rules.
type RuleSet struct {
	Name        string `json:"name" yaml:"name"`
	Version     string `json:"version" yaml:"version"`
	Description string `json:"description" yaml:"description"`

	// DefaultAction applies when no rule matches. This is the policy's posture
	// and the single most consequential line in any rule set.
	DefaultAction ece.Action `json:"default_action" yaml:"default_action"`

	Rules []Rule `json:"rules" yaml:"rules"`
}

// Loader reads rule sets from storage.
type Loader interface {
	// Load reads a rule set from a path.
	Load(ctx context.Context, path string) (*RuleSet, error)

	// Watch reports changes to the rule set, enabling hot reload. Nil is a
	// valid return for implementations that do not support watching.
	Watch(ctx context.Context, path string) (<-chan *RuleSet, error)
}

// Linter checks a rule set for problems before it is loaded.
//
// Worth its own interface because bad policy fails quietly. A rule shadowed by
// an earlier one, or a condition that can never match, produces no runtime
// error; it just fails to protect anything.
type Linter interface {
	Lint(rs *RuleSet) []LintIssue
}

// LintIssue is a problem found in a rule set.
type LintIssue struct {
	Severity capability.Severity `json:"severity"`
	RuleID   string              `json:"rule_id,omitempty"`
	Message  string              `json:"message"`
}

// Done: first-match-wins evaluation is implemented by RuleEngine in
// evaluate.go, ordered by priority descending then declaration order, sorted
// once at load so Rules() reports exactly the sequence Evaluate walks. Two
// rules there are not obvious from these types: Mode selects which rules are
// eligible and never rewrites an action, because monitor mode exists to measure
// what the policy would have done; and a condition with no evidence behind it
// does not match, so a max_risk_score rule cannot fire on an event the risk
// engine never scored.
// TODO(policy): implement Loader over configs/rules.default.yaml. This is where
// the project's first dependency lands (gopkg.in/yaml.v3), which is why it is
// separate from evaluation: the semantics above are testable with no dependency
// at all, and the shipped rule set is not yet loadable by anything.
// TODO(policy): validate the shipped default rule set against the engine. It
// has to be conservative enough to be safe and quiet enough to leave enabled.
// TODO(policy): implement the linter: unreachable rules, shadowed rules,
// conditions that can never match, rule sets whose default action is weaker
// than any rule in them.
// TODO(policy): decide whether rule sets should be signed. Policy is the file
// an attacker with local write access would most want to modify.
// TODO(policy): add a dry-run evaluator replaying a recorded session against a
// candidate rule set, so operators can see what a change would have done before
// enabling it.
