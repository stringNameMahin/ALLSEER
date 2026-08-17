package policy

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/stringNameMahin/ALLSEER/internal/validator"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
)

// Evaluation is first-match-wins, and everything else here follows from that
// one choice.
//
// Rules are ordered once, by priority descending and then by declaration order,
// and the first eligible rule whose conditions all hold decides the action. No
// rule after it is consulted, no scores are combined, and no action is
// synthesized from several matches. The alternative — evaluating everything and
// merging — produces outcomes no operator can predict by reading the file, and
// an unpredictable policy is one that gets disabled.
//
// Three properties are load-bearing and each is pinned by a test:
//
//   - Determinism. The same request against the same rule set always yields the
//     same outcome, including which rule is credited. An audit record that
//     names a different rule on replay is not an audit record.
//   - The engine never rewrites an action. Mode selects which rules are
//     eligible; it does not soften what they say. See modeApplies.
//   - A condition with no evidence behind it does not match. This is the policy
//     analogue of validator.MatchResult.Unevaluable: a rule reading
//     max_risk_score: 60 must not fire on an event whose risk was never scored,
//     because that reports a low-risk finding the system never made.

// RuleEngine is the first-match-wins implementation of Engine.
//
// Safe for concurrent use. Evaluation reads an immutable snapshot through an
// atomic pointer, so a Reload mid-session swaps the rule set between events
// rather than during one: an event is never judged against half of two policies.
type RuleEngine struct {
	active atomic.Pointer[ruleSet]
}

// ruleSet is the immutable evaluation snapshot: rules pre-sorted into
// evaluation order, plus the posture applied when none of them match.
//
// Sorting once at load rather than per event is the only concession to the hot
// path in this file, and it is also what makes ordering auditable: Rules()
// returns exactly the sequence Evaluate walks.
type ruleSet struct {
	rules         []Rule
	defaultAction ece.Action
}

var _ Engine = (*RuleEngine)(nil)

// NewEngine returns an engine over a rule set, rejecting one it cannot evaluate
// unambiguously.
//
// Refusing at construction is deliberate. A malformed rule discovered at
// evaluation time would have to fail somehow on the hot path, and every
// available failure — skip the rule, block the event, allow the event — is
// worse than not starting with it. The checks here are structural admission,
// not linting: whether a rule is shadowed or can never match is Linter's
// question, and it is answered separately because it is advisory.
func NewEngine(rs *RuleSet) (*RuleEngine, error) {
	if rs == nil {
		return nil, fmt.Errorf("policy: rule set is required")
	}
	snapshot, err := compile(rs.Rules, rs.DefaultAction)
	if err != nil {
		return nil, err
	}

	e := &RuleEngine{}
	e.active.Store(snapshot)
	return e, nil
}

// Evaluate selects the action for a validated event.
//
// A nil Validation is an error rather than an allow: policy exists to act on a
// verdict, and a caller with no verdict has a wiring bug. Errors are never a
// quiet allow anywhere on this path.
func (e *RuleEngine) Evaluate(_ context.Context, req EvaluateRequest) (*Outcome, error) {
	if req.Validation == nil {
		return nil, fmt.Errorf("policy: validation result is required")
	}
	active := e.active.Load()

	for i := range active.rules {
		r := &active.rules[i]
		if !r.Enabled || !modeApplies(r, req.Mode) {
			continue
		}
		if !matches(r.Match, req) {
			continue
		}
		return &Outcome{
			Action:   r.Action,
			RuleID:   r.ID,
			Terminal: r.Terminal,
			Reasoning: []decision.ReasoningStep{{
				Stage:      "policy",
				Conclusion: fmt.Sprintf("rule %q matched, action %s", r.ID, r.Action),
				Detail:     describeMatch(r, req),
			}},
		}, nil
	}

	// The posture. Reaching here is not a failure — most rule sets deliberately
	// leave the common case to the default — but it is the outcome an operator
	// should be able to predict, so it names itself rather than the last rule
	// considered.
	return &Outcome{
		Action: active.defaultAction,
		RuleID: DefaultRuleID,
		Reasoning: []decision.ReasoningStep{{
			Stage:      "policy",
			Conclusion: fmt.Sprintf("no rule matched, default action %s", active.defaultAction),
			Detail:     describeRequest(req),
		}},
	}, nil
}

// DefaultRuleID is the RuleID reported when no rule matched. Exported because
// audit queries filter on it: "how often did policy fall through" is the first
// question asked of a rule set that is not doing what its author expected.
const DefaultRuleID = "default"

// Reload swaps in a new rule set without restarting, keeping the current
// default action.
//
// The Engine interface takes rules alone, and that is the right shape for the
// common case: rules change often, while DefaultAction is the posture and
// changing it silently through a rule reload would be the least visible way to
// weaken a policy. ReloadSet exists for the loader, which legitimately replaces
// both.
func (e *RuleEngine) Reload(_ context.Context, rules []Rule) error {
	current := e.active.Load()
	snapshot, err := compile(rules, current.defaultAction)
	if err != nil {
		// The active rule set stays in force. A daemon handed a bad rule file
		// mid-session must keep governing under the policy it already had; the
		// alternative is a window with no policy at all, which is exactly when
		// an attacker would want the reload to fail.
		return err
	}
	e.active.Store(snapshot)
	return nil
}

// ReloadSet swaps in a complete rule set, including its default action.
func (e *RuleEngine) ReloadSet(rs *RuleSet) error {
	if rs == nil {
		return fmt.Errorf("policy: rule set is required")
	}
	snapshot, err := compile(rs.Rules, rs.DefaultAction)
	if err != nil {
		return err
	}
	e.active.Store(snapshot)
	return nil
}

// Rules returns the active rules in evaluation order, which is the order that
// decides outcomes rather than the order they were written in. The returned
// slice is a copy.
func (e *RuleEngine) Rules() []Rule {
	active := e.active.Load()
	out := make([]Rule, len(active.rules))
	copy(out, active.rules)
	return out
}

// DefaultAction reports the posture applied when no rule matches.
func (e *RuleEngine) DefaultAction() ece.Action {
	return e.active.Load().defaultAction
}

// compile validates a rule set and freezes it into evaluation order.
func compile(rules []Rule, defaultAction ece.Action) (*ruleSet, error) {
	if !validAction(defaultAction) {
		return nil, fmt.Errorf("policy: default action %q is not one of allow, warn, request_approval, block", defaultAction)
	}

	ordered := make([]Rule, len(rules))
	copy(ordered, rules)

	seen := make(map[string]bool, len(ordered))
	for i := range ordered {
		if err := validateRule(&ordered[i]); err != nil {
			return nil, err
		}
		if seen[ordered[i].ID] {
			// IDs are the audit key. Two rules sharing one makes "which rule
			// blocked my agent" unanswerable, and the answer is the only reason
			// the field exists.
			return nil, fmt.Errorf("policy: duplicate rule id %q", ordered[i].ID)
		}
		seen[ordered[i].ID] = true
	}

	// Stable, so equal priorities keep declaration order. sort.SliceStable
	// rather than a comparison on index: the file's order is the tiebreak an
	// operator expects when they write two rules at the same priority.
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].Priority > ordered[j].Priority
	})

	return &ruleSet{rules: ordered, defaultAction: defaultAction}, nil
}

func validateRule(r *Rule) error {
	if strings.TrimSpace(r.ID) == "" {
		return fmt.Errorf("policy: rule at priority %d has no id", r.Priority)
	}
	if !validAction(r.Action) {
		return fmt.Errorf("policy: rule %q has action %q, want one of allow, warn, request_approval, block", r.ID, r.Action)
	}
	for _, m := range r.Modes {
		if !validMode(m) {
			return fmt.Errorf("policy: rule %q names unknown mode %q", r.ID, m)
		}
	}
	return nil
}

func validAction(a ece.Action) bool {
	switch a {
	case ece.ActionAllow, ece.ActionWarn, ece.ActionRequestApproval, ece.ActionBlock:
		return true
	}
	return false
}

func validMode(m Mode) bool {
	switch m {
	case ModeMonitor, ModeWarn, ModeInteractive, ModeEnforce:
		return true
	}
	return false
}

// modeApplies reports whether a rule is eligible in this session's mode.
//
// This is the only thing Mode does here, and the restraint is the design. The
// engine never downgrades block to warn in monitor mode: whether an action is
// actually applied is Decision.Enforced's job, decided at enforcement, and
// rewriting the action here would erase the very measurement monitor mode
// exists to produce. "What would this policy have done?" is unanswerable if the
// policy answered a different question while being watched.
//
// Collapsing request_approval to block where no human can be prompted is the
// same kind of judgment, and it belongs in the CI rule set rather than in this
// function, so that an operator reading the file sees it.
func modeApplies(r *Rule, mode Mode) bool {
	if len(r.Modes) == 0 {
		return true
	}
	for _, m := range r.Modes {
		if m == mode {
			return true
		}
	}
	return false
}

// matches reports whether every populated condition holds.
//
// Fields are ANDed and values within a field are ORed, so adding a condition
// always narrows a rule and adding a value always widens one. The inverse on
// either would make rule sets unreadable in the direction that matters: every
// operator writing a second condition expects to be tightening.
//
// An unpopulated field imposes no constraint, which means a Condition with no
// fields set matches everything. That is the honest reading of "all conditions
// hold" over an empty set, and a catch-all rule is a legitimate thing to write;
// Linter flags one that was probably not intended.
func matches(c Condition, req EvaluateRequest) bool {
	if len(c.Verdicts) > 0 && !containsVerdict(c.Verdicts, req.Validation.Verdict) {
		return false
	}

	if len(c.Capabilities) > 0 || len(c.Domains) > 0 {
		kind, ok := eventKind(req)
		if !ok {
			return false
		}
		if len(c.Capabilities) > 0 && !containsKind(c.Capabilities, kind) {
			return false
		}
		if len(c.Domains) > 0 {
			// From the catalog, never Event.Domain: the two can disagree in a
			// mis-decoded record, and every other stage keys on the catalog.
			domain, known := capability.DomainOf(kind)
			if !known || !containsDomain(c.Domains, domain) {
				return false
			}
		}
	}

	if len(c.ViolationTypes) > 0 && !hasViolation(req.Validation.Violations, c.ViolationTypes) {
		return false
	}

	if !riskMatches(c, req.Risk) {
		return false
	}

	if len(c.PathPatterns) > 0 || len(c.Hosts) > 0 {
		if !targetMatches(c, req) {
			return false
		}
	}

	if len(c.TaskTypes) > 0 {
		if req.Envelope == nil || !containsString(c.TaskTypes, req.Envelope.Intent.TaskType) {
			return false
		}
	}

	return true
}

// riskMatches applies the score, level, and confidence conditions.
//
// A missing assessment fails every one of them. Treating it as a zero score
// would be worse than it looks: min_risk_score conditions would behave, but a
// max_risk_score rule — "low risk, just warn" — would fire on every event whose
// risk was never computed, attaching a reassuring classification to evidence
// that does not exist. Until internal/risk lands, rules with risk conditions
// simply do not fire, which is visible in the outcome's RuleID rather than
// hidden behind a fabricated score.
func riskMatches(c Condition, risk *decision.RiskAssessment) bool {
	if c.MinRiskScore == nil && c.MaxRiskScore == nil && c.MinConfidence == nil && len(c.RiskLevels) == 0 {
		return true
	}
	if risk == nil {
		return false
	}

	if c.MinRiskScore != nil && risk.Score < *c.MinRiskScore {
		return false
	}
	// Minimum inclusive, maximum exclusive, so adjacent bands partition the
	// scale instead of overlapping on their shared boundary. This is not a
	// preference: configs/rules.default.yaml pairs indeterminate-high-risk
	// (min 50) with indeterminate-low-risk (max 50), and medium-risk-departure
	// (min 40, max 75) with high-risk-departure (min 75). Under an inclusive
	// maximum a score of exactly 50 or 75 would satisfy both rules of each
	// pair, and first-match-wins would quietly pick one — hiding the ambiguity
	// precisely at the threshold an operator chose deliberately.
	if c.MaxRiskScore != nil && risk.Score >= *c.MaxRiskScore {
		return false
	}
	if c.MinConfidence != nil && risk.Confidence < *c.MinConfidence {
		return false
	}
	if len(c.RiskLevels) > 0 && !containsLevel(c.RiskLevels, risk.Level) {
		return false
	}
	return true
}

// targetMatches applies the path and host conditions.
//
// It borrows the validator's matchers rather than reimplementing them, for the
// reason the envelope linter does: a rule that means something different from
// the grant it was written to complement is a bug nobody can see. An event that
// cannot be resolved to an observation matches neither dimension — the same
// no-evidence rule as risk, and the same reason.
func targetMatches(c Condition, req EvaluateRequest) bool {
	if req.Event == nil {
		return false
	}
	obs, err := validator.ObservationOf(req.Event)
	if err != nil {
		return false
	}

	if len(c.PathPatterns) > 0 {
		if !anyPathMatches(c.PathPatterns, obs.Target) {
			return false
		}
	}

	if len(c.Hosts) > 0 {
		address := obs.Attributes[capability.AttrDestIP]
		if !anyHostMatches(c.Hosts, hostOf(obs.Target), address) {
			return false
		}
	}

	return true
}

func anyPathMatches(patterns []string, target string) bool {
	for _, p := range patterns {
		// An invalid pattern matches nothing, exactly as it does in an
		// envelope. The rule then silently fails to fire, which is why
		// EnvelopeLinter's counterpart for rule sets is a first-class interface.
		if validator.MatchPath(p, target) {
			return true
		}
	}
	return false
}

// anyHostMatches compares both the correlated name and the literal address,
// matching what SelectorMatcher does. Both are facts the kernel or enrichment
// established; what stays forbidden is treating an address as standing in for a
// name nobody observed, and that ends here as no match.
func anyHostMatches(patterns []string, host, address string) bool {
	for _, p := range patterns {
		if host != "" && validator.MatchHost(p, host) {
			return true
		}
		if address != "" && address != host && validator.MatchHost(p, address) {
			return true
		}
	}
	return false
}

// eventKind reports the capability under evaluation.
//
// Taken from the event rather than from the validation result because that is
// where every other stage reads it, including resolve.Observe, which builds the
// observation the validator matched. A result carries violations, and a
// violation carries a Kind, but an allowed event has no violations and the
// condition must still be answerable.
func eventKind(req EvaluateRequest) (capability.Kind, bool) {
	if req.Event == nil || req.Event.Capability == "" {
		return "", false
	}
	return req.Event.Capability, true
}

func hasViolation(violations []validator.Violation, want []validator.ViolationType) bool {
	for _, v := range violations {
		for _, w := range want {
			if v.Type == w {
				return true
			}
		}
	}
	return false
}

// describeMatch summarizes the evidence a rule fired on, so the audit record
// answers "why this rule" without the reader reconstructing the request.
func describeMatch(r *Rule, req EvaluateRequest) string {
	parts := []string{describeRequest(req)}
	if r.Terminal {
		parts = append(parts, "rule is terminal: the session ends after this action")
	}
	return strings.Join(parts, "; ")
}

func describeRequest(req EvaluateRequest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "verdict %s", req.Validation.Verdict)
	if kind, ok := eventKind(req); ok {
		fmt.Fprintf(&b, ", capability %s", kind)
	}
	if req.Risk != nil {
		fmt.Fprintf(&b, ", risk %.0f (%s)", req.Risk.Score, req.Risk.Level)
	} else {
		b.WriteString(", risk not scored")
	}
	if req.Mode != "" {
		fmt.Fprintf(&b, ", mode %s", req.Mode)
	}
	return b.String()
}

// hostOf takes the host half of a network target, which may be "host:port",
// "[v6]:port", or a bare host. A failed split leaves the target whole: a bare
// IPv6 literal is full of colons and looks like host:port to a naive one. Host
// conditions constrain the destination, never the port, so nothing else here
// needs the other half.
func hostOf(target string) string {
	if target == "" {
		return ""
	}
	h, _, err := net.SplitHostPort(target)
	if err != nil {
		return target
	}
	return h
}

func containsVerdict(haystack []decision.Verdict, needle decision.Verdict) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

func containsKind(haystack []capability.Kind, needle capability.Kind) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

func containsDomain(haystack []capability.Domain, needle capability.Domain) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

func containsLevel(haystack []decision.Level, needle decision.Level) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

func containsString(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}
