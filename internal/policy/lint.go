package policy

import (
	"fmt"
	"strings"

	"github.com/stringNameMahin/ALLSEER/internal/validator"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
)

// Linting answers the question loading cannot: this rule set is well-formed,
// but does it do anything?
//
// A rule that can never match produces no error, no log line, and no event. It
// simply is not there, while continuing to read like protection to whoever
// wrote it. That is the same failure mode the ECE linter exists for on the
// envelope side, and it gets the same treatment here.
//
// Two rules govern what is reported, and both are about earning trust:
//
//   - Only findings that follow from the evaluation semantics in evaluate.go.
//     Every check below is a proof that some rule cannot fire, or that some
//     value cannot be produced by any stage upstream. Nothing here is a style
//     preference or a guess about intent.
//   - No false positives. Where a check would have to reason about glob
//     containment or about what an operator meant, it is left out and its
//     absence is documented, because a linter that cries wolf is one operators
//     learn to skip -- and then the real finding scrolls past with the rest.
//
// Severity splits along a single line: critical means the rule can never fire
// and the rule set should not be accepted; everything else is advisory. Linting
// never changes evaluation. A rule set that lints badly still evaluates exactly
// as written, which is what makes it safe to run the linter on a live policy.
//
// One check is about the running build rather than about the rule set, and is
// therefore optional and never critical: lintObservability, which reports rules
// naming capabilities no probe in this build reports. A rule set correct on one
// platform and inert on another is not a defective rule set, but "this binary
// will silently not enforce that" is exactly what an operator needs told.
//
// Deliberately NOT reported, each for a stated reason:
//
//   - A disabled rule. Rule.Enabled exists precisely so a rule can be kept for
//     documentation while inactive; reporting it would report the feature.
//   - A rule set whose default_action is stronger than every rule in it. The
//     obvious reading -- "the rules are decoration" -- is wrong. A rule set that
//     defaults to block and warns on specific cases is an allowlist posture,
//     and its rules are exemptions rather than protections. There is no way to
//     tell that from a permissive mistake without knowing the operator's
//     intent, so nothing is claimed. The one default_action finding that *is*
//     provable is unreachability, below.
//   - A catch-all condition as such. What matters about it is concrete and
//     already reported: the rules it shadows, and the default action it
//     displaces.
//   - Structural defects -- unknown actions or modes, missing or duplicate IDs.
//     Those are admission's job, enforced by compile at construction and by the
//     loader before that. Repeating them here would be a second implementation
//     of the same rule.

// RuleLinter implements Linter over the evaluation semantics in evaluate.go.
//
// The zero value is usable and safe for concurrent use. A linter carrying a
// catalog additionally reports rules this build cannot evaluate; see
// NewLinterWithCatalog.
type RuleLinter struct {
	// catalog, when non-nil, is the observability oracle. It is optional
	// because every other check here is a statement about the rule set alone,
	// answerable from the file, while this one is a statement about a running
	// build -- and a linter that demanded a catalog would be unusable at the
	// point most linting happens, before any probe has attached.
	catalog capability.Catalog
}

var _ Linter = RuleLinter{}

// NewLinter returns a rule set linter that checks the rule set alone.
func NewLinter() RuleLinter { return RuleLinter{} }

// NewLinterWithCatalog returns a linter that also reports rules whose
// capabilities no probe in this build observes.
//
// The daemon calls this after Collector.Probes() has driven
// MemoryCatalog.SetObservable, which is the point at which the catalog stops
// being theoretical and starts describing what this process can see.
//
// Generic on purpose. The concrete case that motivated it is a Windows build,
// where privilege telemetry is uid-and-capability shaped on Linux and token,
// SID and integrity-level shaped on Windows, so every priv.* Kind is
// unobservable -- and a terminal block rule on priv.escalate that can never
// fire reads as coverage. But nothing here knows that: the check is "the
// catalog says no probe reports this", which covers a mechanism that failed to
// load, a capability whose probe was compiled out, and a platform that has no
// such concept, without naming any of them.
func NewLinterWithCatalog(cat capability.Catalog) RuleLinter {
	return RuleLinter{catalog: cat}
}

// Lint reports every provable defect in a rule set, in document order:
// per-rule findings in evaluation order, then rule-set-wide findings.
//
// It assumes the rule set is structurally admissible -- that NewEngine or the
// loader has accepted it -- and reports only semantic defects. A nil rule set
// yields no issues rather than a panic; there is nothing to say about a policy
// that does not exist.
func (l RuleLinter) Lint(rs *RuleSet) []LintIssue { return LintRuleSetWithCatalog(rs, l.catalog) }

// LintRuleSet is Lint as a free function, without an observability check.
func LintRuleSet(rs *RuleSet) []LintIssue { return LintRuleSetWithCatalog(rs, nil) }

// LintRuleSetWithCatalog is LintRuleSet plus the observability check. A nil
// catalog disables that check and nothing else.
func LintRuleSetWithCatalog(rs *RuleSet, cat capability.Catalog) []LintIssue {
	if rs == nil {
		return nil
	}

	ordered := make([]Rule, len(rs.Rules))
	copy(ordered, rs.Rules)
	evaluationOrder(ordered)

	var issues []LintIssue
	for i := range ordered {
		issues = append(issues, lintRule(&ordered[i], cat)...)
		issues = append(issues, lintReachability(ordered, i)...)
	}
	issues = append(issues, lintDefaultAction(rs, ordered)...)
	return issues
}

// BlockingIssues returns the issues that should refuse a rule set.
//
// Exported so the rule lives in one place, as validator.BlockingIssues does for
// envelopes. Critical means proven-unable-to-fire; a caller that treated
// warnings as fatal would refuse rule sets that work.
func BlockingIssues(issues []LintIssue) []LintIssue {
	var out []LintIssue
	for _, i := range issues {
		if i.Severity == capability.SeverityCritical {
			out = append(out, i)
		}
	}
	return out
}

// --- per-rule checks --------------------------------------------------------

func lintRule(r *Rule, cat capability.Catalog) []LintIssue {
	if !r.Enabled {
		// An inert rule cannot mislead anyone about what it does; it says so.
		return nil
	}

	var issues []LintIssue
	c := r.Match

	issues = append(issues, lintClosedSets(r.ID, c)...)
	issues = append(issues, lintRiskRange(r.ID, c)...)
	issues = append(issues, lintCapabilityDomain(r.ID, c)...)
	issues = append(issues, lintPatterns(r.ID, "path_patterns", c.PathPatterns, validator.ValidatePattern)...)
	issues = append(issues, lintPatterns(r.ID, "hosts", c.Hosts, validator.ValidateHostPattern)...)
	issues = append(issues, lintObservability(r.ID, c, cat)...)
	return issues
}

// lintObservability reports a rule this build cannot evaluate, because no probe
// behind it reports the capabilities the rule names.
//
// This is the one check whose finding is about the running build rather than
// about the rule set, and that is why none of it is critical however certain it
// is. A rule set naming priv.escalate is not wrong; it is correct on a Linux
// build and inert on a Windows one, and refusing to load it would mean a policy
// covering two platforms could be loaded on neither. The finding an operator
// needs is loud, not fatal: what this binary will silently not enforce.
//
// The distinction between the two severities is the same one lintPatterns
// draws, and for the same reason. Conditions are ANDed across dimensions and
// ORed within one, so one unobservable capability among observable ones weakens
// a rule, while a list where every entry is unobservable removes it.
//
// A Kind that is not in the catalog at all is skipped rather than reported
// here: lintClosedSets already says so, as a critical, and an unknown Kind
// being unobservable adds nothing to that.
func lintObservability(id string, c Condition, cat capability.Catalog) []LintIssue {
	if cat == nil {
		return nil
	}

	var issues []LintIssue

	if blind := unobservableKinds(c.Capabilities, cat); len(blind) > 0 {
		severity, effect := capability.SeverityMedium, "the rule still fires on the rest"
		if len(blind) == len(c.Capabilities) {
			severity, effect = capability.SeverityHigh, "the rule can never fire in this build"
		}
		issues = append(issues, LintIssue{
			Severity: severity,
			RuleID:   id,
			Message:  fmt.Sprintf("no probe in this build observes %s; %s", join(blind), effect),
		})
	}

	for _, d := range c.Domains {
		known := capability.KindsInDomain(d)
		if len(known) == 0 {
			// An unknown domain, already reported by lintClosedSets.
			continue
		}
		if len(unobservableKinds(known, cat)) == len(known) {
			issues = append(issues, LintIssue{
				Severity: capability.SeverityHigh,
				RuleID:   id,
				Message: fmt.Sprintf("no probe in this build observes any capability in domain %q; the rule can never fire in this build",
					d),
			})
		}
	}

	return issues
}

// unobservableKinds returns the known Kinds among kinds that no probe reports.
func unobservableKinds(kinds []capability.Kind, cat capability.Catalog) []capability.Kind {
	var out []capability.Kind
	for _, k := range kinds {
		if capability.Known(k) && !cat.Observable(k) {
			out = append(out, k)
		}
	}
	return out
}

// lintClosedSets checks the condition fields whose values come from closed
// enums. A value outside one is not merely unusual: no stage upstream can
// produce it, so the rule is dead.
func lintClosedSets(id string, c Condition) []LintIssue {
	var issues []LintIssue

	for _, v := range c.Verdicts {
		if !decision.ValidVerdict(v) {
			issues = append(issues, impossible(id,
				fmt.Sprintf("verdict %q is not one the validator produces (%s)", v, join(decision.AllVerdicts())),
				"the rule can never match, since every event carries one of the known verdicts"))
		}
	}
	for _, k := range c.Capabilities {
		if !capability.Known(k) {
			issues = append(issues, impossible(id,
				fmt.Sprintf("capability %q is not in the catalog", k),
				"no observation can carry it, so the rule can never match"))
		}
	}
	for _, d := range c.Domains {
		if !knownDomain(d) {
			issues = append(issues, impossible(id,
				fmt.Sprintf("domain %q is not one of %s", d, join(capability.AllDomains())),
				"no capability resolves to it, so the rule can never match"))
		}
	}
	for _, vt := range c.ViolationTypes {
		if !validator.ValidViolationType(vt) {
			issues = append(issues, impossible(id,
				fmt.Sprintf("violation type %q is not one the validator reports (%s)", vt, join(validator.AllViolationTypes())),
				"the rule can never match"))
		}
	}
	for _, l := range c.RiskLevels {
		if !decision.ValidLevel(l) {
			issues = append(issues, impossible(id,
				fmt.Sprintf("risk level %q is not one of %s", l, join(decision.AllLevels())),
				"the rule can never match"))
		}
	}

	return issues
}

// lintRiskRange checks the numeric conditions against the ranges pkg/decision
// normalizes to, and against each other.
//
// Note what is *not* reported: a minimum below zero, or a maximum above the top
// of the scale. Those look redundant and are not, because any risk field at all
// makes the rule require a scored assessment -- riskMatches refuses a nil one.
// "min_risk_score: 0" is the idiomatic way to write "only when risk was
// actually scored", and flagging it would flag a working idiom.
func lintRiskRange(id string, c Condition) []LintIssue {
	var issues []LintIssue

	if c.MinRiskScore != nil && c.MaxRiskScore != nil && *c.MinRiskScore >= *c.MaxRiskScore {
		// Minimum inclusive, maximum exclusive, so an equal pair is empty too.
		issues = append(issues, impossible(id,
			fmt.Sprintf("min_risk_score %g is not below max_risk_score %g", *c.MinRiskScore, *c.MaxRiskScore),
			"the band is empty: a score must be at least the minimum and strictly below the maximum"))
	}
	if c.MinRiskScore != nil && *c.MinRiskScore > 100 {
		issues = append(issues, impossible(id,
			fmt.Sprintf("min_risk_score %g is above the top of the scale", *c.MinRiskScore),
			"risk scores are normalized to [0,100]"))
	}
	if c.MaxRiskScore != nil && *c.MaxRiskScore <= 0 {
		issues = append(issues, impossible(id,
			fmt.Sprintf("max_risk_score %g leaves no score below it", *c.MaxRiskScore),
			"risk scores are normalized to [0,100] and the maximum is exclusive"))
	}
	if c.MinConfidence != nil && *c.MinConfidence > 1 {
		issues = append(issues, impossible(id,
			fmt.Sprintf("min_confidence %g is above the top of the scale", *c.MinConfidence),
			"confidence is normalized to [0,1]"))
	}

	return issues
}

// lintCapabilityDomain reports a rule constrained to capabilities that all sit
// outside the domains it also names.
//
// Provable because matching derives the domain from the capability through the
// catalog rather than trusting the event: a rule naming fs.read and the network
// domain is asking for an observation that cannot exist.
func lintCapabilityDomain(id string, c Condition) []LintIssue {
	if len(c.Capabilities) == 0 || len(c.Domains) == 0 {
		return nil
	}

	for _, k := range c.Capabilities {
		d, known := capability.DomainOf(k)
		if !known {
			// Already reported as an unknown capability; saying it twice adds
			// nothing.
			return nil
		}
		for _, want := range c.Domains {
			if d == want {
				return nil
			}
		}
	}

	return []LintIssue{impossible(id,
		fmt.Sprintf("no capability in %v belongs to any domain in %v", c.Capabilities, c.Domains),
		"the two conditions are ANDed, and the catalog places every listed capability elsewhere")}
}

// lintPatterns checks a pattern list with the validator's own admission
// functions, so a rule and the envelope it complements agree about what a
// pattern means.
//
// The severity split follows from OR-within-a-list. One bad pattern among good
// ones is dead weight -- the rule still fires on the others -- while a list whose
// patterns are all unusable is a condition that can never hold.
func lintPatterns(id, field string, patterns []string, validate func(string) error) []LintIssue {
	if len(patterns) == 0 {
		return nil
	}

	var (
		issues []LintIssue
		bad    int
	)
	for i, p := range patterns {
		err := validate(p)
		if err == nil {
			continue
		}
		bad++
		issues = append(issues, LintIssue{
			Severity: capability.SeverityMedium,
			RuleID:   id,
			Message:  fmt.Sprintf("%s[%d] is unusable and matches nothing: %v", field, i, err),
		})
	}

	if bad == len(patterns) {
		// Every alternative is dead, so the dimension can never be satisfied.
		// Reported in addition to the per-pattern findings, because the
		// consequence is different in kind: the rule is gone, not just weaker.
		issues = append(issues, impossible(id,
			fmt.Sprintf("every pattern in %s is unusable", field),
			"the condition can never hold, so the rule can never match"))
	}
	return issues
}

// --- rule set checks --------------------------------------------------------

// lintReachability reports a rule that an earlier rule always beats it to.
//
// Soundness over completeness. Subsumption is decided field by field, with list
// dimensions compared as exact sets: a rule guarding "/ws/**" is not recognized
// as covering one guarding "/ws/src/**", because deciding glob containment is a
// different problem and a wrong answer here is a false accusation. Everything
// this does report is a rule that provably cannot fire.
func lintReachability(ordered []Rule, i int) []LintIssue {
	r := &ordered[i]
	if !r.Enabled {
		return nil
	}

	for j := 0; j < i; j++ {
		earlier := &ordered[j]
		if !earlier.Enabled || !subsumes(earlier, r) {
			continue
		}

		// Same action is redundancy; a different action is a surprise, because
		// the operator wrote an outcome that never happens.
		severity := capability.SeverityLow
		detail := "it can never fire, and its ID will never appear in an audit record"
		if earlier.Action != r.Action {
			severity = capability.SeverityHigh
			detail = fmt.Sprintf("it can never fire: every event it describes is already %s by the earlier rule, never %s",
				earlier.Action, r.Action)
		}

		return []LintIssue{{
			Severity: severity,
			RuleID:   r.ID,
			Message: fmt.Sprintf("unreachable: rule %q (priority %d) matches everything this rule does; %s",
				earlier.ID, earlier.Priority, detail),
		}}
	}
	return nil
}

// subsumes reports whether every request matching b also matches a -- that is,
// whether a always wins first.
//
// Each dimension follows directly from matches(): an unconstrained dimension in
// a covers anything b does, and a constrained one requires b to be constrained
// at least as tightly. The risk dimensions are the subtle case: a having no
// risk condition subsumes b having one, because b additionally requires a
// scored assessment, which is strictly narrower.
func subsumes(a, b *Rule) bool {
	if !modesSubsume(a.Modes, b.Modes) {
		return false
	}

	ac, bc := a.Match, b.Match
	return subsumeStrings(verdictStrings(ac.Verdicts), verdictStrings(bc.Verdicts)) &&
		subsumeStrings(kindStrings(ac.Capabilities), kindStrings(bc.Capabilities)) &&
		subsumeStrings(domainStrings(ac.Domains), domainStrings(bc.Domains)) &&
		subsumeStrings(violationStrings(ac.ViolationTypes), violationStrings(bc.ViolationTypes)) &&
		subsumeStrings(levelStrings(ac.RiskLevels), levelStrings(bc.RiskLevels)) &&
		subsumeStrings(ac.TaskTypes, bc.TaskTypes) &&
		subsumeStrings(ac.PathPatterns, bc.PathPatterns) &&
		subsumeStrings(ac.Hosts, bc.Hosts) &&
		subsumeMin(ac.MinRiskScore, bc.MinRiskScore) &&
		subsumeMax(ac.MaxRiskScore, bc.MaxRiskScore) &&
		subsumeMin(ac.MinConfidence, bc.MinConfidence)
}

// subsumeStrings reports whether constraint a is no narrower than constraint b.
// An empty a constrains nothing and covers everything; a non-empty a needs b to
// be a non-empty subset.
func subsumeStrings(a, b []string) bool {
	if len(a) == 0 {
		return true
	}
	if len(b) == 0 {
		return false
	}
	for _, v := range b {
		if !containsString(a, v) {
			return false
		}
	}
	return true
}

// modesSubsume reports whether a is eligible in every mode b is. Empty means
// every mode, so an unrestricted rule subsumes a restricted one.
func modesSubsume(a, b []Mode) bool {
	if len(a) == 0 {
		return true
	}
	if len(b) == 0 {
		return false
	}
	for _, m := range b {
		found := false
		for _, n := range a {
			if n == m {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// subsumeMin reports whether a floor of a is no higher than a floor of b.
func subsumeMin(a, b *float64) bool {
	if a == nil {
		return true
	}
	return b != nil && *b >= *a
}

// subsumeMax reports whether a ceiling of a is no lower than a ceiling of b.
func subsumeMax(a, b *float64) bool {
	if a == nil {
		return true
	}
	return b != nil && *b <= *a
}

// lintDefaultAction reports the one provable finding about a rule set's
// posture: that it can never be reached.
//
// An enabled rule with an empty condition and no mode restriction matches every
// event, so nothing below it runs and the default action -- the most
// consequential line in the file -- is dead. Nothing else about default_action
// is claimed; see the package comment for why "the default is stronger than
// every rule" is not a defect.
func lintDefaultAction(rs *RuleSet, ordered []Rule) []LintIssue {
	for i := range ordered {
		r := &ordered[i]
		if !r.Enabled || len(r.Modes) > 0 || !matchesEverything(r.Match) {
			continue
		}
		return []LintIssue{{
			Severity: capability.SeverityMedium,
			RuleID:   r.ID,
			Message: fmt.Sprintf("this rule has no conditions and matches every event, so default_action %q can never apply",
				rs.DefaultAction),
		}}
	}
	return nil
}

// matchesEverything reports a condition that constrains nothing. It mirrors
// matches(), which checks each field only when it is populated.
func matchesEverything(c Condition) bool {
	return len(c.Verdicts) == 0 && len(c.Capabilities) == 0 && len(c.Domains) == 0 &&
		len(c.ViolationTypes) == 0 && len(c.RiskLevels) == 0 && len(c.TaskTypes) == 0 &&
		len(c.PathPatterns) == 0 && len(c.Hosts) == 0 &&
		c.MinRiskScore == nil && c.MaxRiskScore == nil && c.MinConfidence == nil
}

// RiskConditioned reports whether a rule's outcome depends on a risk
// assessment.
//
// Not a lint finding -- a risk-conditioned rule is correct policy -- but callers
// running the engine without a risk stage need to say why such rules never
// fire, rather than leaving an operator to wonder. See the dry-run command.
func RiskConditioned(r Rule) bool {
	c := r.Match
	return c.MinRiskScore != nil || c.MaxRiskScore != nil || c.MinConfidence != nil || len(c.RiskLevels) > 0
}

// --- helpers ----------------------------------------------------------------

func impossible(id, what, why string) LintIssue {
	return LintIssue{
		Severity: capability.SeverityCritical,
		RuleID:   id,
		Message:  what + "; " + why,
	}
}

func knownDomain(d capability.Domain) bool {
	for _, known := range capability.AllDomains() {
		if known == d {
			return true
		}
	}
	return false
}

func join[T ~string](values []T) string {
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = string(v)
	}
	return strings.Join(parts, ", ")
}

func verdictStrings(v []decision.Verdict) []string { return asStrings(v) }
func kindStrings(v []capability.Kind) []string     { return asStrings(v) }
func domainStrings(v []capability.Domain) []string { return asStrings(v) }
func levelStrings(v []decision.Level) []string     { return asStrings(v) }
func violationStrings(v []validator.ViolationType) []string {
	return asStrings(v)
}

func asStrings[T ~string](values []T) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = string(v)
	}
	return out
}
