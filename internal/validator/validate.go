package validator

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
)

// Validate is the system's core question, and the order it asks things in is
// the whole design:
//
//  1. Is the envelope still in force? An expired envelope authorizes nothing.
//  2. Can the event be resolved to an observation at all?
//  3. Did a denial match? Denials override grants unconditionally.
//  4. Could a denial not be evaluated? A prohibition that might apply is not a
//     prohibition that does not.
//  5. Did a grant match, and does it have budget left?
//  6. Could a grant not be evaluated?
//  7. Otherwise: was the capability granted at all, or only mis-targeted?
//
// Steps 4 and 6 are the ones that distinguish this from an obvious
// implementation. Everything the matcher could not evaluate stops at
// indeterminate, and indeterminate is never treated as allowed. A validator
// that skipped them would answer "outside envelope" for a truncated path and
// "within envelope" for a connection whose denial could not be checked, and
// both answers would be fabrications.

// ErrNoEnvelope and friends report inputs that make validation meaningless.
// They are errors rather than verdicts because a caller that cannot supply an
// envelope has a wiring bug, not a governance finding.
var (
	ErrNoEnvelope = errors.New("validate: envelope is required")
	ErrNoEvent    = errors.New("validate: event is required")
	ErrNoState    = errors.New("validate: session state is required")
)

// DefaultValidator is the pure-function implementation of Validator.
//
// It composes the pieces that already exist -- the event bridge, the selector
// matcher, and grant precedence -- and adds only the ordering above. Safe for
// concurrent use; holds no per-session state, which is what keeps it a function
// of its inputs.
type DefaultValidator struct {
	matcher *SelectorMatcher

	// now supplies the fallback clock for envelope expiry, used only when the
	// event carries no wall clock of its own. Injectable so expiry is testable
	// without sleeping.
	now func() time.Time
}

var _ Validator = (*DefaultValidator)(nil)

// NewValidator returns a validator over the default matchers.
func NewValidator() *DefaultValidator {
	return &DefaultValidator{matcher: NewMatcher(), now: time.Now}
}

// NewValidatorWith returns a validator over a specific matcher, for a daemon
// that resolves symlinked workspace roots, and a specific clock, for tests.
// A nil clock uses time.Now.
func NewValidatorWith(m *SelectorMatcher, now func() time.Time) *DefaultValidator {
	if m == nil {
		m = NewMatcher()
	}
	if now == nil {
		now = time.Now
	}
	return &DefaultValidator{matcher: m, now: now}
}

// Validate classifies a single event against the envelope.
//
// The returned Result is never nil when the error is nil, and its Verdict is
// always set. Callers must not treat an error as "allowed": an error means no
// verdict was reached.
func (v *DefaultValidator) Validate(_ context.Context, req ValidateRequest) (*Result, error) {
	if req.Envelope == nil {
		return nil, ErrNoEnvelope
	}
	if req.Event == nil {
		return nil, ErrNoEvent
	}

	res := &Result{}

	// --- 1. Is the envelope still in force? ---------------------------------
	if expired, at := v.expired(req.Envelope, req.Event.WallClock); expired {
		// An expired envelope authorizes nothing, so evaluation stops here
		// rather than continuing to report a grant as having covered something
		// it no longer covers.
		res.Verdict = decision.VerdictOutsideEnvelope
		res.Violations = append(res.Violations, Violation{
			Type:       ViolationEnvelopeExpired,
			Capability: req.Event.Capability,
			Expected:   fmt.Sprintf("envelope valid until %s", req.Envelope.ExpiresAt.UTC().Format(time.RFC3339)),
			Observed:   fmt.Sprintf("event at %s", at.UTC().Format(time.RFC3339)),
			Detail:     "an expired envelope authorizes nothing; every operation under it is outside the envelope",
			Severity:   severityFor(ViolationEnvelopeExpired, req.Event.Capability),
		})
		res.Reasoning = append(res.Reasoning, step("envelope expired",
			"expired at %s, event at %s", req.Envelope.ExpiresAt.UTC().Format(time.RFC3339), at.UTC().Format(time.RFC3339)))
		return res, nil
	}

	// --- 2. Can the event be resolved at all? -------------------------------
	obs, err := ObservationOf(req.Event)
	if err != nil {
		return indeterminate(res, Violation{
			Type:       ViolationUnresolvable,
			Capability: req.Event.Capability,
			Expected:   "an event resolvable to an observation",
			Observed:   err.Error(),
			Detail:     "the event could not be interpreted, so no statement about coverage is possible",
			Severity:   severityFor(ViolationUnresolvable, req.Event.Capability),
		}, "event could not be resolved to an observation", err.Error()), nil
	}
	res.Reasoning = append(res.Reasoning, step("resolved observation",
		"%s on %q", obs.Kind, obs.Target))

	// --- 3 & 4. Denials -----------------------------------------------------
	denials, denialUnevaluable := v.evaluate(req.Envelope.Denials, obs)

	if len(denials) > 0 {
		resolution := ResolvePrecedence(nil, denials)
		res.Verdict = decision.VerdictExplicitlyDenied
		res.MatchedDenial = resolution.Winner.Grant
		res.Violations = append(res.Violations, Violation{
			Type:       ViolationExplicitDenial,
			Capability: obs.Kind,
			Expected:   "no operation matching an envelope denial",
			Observed:   describeTarget(obs),
			Detail:     resolution.Reason,
			Severity:   severityFor(ViolationExplicitDenial, obs.Kind),
		})
		res.Reasoning = append(res.Reasoning, step("explicit denial matched", "%s", resolution.Reason))
		return res, nil
	}

	if denialUnevaluable != nil {
		// A denial whose applicability could not be determined cannot be
		// dismissed. Deciding "allowed" here would mean the cheapest way past a
		// denial is to make its target unresolvable.
		return indeterminate(res, Violation{
			Type:       ViolationUnresolvable,
			Capability: obs.Kind,
			Expected:   "a denial that can be evaluated against this observation",
			Observed:   describeTarget(obs),
			Detail:     unresolvableDetail(obs, denialUnevaluable.Reason),
			Severity:   severityFor(ViolationUnresolvable, obs.Kind),
		}, "a matching denial could not be evaluated", denialUnevaluable.Reason), nil
	}

	// --- 5 & 6. Grants ------------------------------------------------------
	grants, grantUnevaluable := v.evaluate(req.Envelope.Grants, obs)

	if len(grants) > 0 {
		resolution := ResolvePrecedence(grants, nil)
		winner := resolution.Winner
		res.MatchedGrant = winner.Grant
		res.MatchedGrantIndex = winner.Index
		res.Reasoning = append(res.Reasoning, step("grant matched", "%s", resolution.Reason))

		if exceeded, used, limit := budgetExhausted(winner, req.State); exceeded {
			res.Verdict = decision.VerdictGrantExceeded
			res.Violations = append(res.Violations, Violation{
				Type:       ViolationCountExceeded,
				Capability: obs.Kind,
				Expected:   fmt.Sprintf("at most %d uses of grant %d", limit, winner.Index),
				Observed:   fmt.Sprintf("%d uses already recorded", used),
				Detail:     "the grant covers this operation but its budget is spent",
				Severity:   severityFor(ViolationCountExceeded, obs.Kind),
			})
			res.Reasoning = append(res.Reasoning, step("grant budget exhausted",
				"grant %d allows %d uses, %d already recorded", winner.Index, limit, used))
			return res, nil
		}

		// Granted individually, but the session as a whole may already have
		// spent the budget this event draws on. Checked after the grant's own
		// MaxCount because a grant-specific finding names the grant and is the
		// more actionable of the two.
		if viol, over := v.sessionConstraint(req.Envelope, obs, req.State); over {
			res.Verdict = decision.VerdictConstraintViolation
			res.Violations = append(res.Violations, viol)
			res.Reasoning = append(res.Reasoning, step("session constraint exceeded",
				"%s; %s", viol.Expected, viol.Observed))
			return res, nil
		}

		res.Verdict = decision.VerdictWithinEnvelope
		return res, nil
	}

	if grantUnevaluable != nil {
		return indeterminate(res, Violation{
			Type:       ViolationUnresolvable,
			Capability: obs.Kind,
			Expected:   "a grant that can be evaluated against this observation",
			Observed:   describeTarget(obs),
			Detail:     unresolvableDetail(obs, grantUnevaluable.Reason),
			Severity:   severityFor(ViolationUnresolvable, obs.Kind),
		}, "no grant could be evaluated against this observation", grantUnevaluable.Reason), nil
	}

	// --- 7. Nothing covered it ----------------------------------------------
	//
	// "The capability was never expected" and "the capability was expected, but
	// not here" are different stories about the agent, and collapsing them
	// would lose the more informative one.
	if grantsFor(req.Envelope.Grants, obs.Kind) > 0 {
		res.Verdict = decision.VerdictGrantExceeded
		res.Violations = append(res.Violations, Violation{
			Type:       ViolationSelectorMismatch,
			Capability: obs.Kind,
			Expected:   describeSelectors(req.Envelope.Grants, obs.Kind),
			Observed:   describeTarget(obs),
			Detail:     "the capability is granted, but no grant's selector covers this target",
			Severity:   severityFor(ViolationSelectorMismatch, obs.Kind),
		})
		res.Reasoning = append(res.Reasoning, step("selector mismatch",
			"%s is granted but not for %q", obs.Kind, obs.Target))
	} else {
		res.Verdict = decision.VerdictOutsideEnvelope
		res.Violations = append(res.Violations, Violation{
			Type:       ViolationUngrantedCapability,
			Capability: obs.Kind,
			Expected:   "no use of this capability",
			Observed:   describeTarget(obs),
			Detail:     "the envelope contains no grant for this capability",
			Severity:   severityFor(ViolationUngrantedCapability, obs.Kind),
		})
		res.Reasoning = append(res.Reasoning, step("ungranted capability",
			"the envelope grants no %s", obs.Kind))
	}

	// Leaving the workspace is reported separately from touching the wrong file
	// inside it. Both can be true of one operation, and a risk engine that only
	// saw "selector mismatch" could not tell an edit of the wrong source file
	// from a write to /etc.
	if esc, ok := v.workspaceEscape(req.Envelope, obs); ok {
		res.Violations = append(res.Violations, esc)
		res.Reasoning = append(res.Reasoning, step("workspace escape",
			"%q is outside %q", obs.Target, req.Envelope.Constraints.WorkspaceRoot))
	}

	return res, nil
}

// evaluate matches an observation against a list of envelope entries.
//
// It returns every entry that matched, in envelope order, and the first entry
// that could not be evaluated. Precedence chooses between the matches; the
// unevaluable one only matters when nothing matched, so the first is enough to
// explain why no conclusion is possible.
func (v *DefaultValidator) evaluate(entries []capability.Grant, obs capability.Observation) ([]Match, *MatchResult) {
	var (
		matches     []Match
		unevaluable *MatchResult
	)

	for i := range entries {
		// Kind is checked by the matcher too, but skipping early keeps an
		// envelope full of filesystem denials from reporting every network
		// event as unevaluable.
		if entries[i].Kind != obs.Kind {
			continue
		}

		r := v.matcher.Match(entries[i], obs)
		switch {
		case r.Matched:
			matches = append(matches, Match{Index: i, Grant: &entries[i]})
		case r.Unevaluable && unevaluable == nil:
			cp := r
			unevaluable = &cp
		}
	}
	return matches, unevaluable
}

// expired reports whether the envelope's validity has lapsed, and at what
// instant the judgment was made.
//
// The event's own wall clock is preferred over the host clock: a session
// replayed months later must reach the same verdict it reached live, and
// validating a recorded event against today's time would make every archived
// stream expire.
func (v *DefaultValidator) expired(env *ece.Envelope, eventTime time.Time) (bool, time.Time) {
	if env.ExpiresAt.IsZero() {
		return false, time.Time{}
	}
	at := eventTime
	if at.IsZero() {
		at = v.now()
	}
	return at.After(env.ExpiresAt), at
}

// workspaceEscape reports a filesystem operation that left the workspace root.
//
// Only for uncovered operations: a grant that deliberately reaches outside the
// workspace -- a module cache, a toolchain -- is authorized, and flagging it
// would make the signal useless in exactly the sessions where it matters.
func (v *DefaultValidator) workspaceEscape(env *ece.Envelope, obs capability.Observation) (Violation, bool) {
	root := env.Constraints.WorkspaceRoot
	if root == "" || obs.Domain != capability.DomainFilesystem {
		return Violation{}, false
	}
	if !IsResolved(obs.Target) {
		// Unresolved paths are already reported as unresolvable; guessing that
		// one escaped would be inventing evidence.
		return Violation{}, false
	}
	if v.matcher.paths.WithinRoot(root, obs.Target) {
		return Violation{}, false
	}

	return Violation{
		Type:       ViolationWorkspaceEscape,
		Capability: obs.Kind,
		Expected:   fmt.Sprintf("filesystem access within %q", root),
		Observed:   obs.Target,
		Detail:     "the operation left the workspace root, which is categorically different from touching the wrong file inside it",
		Severity:   severityFor(ViolationWorkspaceEscape, obs.Kind),
	}, true
}

// sessionConstraint reports whether the session has already spent the budget
// this observation draws on.
//
// It is the per-event face of ValidateSession, and it exists because the moment
// a budget runs out is an event, not a background condition: the write that
// takes a session past its limit is the one a human needs to see. Only the
// dimension the observation actually exercises is consulted, so an exhausted
// egress budget does not start flagging file reads.
//
// The counters belong to the session manager and are read, never advanced. A
// count-based limit is breached when the recorded count has already reached it,
// because this event would be the one past.
func (v *DefaultValidator) sessionConstraint(env *ece.Envelope, obs capability.Observation, st SessionState) (Violation, bool) {
	if st == nil {
		return Violation{}, false
	}
	c := env.Constraints

	// Duration applies to every observation: past the deadline, nothing the
	// session does is still within the time it was granted.
	if c.MaxDuration > 0 {
		if elapsed := time.Duration(st.ElapsedSeconds() * float64(time.Second)); elapsed > c.MaxDuration {
			return sessionViolation(obs.Kind, "session duration", c.MaxDuration.String(),
				elapsed.Round(time.Second).String()), true
		}
	}

	switch {
	case c.MaxProcesses > 0 && SpawnsProcess(obs.Kind) && st.ProcessCount() >= c.MaxProcesses:
		return sessionViolation(obs.Kind, "process count",
			fmt.Sprint(c.MaxProcesses), fmt.Sprint(st.ProcessCount())), true

	case c.MaxFileWrites > 0 && ModifiesFilesystem(obs.Kind) && st.FileWriteCount() >= c.MaxFileWrites:
		return sessionViolation(obs.Kind, "file writes",
			fmt.Sprint(c.MaxFileWrites), fmt.Sprint(st.FileWriteCount())), true

	case c.MaxNetworkBytes > 0 && obs.Domain == capability.DomainNetwork && st.NetworkBytesSent() >= c.MaxNetworkBytes:
		return sessionViolation(obs.Kind, "network bytes sent",
			fmt.Sprint(c.MaxNetworkBytes), fmt.Sprint(st.NetworkBytesSent())), true
	}

	return Violation{}, false
}

// ModifiesFilesystem reports whether a capability changes the filesystem, and
// so draws on the session's write budget.
//
func ModifiesFilesystem(k capability.Kind) bool {
	switch k {
	case capability.KindFileWrite, capability.KindFileCreate, capability.KindFileDelete,
		capability.KindFileRename, capability.KindFileTruncate, capability.KindFileLink:
		return true
	}
	return false
}

// SpawnsProcess reports whether a capability starts a new process, and so draws
// on the session's process budget.
//
// Exported for the same reason ModifiesFilesystem is: SessionState.ProcessCount
// has to be a count of exactly these events. Note that it counts processes
// *started*, not processes alive -- MaxProcesses is a budget on how much the
// session spawned, and reclaiming budget on exit would make the limit depend on
// when children happened to be reaped.
func SpawnsProcess(k capability.Kind) bool {
	return k == capability.KindProcessExec || k == capability.KindProcessFork
}

func sessionViolation(kind capability.Kind, what, expected, observed string) Violation {
	v := constraintViolation(what, expected, observed)
	v.Capability = kind
	v.Severity = severityFor(ViolationConstraintExceeded, kind)
	return v
}

// ValidateSession checks the constraints no single event can violate alone.
//
// It is a separate call because these are properties of the session's history
// rather than of any one observation: every individual write may be granted
// while the thousandth is still the moment something went wrong.
func (v *DefaultValidator) ValidateSession(_ context.Context, env *ece.Envelope, st SessionState) ([]Violation, error) {
	if env == nil {
		return nil, ErrNoEnvelope
	}
	if st == nil {
		return nil, ErrNoState
	}

	c := env.Constraints
	var violations []Violation

	// Zero means unlimited throughout: an unset budget is not a budget of zero,
	// the same rule empty selector lists follow.
	if c.MaxDuration > 0 {
		if elapsed := time.Duration(st.ElapsedSeconds() * float64(time.Second)); elapsed > c.MaxDuration {
			violations = append(violations, constraintViolation(
				"session duration", c.MaxDuration.String(), elapsed.Round(time.Second).String()))
		}
	}
	if c.MaxProcesses > 0 && st.ProcessCount() > c.MaxProcesses {
		violations = append(violations, constraintViolation(
			"process count", fmt.Sprint(c.MaxProcesses), fmt.Sprint(st.ProcessCount())))
	}
	if c.MaxFileWrites > 0 && st.FileWriteCount() > c.MaxFileWrites {
		violations = append(violations, constraintViolation(
			"file writes", fmt.Sprint(c.MaxFileWrites), fmt.Sprint(st.FileWriteCount())))
	}
	if c.MaxNetworkBytes > 0 && st.NetworkBytesSent() > c.MaxNetworkBytes {
		violations = append(violations, constraintViolation(
			"network bytes sent", fmt.Sprint(c.MaxNetworkBytes), fmt.Sprint(st.NetworkBytesSent())))
	}

	return violations, nil
}

func constraintViolation(what, expected, observed string) Violation {
	return Violation{
		Type:     ViolationConstraintExceeded,
		Expected: fmt.Sprintf("%s at most %s", what, expected),
		Observed: fmt.Sprintf("%s of %s", what, observed),
		Detail:   "individually granted operations exceeded a session-wide budget",
		Severity: severityFloor[ViolationConstraintExceeded],
	}
}

// budgetExhausted reports whether the winning grant has any MaxCount budget
// left. The validator reads the counter and never advances it; the session
// manager owns mutation, which is what keeps validation a pure function.
func budgetExhausted(winner *Match, st SessionState) (exhausted bool, used, limit int) {
	limit = winner.Grant.Selector.MaxCount
	if limit <= 0 {
		return false, 0, 0
	}
	if st == nil {
		// No history means nothing has been spent. A caller validating without
		// session state is asking a stateless question and gets a stateless
		// answer.
		return false, 0, limit
	}
	used = st.GrantUseCount(winner.Index)
	return used >= limit, used, limit
}

// grantsFor counts the envelope's grants for a capability, which is what
// separates "never expected" from "expected elsewhere".
func grantsFor(grants []capability.Grant, kind capability.Kind) int {
	n := 0
	for i := range grants {
		if grants[i].Kind == kind {
			n++
		}
	}
	return n
}

// describeSelectors summarizes what the envelope did expect for a capability,
// so the violation says more than "not this".
func describeSelectors(grants []capability.Grant, kind capability.Kind) string {
	var parts []string
	for i := range grants {
		if grants[i].Kind != kind {
			continue
		}
		sel := grants[i].Selector
		switch {
		case len(sel.PathPatterns) > 0:
			parts = append(parts, fmt.Sprint(sel.PathPatterns))
		case len(sel.Hosts) > 0:
			parts = append(parts, fmt.Sprint(sel.Hosts))
		case len(sel.Executables) > 0:
			parts = append(parts, fmt.Sprint(sel.Executables))
		default:
			parts = append(parts, "(unconstrained)")
		}
	}
	if len(parts) == 0 {
		return "no grant for this capability"
	}
	return fmt.Sprintf("%s within %v", kind, parts)
}

func describeTarget(obs capability.Observation) string {
	if obs.Target == "" {
		return fmt.Sprintf("%s with no resolved target", obs.Kind)
	}
	return obs.Target
}

// unresolvableDetail states why evaluation failed, distinguishing the two
// causes that look alike in a log and are not alike at all: a path enrichment
// could not resolve, and a destination whose name was never learned.
func unresolvableDetail(obs capability.Observation, reason string) string {
	if obs.Attributes[capability.AttrHostnameCorrelated] == "false" {
		return "DNS correlation failed, so the destination is known only by address: " + reason
	}
	return reason
}

// indeterminate finishes a result that could not reach a conclusion. It exists
// so every such exit sets the same verdict; a missed one would default to the
// zero Verdict, which is the empty string and reads as nothing at all.
func indeterminate(res *Result, v Violation, conclusion, detail string) *Result {
	res.Verdict = decision.VerdictIndeterminate
	res.Violations = append(res.Violations, v)
	res.Reasoning = append(res.Reasoning, step(conclusion, "%s", detail))
	return res
}

func step(conclusion, format string, args ...any) decision.ReasoningStep {
	return decision.ReasoningStep{
		Stage:      "validator",
		Conclusion: conclusion,
		Detail:     fmt.Sprintf(format, args...),
	}
}

// severityFloor is the inherent seriousness of each violation type, before any
// context. Context is the risk engine's job, and nothing here weighs, scores,
// or aggregates.
var severityFloor = map[ViolationType]capability.Severity{
	ViolationExplicitDenial:      capability.SeverityHigh,
	ViolationWorkspaceEscape:     capability.SeverityHigh,
	ViolationEnvelopeExpired:     capability.SeverityHigh,
	ViolationUnresolvable:        capability.SeverityMedium,
	ViolationUngrantedCapability: capability.SeverityMedium,
	ViolationSelectorMismatch:    capability.SeverityMedium,
	ViolationCountExceeded:       capability.SeverityMedium,
	ViolationConstraintExceeded:  capability.SeverityMedium,
}

var severityRank = map[capability.Severity]int{
	capability.SeverityInfo:     0,
	capability.SeverityLow:      1,
	capability.SeverityMedium:   2,
	capability.SeverityHigh:     3,
	capability.SeverityCritical: 4,
}

// severityFor combines the violation type's floor with the capability's own
// baseline, taking the higher of the two.
//
// Both are statements about inherent consequence: the type says how bad this
// kind of departure is, the catalog says how bad exercising this capability is
// at all. An ungranted kernel.bpfload and an ungranted fs.read are not the same
// event, and the catalog already records why.
func severityFor(vt ViolationType, kind capability.Kind) capability.Severity {
	floor := severityFloor[vt]
	if floor == "" {
		floor = capability.SeverityMedium
	}

	desc, ok := capability.Describe(kind)
	if !ok || severityRank[desc.BaselineSeverity] <= severityRank[floor] {
		return floor
	}
	return desc.BaselineSeverity
}
