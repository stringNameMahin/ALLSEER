// Package validator compares observed kernel behavior against the Expected
// Capability Envelope.
//
// This is the analytical core, and the simplest module in the system. It
// answers one question, whether an observation is covered by the envelope, and
// answers it deterministically: no I/O, no model calls, no configuration beyond
// the envelope itself.
//
// That simplicity is a design goal. Validation runs on every event on the hot
// path, its correctness is the system's correctness, and it must be
// exhaustively testable as a pure function. Anything requiring judgment or
// tuning belongs downstream in the risk engine; anything requiring lookups
// belongs upstream in enrichment.
package validator

import (
	"context"

	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// Validator checks observations against an envelope.
//
// Implementations must be safe for concurrent use and must not mutate the
// envelope. Given the same envelope, session state, and event, Validate always
// returns the same result; reproducibility is what makes an audit defensible.
type Validator interface {
	// Validate classifies a single event against the envelope.
	Validate(ctx context.Context, req ValidateRequest) (*Result, error)

	// ValidateSession checks session-wide constraints no single event can
	// violate on its own, such as cumulative write counts or egress volume.
	ValidateSession(ctx context.Context, env *ece.Envelope, st SessionState) ([]Violation, error)
}

// ValidateRequest is the input to single-event validation.
type ValidateRequest struct {
	// Envelope is the sealed envelope governing this session.
	Envelope *ece.Envelope

	// Event is the enriched event to classify.
	Event *event.Event

	// State is needed for constraint checks and for grants carrying a MaxCount.
	State SessionState
}

// Result is the outcome of validating one event.
type Result struct {
	Verdict decision.Verdict

	MatchedGrant  *capability.Grant
	MatchedDenial *capability.Grant

	// Violations details every way the observation departed from the envelope.
	// A single event may violate more than once: an ungranted capability
	// against a sensitive path that also exceeds a budget.
	Violations []Violation

	// Reasoning explains how the verdict was reached, and is carried into the
	// final Decision so the explanation survives to the audit log.
	Reasoning []decision.ReasoningStep
}

// Violation is one specific departure from the envelope.
type Violation struct {
	Type       ViolationType
	Capability capability.Kind

	// Expected describes what the envelope allowed; Observed, what happened.
	Expected string
	Observed string

	Detail string

	// Severity is the inherent seriousness of this violation type, before the
	// risk engine applies context.
	Severity capability.Severity
}

// ViolationType classifies departures from the envelope.
type ViolationType string

const (
	// ViolationUngrantedCapability: the capability appears in no grant.
	ViolationUngrantedCapability ViolationType = "ungranted_capability"

	// ViolationSelectorMismatch: granted, but the target fell outside the
	// grant's selector.
	ViolationSelectorMismatch ViolationType = "selector_mismatch"

	// ViolationExplicitDenial: an explicit denial matched.
	ViolationExplicitDenial ViolationType = "explicit_denial"

	// ViolationCountExceeded: a grant's MaxCount was exhausted.
	ViolationCountExceeded ViolationType = "count_exceeded"

	// ViolationConstraintExceeded: a session-wide constraint was breached.
	ViolationConstraintExceeded ViolationType = "constraint_exceeded"

	// ViolationEnvelopeExpired: the envelope's ExpiresAt has passed.
	ViolationEnvelopeExpired ViolationType = "envelope_expired"

	// ViolationWorkspaceEscape: a filesystem operation left WorkspaceRoot.
	// Called out separately from a plain selector mismatch because leaving the
	// workspace is categorically different from touching the wrong file in it.
	ViolationWorkspaceEscape ViolationType = "workspace_escape"

	// ViolationUnresolvable: enrichment failed, so coverage could not be
	// determined. Never treat this as allowed.
	ViolationUnresolvable ViolationType = "unresolvable"
)

// SessionState is the accumulated observation history for a session.
//
// Held behind an interface so the validator stays a pure function of its
// inputs: it reads counters but never advances them. The session manager owns
// mutation, which keeps the concurrency story simple.
type SessionState interface {
	// GrantUseCount reports how many times a grant has been exercised,
	// supporting MaxCount enforcement.
	GrantUseCount(grantIndex int) int

	FileWriteCount() int
	NetworkBytesSent() int64
	ProcessCount() int
	ElapsedSeconds() float64

	// SeenTargets reports whether a target was previously observed. Novelty is
	// a meaningful risk signal: the tenth write to a file the task has been
	// editing all along is unremarkable, the first write to a new one is not.
	SeenTargets(kind capability.Kind, target string) bool
}

// Matcher decides whether an observation falls within a grant.
//
// Its own interface because selector matching is where the subtle security bugs
// live: glob semantics, path normalization, CIDR containment, case sensitivity.
// Isolating it makes those rules exhaustively testable against adversarial
// inputs.
type Matcher interface {
	// Matches reports whether the observation is covered by the grant, and
	// explains why when it is not.
	Matches(g capability.Grant, obs capability.Observation) (bool, string)
}

// PathMatcher handles filesystem selector matching.
//
// Split out because path matching carries the sharpest security requirement in
// the system. Implementations must match against fully resolved absolute paths.
// Matching a pattern against an unresolved path lets a symlink inside a granted
// directory point anywhere on the filesystem, converting a narrow grant into an
// unbounded one.
type PathMatcher interface {
	// Match reports whether path satisfies pattern. Both must be absolute and
	// resolved.
	Match(pattern, path string) bool

	// WithinRoot reports whether path is contained by root, after resolution.
	WithinRoot(root, path string) bool
}

// NetworkMatcher handles network selector matching.
//
// Also split out, because the hostname-to-IP relationship is genuinely hard: an
// envelope grants "api.github.com" while the kernel observes a connection to an
// IP. Implementations must be explicit about correlation failure. The safe
// answer is no match, escalating to the risk engine, never a hopeful assumption
// of equivalence.
type NetworkMatcher interface {
	// MatchHost reports whether host or IP satisfies the pattern, which may be
	// a hostname, a wildcard domain, a CIDR block, or a literal IP.
	MatchHost(pattern, hostOrIP string) bool

	// MatchPort reports whether port is in the allowed list. Empty means any.
	MatchPort(allowed []int, port int) bool
}

// Done: glob semantics are specified in docs/path-matching.md and implemented
// by GlobPathMatcher in path.go. ** spans whole segments only, patterns match
// dotfiles, matching is byte-exact, and unresolved input never matches.
// Done: the adversarial path corpus lives in test/testdata/paths/, with the
// cases whose bytes cannot be reviewed as text (unicode normalization,
// symlinks) in path_test.go.
// Done: network semantics are specified in docs/network-matching.md and
// implemented by NetworkPatternMatcher in network.go, with its corpus in
// test/testdata/network/. Names and addresses are never assumed equivalent;
// CorrelationMissing distinguishes an uncorrelated destination from a genuine
// mismatch so the risk engine sees the difference.
//
// Done: grant precedence is specified in docs/grant-precedence.md and
// implemented by ResolvePrecedence in precedence.go. Denials always override
// grants; within a class the most specific entry wins, measured from a grant's
// broadest selector; ties break toward the earlier envelope index.
//
// TODO(validator): implement the default validator as a pure function, with a
// table-driven suite covering every ViolationType. It owns envelope expiry,
// MaxCount enforcement against SessionState.GrantUseCount, and mapping a
// MatchResult carrying Unevaluable to ViolationUnresolvable and
// VerdictIndeterminate rather than to a selector mismatch.
// TODO(validator): decide how a two-path operation is validated. A rename or
// link names a source and a destination, Observation has one Target, and
// selector matching evaluates only that, so a rename *into* a protected path is
// matched on its source. internal/telemetry/resolve preserves the destination
// in AttrNewPath; nothing matches against it. See docs/selector-matching.md
// §4.1.
// TODO(validator): treat an invalid pattern in a denial as an envelope error
// rather than a warning. An invalid grant pattern grants nothing, which is
// safe; an invalid denial pattern denies nothing, which is the one place the
// fail-closed posture inverts. See docs/grant-precedence.md §5.
// Done: events reach the matcher through event.go. ObservationOf prefers a
// recorded Event.Observation and falls back to internal/telemetry/resolve;
// MatchEvent reports an unresolvable event as unevaluable rather than handing
// the matcher a blank observation, which a Kind-only grant would satisfy.
// Done: the composing Matcher is specified in docs/selector-matching.md and
// implemented by SelectorMatcher in matcher.go. Dimensions combine with AND,
// lists with OR, and an unconstrained dimension covers everything. Its
// MatchResult carries an Unevaluable flag so a caller never has to tell a
// mismatch from a blind spot by reading the reason string.
// TODO(validator): lint selector patterns at envelope admission with
// ValidatePattern and ValidateHostPattern, and warn on the case and unicode
// ambiguities documented in docs/path-matching.md §5. An invalid denial denies
// nothing.
// TODO(validator): benchmark against a realistic build. A linear scan over
// grants per event may not hold up on the hot path; BenchmarkMatchPath and
// BenchmarkMatchHost cover only the single-pattern cost.
