// Package risk scores observations to separate behavior that is merely
// unexpected from behavior that is dangerous.
//
// The validator answers a binary question: was this in the envelope? That alone
// is too blunt to act on. A build tool writing to a cache directory outside the
// declared workspace is unexpected and harmless; a process reading SSH keys and
// opening a socket to an unfamiliar host is unexpected and serious. Both are
// "outside envelope", and treating them identically produces either a system
// that blocks constantly or one that never blocks at all.
//
// Three boundaries hold this module in place:
//
//   - The validator stays pure and binary; risk holds the tunable heuristics.
//   - Risk scores but never decides. Mapping a score to an action is policy,
//     which is separately configurable and separately auditable.
//   - Every score decomposes into named, weighted factors. An opaque score
//     cannot be debugged, tuned, or defended to a user.
package risk

import (
	"context"

	"github.com/stringNameMahin/ALLSEER/internal/validator"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// Engine scores observations.
//
// Implementations must be deterministic and free of I/O on the hot path.
// Anything a scorer needs, whether sensitive path lists, threat feeds, or
// historical baselines, must be loaded ahead of time; a network call here
// stalls every governed syscall behind it.
type Engine interface {
	// Score assesses a single validated event.
	Score(ctx context.Context, req ScoreRequest) (*decision.RiskAssessment, error)

	// ScoreSession assesses the session as a whole. Some risks are only visible
	// in aggregate: no single file read is alarming, but reading every file in
	// a credentials directory is.
	ScoreSession(ctx context.Context, req SessionScoreRequest) (*decision.RiskAssessment, error)
}

// ScoreRequest is the input to single-event scoring.
type ScoreRequest struct {
	Event      *event.Event
	Validation *validator.Result
	Envelope   *ece.Envelope

	// History provides context for temporal and behavioral factors.
	History History
}

// SessionScoreRequest is the input to session-level scoring.
type SessionScoreRequest struct {
	Envelope *ece.Envelope
	History  History

	// Violations are the accumulated validation failures for the session.
	Violations []validator.Violation
}

// Scorer computes one risk factor.
//
// The engine composes many. Each is independently testable and independently
// enabled, so a noisy heuristic can be switched off without touching the
// others. Tuning is the hardest part of making a system like this usable rather
// than merely correct.
type Scorer interface {
	// Name identifies the factor for configuration and explanation.
	Name() string

	// Evaluate returns this scorer's contribution, or nil if it does not apply.
	Evaluate(ctx context.Context, req ScoreRequest) (*decision.Factor, error)

	// Weight is the scorer's relative influence before normalization.
	Weight() float64
}

// History provides behavioral context for scoring.
//
// Read-only by design: scorers observe the past but never write to it, so
// scoring cannot introduce order-dependent state bugs into the pipeline.
type History interface {
	// CapabilityCount reports how often a capability was exercised this session.
	CapabilityCount(k capability.Kind) int

	// TargetSeen reports whether this specific target was touched before.
	TargetSeen(k capability.Kind, target string) bool

	// ViolationCount reports total violations so far. An escalating violation
	// rate is itself a signal: an agent producing its twentieth violation is in
	// a different state from one producing its first.
	ViolationCount() int

	// RecentEvents returns the last n events for sequence detection. Some
	// patterns are only visible as sequences: read credentials, connect
	// outbound, write nothing locally.
	RecentEvents(n int) []event.Event

	// SessionDurationSeconds reports elapsed session time.
	SessionDurationSeconds() float64
}

// SensitivityOracle classifies resources by inherent sensitivity.
//
// Separate from the scorers because what counts as sensitive is deployment
// specific. /etc/shadow always is, and so is a company's internal artifact
// registry, and that should be configurable without touching scoring logic.
type SensitivityOracle interface {
	// PathSensitivity rates a filesystem path.
	PathSensitivity(path string) capability.Severity

	// HostSensitivity rates a network destination.
	HostSensitivity(hostOrIP string) capability.Severity

	// ExecutableSensitivity rates a binary. Some tools are high-consequence in
	// an agent context whatever their arguments: curl, ssh, and a shell all
	// mean something different from a compiler.
	ExecutableSensitivity(path string) capability.Severity
}

// Aggregator combines individual factors into a final score.
//
// Isolated because the combination rule is a real design decision with no
// obvious right answer. A weighted sum is easy to explain but lets many small
// factors overwhelm one critical finding; a max rule respects criticality but
// ignores accumulation. The choice has to stay swappable and measurable.
type Aggregator interface {
	// Aggregate produces the final score in [0,100] and a confidence in [0,1].
	Aggregate(factors []decision.Factor) (score float64, confidence float64)
}

// Baseline models normal behavior for a task type, so risk can be assessed
// relative to what similar tasks usually do rather than against fixed rules
// alone.
//
// This is the research-forward part of the module and it is optional: the
// system must work without it, on static heuristics. Baselines need accumulated
// data a new deployment does not have.
type Baseline interface {
	// Deviation reports how far an observation departs from the baseline for a
	// task type, normalized to [0,1].
	Deviation(taskType string, obs capability.Observation) float64

	// Known reports whether a baseline exists for this task type. When false,
	// callers must fall back to static scoring rather than reading an absent
	// baseline as "no deviation".
	Known(taskType string) bool
}

// Done: BaselineEngine in score.go implements Engine as a deterministic,
// explainable baseline. Nine factors — verdict, violation_severity,
// sensitive_path, sensitive_host, uncorrelated_destination,
// credential_access_egress, workspace_escape, novel_target, violation_history —
// are summed as integer points and clamped to [0,100]; three of them are
// present only when an oracle was supplied, and the two resource factors only
// when the list actually grades that kind of resource.
// uncorrelated_destination is in every engine, its evidence being telemetry
// rather than configuration. It is still not the engine §3.6 describes: there is no learned
// baseline, no executable rating, and one sequence shape rather than a
// behavioral model, and score.go says so at the top.
// Done: four of the seven planned scorers exist, plus one the plan did not
// name. workspace_escape is WorkspaceEscapeScorer, violation_rate is
// ViolationHistoryScorer — renamed because what it actually reads is a count
// rather than a rate, and a rate would need a window there is no measurement to
// choose — sensitive_path is SensitivePathScorer, and exfiltration_pattern is
// CredentialEgressScorer in sequence.go, narrowed to the one shape it can
// prove: a successful read of a high-or-critical resource followed within a
// bounded window by egress. The narrowing is in the name; "exfiltration" would
// be a conclusion the evidence does not support.
// Done: sensitive_host in host.go is the one the plan folded into
// sensitive_path and that turned out to need its own factor. Host patterns are
// not glob-shaped, so it reads its own section of the list through
// validator.MatchHost rather than through the path matcher — different
// configuration, different vocabulary, different matcher, and therefore a
// factor of its own rather than a dimension of another one.
// Closed: novel_network_destination will not be built. docs/milestones.md
// specifies it as "using risk.History.TargetSeen", and NovelTargetScorer
// implements exactly that, is domain-agnostic, and already fires on network
// events — registry.npmjs.org alone produces three separate novelty findings in
// the npm recording, one per capability that touched it. It was closed as a
// duplicate and UncorrelatedDestinationScorer in correlation.go was built
// instead: the distinct network signal that analysis actually turned up, which
// reads no history at all.
// TODO(risk): the last planned scorer is privilege_change, which wants
// ExecutableSensitivity. A standalone credential_access scorer is deliberately
// not planned any more: the sequence detector charges the relationship,
// sensitive_path charges the resource, and a third factor between them would
// charge the same read twice.
// Done: the aggregation rule is BoundedSumAggregator, a plain clamped sum. The
// weighted sum with a critical-factor floor was considered and deferred rather
// than adopted: with seven factors and a heaviest contribution of 55, no
// accumulation of small factors can bury a large one, so the floor would be a
// mechanism with no failure to prevent. It becomes worth adding when the scorer
// set is large enough for dilution to be possible; the sequence detector's 30
// points, sensitive_host's 25, and uncorrelated_destination's 5 moved the
// oracle-backed ceiling from 135 to 195, and the clamp rather than a rescale is
// what keeps an operator's existing threshold meaning what it meant.
// TODO(risk): the point values are calibrated against the shipped rule set's
// own stated bands, not measured. They are a documented starting point; the
// labeled corpus below is what turns them into a tuned result.
// Done: a destination known only by address now scores above one reached by a
// correlated name. UncorrelatedDestinationScorer in correlation.go charges the
// gap capability.AttrHostnameCorrelated has recorded since enrichment was
// written, and which sensitive_host reports without charging — deliberately,
// because charging it there would have put two unrelated findings under one
// factor name. It reads no history, no list, and no envelope, and it costs a
// non-network event nothing measurable.
// TODO(risk): assemble a labeled evaluation set of benign and malicious
// sessions. Tuning without measurement produces a system that is either ignored
// or distrusted.
// Done: the credential-access-then-egress sequence detector is
// CredentialEgressScorer in sequence.go. It is the first factor that reads more
// than the event under judgment, and the ordering it depends on is the
// pipeline's: history is read before the event is committed, so an egress event
// cannot be its own antecedent. Its window is an event count it owns rather
// than the ring depth it happens to coincide with, and the distance between the
// two halves is recorded on every finding so the window can eventually be
// measured rather than argued about.
// Done: host sensitivity is ResourceOracle's HostSensitivity plus
// SensitiveHostScorer in host.go, over a hosts section of the same list file.
// The vocabulary is validator.ValidateHostPattern and MatchHost rather than a
// second one, so an entry means exactly what an identically written network
// grant means, and the name/address boundary of docs/network-matching.md §1
// holds inside sensitivity too: a destination is rated by the identity the
// observation carries, and a list meaning to cover both spellings writes both.
// TODO(risk): the detector proves a temporal relationship and claims nothing
// stronger. It cannot connect the bytes read to the bytes sent — payload
// inspection is out of scope — so "sensitive resource access followed by
// egress" is the whole finding, and neither the factor name nor the record may
// grow into "exfiltration" without evidence that does not exist here.
// TODO(risk): decide whether Baseline learning ships in v1 at all. It is
// valuable for the research contribution but adds a poisoning surface: an
// attacker who can shape the baseline can normalize their own behavior.
