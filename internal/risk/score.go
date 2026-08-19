package risk

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"

	"github.com/stringNameMahin/ALLSEER/internal/validator"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
)

// This file is the first real risk stage: a deterministic, explainable baseline
// scorer. It is deliberately not the engine the handbook's §3.6 describes.
// There is no baseline learning and no behavioral model here. What there is, is
// a scorer that turns evidence the pipeline already produces into a bounded
// score, so that the risk-conditioned rules in configs/rules.default.yaml stop
// being inert. Two of its factors are fed by configuration rather than by
// observation and live in their own files beside their own data: sensitive_path
// in sensitivity.go, and the credential-access-to-egress sequence detector in
// sequence.go.
//
// # The model, in one paragraph
//
// A score is a bounded sum of integer points contributed by independent
// factors, clamped to [0,100]. Most read the validator's answer about *this*
// event; the three that do not read the session history, which the pipeline
// guarantees is the history *before* this event is committed. Nothing is
// multiplied, averaged, or weighed against a learned distribution, because
// every one of those makes a score harder to explain and none of them is
// justified by evidence this build actually has.
//
//	factor                    points                                       source
//	------------------------  -------------------------------------------  ----------------------
//	verdict                   0 / 20 / 25 / 25 / 30 / 55 by classification  validator.Result
//	violation_severity        0 / 5 / 10 / 15 / 30 by highest severity      validator.Violation
//	sensitive_path            0 / 0 / 8 / 15 / 25 by the oracle's grade     SensitivityOracle
//	credential_access_egress  30 for a proven sequence into this egress     History.RecentEvents
//	workspace_escape          10 when the workspace boundary was crossed    validator.Violation
//	novel_target              5 when this target is new to the session      History.TargetSeen
//	violation_history         1 per prior violation, capped at 10           History.ViolationCount
//
// sensitive_path and credential_access_egress are present only when an engine
// was built with a SensitivityOracle; NewEngine has neither, and the absence is
// visible in the factor list rather than hidden in a zero. They are the two
// factors whose input is configuration rather than observation, which is why
// each lives beside its own data file and its own admission check — see
// sensitivity.go and sequence.go.
//
// # Three rules the model follows without exception
//
//  1. **Absence of evidence is never evidence of safety.** A factor that cannot
//     be evaluated contributes nothing to the score *and* removes a third of
//     the available confidence. It never contributes a reassuring zero.
//
//  2. **Only observed evidence is scored.** Every factor names the field it
//     read in its Evidence map. A reader can check each one against the event
//     and the validator result by hand.
//
//  3. **An expected event scores exactly zero.** A within-envelope verdict is a
//     positive finding by the validator, not an absence, so LevelNone means
//     "nothing departed" rather than "nothing was looked at". The two factors
//     that can still find something on a covered event — sensitive_path and
//     credential_access_egress — report the finding and withhold the points,
//     saying so with not_charged, rather than going silent about it.
//
// # Calibration
//
// The point values are not arbitrary, but neither are they measured: no labeled
// corpus exists yet (see the TODO at the foot of risk.go). They are calibrated
// against the one artifact that already states the intended bands — the shipped
// rule set — so that its own descriptions come true. Its workspace-escape-read
// rule calls such reads "common and usually benign" and guards itself with
// max_risk_score: 60; an ordinary workspace-escape read scores 55 under this
// model, so that rule now fires instead of falling through to the default
// posture. Its high-risk-departure rule wants a genuine escalation at 75, and a
// bare departure cannot reach that without either critical-severity consequence
// or an accumulation of prior violations.
//
// Treat the numbers as a documented starting point to be measured, not as a
// tuned result.

// Score bounds. The scale is closed at both ends because decision thresholds are
// operator-configurable and nobody can reason about an unbounded scale.
const (
	ScoreMin = 0.0
	ScoreMax = 100.0
)

// Level boundaries, minimum inclusive and maximum exclusive.
//
// The same convention internal/policy uses for risk bands, so adjacent levels
// partition the scale rather than overlapping on a threshold. Each boundary is
// read off the verdict table rather than picked for roundness, which is what
// makes the mapping explainable:
//
//   - LevelNone is the single point 0: no factor applied at all.
//   - 25 is the lightest departure the verdict factor alone can produce
//     (grant_exceeded, constraint_violation), so below it lies an indeterminate
//     result on its own, or a departure softened by nothing else.
//   - 55 is an explicit denial with nothing added: at or above it the event is
//     at least as serious as the envelope's author having forbidden it.
//   - 85 is an explicit denial carrying critical-severity consequence.
const (
	LevelBoundaryMedium   = 25.0
	LevelBoundaryHigh     = 55.0
	LevelBoundaryCritical = 85.0
)

// LevelFor buckets a score.
//
// Deterministic and total: every float in [0,100] maps to exactly one level, and
// a score outside the range is clamped first rather than falling off the end of
// the table. A NaN score is LevelCritical, because a score that is not a number
// is a fault in scoring, and a fault in the governance system must not present
// as the reassuring end of the scale.
func LevelFor(score float64) decision.Level {
	if math.IsNaN(score) {
		return decision.LevelCritical
	}
	switch s := clampScore(score); {
	case s <= ScoreMin:
		return decision.LevelNone
	case s < LevelBoundaryMedium:
		return decision.LevelLow
	case s < LevelBoundaryHigh:
		return decision.LevelMedium
	case s < LevelBoundaryCritical:
		return decision.LevelHigh
	default:
		return decision.LevelCritical
	}
}

func clampScore(s float64) float64 {
	if math.IsNaN(s) {
		return ScoreMax
	}
	return math.Max(ScoreMin, math.Min(ScoreMax, s))
}

// --- factor names ---------------------------------------------------------------

// Factor names are a wire contract: they appear in every audit record, and an
// operator tuning a policy reads them.
const (
	FactorVerdict           = "verdict"
	FactorViolationSeverity = "violation_severity"
	FactorWorkspaceEscape   = "workspace_escape"
	FactorSensitivePath     = "sensitive_path"
	FactorNovelTarget       = "novel_target"
	FactorViolationHistory  = "violation_history"

	// FactorEvidenceBasis carries no points. It states which of the model's
	// evidence inputs were actually available, and it is the only thing
	// confidence is computed from — so a reader can check a confidence value by
	// counting the trues in one map rather than by trusting a number.
	FactorEvidenceBasis = "evidence_basis"
)

// Evidence keys on the sensitive_path factor.
//
// EvidenceSensitivity is always present when the factor is, and carries the
// literal string "unknown" for a resource the oracle could not rate. That is
// the point of the factor existing even when it contributes nothing: an absent
// factor means nobody asked, and "unknown" means somebody asked and does not
// know. Neither means the resource is fine.
const (
	EvidenceSensitivity = "sensitivity"
	EvidenceDimension   = "dimension"
	EvidenceReason      = "reason"
	EvidenceTarget      = "target"

	// EvidenceNotCharged appears when the oracle rated the resource but the
	// points were withheld because the envelope covered the operation. The
	// grade is still reported: a grant over a credential path is worth seeing
	// in an audit even though it is the envelope author's decision rather than
	// a departure.
	EvidenceNotCharged = "not_charged"

	// SensitivityUnknownLabel is what EvidenceSensitivity carries for an
	// unrated resource. Spelled out rather than left as the empty string,
	// because an empty value in a record reads as a missing field.
	SensitivityUnknownLabel = "unknown"
)

// Sensitivity dimensions, naming which oracle method was consulted. Recorded so
// that "unknown" is attributable: an unrated host and an unrated path are the
// same word about different gaps.
const (
	DimensionPath       = "path"
	DimensionHost       = "host"
	DimensionExecutable = "executable"

	// DimensionUnrated is for a domain no oracle method covers — kernel, IPC,
	// privilege. There is no method to call, so nothing was asked, and saying
	// that is better than implying a lookup happened.
	DimensionUnrated = "unrated"
)

// Evidence keys on the evidence_basis factor. Each true is worth
// ConfidencePerBasis.
const (
	BasisVerdictConclusive = "verdict_conclusive"
	BasisTargetResolved    = "target_resolved"
	BasisHistoryAvailable  = "history_available"

	// BasisViolationsAvailable replaces BasisVerdictConclusive for session
	// scoring, which has no per-event classification behind it.
	BasisViolationsAvailable = "violations_available"
)

// Confidence is a count of available evidence inputs, not an estimate.
//
// ConfidenceCeiling is below 1.0 deliberately and permanently for this scorer.
// Full confidence would claim the model saw everything worth seeing, and this
// model has no learned baseline, no host or executable ratings, and exactly one
// sequence shape rather than a behavioral model. Reserving the top of the scale
// leaves room for an engine that has them.
//
// Adding the sequence detector did not move the ceiling, and deliberately does
// not touch confidence at all. Confidence counts *inputs available*, and the
// detector's input — the session history — is already one of the three the
// basis factor names. A scorer that raised confidence because it happened to
// find something would be reporting its own conclusion twice.
const (
	ConfidencePerBasis = 0.3
	ConfidenceCeiling  = 0.9
)

// confidenceByBasisCount is the count-to-confidence table, written out rather
// than multiplied.
//
// ConfidencePerBasis times three is 0.8999999999999999 in binary floating point,
// and confidence is compared against operator-written thresholds — a rule
// reading min_confidence: 0.9 would silently never match. Tabulating the four
// reachable values keeps every confidence a number an operator can type. A count
// above the table is clamped to the ceiling, which is where a custom basis
// factor with extra keys would land.
var confidenceByBasisCount = [...]float64{0, 0.3, 0.6, ConfidenceCeiling}

func confidenceFor(basisCount int) float64 {
	if basisCount < 0 {
		return 0
	}
	if basisCount >= len(confidenceByBasisCount) {
		return ConfidenceCeiling
	}
	return confidenceByBasisCount[basisCount]
}

// --- point tables ------------------------------------------------------------------

// verdictPoints is the weight of the classification itself.
//
// Ordered by what the verdict says about intent as much as about consequence. An
// explicit denial is heaviest because the envelope's author anticipated the
// operation and forbade it, so crossing it is a deliberate boundary rather than
// an unanticipated one. Indeterminate is the lightest non-zero entry because it
// is a statement about our own blind spot; it is not zero, because unresolved is
// not safe.
var verdictPoints = map[decision.Verdict]float64{
	decision.VerdictWithinEnvelope:      0,
	decision.VerdictIndeterminate:       20,
	decision.VerdictConstraintViolation: 25,
	decision.VerdictGrantExceeded:       25,
	decision.VerdictOutsideEnvelope:     30,
	decision.VerdictExplicitlyDenied:    55,
}

// severityPoints weights the most serious violation on the event.
//
// The severity is the validator's, not a second opinion: its severityFor already
// combines the violation type's floor with the capability catalog's baseline
// severity. Re-deriving it here would be a parallel model of how bad things are,
// and the two would drift.
var severityPoints = map[capability.Severity]float64{
	capability.SeverityInfo:     0,
	capability.SeverityLow:      5,
	capability.SeverityMedium:   10,
	capability.SeverityHigh:     15,
	capability.SeverityCritical: 30,
}

// sensitivityPoints weights the oracle's grade for the resource touched.
//
// A separate table from severityPoints, and deliberately not the same numbers.
// They answer different questions: severityPoints asks how bad this *kind of
// departure* is, and this asks how consequential the *resource* is. Sharing one
// table would have made a change to either silently move the other.
//
// info and low are both zero. A graded-but-unremarkable location contributes
// nothing to a score and everything to the record: it is what lets an audit
// distinguish "rated, and ordinary" from "never heard of it", which is the
// distinction sensitivity.go exists to keep. Nothing here is negative, and
// nothing can be configured to be — the list may only raise.
var sensitivityPoints = map[capability.Severity]float64{
	capability.SeverityInfo:     0,
	capability.SeverityLow:      0,
	capability.SeverityMedium:   8,
	capability.SeverityHigh:     15,
	capability.SeverityCritical: 25,
}

const (
	// WorkspaceEscapePoints is charged on top of the severity the escape already
	// carries. The overlap is deliberate: severity says how bad the worst
	// finding on this event is, and the escape factor says which specific
	// boundary was crossed. An operator reading the factor list should see the
	// escape named rather than have to infer it from a severity of "high".
	WorkspaceEscapePoints = 10.0

	// NovelTargetPoints is small on purpose. First contact with a target is weak
	// evidence — every session's first write to every file is novel — and it
	// earns its place by sharpening events that are already departures rather
	// than by carrying a verdict on its own.
	NovelTargetPoints = 5.0

	// ViolationHistoryCap bounds the session-history factor at one point per
	// prior violation. An escalating violation rate is real signal, but it is
	// the one factor that grows with time rather than with the event, and an
	// uncapped counter would eventually score every event critical purely for
	// arriving late in a noisy session.
	ViolationHistoryCap = 10.0
)

// --- engine -------------------------------------------------------------------------

// BaselineEngine is the deterministic baseline scorer.
//
// Safe for concurrent use: it holds no mutable state, performs no I/O and reads
// only what the request carries. Given the same request it returns the same
// assessment, field for field, which is what lets a recorded session be replayed
// to the decisions it produced live.
type BaselineEngine struct {
	scorers []Scorer
	agg     Aggregator
}

var _ Engine = (*BaselineEngine)(nil)

// Errors reported when the request cannot support a score at all. They are
// errors rather than a low score: the pipeline turns a stage error into an
// explicit indeterminate decision, and a scorer that answered "0" to a request
// it could not read would be exactly the fabricated evidence this package
// exists to avoid.
var (
	ErrNoEvent      = errors.New("risk: event is required")
	ErrNoValidation = errors.New("risk: validation result is required; an event that was never validated cannot be scored")
)

// NewEngine returns the baseline engine with the standard scorer set.
//
// No SensitivityOracle, so no sensitive_path factor is produced at all. That
// absence is the honest state for a build with no sensitivity list: nothing was
// asked. Use NewEngineWithOracle to ask.
func NewEngine() *BaselineEngine {
	return &BaselineEngine{
		// Fixed order. The factor list is part of the audit record, and a
		// record whose fields arrive in a different order on every run is not
		// comparable between runs.
		scorers: []Scorer{
			VerdictScorer{},
			ViolationSeverityScorer{},
			WorkspaceEscapeScorer{},
			NovelTargetScorer{},
			ViolationHistoryScorer{},
			EvidenceBasisScorer{},
		},
		agg: BoundedSumAggregator{},
	}
}

// NewEngineWithOracle returns the baseline engine with sensitivity scoring and
// the credential-access-to-egress sequence detector.
//
// sensitive_path is inserted after violation_severity and before
// workspace_escape, which groups the two consequence factors — how bad the
// departure is, how consequential the resource is — ahead of the two contextual
// ones. credential_access_egress follows it, because it is the factor that
// reasons *about* a sensitivity grade and reads as a continuation of it. The
// order is presentational, since the aggregation is a sum, but the factor list
// is what a human reads to check a score by hand and it should read in the
// order the reasoning goes.
//
// Both extra scorers arrive together because both are defined in terms of the
// oracle: the sequence detector's first half is "a read the list grades high or
// above", which is unaskable without a list. An engine with a list is therefore
// an engine that can see the sequence, and splitting them into two
// constructors would let a caller configure the evidence without the finding
// it exists to support.
//
// A nil oracle is refused rather than defaulted away. Accepting one would
// produce an engine that silently rates nothing while looking configured, which
// is the failure the whole sensitivity file is arranged to prevent.
func NewEngineWithOracle(o SensitivityOracle) (*BaselineEngine, error) {
	if o == nil {
		return nil, errors.New("risk: sensitivity oracle is required; " +
			"use NewEngine for an engine that deliberately rates no resources")
	}
	seq, err := NewCredentialEgressScorer(o)
	if err != nil {
		return nil, err
	}
	return &BaselineEngine{
		scorers: []Scorer{
			VerdictScorer{},
			ViolationSeverityScorer{},
			SensitivePathScorer{oracle: o},
			seq,
			WorkspaceEscapeScorer{},
			NovelTargetScorer{},
			ViolationHistoryScorer{},
			EvidenceBasisScorer{},
		},
		agg: BoundedSumAggregator{},
	}, nil
}

// NewEngineWith returns an engine over a specific scorer set and aggregator.
//
// Exposed because Scorer and Aggregator exist to be swapped and measured
// independently, which is only true if something can actually swap them. A nil
// aggregator uses BoundedSumAggregator.
func NewEngineWith(scorers []Scorer, agg Aggregator) (*BaselineEngine, error) {
	if len(scorers) == 0 {
		return nil, errors.New("risk: at least one scorer is required")
	}
	seen := make(map[string]bool, len(scorers))
	for i, s := range scorers {
		if s == nil {
			return nil, fmt.Errorf("risk: scorer %d is nil", i)
		}
		if s.Name() == "" {
			return nil, fmt.Errorf("risk: scorer %d has no name", i)
		}
		// Factor names are the key an operator tunes and audits by. Two scorers
		// sharing one would make "which heuristic produced this" unanswerable
		// from the record.
		if seen[s.Name()] {
			return nil, fmt.Errorf("risk: duplicate scorer name %q", s.Name())
		}
		seen[s.Name()] = true
	}
	if agg == nil {
		agg = BoundedSumAggregator{}
	}
	return &BaselineEngine{scorers: scorers, agg: agg}, nil
}

// Scorers returns the scorer set in the order Score runs it.
func (e *BaselineEngine) Scorers() []Scorer {
	out := make([]Scorer, len(e.scorers))
	copy(out, e.scorers)
	return out
}

// Score assesses a single validated event.
//
// The request must carry the validator's answer. History may be nil, and a nil
// history is treated as an absent input rather than as an empty one: the factors
// that read it do not apply, and confidence falls accordingly.
//
// Called from the pipeline's score stage, which runs after validate and before
// commit. That ordering is what makes the novelty factor meaningful — see the
// ordering note on pipeline.EventPipeline — and this engine depends on it: an
// event recorded before scoring would already have made its own target familiar.
func (e *BaselineEngine) Score(ctx context.Context, req ScoreRequest) (*decision.RiskAssessment, error) {
	if req.Event == nil {
		return nil, ErrNoEvent
	}
	if req.Validation == nil {
		return nil, ErrNoValidation
	}

	sc := newScoreCtx(req)

	factors := make([]decision.Factor, 0, len(e.scorers))
	for _, s := range e.scorers {
		var f decision.Factor
		applied, err := scoreOne(ctx, s, sc, &f)
		if err != nil {
			return nil, err
		}
		if applied {
			factors = append(factors, f)
		}
	}

	score, confidence := e.agg.Aggregate(factors)
	return &decision.RiskAssessment{
		Score:      score,
		Level:      LevelFor(score),
		Factors:    factors,
		Confidence: confidence,
	}, nil
}

// scoreOne runs one scorer, reusing the pre-resolved observation when the scorer
// is one of this package's own.
//
// The fast path exists because resolving an observation is the only work in
// scoring that is not a map lookup, and two scorers need it. A third-party
// Scorer still gets the plain interface call and derives what it needs itself.
func scoreOne(ctx context.Context, s Scorer, sc *scoreCtx, out *decision.Factor) (bool, error) {
	if ls, ok := s.(localScorer); ok {
		f, applied, err := ls.evaluate(sc)
		if err != nil || !applied {
			return false, err
		}
		*out = f
		return true, nil
	}

	f, err := s.Evaluate(ctx, sc.req)
	if err != nil || f == nil {
		return false, err
	}
	*out = *f
	return true, nil
}

// ScoreSession assesses the session as a whole.
//
// Deliberately narrow, and narrower than the event scorer: it reads the
// accumulated violations and the session's violation count, and nothing else.
// It still cannot see sequences — credential access followed by egress — even
// though CredentialEgressScorer now can, because SessionScoreRequest hands it a
// violation list rather than the event stream. Inferring a sequence from
// violations would be a second and weaker implementation of a detector that
// already exists, and the two would drift. The event scorer reports the
// sequence on the egress event, which is where it is provable.
//
// Its confidence therefore tops out at 0.6 rather than 0.9: two evidence inputs
// where event scoring has three, and no per-event classification behind it.
func (e *BaselineEngine) ScoreSession(_ context.Context, req SessionScoreRequest) (*decision.RiskAssessment, error) {
	factors := make([]decision.Factor, 0, 3)

	if len(req.Violations) > 0 {
		worst := worstSeverity(req.Violations)
		factors = append(factors, decision.Factor{
			Name:        FactorViolationSeverity,
			Weight:      severityPointsFor(worst),
			Description: "the most serious violation recorded this session",
			Evidence:    severityEvidence(worst),
		})
	}

	if n := violationCount(req.History, req.Violations); n > 0 {
		factors = append(factors, decision.Factor{
			Name:        FactorViolationHistory,
			Weight:      historyPoints(n),
			Description: "violations accumulated this session, one point each up to the cap",
			Evidence:    map[string]string{"prior_violations": strconv.Itoa(n)},
		})
	}

	factors = append(factors, decision.Factor{
		Name:        FactorEvidenceBasis,
		Weight:      0,
		Description: "which of the model's evidence inputs were available",
		Evidence:    sessionBasis(req.Violations != nil, req.History != nil),
	})

	score, confidence := e.agg.Aggregate(factors)
	return &decision.RiskAssessment{
		Score:      score,
		Level:      LevelFor(score),
		Factors:    factors,
		Confidence: confidence,
	}, nil
}

// violationCount prefers the session's own counter and falls back to the length
// of the violation slice.
//
// The counter is the authority: History counts every violation the session
// recorded, while the slice is whatever the caller chose to accumulate and may
// be a filtered view.
func violationCount(h History, vs []validator.Violation) int {
	if h != nil {
		return h.ViolationCount()
	}
	return len(vs)
}

// --- scoring context -------------------------------------------------------------------

// scoreCtx is the request plus the work every scorer would otherwise repeat.
//
// The observation is resolved exactly once. It is the only part of scoring that
// is not a map lookup, and both the novelty factor and the evidence basis need
// it.
type scoreCtx struct {
	req ScoreRequest

	// target is the resolved observation target, empty when the event could not
	// be resolved. Empty means "we do not know what this touched", never "it
	// touched nothing".
	target string
	kind   capability.Kind

	// departed reports that the validator did not conclude within_envelope. The
	// two history-reading factors apply only to departures: a grant that covered
	// the operation already established it was expected, so the target being new
	// carries no additional information about it.
	departed bool
}

// localScorer is the fast path for this package's own scorers.
//
// It returns the factor by value rather than by pointer, which is the whole
// point of it: a *decision.Factor returned through an interface method escapes
// to the heap, so the exported Scorer signature costs one allocation per factor
// on a path that runs for every governed syscall. The engine appends the value
// straight into its slice and allocates nothing per factor. The bool reports
// whether the factor applies, which a nil pointer used to say.
type localScorer interface {
	evaluate(sc *scoreCtx) (decision.Factor, bool, error)
}

func newScoreCtx(req ScoreRequest) *scoreCtx {
	sc := &scoreCtx{
		req:      req,
		departed: req.Validation.Verdict != decision.VerdictWithinEnvelope,
	}
	// An unresolvable event is exactly the case the validator reports as
	// indeterminate. Failing to resolve it here is not an error: it is the
	// absent-evidence state, and it is recorded as such on the evidence basis
	// rather than substituted for.
	if obs, err := validator.ObservationOf(req.Event); err == nil {
		sc.target, sc.kind = obs.Target, obs.Kind
	}
	return sc
}

// --- scorers ---------------------------------------------------------------------------

// VerdictScorer weighs the classification itself.
//
// The only scorer that always contributes a factor, including a zero-point one
// for a within-envelope event. That zero is a finding — the validator matched a
// grant — and stating it is what keeps LevelNone distinct from "not assessed".
type VerdictScorer struct{}

var (
	_ Scorer      = VerdictScorer{}
	_ localScorer = VerdictScorer{}
)

// Name identifies the factor this scorer produces.
func (VerdictScorer) Name() string { return FactorVerdict }

// Weight is the most this scorer can contribute.
func (VerdictScorer) Weight() float64 { return verdictPoints[decision.VerdictExplicitlyDenied] }

// Evaluate returns the verdict factor.
func (s VerdictScorer) Evaluate(_ context.Context, req ScoreRequest) (*decision.Factor, error) {
	if req.Validation == nil {
		return nil, ErrNoValidation
	}
	f, applied, err := s.evaluate(&scoreCtx{req: req})
	if err != nil || !applied {
		return nil, err
	}
	return &f, nil
}

func (VerdictScorer) evaluate(sc *scoreCtx) (decision.Factor, bool, error) {
	v := sc.req.Validation.Verdict
	pts, ok := verdictPoints[v]
	if !ok {
		// A verdict this build does not know cannot be scored, and guessing a
		// value for it would be the fabricated evidence the package refuses. The
		// error reaches the pipeline, which turns it into an explicit
		// indeterminate decision — visible, and never an implicit allow.
		return decision.Factor{}, false, fmt.Errorf("risk: unknown verdict %q; this build cannot score it", v)
	}
	return decision.Factor{
		Name:        FactorVerdict,
		Weight:      pts,
		Description: "how the validator classified this event against the envelope",
		Evidence:    verdictEvidence(v),
	}, true, nil
}

// ViolationSeverityScorer weighs the most serious violation on the event.
type ViolationSeverityScorer struct{}

var (
	_ Scorer      = ViolationSeverityScorer{}
	_ localScorer = ViolationSeverityScorer{}
)

// Name identifies the factor this scorer produces.
func (ViolationSeverityScorer) Name() string { return FactorViolationSeverity }

// Weight is the most this scorer can contribute.
func (ViolationSeverityScorer) Weight() float64 { return severityPoints[capability.SeverityCritical] }

// Evaluate returns the severity factor, or nil when the event violated nothing.
func (s ViolationSeverityScorer) Evaluate(_ context.Context, req ScoreRequest) (*decision.Factor, error) {
	if req.Validation == nil {
		return nil, ErrNoValidation
	}
	f, applied, err := s.evaluate(&scoreCtx{req: req})
	if err != nil || !applied {
		return nil, err
	}
	return &f, nil
}

func (ViolationSeverityScorer) evaluate(sc *scoreCtx) (decision.Factor, bool, error) {
	vs := sc.req.Validation.Violations
	if len(vs) == 0 {
		return decision.Factor{}, false, nil
	}
	// The maximum, not the sum. Several findings about one operation are several
	// descriptions of the same act, and adding them would score a selector
	// mismatch that is also a workspace escape as though the agent had done two
	// things.
	worst := worstSeverity(vs)
	return decision.Factor{
		Name:        FactorViolationSeverity,
		Weight:      severityPointsFor(worst),
		Description: "the inherent seriousness of the most serious violation on this event",
		Evidence:    severityEvidence(worst),
	}, true, nil
}

// WorkspaceEscapeScorer fires when the operation left the declared workspace.
type WorkspaceEscapeScorer struct{}

var (
	_ Scorer      = WorkspaceEscapeScorer{}
	_ localScorer = WorkspaceEscapeScorer{}
)

// Name identifies the factor this scorer produces.
func (WorkspaceEscapeScorer) Name() string { return FactorWorkspaceEscape }

// Weight is the most this scorer can contribute.
func (WorkspaceEscapeScorer) Weight() float64 { return WorkspaceEscapePoints }

// Evaluate returns the escape factor, or nil when the boundary held.
func (s WorkspaceEscapeScorer) Evaluate(_ context.Context, req ScoreRequest) (*decision.Factor, error) {
	if req.Validation == nil {
		return nil, ErrNoValidation
	}
	f, applied, err := s.evaluate(&scoreCtx{req: req})
	if err != nil || !applied {
		return nil, err
	}
	return &f, nil
}

func (WorkspaceEscapeScorer) evaluate(sc *scoreCtx) (decision.Factor, bool, error) {
	// Read from the validator's violation list rather than recomputed from the
	// envelope's WorkspaceRoot. The validator already resolved the path and
	// applied containment; a second containment check here could disagree with
	// it, and the disagreement would be invisible.
	for _, v := range sc.req.Validation.Violations {
		if v.Type != validator.ViolationWorkspaceEscape {
			continue
		}
		return decision.Factor{
			Name:        FactorWorkspaceEscape,
			Weight:      WorkspaceEscapePoints,
			Description: "the operation left the workspace the task declared",
			Evidence: map[string]string{
				"expected": v.Expected,
				"observed": v.Observed,
			},
		}, true, nil
	}
	return decision.Factor{}, false, nil
}

// SensitivePathScorer weighs how consequential the resource touched is.
//
// The first scorer whose input is configuration rather than observation, and it
// is arranged so that the configuration can only ever add. It reads the
// SensitivityOracle and nothing else — it does not consult the envelope, does
// not look at the path itself, and does not carry a list of its own.
//
// It consults the oracle method matching the observation's domain, so the whole
// interface is used rather than a quarter of it. Host and executable
// sensitivity are unknown in this build, and the factor says so by name instead
// of omitting the dimension, because "we do not rate network destinations yet"
// is a fact an operator reading an egress decision should be told.
type SensitivePathScorer struct{ oracle SensitivityOracle }

var (
	_ Scorer      = SensitivePathScorer{}
	_ localScorer = SensitivePathScorer{}
)

// NewSensitivePathScorer wraps an oracle as a standalone scorer.
func NewSensitivePathScorer(o SensitivityOracle) SensitivePathScorer {
	return SensitivePathScorer{oracle: o}
}

// Name identifies the factor this scorer produces.
func (SensitivePathScorer) Name() string { return FactorSensitivePath }

// Weight is the most this scorer can contribute.
func (SensitivePathScorer) Weight() float64 { return sensitivityPoints[capability.SeverityCritical] }

// Evaluate returns the sensitivity factor.
func (s SensitivePathScorer) Evaluate(_ context.Context, req ScoreRequest) (*decision.Factor, error) {
	if req.Validation == nil {
		return nil, ErrNoValidation
	}
	f, applied, err := s.evaluate(newScoreCtx(req))
	if err != nil || !applied {
		return nil, err
	}
	return &f, nil
}

// evaluate always produces a factor when an oracle is configured.
//
// Unlike every other scorer here, it does not go silent when it finds nothing.
// Silence would be indistinguishable from an engine built without an oracle,
// and those are different claims: no factor means nobody asked, and a factor
// reading "unknown" means somebody asked and does not know. Collapsing them is
// exactly how a sensitivity list becomes the only thing between a credential
// read and a warning, with everything it has not been taught about silently
// safe.
//
// Points are withheld — not the finding — for an event the envelope covered.
// A grant over a credential path is the envelope author's decision, and the
// place to challenge it is envelope linting rather than a risk score; charging
// it here would break the invariant that an expected event scores exactly zero.
// The grade is still reported, with EvidenceNotCharged saying why, so an
// auditor can see that a granted read touched credential material.
func (s SensitivePathScorer) evaluate(sc *scoreCtx) (decision.Factor, bool, error) {
	if s.oracle == nil {
		// Only reachable through a hand-built scorer set. Refused rather than
		// reported as unknown: an unknown is a statement about a resource, and
		// this is a statement about the wiring.
		return decision.Factor{}, false, errors.New("risk: sensitive_path scorer has no oracle")
	}

	dim := dimensionFor(sc.kind)
	grade := s.rate(dim, sc.target)

	// Only the *empty* grade takes the unknown branch. A non-empty grade this
	// build does not recognize — reachable through a third-party oracle with
	// its own vocabulary, since the loader refuses one in a file — is reported
	// verbatim and charged at the medium fallback below. Folding it in here
	// would erase the difference between "the oracle said nothing" and "the
	// oracle said something I cannot read", and would let an unfamiliar
	// vocabulary contribute nothing at all.
	if grade == SensitivityUnknown {
		return decision.Factor{
			Name:        FactorSensitivePath,
			Weight:      0,
			Description: "how consequential the resource touched is; this one is unrated",
			Evidence:    unknownSensitivityEvidence(dim),
		}, true, nil
	}

	ev := map[string]string{
		EvidenceDimension:   dim,
		EvidenceSensitivity: string(grade),
		EvidenceTarget:      sc.target,
	}
	// The written reason travels into the audit record, so "why did this score
	// go up" is answered by the sentence the list's author wrote rather than by
	// a glob the reader has to interpret.
	if o, ok := s.oracle.(interface {
		PathSensitivityReason(string) (capability.Severity, string)
	}); ok && dim == DimensionPath {
		if _, reason := o.PathSensitivityReason(sc.target); reason != "" {
			ev[EvidenceReason] = reason
		}
	}

	points := sensitivityPointsFor(grade)
	if !sc.departed {
		points = 0
		ev[EvidenceNotCharged] = "the envelope covered this operation"
	}

	return decision.Factor{
		Name:        FactorSensitivePath,
		Weight:      points,
		Description: "how consequential the resource touched is",
		Evidence:    ev,
	}, true, nil
}

// rate asks the oracle method that matches the observation's domain.
func (s SensitivePathScorer) rate(dimension, target string) capability.Severity {
	if target == "" {
		return SensitivityUnknown
	}
	switch dimension {
	case DimensionPath:
		return s.oracle.PathSensitivity(target)
	case DimensionHost:
		return s.oracle.HostSensitivity(target)
	case DimensionExecutable:
		return s.oracle.ExecutableSensitivity(target)
	default:
		return SensitivityUnknown
	}
}

// dimensionFor maps a capability to the oracle method that rates its target.
//
// Derived from the catalog rather than from the event's own Domain field, for
// the reason internal/policy derives domains the same way: a mis-decoded record
// must not be able to redirect which oracle a resource is rated by.
func dimensionFor(k capability.Kind) string {
	domain, ok := capability.DomainOf(k)
	if !ok {
		return DimensionUnrated
	}
	switch domain {
	case capability.DomainFilesystem:
		return DimensionPath
	case capability.DomainNetwork:
		return DimensionHost
	case capability.DomainProcess:
		return DimensionExecutable
	default:
		// Kernel, privilege, and IPC have no oracle method. Saying "unrated"
		// is better than implying a lookup happened and came back clean.
		return DimensionUnrated
	}
}

// sensitivityPointsFor weights a grade the oracle assigned.
//
// SensitivityUnknown is zero and is never reached here — the caller checks
// KnownSensitivity first — while an *unrecognized* non-empty grade from a
// third-party oracle falls back to medium. The two are opposite cases: absence
// of a rating contributes nothing, and a rating this build cannot read is an
// unknown quantity that must not be the cheapest way to look harmless.
func sensitivityPointsFor(s capability.Severity) float64 {
	if s == SensitivityUnknown {
		return 0
	}
	if p, ok := sensitivityPoints[s]; ok {
		return p
	}
	return sensitivityPoints[capability.SeverityMedium]
}

// NovelTargetScorer fires the first time a departing event touches a target.
type NovelTargetScorer struct{}

var (
	_ Scorer      = NovelTargetScorer{}
	_ localScorer = NovelTargetScorer{}
)

// Name identifies the factor this scorer produces.
func (NovelTargetScorer) Name() string { return FactorNovelTarget }

// Weight is the most this scorer can contribute.
func (NovelTargetScorer) Weight() float64 { return NovelTargetPoints }

// Evaluate returns the novelty factor, or nil when it does not apply.
func (s NovelTargetScorer) Evaluate(_ context.Context, req ScoreRequest) (*decision.Factor, error) {
	if req.Validation == nil {
		return nil, ErrNoValidation
	}
	f, applied, err := s.evaluate(newScoreCtx(req))
	if err != nil || !applied {
		return nil, err
	}
	return &f, nil
}

// evaluate reports novelty only when all three of its preconditions hold.
//
// Each omission is an absent input rather than a reassuring answer:
//
//   - No history: nothing is known about what came before, so nothing is said.
//     It is not "everything is familiar".
//   - No resolved target: the event could not be interpreted, so there is no
//     target to have seen before.
//   - Within envelope: a grant covered the operation, which already establishes
//     it was expected. Novelty adds nothing to that, and charging it would put
//     every session's first write to every file above LevelNone.
func (NovelTargetScorer) evaluate(sc *scoreCtx) (decision.Factor, bool, error) {
	if !sc.departed || sc.req.History == nil || sc.target == "" {
		return decision.Factor{}, false, nil
	}
	// History is read here, before the pipeline commits this event. Were the
	// order reversed the target would already be familiar and this factor could
	// never fire — see the ordering note on pipeline.EventPipeline.
	if sc.req.History.TargetSeen(sc.kind, sc.target) {
		return decision.Factor{}, false, nil
	}

	ev := map[string]string{
		"capability": string(sc.kind),
		"target":     sc.target,
	}
	// Saturation is reported rather than ignored. Past the novelty set's
	// ceiling, targets stop being recorded and so keep reading as unseen, which
	// is the safe direction but makes this factor weaker evidence than it looks.
	// Stated in the record so a reader is not misled; the points are unchanged,
	// because the state it describes is one where more scrutiny, not less, is
	// warranted.
	if s, ok := sc.req.History.(interface{ SeenTargetsSaturated() bool }); ok && s.SeenTargetsSaturated() {
		ev["novelty_set_saturated"] = "true"
	}

	return decision.Factor{
		Name:        FactorNovelTarget,
		Weight:      NovelTargetPoints,
		Description: "this target had not been touched earlier in the session",
		Evidence:    ev,
	}, true, nil
}

// ViolationHistoryScorer weighs how many violations the session already produced.
type ViolationHistoryScorer struct{}

var (
	_ Scorer      = ViolationHistoryScorer{}
	_ localScorer = ViolationHistoryScorer{}
)

// Name identifies the factor this scorer produces.
func (ViolationHistoryScorer) Name() string { return FactorViolationHistory }

// Weight is the most this scorer can contribute.
func (ViolationHistoryScorer) Weight() float64 { return ViolationHistoryCap }

// Evaluate returns the violation-history factor, or nil when it does not apply.
func (s ViolationHistoryScorer) Evaluate(_ context.Context, req ScoreRequest) (*decision.Factor, error) {
	if req.Validation == nil {
		return nil, ErrNoValidation
	}
	f, applied, err := s.evaluate(newScoreCtx(req))
	if err != nil || !applied {
		return nil, err
	}
	return &f, nil
}

func (ViolationHistoryScorer) evaluate(sc *scoreCtx) (decision.Factor, bool, error) {
	if !sc.departed || sc.req.History == nil {
		return decision.Factor{}, false, nil
	}
	n := sc.req.History.ViolationCount()
	if n <= 0 {
		return decision.Factor{}, false, nil
	}
	return decision.Factor{
		Name:        FactorViolationHistory,
		Weight:      historyPoints(n),
		Description: "violations already recorded this session, one point each up to the cap",
		Evidence:    map[string]string{"prior_violations": strconv.Itoa(n)},
	}, true, nil
}

// EvidenceBasisScorer contributes no points and states what the model could see.
//
// It exists so confidence is auditable. Aggregate computes confidence from this
// factor and from nothing else, so a reader checking a confidence value counts
// the trues in one map instead of trusting a number that came from somewhere.
type EvidenceBasisScorer struct{}

var (
	_ Scorer      = EvidenceBasisScorer{}
	_ localScorer = EvidenceBasisScorer{}
)

// Name identifies the factor this scorer produces.
func (EvidenceBasisScorer) Name() string { return FactorEvidenceBasis }

// Weight is zero: the basis explains the score, it does not contribute to it.
func (EvidenceBasisScorer) Weight() float64 { return 0 }

// Evaluate returns the evidence-basis factor, which always applies.
func (s EvidenceBasisScorer) Evaluate(_ context.Context, req ScoreRequest) (*decision.Factor, error) {
	if req.Validation == nil {
		return nil, ErrNoValidation
	}
	f, applied, err := s.evaluate(newScoreCtx(req))
	if err != nil || !applied {
		return nil, err
	}
	return &f, nil
}

func (EvidenceBasisScorer) evaluate(sc *scoreCtx) (decision.Factor, bool, error) {
	return decision.Factor{
		Name:        FactorEvidenceBasis,
		Weight:      0,
		Description: "which of the model's evidence inputs were available",
		Evidence: eventBasis(
			sc.req.Validation.Verdict != decision.VerdictIndeterminate,
			sc.target != "",
			sc.req.History != nil,
		),
	}, true, nil
}

// --- aggregation --------------------------------------------------------------------------

// BoundedSumAggregator adds the factors and clamps.
//
// A plain sum, chosen over the weighted sum with a critical-factor floor the
// module's TODO leans toward, for one reason: with five factors and a heaviest
// contribution of 55, no accumulation of small factors can bury a large one, so
// the floor has nothing to protect against yet. It becomes worth adding when a
// scorer set is large enough for dilution to be possible, and adding it now
// would be a mechanism with no failure to prevent.
//
// Clamping rather than rescaling: the theoretical maximum is 110 for the
// unrated scorer set and 165 with an oracle behind it, and rescaling by either
// would mean adding a scorer silently moved every existing score. A policy
// threshold an operator set last week has to keep meaning what it meant — which
// is exactly what adding the sequence detector would otherwise have broken.
type BoundedSumAggregator struct{}

var _ Aggregator = BoundedSumAggregator{}

// Aggregate returns the clamped sum and the confidence stated by the evidence
// basis factor.
//
// Confidence is a count, not an estimate: ConfidencePerBasis for each evidence
// input the basis factor reports as available, capped at ConfidenceCeiling. A
// factor list with no evidence basis yields zero confidence, which is the honest
// answer to "how much backed this" when nothing said.
func (BoundedSumAggregator) Aggregate(factors []decision.Factor) (float64, float64) {
	var sum, confidence float64

	for _, f := range factors {
		if f.Name == FactorEvidenceBasis {
			confidence = confidenceFor(countTrue(f.Evidence))
			continue
		}
		sum += f.Weight
	}
	return clampScore(sum), confidence
}

func countTrue(ev map[string]string) int {
	n := 0
	for _, v := range ev {
		if v == "true" {
			n++
		}
	}
	return n
}

// --- shared helpers ----------------------------------------------------------------------

func worstSeverity(vs []validator.Violation) capability.Severity {
	worst := capability.SeverityInfo
	for _, v := range vs {
		if severityPointsFor(v.Severity) > severityPointsFor(worst) {
			worst = v.Severity
		}
	}
	return worst
}

// severityPointsFor treats an unrecognized severity as medium.
//
// The same fallback validator.severityFor applies to a violation type with no
// declared floor, and for the same reason: a severity string this build does not
// know is an unknown quantity, and scoring an unknown as harmless would make an
// unrecognized value the cheapest way to look safe.
func severityPointsFor(s capability.Severity) float64 {
	if p, ok := severityPoints[s]; ok {
		return p
	}
	return severityPoints[capability.SeverityMedium]
}

func historyPoints(n int) float64 {
	return math.Min(float64(n), ViolationHistoryCap)
}

// --- preallocated evidence ------------------------------------------------------------------
//
// The evidence maps for the closed-vocabulary factors are built once at package
// initialization and shared. They are never mutated — nothing here writes to a
// Factor's Evidence after construction, and the assessment is handed to callers
// that only read it — which makes them safe to share across goroutines and keeps
// the common path free of map allocation. An event the envelope covered
// allocates one factor slice and one assessment, and nothing else.

var (
	verdictEvidenceTable  = map[decision.Verdict]map[string]string{}
	severityEvidenceTable = map[capability.Severity]map[string]string{}

	// The basis tables are indexed by a bit mask of the evidence inputs, so
	// every combination exists without allocating per event.
	eventBasisTable   [8]map[string]string
	sessionBasisTable [4]map[string]string

	// unknownSensitivityTable covers the common answer. Most resources an agent
	// touches are on no list, and "unrated" must not cost an allocation per
	// event to say.
	unknownSensitivityTable = map[string]map[string]string{}
)

func init() {
	for _, v := range decision.AllVerdicts() {
		verdictEvidenceTable[v] = map[string]string{"verdict": string(v)}
	}
	for s := range severityPoints {
		severityEvidenceTable[s] = map[string]string{"severity": string(s)}
	}
	for i := range eventBasisTable {
		eventBasisTable[i] = map[string]string{
			BasisVerdictConclusive: boolStr(i&1 != 0),
			BasisTargetResolved:    boolStr(i&2 != 0),
			BasisHistoryAvailable:  boolStr(i&4 != 0),
		}
	}
	for i := range sessionBasisTable {
		sessionBasisTable[i] = map[string]string{
			BasisViolationsAvailable: boolStr(i&1 != 0),
			BasisHistoryAvailable:    boolStr(i&2 != 0),
		}
	}
	for _, d := range []string{DimensionPath, DimensionHost, DimensionExecutable, DimensionUnrated} {
		unknownSensitivityTable[d] = map[string]string{
			EvidenceDimension:   d,
			EvidenceSensitivity: SensitivityUnknownLabel,
		}
	}
}

func unknownSensitivityEvidence(dimension string) map[string]string {
	if ev, ok := unknownSensitivityTable[dimension]; ok {
		return ev
	}
	return map[string]string{
		EvidenceDimension:   dimension,
		EvidenceSensitivity: SensitivityUnknownLabel,
	}
}

func verdictEvidence(v decision.Verdict) map[string]string {
	if ev, ok := verdictEvidenceTable[v]; ok {
		return ev
	}
	return map[string]string{"verdict": string(v)}
}

func severityEvidence(s capability.Severity) map[string]string {
	if ev, ok := severityEvidenceTable[s]; ok {
		return ev
	}
	return map[string]string{"severity": string(s)}
}

func eventBasis(verdictConclusive, targetResolved, historyAvailable bool) map[string]string {
	return eventBasisTable[bit(verdictConclusive, 1)|bit(targetResolved, 2)|bit(historyAvailable, 4)]
}

func sessionBasis(violationsAvailable, historyAvailable bool) map[string]string {
	return sessionBasisTable[bit(violationsAvailable, 1)|bit(historyAvailable, 2)]
}

func bit(b bool, mask int) int {
	if b {
		return mask
	}
	return 0
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
