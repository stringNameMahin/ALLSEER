// Package pipeline wires the governance stages into a single processing path.
//
// The pipeline is the composition root for the hot path. It owns the sequence,
// enrich then validate then score then decide then enforce then audit, and
// nothing else. All judgment lives in the stages it calls; this package
// contributes ordering, concurrency, and error handling.
//
// Keeping that separation strict is what makes the system testable. Each stage
// is a pure function tested in isolation, and the pipeline is tested for
// plumbing, meaning ordering, backpressure, and shutdown, against stubs.
//
// Two properties govern the design:
//
//   - Ordering within a session must be preserved. Risk scoring depends on
//     history, so processing events out of order silently changes verdicts.
//   - A stage failure must not silently allow. Any error has to produce an
//     explicit indeterminate decision that policy then handles, because a
//     dropped event is indistinguishable from an event that never happened.
package pipeline

import (
	"context"
	"time"

	"github.com/stringNameMahin/ALLSEER/internal/policy"
	"github.com/stringNameMahin/ALLSEER/internal/risk"
	"github.com/stringNameMahin/ALLSEER/internal/validator"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// Pipeline processes events into decisions.
type Pipeline interface {
	// Run consumes from the source until ctx is cancelled or the source closes.
	// Blocks for the pipeline's lifetime.
	Run(ctx context.Context, src event.Source) error

	// Process handles a single event synchronously. Exposed for testing and for
	// replay-based analysis, where deterministic single-stepping is more useful
	// than throughput.
	Process(ctx context.Context, e *event.Event) (*decision.Decision, error)

	// Stats reports pipeline health.
	Stats() Stats
}

// Stage is one step in processing.
//
// A uniform stage interface lets the pipeline be assembled from a list, and
// lets cross-cutting concerns like timing, tracing, and panic recovery be
// applied once via a decorator rather than repeated in every stage.
type Stage interface {
	// Name identifies the stage in metrics and reasoning chains.
	Name() string

	// Execute processes the context, mutating it in place.
	//
	// Returning an error aborts the remaining stages and produces an
	// indeterminate decision. A stage that cannot reach a conclusion must
	// return an error rather than guessing; a hopeful guess here is an unlogged
	// security decision.
	Execute(ctx context.Context, pc *ProcessingContext) error
}

// ProcessingContext carries state through the stages.
//
// A single mutable value threaded through the pipeline rather than a chain of
// return types. That is a concession to readability: the alternative produces
// deeply nested generic signatures for no practical gain, since the context
// stays confined to one goroutine for its whole lifetime.
//
// The intermediate results are **typed fields, not entries in Values**. They are
// the system's central artifacts — the validator's answer is what policy reads,
// and it is what the audit record is assembled from — and routing them through
// an `any` map would turn a rename or a type change into a runtime type
// assertion failure on the hot path, in the one component whose whole job is to
// not lose events. Values survives for genuinely private stage-to-stage data,
// which none of the stages here has.
type ProcessingContext struct {
	Event     *event.Event
	SessionID string

	// Started is when processing began, used to compute decision latency.
	Started time.Time

	// --- session binding ----------------------------------------------------
	// Set by the pipeline before the first stage runs, identically for every
	// event in the session. Stages read it rather than closing over it, which
	// is what keeps a stage a pure function of its context and safe to share.

	// Envelope governs this session. Sealed, and never modified here.
	Envelope *ece.Envelope

	// Mode is the enforcement posture passed through to policy. The pipeline
	// does not interpret it: whether a mode changes which rules are eligible is
	// policy's business, and second-guessing it here would be a second set of
	// mode semantics.
	Mode policy.Mode

	// State is the session's accumulated counters. Stages **read** it; only the
	// pipeline writes to it, and only after every stage has run. See the
	// ordering note on EventPipeline.
	State State

	// --- stage output -------------------------------------------------------

	// Validation is what the validator concluded. Nil until the validate stage
	// has run, and a later stage that needs it must fail rather than proceed
	// without it — a policy decision made against an absent verdict is a
	// decision made about nothing.
	Validation *validator.Result

	// Risk is the scored assessment, or nil when no risk stage ran. Nil is
	// meaningful and must not be replaced with a zero assessment: policy treats
	// a condition with no evidence behind it as not matching, and a fabricated
	// score of zero would satisfy every max_risk_score rule in the set. A
	// pipeline built by New still leaves it nil; NewWithRisk is the composition
	// that fills it in.
	Risk *decision.RiskAssessment

	// Outcome is the action policy selected.
	Outcome *policy.Outcome

	// Decision is the finished record. Assembled by the pipeline from the
	// fields above once the stages are done, rather than accumulated piecemeal,
	// so there is exactly one place the system's public product is constructed
	// and the failure path cannot produce a differently shaped one.
	Decision *decision.Decision

	// FailedStage and Err report the stage that stopped processing, if any.
	//
	// The Decision alone cannot carry this: an indeterminate decision says the
	// event could not be classified, not whether that was the validator's
	// honest answer about an unresolvable path or the pipeline falling over.
	// Those are the same finding about the agent and opposite findings about
	// the system, and a caller that has to tell them apart — a dry run
	// reporting on a policy, a daemon deciding whether to keep going — should
	// not have to parse a reason string to do it.
	FailedStage string
	Err         error

	// Values holds inter-stage data that does not belong on the Decision.
	// Untyped and discouraged: reach for it only when a stage genuinely needs
	// to pass something private to a later stage.
	Values map[string]any
}

// State is the per-session state the pipeline reads through and writes to.
//
// A narrow interface declared at the point of use rather than an import of
// internal/session, which is the pattern validator.SessionState and risk.History
// already established: the pipeline names what it needs, and session.MemoryState
// happens to satisfy it. It is both read sides plus the three writes, because
// the pipeline is the component that owns advancing them.
//
// risk.History is named here rather than reached for with a type assertion in
// the score stage. The two read sides describe one session and
// session.MemoryState was built to satisfy both from one set of counters; a
// stage that asserted its way to the history would silently score against no
// history at all when the assertion failed, and "no history" is a state this
// system treats as meaningful evidence rather than as a shrug.
type State interface {
	validator.SessionState
	risk.History

	// RecordEvent folds an observed event into the counters.
	RecordEvent(e *event.Event)

	// RecordDecision folds a rendered decision into the counters.
	RecordDecision(d *decision.Decision)

	// RecordGrantUse charges one use against a grant, by envelope index.
	RecordGrantUse(grantIndex int)
}

// Session is what one pipeline governs: one envelope, one mode, one state.
//
// Distinct from session.Session, which is the lifecycle record. This is only
// the binding a pipeline needs to process events, and the pipeline deliberately
// does not import internal/session to get it — a pipeline is constructed for a
// session, not the other way round.
type Session struct {
	// ID is the session identifier stamped onto every decision. Defaults to
	// Envelope.SessionID when empty.
	ID string

	Envelope *ece.Envelope
	Mode     policy.Mode
	State    State
}

// Stats reports pipeline throughput and health.
type Stats struct {
	EventsProcessed uint64        `json:"events_processed"`
	DecisionsIssued uint64        `json:"decisions_issued"`
	Errors          uint64        `json:"errors"`
	AvgLatency      time.Duration `json:"avg_latency"`
	P99Latency      time.Duration `json:"p99_latency"`

	// QueueDepth is the current backlog. Sustained growth means the pipeline
	// cannot keep up, which in enforce mode translates directly into agent
	// latency.
	QueueDepth int `json:"queue_depth"`

	// StageLatencies breaks latency down by stage, so a regression can be
	// attributed rather than guessed at.
	StageLatencies map[string]time.Duration `json:"stage_latencies"`
}

// Builder assembles a pipeline from stages.
type Builder interface {
	// WithStage appends a stage. Order of addition is order of execution.
	WithStage(s Stage) Builder

	// WithErrorHandler sets the handler for stage failures.
	WithErrorHandler(h ErrorHandler) Builder

	// WithConcurrency sets how many sessions are processed in parallel. Events
	// within a session are always serial to preserve ordering; this controls
	// parallelism across sessions.
	WithConcurrency(n int) Builder

	// Build produces the pipeline.
	Build() (Pipeline, error)
}

// ErrorHandler decides what happens when a stage fails.
//
// A security decision rather than an operational one, which is why it is an
// explicit interface and not a log statement. The safe answer is to produce an
// indeterminate decision and let policy handle it; the convenient answer is to
// skip the event. Making the choice explicit keeps it from being made by
// accident.
type ErrorHandler interface {
	// Handle processes a stage error and returns the decision to emit.
	//
	// Returning nil emits no decision, which must be reserved for cases where
	// having no audit record is provably safe. It does **not** drop the event:
	// the pipeline still folds the event into the session counters, because the
	// counters describe what the kernel observed and a failure in our analysis
	// is not evidence that the agent did less. Returning budget on a stage
	// failure would make failing a stage the cheapest way to spend one.
	Handle(ctx context.Context, pc *ProcessingContext, stage string, err error) *decision.Decision
}

// Done: per-session serial processing is EventPipeline in process.go. A
// pipeline is bound to one session and processes it on one goroutine, which is
// what makes session.MemoryState's single-writer assumption a guarantee rather
// than a convention. The stages read, the pipeline writes, and the write
// happens after the whole stage list — so a budget stays inclusive and the risk
// stage can still tell a novel target from a familiar one.
// Done: the risk stage is ScoreStage in stage.go, over internal/risk. It sits
// between validate and decide, and NewWithRisk in process.go is the composition
// a daemon should run; New is kept as the unscored one the equivalence test
// pins against the original hand-written loop. Nothing else in this package
// changed to accommodate it, which is what the write-last ordering was for.
// TestRiskStageSeesHistoryBeforeCommit is the end-to-end proof that the scorer
// sees the session as it stood before the event under judgment.
// Done: every stage runs under panic recovery in process.go. A panic becomes an
// ordinary stage error and travels the same route to an indeterminate decision,
// so one scorer mishandling one malformed path cannot end governance for the
// session, or for every session sharing the process.
// TODO(pipeline): cross-session parallelism, keyed by session ID. Deliberately
// not here: dispatching an event to the right envelope and state is
// session.Manager's job, and a pipeline that looked sessions up would be a
// session registry with a stage list attached. Builder.WithConcurrency refuses
// anything above one rather than accepting a number it would ignore.
// TODO(pipeline): define the backpressure policy end to end, from the kernel
// ring buffer through to the audit sink, and document where events can be lost.
// Nothing here buffers yet — Process is synchronous and Run holds no queue —
// which is why Stats.QueueDepth is a measured zero rather than an unmeasured
// one. It stops being trivially true the moment a queue exists.
// TODO(pipeline): add a tracing decorator so a single event's path through all
// stages can be inspected during development. ProcessContext already exposes
// every intermediate result, so this is presentation rather than plumbing.
// TODO(pipeline): benchmark the number that actually matters — added latency
// per governed syscall in enforce mode. BenchmarkProcess covers the
// deterministic path (2.5 µs/op, 38 allocs/op over validate and decide) but
// enforcement is M12, and the cost that will decide whether this can be left
// enabled is the one charged to the agent's syscall.
