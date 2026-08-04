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

	"github.com/stringNameMahin/ALLSEER/pkg/decision"
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
type ProcessingContext struct {
	Event     *event.Event
	SessionID string

	// Started is when processing began, used to compute decision latency.
	Started time.Time

	// Decision accumulates the outcome. Stages fill in their portion.
	Decision *decision.Decision

	// Values holds inter-stage data that does not belong on the Decision.
	// Untyped and discouraged: reach for it only when a stage genuinely needs
	// to pass something private to a later stage.
	Values map[string]any
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
	// Returning nil drops the event, which must be reserved for cases where
	// dropping is provably safe.
	Handle(ctx context.Context, pc *ProcessingContext, stage string, err error) *decision.Decision
}

// TODO(pipeline): implement per-session serial processing with cross-session
// parallelism, keyed by session ID.
// TODO(pipeline): add panic recovery around every stage. A panic in a scorer
// must not take down governance for every session on the host.
// TODO(pipeline): define the backpressure policy end to end, from the kernel
// ring buffer through to the audit sink, and document where events can be lost.
// TODO(pipeline): add a tracing decorator so a single event's path through all
// stages can be inspected during development.
// TODO(pipeline): benchmark the full path. The number that matters is added
// latency per governed syscall in enforce mode.
