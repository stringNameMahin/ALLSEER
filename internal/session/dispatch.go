package session

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/stringNameMahin/ALLSEER/internal/policy"
	"github.com/stringNameMahin/ALLSEER/internal/risk"
	"github.com/stringNameMahin/ALLSEER/internal/validator"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// This file holds cross-session event dispatch: routing each event on one
// multi-session stream to the processor governing the session it belongs to.
//
// # Why it exists
//
// A pipeline governs exactly one session and processes it serially, which is
// what makes MemoryState's single-writer assumption a guarantee rather than a
// convention. A collector, by contrast, reads one ring buffer for every
// governed session on the host. Something has to stand between them and decide
// which pipeline an event belongs to. That decision needs a registry of
// sessions, their envelopes, and their tracking state — which is this package —
// and it was deliberately split out of internal/pipeline, where a component
// that looked sessions up would have been a session registry with a stage list
// attached.
//
// # Why it is not MemoryManager
//
// The manager owns identity, lifecycle, and State_. It does not own pipelines,
// and a Dispatch method hanging off it would make it own them. The Dispatcher
// is a separate type that *reads* a registry through the narrowest interface
// that answers its question, and builds processors through a factory the caller
// supplies. It never imports internal/pipeline: EventProcessor is declared here
// at the point of use, the same pattern validator.SessionState, risk.History,
// and pipeline.State already established, and *pipeline.EventPipeline happens
// to satisfy it.
//
// # What it deliberately is not
//
// It is routing, not parallelism. A Dispatcher processes one stream on one
// goroutine, in arrival order, exactly as EventPipeline.Run does. That is what
// preserves per-session ordering — and per-session ordering is not a nicety,
// since history-dependent risk scoring reaches different verdicts on reordered
// events.
//
// Cross-session parallelism would mean a queue and a worker per session, and a
// bounded queue needs an answer to what happens when it fills. That answer is
// the end-to-end backpressure policy, which docs/milestones.md assigns to M6,
// where the kernel ring buffer it is really about lives, and which cannot be
// settled before M5 and M6 establish what the kernel side does under load.
// Building the queue here would be settling it by accident.
//
// One consequence is worth stating plainly, because the project's own notes
// predicted otherwise: this does not turn pipeline.Stats.QueueDepth into a
// measured number. Nothing here buffers, so QueueDepth stays the measured zero
// it already was. The queue belongs to the fan-out, and the fan-out is M6's.

// EventProcessor is the per-session half of dispatch: something that turns one
// event into one decision.
//
// Declared here rather than imported so this package does not depend on
// internal/pipeline. *pipeline.EventPipeline satisfies it, and so does a stub,
// which is what lets the routing be tested without the stages.
//
// An implementation must not audit the decision it returns. The Dispatcher owns
// the sink, because one daemon writes one audit stream and a sink per session
// would produce a file per session that nothing reads in order. The pipeline
// honors this already: EventPipeline.Process returns a decision and emits
// nothing, and only its own Run emits.
type EventProcessor interface {
	Process(ctx context.Context, e *event.Event) (*decision.Decision, error)
}

// ProcessorFactory builds the processor for a session, once, on the first event
// routed to it.
//
// A function rather than an interface because there is exactly one thing to
// ask, and because the caller supplying it is the point: constructing a
// pipeline means choosing a validator, a risk engine, a policy engine, and a
// stage order, and every one of those is a composition decision that belongs to
// whoever assembled the daemon rather than to a router.
//
// Returning an error refuses the session. The events are counted as
// unprocessable and the factory is asked again on the next one — there is no
// negative cache, because a factory that failed on a transient condition should
// not have the session written off for the rest of its life.
type ProcessorFactory func(b Binding) (EventProcessor, error)

// Registry is the narrow view of a session manager that routing needs.
//
// Deliberately one method. A router that took the whole Manager could create,
// seal, and end sessions on the hot path, and the interface a component accepts
// is the honest statement of what it is able to do.
type Registry interface {
	// Binding returns what routing an event to a session requires, and whether
	// the registry holds that session at all. It must be safe to call from any
	// goroutine and cheap enough for the hot path: it is consulted once per
	// event.
	Binding(sessionID string) (Binding, bool)
}

// TrackingState is the per-session tracking state a processor needs.
//
// State_ alone is too narrow to hand to a pipeline: every method on it is a
// write, which is exactly what its documentation promises, and a pipeline also
// reads — the validator compares counters against a budget and the risk engine
// scores against history. Widening State_ would break the promise; naming the
// union here does not.
//
// It costs nothing. state.go already asserts *MemoryState against both read
// sides at compile time, so this is the same claim written down where dispatch
// needs it, and it adds no import this package did not already have.
//
// Structurally identical to pipeline.State, and deliberately not that type:
// naming it would make this package depend on internal/pipeline, which is the
// dependency EventProcessor exists to avoid.
type TrackingState interface {
	State_
	validator.SessionState
	risk.History
}

var _ TrackingState = (*MemoryState)(nil)

// Binding is everything routing an event needs to know about a session.
//
// A value with no allocation in it, because it is built once per event. The
// envelope is shared rather than copied — it is sealed and read only, the same
// rule Session.clone applies — and State_ is shared deliberately: it is what
// the session's processor records into, and a copy would be a pipeline
// recording into nothing.
type Binding struct {
	SessionID string

	// Envelope governs the session. Sealed by the time a session accepts
	// events, since Start is reachable only through Seal.
	Envelope *ece.Envelope

	// Mode is the enforcement posture the session runs under.
	Mode policy.Mode

	// State is the session's tracking state, shared by reference.
	State TrackingState

	// Lifecycle is the session's lifecycle position, which is what decides
	// whether an event may be routed at all. See AcceptsEvents.
	Lifecycle State
}

// Errors reported for events that cannot be routed.
//
// Each is a sentinel and each names a different finding, because the three are
// not interchangeable: a stream with no session IDs is a decoder fault, a
// stream naming sessions nobody registered is an attribution fault, and events
// arriving for an ended session are either late telemetry or PID reuse. Folding
// them into one "could not route" would hide which of those is happening on a
// host, and they call for different responses.
var (
	// ErrEventUnidentified means the event names no session. Nothing can be
	// validated without an envelope, and the envelope is reached through the
	// session ID.
	ErrEventUnidentified = errors.New("session: event carries no session_id")

	// ErrUnattributed means the event names a session this registry does not
	// hold. The event is real and was observed; what is missing is the
	// governance context for it. It is counted rather than dropped quietly,
	// because an event nobody could attribute is not an event that did not
	// happen.
	ErrUnattributed = errors.New("session: no such session in the registry")

	// ErrNotAccepting means the session exists but is not in a state that
	// accepts events. See AcceptsEvents for which states do, and why.
	ErrNotAccepting = errors.New("session: session is not accepting events")

	// ErrNoRegistry and ErrNoFactory are construction failures, refused at
	// NewDispatcher rather than discovered on the first event.
	ErrNoRegistry = errors.New("session: a registry is required")
	ErrNoFactory  = errors.New("session: a processor factory is required")

	// ErrNoSource means Run was called with no source, mirroring the pipeline's
	// own refusal.
	ErrNoSource = errors.New("session: an event source is required")

	// ErrNilEvent means Dispatch was handed no event at all, which is a caller
	// fault rather than a finding about a session.
	ErrNilEvent = errors.New("session: dispatch requires an event")
)

// DispatchConfig configures a Dispatcher.
type DispatchConfig struct {
	// Registry resolves a session ID to its binding. Required.
	Registry Registry

	// Factory builds the processor for a session. Required.
	Factory ProcessorFactory

	// Sink receives every decision the dispatcher produces. Optional: a nil
	// sink means decisions are returned but not audited, which is what
	// replay-based analysis wants and what a daemon must not do. This mirrors
	// pipeline.Config.Sink exactly, including the reason.
	Sink decision.Sink
}

// Dispatcher routes events to the processor governing each event's session.
//
// One stream, one goroutine. Dispatch, Run, and Release must be called from a
// single goroutine; Stats may be called from any. That is the same contract
// EventPipeline has and it is load-bearing for the same reason: each session's
// State_ has exactly one writer, and here that writer is this goroutine acting
// on that session's behalf. A dispatcher that accepted concurrent calls would
// need a lock per session on the hot path to be safe, and would still not
// preserve arrival order, since mutual exclusion is not a queue. Several
// streams means several dispatchers.
//
// The zero value is not usable; use NewDispatcher.
type Dispatcher struct {
	registry Registry
	factory  ProcessorFactory
	sink     decision.Sink

	// processors caches one processor per session, built on first use. Owned by
	// the dispatch goroutine and read without synchronization for the same
	// reason MemoryState's ring is: there is one writer, by contract.
	processors map[string]EventProcessor

	stats dispatchStats
}

// NewDispatcher returns a dispatcher over cfg.
func NewDispatcher(cfg DispatchConfig) (*Dispatcher, error) {
	if cfg.Registry == nil {
		return nil, ErrNoRegistry
	}
	if cfg.Factory == nil {
		return nil, ErrNoFactory
	}
	return &Dispatcher{
		registry:   cfg.Registry,
		factory:    cfg.Factory,
		sink:       cfg.Sink,
		processors: make(map[string]EventProcessor),
	}, nil
}

// Dispatch routes one event and returns the decision its session's processor
// reached.
//
// Returns a nil decision with one of ErrEventUnidentified, ErrUnattributed, or
// ErrNotAccepting when the event could not be routed. Those are refusals rather
// than failures: the event was observed and is counted, and the caller learns
// which of the three happened. Run treats them as ordinary and continues.
//
// A decision is emitted to the sink before it is returned, so a caller that
// ignores the return value still produces an audit record.
func (d *Dispatcher) Dispatch(ctx context.Context, e *event.Event) (*decision.Decision, error) {
	if e == nil {
		return nil, ErrNilEvent
	}
	d.stats.observed.Add(1)

	if e.SessionID == "" {
		d.stats.unidentified.Add(1)
		return nil, ErrEventUnidentified
	}

	b, ok := d.registry.Binding(e.SessionID)
	if !ok {
		d.stats.unattributed.Add(1)
		return nil, fmt.Errorf("%w: %q", ErrUnattributed, e.SessionID)
	}
	if !AcceptsEvents(b.Lifecycle) {
		// The session stopped accepting events, so anything cached for it is
		// dead weight. Dropped here rather than left for Release, which is the
		// caller's optional courtesy and not something a router may depend on.
		d.Release(e.SessionID)
		d.stats.notAccepting.Add(1)
		return nil, fmt.Errorf("%w: %q is %s", ErrNotAccepting, e.SessionID, b.Lifecycle)
	}

	p, err := d.processorFor(b)
	if err != nil {
		d.stats.factoryErrors.Add(1)
		return nil, fmt.Errorf("session: building a processor for %q: %w", e.SessionID, err)
	}

	dec, err := p.Process(ctx, e)
	if err != nil {
		// Counted and returned, never fatal to the stream. One session's
		// processor falling over must not end governance for every other
		// session sharing the host — the same containment argument that puts
		// panic recovery around each pipeline stage. Run acts on that by
		// continuing; a caller of Dispatch decides for itself.
		d.stats.processorErrors.Add(1)
		return nil, fmt.Errorf("session: processing event %q for %q: %w", e.ID, e.SessionID, err)
	}

	d.stats.routed.Add(1)
	d.emit(ctx, dec)
	return dec, nil
}

// Run consumes the source until it closes or ctx is cancelled.
//
// The source must already be started, and lifecycle stays with the caller, for
// the reason EventPipeline.Run gives: "probes could not attach" is a startup
// fault to refuse to run under, while anything Run reports is a processing
// fault, and folding them together makes a blind spot look like a hiccup.
//
// Nothing an individual event can do ends the run. Unroutable events and
// processor failures are counted and skipped, because a stream carrying every
// session on the host must not be stoppable by one of them. What does end it is
// context cancellation and the source closing — the two things that are about
// the stream rather than about an event on it.
func (d *Dispatcher) Run(ctx context.Context, src event.Source) error {
	if src == nil {
		return ErrNoSource
	}

	events := src.Events()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e, ok := <-events:
			if !ok {
				return nil
			}
			// Dispatch's errors are all per-event findings, already counted and
			// already distinguished by Stats. Discarded here deliberately: the
			// alternative is a run that dies on the first event belonging to a
			// session that has ended, which is a routine occurrence on a live
			// host and not a reason to stop governing every other one.
			_, _ = d.Dispatch(ctx, &e)
		}
	}
}

// Release forgets the cached processor for a session.
//
// Optional, and only about memory: a caller that ends sessions and knows it
// will see no more of their events can hand the processor back rather than wait
// for the dispatcher to notice. The dispatcher already drops an entry when it
// sees an event for a session that has stopped accepting them, but a session
// whose events simply stop leaves one behind, and on a long-lived daemon that
// is a slow accumulation proportional to sessions served.
//
// Must be called from the dispatch goroutine, like Dispatch itself.
func (d *Dispatcher) Release(sessionID string) {
	if _, ok := d.processors[sessionID]; ok {
		delete(d.processors, sessionID)
		d.stats.live.Add(-1)
	}
}

// Stats reports routing health. Safe to call from any goroutine.
func (d *Dispatcher) Stats() DispatchStats { return d.stats.snapshot() }

// processorFor returns the session's processor, building it on first use.
func (d *Dispatcher) processorFor(b Binding) (EventProcessor, error) {
	if p, ok := d.processors[b.SessionID]; ok {
		return p, nil
	}
	p, err := d.factory(b)
	if err != nil {
		return nil, err
	}
	if p == nil {
		// Refused rather than cached. A nil processor would panic on the next
		// event, and a factory that returns (nil, nil) has not told anybody
		// that it declined.
		return nil, fmt.Errorf("session: the processor factory returned nil for %q", b.SessionID)
	}
	d.processors[b.SessionID] = p
	d.stats.built.Add(1)
	d.stats.live.Add(1)
	return p, nil
}

// emit writes the decision to the sink, if there is one.
//
// A sink failure is counted and never returned, for the reason
// EventPipeline.emit gives: recording what was decided and acting on it are
// different responsibilities with different failure modes, and an audit sink
// that cannot write must not be able to stop governance — that would turn a
// full disk into an outage.
func (d *Dispatcher) emit(ctx context.Context, dec *decision.Decision) {
	if dec == nil || d.sink == nil {
		return
	}
	if err := d.sink.Emit(ctx, *dec); err != nil {
		d.stats.sinkErrors.Add(1)
	}
}

// AcceptsEvents reports whether a session in state s may have events routed to
// it.
//
// Active and suspended, and nothing else. The rule is that a session accepts
// events exactly when a governed process tree exists under it:
//
//   - pending, awaiting_approval, ready have no tree. Start is what supplies
//     the root PID, so an event naming one of these sessions is misattribution
//     rather than early telemetry, and processing it would charge a budget
//     against a session that had not begun.
//   - active is the ordinary case.
//   - suspended accepts, deliberately. Suspension pauses the agent, not
//     governance. Events observed while a tree is stopped are either genuinely
//     in flight — submitted before the stop landed — or evidence that the tree
//     did not actually stop, and the second is precisely the event that must
//     not be discarded. Refusing them would make suspension a hole in the
//     record exactly when scrutiny is highest.
//   - completed, terminated, failed have no tree any more, and their Summary
//     has already been captured. Recording into them would mutate a session
//     record that has been reported on, which is the same disagreement between
//     the record and the world that an illegal transition creates.
//
// Exported and declared here, beside the transition table, for the reason
// Allowed is: a caller working it out from the state enum would be re-deriving
// it, and two derivations of one rule eventually disagree.
func AcceptsEvents(s State) bool {
	return s == StateActive || s == StateSuspended
}

// DispatchStats reports what routing did and, more importantly, what it could
// not do.
//
// The four refusal counters are the honest half. Every one of them is an event
// the kernel observed that produced no decision, and a nonzero value qualifies
// every conclusion drawn from the audit stream for that period — the same way
// Outcome.TelemetryComplete qualifies a session. They are reported rather than
// logged because a number a caller can assert on is the only form in which
// "some events were not governed" survives into a test.
type DispatchStats struct {
	// EventsObserved is every event handed to the dispatcher, routed or not.
	// The denominator for everything below.
	EventsObserved uint64 `json:"events_observed"`

	// EventsRouted reached a processor and produced a decision.
	EventsRouted uint64 `json:"events_routed"`

	// Unidentified carried no session ID. A decoder or attribution fault: no
	// session ID means no envelope, and no envelope means nothing to judge the
	// event against.
	Unidentified uint64 `json:"unidentified"`

	// Unattributed named a session the registry does not hold. On a live host
	// this is misattribution — most likely PID reuse, which M6's ProcessTracker
	// keyed on (PID, StartTime) exists to prevent.
	Unattributed uint64 `json:"unattributed"`

	// NotAccepting named a session that exists but is not active or suspended.
	// Late telemetry from a tree that has exited, most of the time.
	NotAccepting uint64 `json:"not_accepting"`

	// FactoryErrors are sessions whose processor could not be built. Their
	// events are lost to analysis, which is why this is not folded into the
	// next one.
	FactoryErrors uint64 `json:"factory_errors"`

	// ProcessorErrors are events a processor refused. An ordinary stage failure
	// is not one of these: a pipeline turns that into an explicit indeterminate
	// decision and returns it, so it lands in EventsRouted. Reaching here means
	// the processor could not produce even that.
	ProcessorErrors uint64 `json:"processor_errors"`

	// SinkErrors are decisions that were made but could not be recorded.
	SinkErrors uint64 `json:"sink_errors"`

	// SessionsSeen is how many distinct sessions have had a processor built.
	SessionsSeen uint64 `json:"sessions_seen"`

	// SessionsLive is how many processors are currently held.
	SessionsLive int `json:"sessions_live"`
}

// dispatchStats is the mutable half. Atomics rather than a lock because the
// writer is the dispatch goroutine and the readers are whoever asks — a status
// query, a test — which is the arrangement MemoryState's counters already use.
type dispatchStats struct {
	observed        atomic.Uint64
	routed          atomic.Uint64
	unidentified    atomic.Uint64
	unattributed    atomic.Uint64
	notAccepting    atomic.Uint64
	factoryErrors   atomic.Uint64
	processorErrors atomic.Uint64
	sinkErrors      atomic.Uint64
	built           atomic.Uint64
	live            atomic.Int64
}

func (s *dispatchStats) snapshot() DispatchStats {
	return DispatchStats{
		EventsObserved:  s.observed.Load(),
		EventsRouted:    s.routed.Load(),
		Unidentified:    s.unidentified.Load(),
		Unattributed:    s.unattributed.Load(),
		NotAccepting:    s.notAccepting.Load(),
		FactoryErrors:   s.factoryErrors.Load(),
		ProcessorErrors: s.processorErrors.Load(),
		SinkErrors:      s.sinkErrors.Load(),
		SessionsSeen:    s.built.Load(),
		SessionsLive:    int(s.live.Load()),
	}
}

// TODO(session): decide what a governed host does with an unroutable event
// beyond counting it. It cannot become a decision — there is no envelope to
// judge it against, and fabricating one would be granting capabilities nobody
// authorized — but "we observed something we could not attribute" is a
// governance finding in its own right, and today it reaches nobody but a status
// query. The shape it probably wants is an envelope-less record on the audit
// stream, which needs the unscored-decision wire format (M4 issue 3c) settled
// first, since such a record has no risk assessment either.
// TODO(session): cross-session parallelism. Deliberately not here: it needs a
// queue and a worker per session, and a bounded queue needs an overflow policy,
// which is the end-to-end backpressure decision M6 owns. Until then a
// dispatcher is one stream on one goroutine, which is also what makes each
// session's single-writer guarantee true by construction rather than by lock.
// TODO(session): report per-session pipeline stats through the dispatcher.
// It holds every live processor, so it is the only place that could aggregate
// them, but pipeline.Stats is internal/pipeline's type and naming it here would
// undo the import boundary EventProcessor exists to keep.
