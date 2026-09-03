package pipeline

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"sync/atomic"
	"time"

	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// EventPipeline is the composition of the deterministic stages.
//
// # Scope: one pipeline governs one session
//
// A pipeline is bound to a single envelope, mode, and session state, and
// processes that session's events serially on the goroutine that calls it. That
// is not a simplification to be undone later -- it is what turns
// session.MemoryState's single-writer *assumption* into an actual guarantee.
// MemoryState takes no lock on the hot path because the architecture promises
// one writer per session; this is the component that has to keep the promise,
// and it keeps it by construction rather than by discipline.
//
// Cross-session parallelism is therefore a question of running several
// pipelines, one per session, which is session.Manager's job and is not
// implemented. Builder.WithConcurrency refuses anything above one rather than
// accepting a number it would silently ignore.
//
// # Order, and why
//
//	validate --> [score] --> decide --> commit
//	  reads state          reads verdict   writes state
//
// The stages read; the pipeline writes; the write happens last. Three separate
// reasons converge on that ordering, and only the first is obvious:
//
//  1. **Budgets stay inclusive.** The counters a stage reads describe the
//     session up to but excluding the event under judgment, so the Nth use of a
//     MaxCount-N grant sees N-1 recorded uses and is allowed. Recording first
//     would spend the budget on the event being judged and cost every grant one
//     use.
//
//  2. **Novelty survives.** risk.History reports whether a target was seen
//     before. If the event were recorded before scoring, every target would
//     already be familiar by the time a scorer asked, and "first write to a new
//     file" -- the signal -- would be unobservable. This is why commit sits after
//     the whole stage list rather than immediately after validation, even
//     though policy itself reads no state today.
//
//  3. **One writer, one place.** Recording is not a Stage. A stage list is
//     caller-supplied, and a caller who omitted the recording stage would get a
//     pipeline that silently never charges a budget. Making it the pipeline's
//     own obligation means it cannot be left out, and it runs even when a stage
//     failed.
//
// EventPipeline is safe to construct once and call from one goroutine. Stats is
// safe from any goroutine.
type EventPipeline struct {
	session Session
	stages  []Stage
	handler ErrorHandler
	sink    decision.Sink

	// now is injectable so latency and fallback timestamps are testable without
	// sleeping, and so a replayed session produces a reproducible record.
	now func() time.Time

	stats *statsCollector
}

var _ Pipeline = (*EventPipeline)(nil)

// Errors reported for inputs that make processing meaningless. They are errors
// rather than indeterminate decisions because a caller that cannot supply an
// event has a wiring bug, not a governance finding.
var (
	ErrNoEvent   = errors.New("pipeline: event is required")
	ErrNoSource  = errors.New("pipeline: event source is required")
	ErrNoOutcome = errors.New("pipeline: no stage produced a policy outcome")
)

// Process handles a single event synchronously and returns the decision.
//
// The returned error is reserved for misuse -- a nil event. A stage failure is
// *handled*, not propagated: that is the entire purpose of ErrorHandler, and
// returning an error here instead would hand the caller a dropped event and no
// record, which is the outcome the error handling exists to prevent. A nil
// decision with a nil error means the handler chose to emit no record; the
// event was still counted.
func (p *EventPipeline) Process(ctx context.Context, e *event.Event) (*decision.Decision, error) {
	pc, err := p.ProcessContext(ctx, e)
	if err != nil {
		return nil, err
	}
	return pc.Decision, nil
}

// ProcessContext is Process with the working detail kept.
//
// Process returns the audit record, which is what a daemon needs and all it
// needs. Analysis tools need more: `allseerctl policy dry-run` reports the
// violation list and whether the matched rule was terminal, neither of which a
// Decision carries, and it reports them precisely because it does not emit a
// Decision -- publishing one with no risk stage would state a score of zero as
// though it had been assessed.
//
// Returning the context rather than adding an observer callback keeps the data
// flow explicit: there is no hook to register, nothing runs out of band, and a
// caller reads the same value the stages wrote.
func (p *EventPipeline) ProcessContext(ctx context.Context, e *event.Event) (*ProcessingContext, error) {
	if e == nil {
		return nil, ErrNoEvent
	}

	started := p.now()
	pc := &ProcessingContext{
		Event:     e,
		SessionID: p.session.ID,
		Started:   started,
		Envelope:  p.session.Envelope,
		Mode:      p.session.Mode,
		State:     p.session.State,
	}

	stage, err := p.runStages(ctx, pc)

	if err == nil && pc.Outcome == nil {
		// Every path has to end in an action. A pipeline whose stage list never
		// reached policy cannot say what should happen, and reporting the zero
		// Action ("") would put an unreadable value into the audit log rather
		// than an admission that nothing decided.
		stage, err = "finalize", ErrNoOutcome
	}

	if err != nil {
		pc.FailedStage, pc.Err = stage, err
		p.stats.error()
		pc.Decision = p.handler.Handle(ctx, pc, stage, err)
	} else {
		pc.Decision = p.finalize(pc)
	}

	p.commit(pc)
	p.stats.observe(p.now().Sub(started), pc.Decision != nil)
	return pc, nil
}

// runStages executes the stage list in order, stopping at the first failure and
// naming the stage that produced it.
func (p *EventPipeline) runStages(ctx context.Context, pc *ProcessingContext) (string, error) {
	for _, s := range p.stages {
		start := p.now()
		err := execute(ctx, s, pc)
		p.stats.observeStage(s.Name(), p.now().Sub(start))
		if err != nil {
			return s.Name(), err
		}
	}
	return "", nil
}

// execute runs one stage with panic recovery.
//
// A panic in a stage becomes an ordinary stage error and travels the same route
// as any other failure. The alternative -- letting it unwind -- would end
// governance for the session, and in a daemon governing several sessions it
// would end governance for all of them, because one scorer mishandled one
// malformed path.
//
// TODO(pipeline): the panic value survives into the decision's reasoning but
// the stack does not, and a stack is the only practical way to find the cause.
// It belongs in diagnostic logging rather than in an audit record; wire it when
// internal/logging exists.
func execute(ctx context.Context, s Stage, pc *ProcessingContext) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("stage panicked: %v", r)
		}
	}()
	return s.Execute(ctx, pc)
}

// commit folds the event into the session state.
//
// Always runs, including after a stage failure, and always last. The single
// writer to a session's counters is here and nowhere else.
func (p *EventPipeline) commit(pc *ProcessingContext) {
	if pc.State == nil {
		return
	}

	// A grant is charged only when it actually covered the operation. A
	// grant_exceeded result still names the grant it ran out of, and charging
	// that would keep spending a budget the operation was already refused.
	// Gated on the validation rather than on whether a later stage failed: that
	// the envelope covered this event is a fact the validator established, and
	// a policy failure afterwards does not unmake it.
	if v := pc.Validation; v != nil &&
		v.Verdict == decision.VerdictWithinEnvelope && v.MatchedGrant != nil {
		pc.State.RecordGrantUse(v.MatchedGrantIndex)
	}

	// The event is counted whatever happened upstream. It is a record of what
	// the kernel observed, and a stage failure is a fault in our analysis
	// rather than evidence the agent did less -- the same reasoning that makes
	// an unresolvable write still charge the write budget.
	pc.State.RecordEvent(pc.Event)

	if pc.Decision != nil {
		pc.State.RecordDecision(pc.Decision)
	}
}

// finalize assembles the decision from what the stages established.
//
// Assembly, not judgment: every field is copied from a stage's conclusion. The
// one thing decided here is what to do about evidence that was never produced,
// and the answer is to say so rather than to supply a plausible value.
func (p *EventPipeline) finalize(pc *ProcessingContext) *decision.Decision {
	d := &decision.Decision{
		ID:          decisionID(pc),
		SessionID:   pc.SessionID,
		EventID:     pc.Event.ID,
		Timestamp:   p.timestampOf(pc),
		Action:      pc.Outcome.Action,
		Verdict:     pc.Validation.Verdict,
		MatchedRule: pc.Outcome.RuleID,

		// Enforcement is M12. False is not a placeholder here, it is the truth:
		// no decision.Enforcer exists, so nothing was applied. A "block" that
		// reads as though it stopped something is the specific dishonesty
		// Decision.Enforced was added to prevent.
		Enforced: false,
	}

	// MatchedGrant is what covered the operation, so it is carried only when
	// something did. The validator already withholds it from a denied result
	// for the same reason.
	if pc.Validation.Verdict == decision.VerdictWithinEnvelope {
		d.MatchedGrant = pc.Validation.MatchedGrant
	}

	d.Reasoning = append(d.Reasoning, pc.Validation.Reasoning...)

	if pc.Risk != nil {
		d.Risk = *pc.Risk
	} else {
		// Decision.Risk is a value, so an unscored event publishes a zero
		// assessment no matter what. What keeps that from reading as an
		// assessment is Level: "" is not a member of decision.AllLevels, so a
		// consumer can tell unscored from scored-none. The reasoning says it in
		// words as well, because a reader should not have to know that.
		d.Reasoning = append(d.Reasoning, decision.ReasoningStep{
			Stage:      "risk",
			Conclusion: "not assessed",
			Detail: "no risk stage ran, so this decision carries no score; " +
				"an empty risk level is absence of evidence, not a low score",
		})
	}

	d.Reasoning = append(d.Reasoning, pc.Outcome.Reasoning...)
	d.Latency = p.now().Sub(pc.Started)
	return d
}

// timestampOf dates the decision by the event's own wall clock where it has
// one.
//
// The same rule the validator applies to envelope expiry, for the same reason:
// a recorded session replayed later must produce the record it produced live,
// and stamping today's date on an archived event would make every replayed
// decision disagree with the one it is supposed to reproduce.
func (p *EventPipeline) timestampOf(pc *ProcessingContext) time.Time {
	if !pc.Event.WallClock.IsZero() {
		return pc.Event.WallClock
	}
	return p.now()
}

// decisionID derives a stable identifier from the event.
//
// Deterministic on purpose. A random identifier would make two runs of the same
// recording produce different audit records, which breaks the evaluation corpus
// and every regression test built on replay. The event's own ID is preferred
// because it is what ties the decision back to the record it was made about.
func decisionID(pc *ProcessingContext) string {
	if pc.Event.ID != "" {
		return "d-" + pc.Event.ID
	}
	return fmt.Sprintf("d-%s-%d", pc.SessionID, pc.Event.Sequence)
}

// Run consumes the source until it closes or ctx is cancelled.
//
// The source must already be started. Lifecycle stays with the caller because
// the failure it reports is categorically different: "probes could not attach"
// is a startup fault the daemon has to surface loudly and refuse to run under,
// while anything Run returns is a processing fault. Folding them together would
// make a blind spot look like a hiccup.
func (p *EventPipeline) Run(ctx context.Context, src event.Source) error {
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
			d, err := p.Process(ctx, &e)
			if err != nil {
				return err
			}
			p.emit(ctx, d)
		}
	}
}

// emit writes the decision to the audit sink, if there is one.
//
// A sink failure is counted and never returned. Recording what was decided and
// acting on it are different responsibilities with different failure modes, and
// an audit sink that cannot write must not be able to stop the pipeline: that
// would turn a full disk into a governance outage.
func (p *EventPipeline) emit(ctx context.Context, d *decision.Decision) {
	if d == nil || p.sink == nil {
		return
	}
	if err := p.sink.Emit(ctx, *d); err != nil {
		p.stats.error()
	}
}

// Stats reports pipeline health. Safe to call from any goroutine.
func (p *EventPipeline) Stats() Stats { return p.stats.snapshot() }

// --- statistics --------------------------------------------------------------

// latencyWindow is how many recent event latencies P99 is computed over.
//
// Bounded because a per-session pipeline outlives its own history: keeping
// every latency would make memory a function of session length, the same
// problem session history has. A window rather than a full histogram because
// the question this answers is "is the pipeline slow *now*", and a number
// averaged over a session that started fast hides exactly the regression worth
// seeing.
const latencyWindow = 1024

// statsCollector accumulates pipeline metrics.
//
// Single writer, atomic counters, no lock -- the same arrangement
// session.MemoryState uses and for the same reason. The latency ring is a slice
// of atomics rather than a mutex-guarded buffer so that Stats stays callable
// from a health endpoint without putting a lock on the hot path.
type statsCollector struct {
	events    atomic.Uint64
	decisions atomic.Uint64
	errors    atomic.Uint64

	totalLatency atomic.Uint64

	// stages is keyed at construction from the stage list and never written to
	// afterwards, which is what makes it readable without synchronization.
	stages map[string]*stageStat

	ring     []atomic.Uint64
	ringNext atomic.Uint64
}

type stageStat struct {
	total atomic.Uint64
	count atomic.Uint64
}

func newStatsCollector(stages []Stage) *statsCollector {
	c := &statsCollector{
		stages: make(map[string]*stageStat, len(stages)),
		ring:   make([]atomic.Uint64, latencyWindow),
	}
	for _, s := range stages {
		c.stages[s.Name()] = &stageStat{}
	}
	return c
}

func (c *statsCollector) observe(d time.Duration, emitted bool) {
	c.events.Add(1)
	if emitted {
		c.decisions.Add(1)
	}
	if d < 0 {
		d = 0
	}
	c.totalLatency.Add(uint64(d))

	i := c.ringNext.Add(1) - 1
	c.ring[i%uint64(len(c.ring))].Store(uint64(d))
}

func (c *statsCollector) observeStage(name string, d time.Duration) {
	s := c.stages[name]
	if s == nil || d < 0 {
		return
	}
	s.total.Add(uint64(d))
	s.count.Add(1)
}

func (c *statsCollector) error() { c.errors.Add(1) }

func (c *statsCollector) snapshot() Stats {
	events := c.events.Load()

	st := Stats{
		EventsProcessed: events,
		DecisionsIssued: c.decisions.Load(),
		Errors:          c.errors.Load(),
		StageLatencies:  make(map[string]time.Duration, len(c.stages)),

		// QueueDepth is genuinely zero rather than unmeasured: Process is
		// synchronous and Run holds no buffer of its own, so an event is either
		// being processed or has not been read from the source yet. It becomes
		// a real number when cross-session dispatch introduces a queue.
		QueueDepth: 0,
	}

	if events > 0 {
		st.AvgLatency = time.Duration(c.totalLatency.Load() / events)
	}
	for name, s := range c.stages {
		if n := s.count.Load(); n > 0 {
			st.StageLatencies[name] = time.Duration(s.total.Load() / n)
		}
	}
	st.P99Latency = c.percentile(0.99)
	return st
}

// percentile computes a latency quantile over the recent window.
//
// Sorting happens here rather than on the hot path, so the cost falls on
// whoever asks for the number instead of on every governed syscall.
func (c *statsCollector) percentile(q float64) time.Duration {
	n := int(c.ringNext.Load())
	if n > len(c.ring) {
		n = len(c.ring)
	}
	if n == 0 {
		return 0
	}

	samples := make([]uint64, 0, n)
	for i := 0; i < n; i++ {
		samples = append(samples, c.ring[i].Load())
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })

	idx := int(math.Ceil(q*float64(n))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= n {
		idx = n - 1
	}
	return time.Duration(samples[idx])
}

// --- construction --------------------------------------------------------------

// Config holds what a pipeline needs beyond its stages.
//
// Separate from Builder's fluent methods because these are properties of the
// pipeline's identity rather than of its composition, and because leaving the
// declared Builder interface untouched is worth more than uniformity: a
// component that grows an interface to fit its first implementation is a
// component whose interface stopped meaning anything.
type Config struct {
	// Session is what this pipeline governs. Required.
	Session Session

	// Sink receives every decision from Run. Optional: a nil sink means
	// decisions are returned but not audited, which is what replay-based
	// analysis wants and what a daemon must not do.
	Sink decision.Sink

	// Now supplies the clock for latency and for the fallback decision
	// timestamp. Nil means time.Now.
	Now func() time.Time
}

type builder struct {
	cfg         Config
	stages      []Stage
	handler     ErrorHandler
	concurrency int
}

var _ Builder = (*builder)(nil)

// NewBuilder starts assembling a pipeline for one session.
func NewBuilder(cfg Config) Builder {
	return &builder{cfg: cfg, concurrency: 1}
}

func (b *builder) WithStage(s Stage) Builder {
	b.stages = append(b.stages, s)
	return b
}

func (b *builder) WithErrorHandler(h ErrorHandler) Builder {
	b.handler = h
	return b
}

func (b *builder) WithConcurrency(n int) Builder {
	b.concurrency = n
	return b
}

// Build validates the assembly and produces the pipeline.
func (b *builder) Build() (Pipeline, error) {
	if b.cfg.Session.Envelope == nil {
		return nil, errors.New("pipeline: session envelope is required")
	}
	if b.cfg.Session.State == nil {
		// Not defaulted to a throwaway state. A pipeline whose counters go
		// nowhere evaluates every budget against zero forever, which reads as a
		// session that never spends anything -- indistinguishable in the output
		// from a session that genuinely did not.
		return nil, errors.New("pipeline: session state is required")
	}
	if b.cfg.Session.Mode == "" {
		return nil, errors.New("pipeline: session mode is required")
	}
	if len(b.stages) == 0 {
		return nil, errors.New("pipeline: at least one stage is required")
	}
	for i, s := range b.stages {
		if s == nil {
			return nil, fmt.Errorf("pipeline: stage %d is nil", i)
		}
		if s.Name() == "" {
			return nil, fmt.Errorf("pipeline: stage %d has no name", i)
		}
	}
	if b.concurrency > 1 {
		// Refused rather than ignored. A pipeline is bound to one session and
		// processes it serially, which is what makes the session state's
		// single-writer guarantee real; running several sessions in parallel
		// means several pipelines, and deciding which event belongs to which is
		// session.Manager's job. Accepting the number and running serially
		// anyway would promise throughput that is not there.
		return nil, fmt.Errorf(
			"pipeline: concurrency %d requested, but a pipeline governs one session and processes it serially; "+
				"run one pipeline per session instead", b.concurrency)
	}

	sess := b.cfg.Session
	if sess.ID == "" {
		sess.ID = sess.Envelope.SessionID
	}

	handler := b.handler
	if handler == nil {
		handler = NewErrorHandler()
	}
	now := b.cfg.Now
	if now == nil {
		now = time.Now
	}

	return &EventPipeline{
		session: sess,
		stages:  b.stages,
		handler: handler,
		sink:    b.cfg.Sink,
		now:     now,
		stats:   newStatsCollector(b.stages),
	}, nil
}

// New assembles the unscored pipeline: validate, then decide.
//
// The sequence cmd/allseerctl's dry-run wrote out by hand, which is the
// reference this package was built to replace, and it is kept exactly as it was
// so that reference stays checkable. A pipeline built here leaves
// ProcessingContext.Risk nil, which policy reads as "no evidence" -- every
// risk-conditioned rule is inert under it, visibly rather than silently.
//
// Prefer NewWithRisk. This constructor is for the equivalence test that pins the
// stage list against the original hand-written loop, and for a caller that
// deliberately wants validation semantics with nothing scored.
func New(cfg Config, v Validator, e PolicyEngine) (*EventPipeline, error) {
	p, err := NewBuilder(cfg).
		WithStage(NewValidateStage(v)).
		WithStage(NewDecideStage(e)).
		Build()
	if err != nil {
		return nil, err
	}
	return p.(*EventPipeline), nil
}

// NewWithRisk assembles the full deterministic pipeline: validate, score, decide.
//
// The composition the ordering note at the top of this file describes, and the
// one a daemon should run. Adding the score stage changed nothing else here,
// which was the point of putting commit after the whole stage list rather than
// after validation: the scorer reads the session history as it stood before this
// event, so a target the agent is touching for the first time still reads as
// novel.
func NewWithRisk(cfg Config, v Validator, r RiskEngine, e PolicyEngine) (*EventPipeline, error) {
	p, err := NewBuilder(cfg).
		WithStage(NewValidateStage(v)).
		WithStage(NewScoreStage(r)).
		WithStage(NewDecideStage(e)).
		Build()
	if err != nil {
		return nil, err
	}
	return p.(*EventPipeline), nil
}

// ActionForFailure is the action the default error handler assigns when the
// pipeline itself could not reach a conclusion.
//
// Asking a human is the conservative answer to "the governance system broke",
// and it is deliberately not the envelope's DefaultAction: that field describes
// what to do about an *observation* the envelope did not account for, which is
// a statement about the agent. A stage failure is a statement about us, and
// borrowing the envelope's posture for it would silently give the envelope a
// second meaning nothing else in the system reads it as having.
//
// In monitor and warn modes nothing is applied regardless, and Enforced stays
// false everywhere until M12, so this is a reporting posture today.
const ActionForFailure = ece.ActionRequestApproval
