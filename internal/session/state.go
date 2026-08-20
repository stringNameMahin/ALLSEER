package session

import (
	"fmt"
	"math"
	"sort"
	"sync/atomic"
	"time"

	"github.com/stringNameMahin/ALLSEER/internal/risk"
	"github.com/stringNameMahin/ALLSEER/internal/validator"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// This file holds the mutable state of a session: the counters the validator
// reads to decide whether a budget is spent, the history the risk engine reads
// to decide whether behavior is novel, and the aggregate a human reads
// afterwards. It is the only place in the deterministic core where anything
// accumulates.
//
// # Ownership
//
// Exactly one goroutine writes a session's state — the pipeline worker that
// processes that session's events serially. That is an architectural guarantee
// rather than a convention (see internal/pipeline: ordering within a session is
// preserved, which requires a single processor), and it is what lets this type
// avoid a mutex on the hot path. A lock here would be taken and released on
// every syscall the agent makes, to protect against a second writer the design
// does not permit.
//
// Readers fall into two classes, with different guarantees, both stated
// explicitly because a reader that guesses wrong gets a data race rather than a
// wrong answer:
//
//   - Counters — everything reachable through validator.SessionState, plus
//     CapabilityCount, ViolationCount, BlockedCount, DroppedEvents and
//     TelemetryComplete — are backed by atomics and may be read from any
//     goroutine. They cost the writer nothing extra (a single-writer atomic add
//     needs no contention handling) and they are what a daemon status query
//     wants. Each is individually consistent; a reader sampling several is not
//     guaranteed to see them from the same instant, which is fine for reporting
//     and is why nothing on the decision path samples more than one.
//
//   - Structures — SeenTargets, TargetSeen, RecentEvents, Snapshot,
//     UnusedGrantIndexes — are read on the owner goroutine only. They are backed
//     by a map and a ring buffer, and giving them the same freedom would mean
//     either copying on every event or locking on every read, both of which buy
//     nothing the design needs today. The decision path reads them from the
//     owner goroutine, which is where they are already safe.
//
// # Ordering
//
// Record* is called after the event has been validated and decided, never
// before. That is what makes an inclusive limit inclusive: validating the Nth
// use of a MaxCount-N grant reads N-1 recorded uses and allows it; the (N+1)th
// reads N and is refused. Recording first would spend the budget on the event
// being judged and cost every grant one use.

const (
	// DefaultHistorySize is how far back RecentEvents can reach.
	//
	// The bound exists because history is per session and sessions are
	// long-lived: an agent building a large project emits events for minutes,
	// and keeping all of them would make memory a function of how long the user
	// waited. The number is chosen from what the history is *for* — the
	// credential-access-then-egress sequence detector (internal/risk), which
	// needs the read and the connection to fall inside one window even when a
	// build's file traffic separates them. A few hundred events covers the
	// compile-and-link burst between them; a few dozen does not, and a detector
	// whose window is routinely too short reports nothing while appearing to
	// work.
	//
	// The cost is bounded and small: 256 events at the size of an event.Event
	// plus its retained payload is on the order of a hundred kilobytes per
	// session, which is the right side of the trade against a leak.
	//
	// Revisit when the sequence detector exists and its window can be measured
	// against a labeled corpus rather than reasoned about. Until then this is a
	// documented estimate, not a tuned value.
	DefaultHistorySize = 256

	// DefaultMaxSeenTargets bounds the novelty set.
	//
	// Unlike the ring, this set cannot forget: novelty is a claim about the
	// whole session, so evicting an entry would make a file the agent touched an
	// hour ago look new. The bound is therefore a ceiling on distinct targets
	// rather than a window, and what happens at the ceiling is chosen for the
	// direction it fails in: new targets stop being recorded, so they keep
	// reporting as unseen, so they keep reading as novel and raising scrutiny.
	// The alternative — reporting an unrecorded target as familiar — would let a
	// session past the ceiling launder every subsequent access.
	DefaultMaxSeenTargets = 4096
)

// MemoryState is the in-memory implementation of State_.
//
// It satisfies validator.SessionState and risk.History, so those modules read
// what they need through their own narrow interfaces without depending on this
// package. See the ownership notes at the top of this file before calling it
// from a goroutine other than the session's writer.
//
// The zero value is not usable; use NewState or NewStateWith. A nil
// *MemoryState is usable and reports the state of a session with no history:
// every counter zero, nothing seen, no budget spent. That is deliberate and
// matches what the validator already does with a nil SessionState — an absent
// history means nothing has been spent, never that everything has.
type MemoryState struct {
	// --- immutable after construction ---------------------------------------

	sessionID string

	// envelope is read for grant metadata only and is never modified. It is
	// sealed by the time a session runs, and widening it from here would be the
	// exact failure sealing exists to prevent.
	envelope *ece.Envelope

	now func() time.Time

	maxSeenTargets int

	// --- counters: written by the owner, readable from any goroutine ---------
	//
	// One exception, and it is here rather than buried at the field: startNanos
	// and hostClock are also written by SetStartedAt, which the session
	// lifecycle manager calls from whichever goroutine drives the lifecycle —
	// not the event writer. Both are atomic and the write happens once, guarded
	// by a compare-and-swap, so the two writers cannot interleave into a
	// half-set start. Nothing else here has a second writer.

	// hostClock selects what measures elapsed time; see ElapsedSeconds. Set at
	// construction from Config.StartedAt, or later by SetStartedAt.
	hostClock atomic.Bool

	startNanos  atomic.Int64
	latestNanos atomic.Int64

	eventsObserved  atomic.Uint64
	decisionsIssued atomic.Uint64
	droppedEvents   atomic.Uint64

	fileWrites       atomic.Int64
	processStarts    atomic.Int64
	networkBytesSent atomic.Int64
	violations       atomic.Int64
	blocked          atomic.Int64

	// peakRiskBits holds a float64 in its IEEE-754 bit pattern, which is how a
	// float is made atomic without a lock.
	peakRiskBits atomic.Uint64

	// grantUses is indexed by position in Envelope.Grants and sized once at
	// construction. A sealed envelope cannot grow a grant, so the slice never
	// resizes and an index is a bounds check rather than a map lookup on the hot
	// path.
	grantUses []atomic.Int64

	// capabilityUses is keyed by the closed Kind enum and fully populated at
	// construction. Because no key is ever added or removed afterwards, the map
	// is safe to read concurrently while the counters behind it advance.
	capabilityUses map[capability.Kind]*atomic.Int64

	// --- structures: owner goroutine only ------------------------------------

	seen     map[seenKey]struct{}
	seenFull bool

	ring     []event.Event
	ringNext int
	ringLen  int

	violationTally map[violationKey]int
}

type seenKey struct {
	kind   capability.Kind
	target string
}

type violationKey struct {
	verdict decision.Verdict
	rule    string
}

var (
	_ State_                 = (*MemoryState)(nil)
	_ validator.SessionState = (*MemoryState)(nil)
	_ risk.History           = (*MemoryState)(nil)
)

// Config parameterizes a MemoryState.
type Config struct {
	SessionID string

	// Envelope is the sealed envelope governing the session. It sizes the
	// per-grant counters and supplies the grant list the unused-grant report is
	// computed against. A nil envelope yields a state with no grant budgets,
	// which is what a caller validating without one already gets.
	Envelope *ece.Envelope

	// StartedAt is when the session began, as the daemon that created it
	// measured it. Leaving it zero puts the state on the stream clock; see
	// ElapsedSeconds.
	StartedAt time.Time

	// Now supplies the host clock. Injectable so duration is testable without
	// sleeping. Nil means time.Now.
	Now func() time.Time

	// HistorySize is the depth of the RecentEvents ring. Zero means
	// DefaultHistorySize; negative disables history, which a deployment that
	// runs no sequence detector may legitimately want.
	HistorySize int

	// MaxSeenTargets bounds the novelty set. Zero means DefaultMaxSeenTargets.
	// Negative disables the set, in which case every target reports as unseen.
	MaxSeenTargets int
}

// NewState returns tracking state for a session governed by env.
func NewState(sessionID string, env *ece.Envelope) *MemoryState {
	return NewStateWith(Config{SessionID: sessionID, Envelope: env})
}

// NewStateWith returns tracking state configured by cfg.
func NewStateWith(cfg Config) *MemoryState {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	historySize := cfg.HistorySize
	switch {
	case historySize == 0:
		historySize = DefaultHistorySize
	case historySize < 0:
		historySize = 0
	}

	maxTargets := cfg.MaxSeenTargets
	switch {
	case maxTargets == 0:
		maxTargets = DefaultMaxSeenTargets
	case maxTargets < 0:
		maxTargets = 0
	}

	var grants int
	if cfg.Envelope != nil {
		grants = len(cfg.Envelope.Grants)
	}

	s := &MemoryState{
		sessionID:      cfg.SessionID,
		envelope:       cfg.Envelope,
		now:            now,
		maxSeenTargets: maxTargets,
		grantUses:      make([]atomic.Int64, grants),
		capabilityUses: make(map[capability.Kind]*atomic.Int64, len(capability.AllKinds())),
		seen:           make(map[seenKey]struct{}),
		ring:           make([]event.Event, historySize),
		violationTally: make(map[violationKey]int),
	}

	// Populated for every known Kind up front so the map is never written after
	// construction. That is what makes it readable without synchronization while
	// the session runs.
	for _, k := range capability.AllKinds() {
		s.capabilityUses[k] = new(atomic.Int64)
	}

	if !cfg.StartedAt.IsZero() {
		s.hostClock.Store(true)
		s.startNanos.Store(cfg.StartedAt.UnixNano())
	}
	return s
}

// SessionID reports which session this state belongs to.
func (s *MemoryState) SessionID() string {
	if s == nil {
		return ""
	}
	return s.sessionID
}

// --- writes -----------------------------------------------------------------

// RecordEvent folds an observed event into the session's counters and history.
//
// The single writer for a session's mutable state, and the one that has to
// agree with the validator about what it is counting. It classifies the event
// through validator.ObservationOf — the same bridge the validator uses — so the
// Kind charged to a budget is the Kind the budget check will ask about, and
// then charges the budgets through validator.ModifiesFilesystem and
// validator.SpawnsProcess rather than restating either set.
//
// An event that cannot be resolved to an observation still counts. Its
// capability is known from the decode even when its target is not, and a write
// whose path enrichment failed on is still a write: skipping it would make
// unresolvability a way to spend a budget for free, which is the same failure
// the validator refuses when it stops at indeterminate rather than at allowed.
// What it does not do is record a target it never learned.
func (s *MemoryState) RecordEvent(e *event.Event) {
	if s == nil || e == nil {
		return
	}

	s.eventsObserved.Add(1)
	if e.Dropped > 0 {
		// Loss is recorded, not inferred later. A conclusion drawn across a hole
		// in the stream is unsound, and the session outcome has to be able to
		// say so.
		s.droppedEvents.Add(e.Dropped)
	}
	s.advanceClock(e.WallClock)

	obs, err := validator.ObservationOf(e)
	kind := obs.Kind
	if kind == "" {
		kind = e.Capability
	}

	// A Kind outside the catalog is a decode defect rather than a new
	// capability. It is counted in EventsObserved, which is the honest total,
	// but not given a usage entry: inventing a table entry here would hide the
	// defect behind a plausible-looking count.
	if c := s.capabilityUses[kind]; c != nil {
		c.Add(1)
	}

	if validator.ModifiesFilesystem(kind) {
		s.fileWrites.Add(1)
	}
	if validator.SpawnsProcess(kind) {
		s.processStarts.Add(1)
	}

	// Egress is read off the payload rather than derived from the Kind: the
	// budget is a byte count, and only the payload knows how many. A capability
	// that sent nothing contributes nothing.
	if e.Network != nil && e.Network.BytesSent > 0 {
		s.networkBytesSent.Add(e.Network.BytesSent)
	}

	if err == nil && obs.Target != "" {
		s.markSeen(kind, obs.Target)
	}

	s.push(e)
}

// RecordDecision folds a rendered decision into the session's counters.
//
// Violations are counted from the verdict rather than from a violation list,
// because the verdict is what a Decision carries and it is already the
// classification the rest of the system reasons about. An unset verdict is not
// counted: it is a wiring bug, and a bug reported as a governance finding is
// worse than a bug reported as nothing.
//
// BlockedCount requires Enforced. A block that was never applied did not
// prevent an operation, and the session summary must not read as though it did.
func (s *MemoryState) RecordDecision(d *decision.Decision) {
	if s == nil || d == nil {
		return
	}

	s.decisionsIssued.Add(1)

	if decision.ValidVerdict(d.Verdict) && d.Verdict != decision.VerdictWithinEnvelope {
		s.violations.Add(1)
		s.violationTally[violationKey{verdict: d.Verdict, rule: d.MatchedRule}]++
	}

	if d.Action == ece.ActionBlock && d.Enforced {
		s.blocked.Add(1)
	}

	s.raisePeak(d.Risk.Score)
}

// RecordGrantUse charges one use against the grant at grantIndex, which is
// validator.Result.MatchedGrantIndex for a result whose MatchedGrant is set.
//
// An index outside the envelope's grants is ignored rather than fatal. It can
// only come from a caller that mismatched a result with a state, and panicking
// on the hot path would end governance for the whole session over an accounting
// error — the wrong trade when the alternative is one uncharged use.
func (s *MemoryState) RecordGrantUse(grantIndex int) {
	if s == nil || grantIndex < 0 || grantIndex >= len(s.grantUses) {
		return
	}
	s.grantUses[grantIndex].Add(1)
}

// --- validator.SessionState --------------------------------------------------

// GrantUseCount reports how many times the grant at grantIndex has been
// exercised. An unknown index reports zero, which reads as "no budget spent" —
// the same thing an absent history reports, and the safe direction for a
// counter the validator compares against a limit.
func (s *MemoryState) GrantUseCount(grantIndex int) int {
	if s == nil || grantIndex < 0 || grantIndex >= len(s.grantUses) {
		return 0
	}
	return int(s.grantUses[grantIndex].Load())
}

// FileWriteCount reports how many filesystem-modifying events were recorded,
// counting exactly the set validator.ModifiesFilesystem names.
func (s *MemoryState) FileWriteCount() int {
	if s == nil {
		return 0
	}
	return int(s.fileWrites.Load())
}

// NetworkBytesSent reports total observed egress in bytes.
func (s *MemoryState) NetworkBytesSent() int64 {
	if s == nil {
		return 0
	}
	return s.networkBytesSent.Load()
}

// ProcessCount reports how many processes the session started, counting exactly
// the set validator.SpawnsProcess names.
func (s *MemoryState) ProcessCount() int {
	if s == nil {
		return 0
	}
	return int(s.processStarts.Load())
}

// ElapsedSeconds reports how long the session has been running.
//
// Which clock measures it is fixed at construction, and the split is the same
// one the validator makes about envelope expiry — a recorded session must reach
// the verdicts it reached live, so an archived stream cannot be measured
// against today.
//
//   - Config.StartedAt set: the host clock measures the session, from the
//     instant the daemon created it. An idle session keeps accruing duration,
//     which is what a MaxDuration constraint means for a live agent.
//   - Config.StartedAt unset: the stream measures itself, from the first
//     recorded event's wall clock to the latest. Deterministic under replay,
//     independent of when the replay happens to run.
//
// Zero until something has fixed a start, and never negative: a clock that
// moved backwards must not produce a session that has not begun.
func (s *MemoryState) ElapsedSeconds() float64 {
	if s == nil {
		return 0
	}
	start := s.startNanos.Load()
	if start == 0 {
		return 0
	}

	end := s.latestNanos.Load()
	if s.hostClock.Load() {
		end = s.now().UnixNano()
	}
	if end <= start {
		return 0
	}
	return float64(end-start) / float64(time.Second)
}

// SetStartedAt fixes the session's start on the host clock.
//
// The lifecycle manager calls this at Start, so that elapsed time in a session
// constraint and elapsed time in the lifecycle record are the same measurement
// rather than two clocks started moments apart. A state constructed with a zero
// Config.StartedAt is on the *stream* clock — elapsed time derived from the
// events themselves — which is what a replay wants and what a session that has
// not begun should report; this switches it to the host clock at the moment the
// agent actually starts.
//
// Ignored for a zero time, and ignored once a start is already fixed. A session
// starts once: allowing a second call would let a long-running session have its
// duration reset, and a duration that can decrease is a spent time budget that
// can come back.
//
// Safe from any goroutine, unlike most of the writes here — the manager calls
// it from whichever goroutine drives the lifecycle, which is not the session's
// event writer.
func (s *MemoryState) SetStartedAt(t time.Time) {
	if s == nil || t.IsZero() {
		return
	}
	if s.startNanos.CompareAndSwap(0, t.UnixNano()) {
		s.hostClock.Store(true)
	}
}

// SeenTargets reports whether this session already touched target with kind.
//
// Owner-goroutine only. An empty target is never recorded and never reported as
// seen: treating an unresolved target as familiar would let an unresolvable
// path launder novelty, which is the signal this exists to provide.
func (s *MemoryState) SeenTargets(kind capability.Kind, target string) bool {
	if s == nil || target == "" {
		return false
	}
	_, ok := s.seen[seenKey{kind: kind, target: target}]
	return ok
}

// --- risk.History ------------------------------------------------------------

// CapabilityCount reports how often a capability was exercised this session.
func (s *MemoryState) CapabilityCount(k capability.Kind) int {
	if s == nil {
		return 0
	}
	c := s.capabilityUses[k]
	if c == nil {
		return 0
	}
	return int(c.Load())
}

// TargetSeen is risk.History's name for SeenTargets. One implementation, so the
// two modules cannot come to disagree about what novelty means.
func (s *MemoryState) TargetSeen(k capability.Kind, target string) bool {
	return s.SeenTargets(k, target)
}

// ViolationCount reports how many decisions carried a verdict other than
// within_envelope.
func (s *MemoryState) ViolationCount() int {
	if s == nil {
		return 0
	}
	return int(s.violations.Load())
}

// RecentEvents returns up to the last n events in chronological order, oldest
// first.
//
// Chronological because the patterns this feeds are sequences: "read a
// credential, then connect outbound" is only recognizable in the order it
// happened. The slice is freshly allocated, so a caller cannot reach back into
// the ring; the events in it share payload pointers with the originals, which
// is safe because an event is immutable once decoded.
//
// Owner-goroutine only.
func (s *MemoryState) RecentEvents(n int) []event.Event {
	if s == nil || n <= 0 || s.ringLen == 0 {
		return nil
	}
	if n > s.ringLen {
		n = s.ringLen
	}

	out := make([]event.Event, 0, n)
	start := (s.ringNext - n + len(s.ring)) % len(s.ring)
	for i := 0; i < n; i++ {
		out = append(out, s.ring[(start+i)%len(s.ring)])
	}
	return out
}

// SessionDurationSeconds is risk.History's name for ElapsedSeconds.
func (s *MemoryState) SessionDurationSeconds() float64 {
	return s.ElapsedSeconds()
}

// --- reporting ---------------------------------------------------------------

// BlockedCount reports how many operations were actually prevented.
func (s *MemoryState) BlockedCount() int {
	if s == nil {
		return 0
	}
	return int(s.blocked.Load())
}

// DroppedEvents reports ring buffer records lost before the events that were
// recorded.
func (s *MemoryState) DroppedEvents() uint64 {
	if s == nil {
		return 0
	}
	return s.droppedEvents.Load()
}

// TelemetryComplete reports whether the event stream had no recorded loss.
//
// False qualifies every conclusion drawn from the session, including the
// conclusion that nothing bad happened, which is why it is reported rather than
// assumed.
func (s *MemoryState) TelemetryComplete() bool {
	return s.DroppedEvents() == 0
}

// PeakRiskScore reports the highest risk score any decision carried.
func (s *MemoryState) PeakRiskScore() float64 {
	if s == nil {
		return 0
	}
	return math.Float64frombits(s.peakRiskBits.Load())
}

// UnusedGrantIndexes lists the positions of non-optional grants never
// exercised, in envelope order.
//
// The precise form of what Summary.UnusedGrants reports as Kinds. A caller that
// needs to name the grant — an approval UI explaining that the envelope asked
// for more than the task used — wants the index, because two grants can share a
// Kind and differ entirely in scope.
//
// Owner-goroutine only.
func (s *MemoryState) UnusedGrantIndexes() []int {
	if s == nil || s.envelope == nil {
		return nil
	}
	var out []int
	for i := range s.envelope.Grants {
		if s.envelope.Grants[i].Optional {
			continue
		}
		if s.grantUses[i].Load() == 0 {
			out = append(out, i)
		}
	}
	return out
}

// Outcome builds the session outcome from what was recorded.
//
// The counters already hold everything Outcome states, and deriving it here
// stops each caller from assembling it slightly differently — in particular
// from computing BlockedCount without the Enforced guard.
func (s *MemoryState) Outcome(reason string) Outcome {
	return Outcome{
		Reason:            reason,
		ViolationCount:    s.ViolationCount(),
		BlockedCount:      s.BlockedCount(),
		TelemetryComplete: s.TelemetryComplete(),
	}
}

// Snapshot returns an immutable view of the session for reporting.
//
// Owner-goroutine only, and a copy: the maps and slices in the returned Summary
// are freshly allocated, so a reporting path can hold one while the session
// keeps running.
func (s *MemoryState) Snapshot() Summary {
	if s == nil {
		return Summary{}
	}

	sum := Summary{
		EventsObserved:  s.eventsObserved.Load(),
		DecisionsIssued: s.decisionsIssued.Load(),
		CapabilityUsage: make(map[capability.Kind]int),
		PeakRiskScore:   s.PeakRiskScore(),
	}

	// Only capabilities actually exercised. A map with 34 keys, 31 of them
	// zero, is a worse report than one with three entries.
	for k, c := range s.capabilityUses {
		if n := c.Load(); n > 0 {
			sum.CapabilityUsage[k] = int(n)
		}
	}

	sum.UnusedGrants = s.unusedGrantKinds()
	sum.TopViolations = s.topViolations()
	return sum
}

// unusedGrantKinds projects UnusedGrantIndexes onto Kinds, deduplicated and in
// envelope order.
//
// The projection is lossy: a Kind granted twice, exercised through one grant
// and not the other, is reported. That is the honest reading of "a non-optional
// grant was never exercised" given a field typed as a Kind list, and
// UnusedGrantIndexes exists for callers that need the distinction.
func (s *MemoryState) unusedGrantKinds() []capability.Kind {
	idx := s.UnusedGrantIndexes()
	if len(idx) == 0 {
		return nil
	}
	seen := make(map[capability.Kind]struct{}, len(idx))
	out := make([]capability.Kind, 0, len(idx))
	for _, i := range idx {
		k := s.envelope.Grants[i].Kind
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	return out
}

// maxTopViolations bounds the summary's violation list. A summary is read by a
// human in a few seconds; a hundred lines of it is not read at all.
const maxTopViolations = 5

// topViolations renders the most frequent violating verdict/rule pairs, most
// frequent first.
//
// Ties break on the rendered text so the same session always produces the same
// summary. A report whose order depends on map iteration is a report that
// cannot be diffed between two runs of the same recording, which is what the
// evaluation corpus does with it.
func (s *MemoryState) topViolations() []string {
	if len(s.violationTally) == 0 {
		return nil
	}

	type entry struct {
		text string
		n    int
	}
	entries := make([]entry, 0, len(s.violationTally))
	for k, n := range s.violationTally {
		text := fmt.Sprintf("%s ×%d (no rule matched)", k.verdict, n)
		if k.rule != "" {
			text = fmt.Sprintf("%s ×%d (rule %s)", k.verdict, n, k.rule)
		}
		entries = append(entries, entry{text: text, n: n})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].n != entries[j].n {
			return entries[i].n > entries[j].n
		}
		return entries[i].text < entries[j].text
	})

	if len(entries) > maxTopViolations {
		entries = entries[:maxTopViolations]
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.text)
	}
	return out
}

// --- internals ---------------------------------------------------------------

// advanceClock records the stream's own notion of time.
//
// The latest instant only ever moves forward. Wall clock is subject to
// adjustment and is explicitly not the ordering key (pkg/event), so a record
// that arrives with an earlier timestamp must not shorten the session — a
// duration that could decrease would let an exhausted budget come back.
func (s *MemoryState) advanceClock(t time.Time) {
	if t.IsZero() {
		return
	}
	n := t.UnixNano()

	// Single writer, so a plain read-modify-write is correct here; the atomics
	// are for the benefit of readers on other goroutines.
	if s.startNanos.Load() == 0 {
		s.startNanos.Store(n)
	}
	if n > s.latestNanos.Load() {
		s.latestNanos.Store(n)
	}
}

// markSeen adds a target to the novelty set, stopping at the ceiling.
func (s *MemoryState) markSeen(kind capability.Kind, target string) {
	if s.maxSeenTargets == 0 {
		return
	}
	k := seenKey{kind: kind, target: target}
	if _, ok := s.seen[k]; ok {
		return
	}
	if len(s.seen) >= s.maxSeenTargets {
		s.seenFull = true
		return
	}
	s.seen[k] = struct{}{}
}

// SeenTargetsSaturated reports whether the novelty set hit its ceiling, at which
// point unrecorded targets keep reporting as novel. Exposed so a risk factor
// built on novelty can qualify itself rather than silently degrade.
func (s *MemoryState) SeenTargetsSaturated() bool {
	if s == nil {
		return false
	}
	return s.seenFull
}

// push appends to the history ring, overwriting the oldest entry when full.
func (s *MemoryState) push(e *event.Event) {
	if len(s.ring) == 0 {
		return
	}
	s.ring[s.ringNext] = *e
	s.ringNext = (s.ringNext + 1) % len(s.ring)
	if s.ringLen < len(s.ring) {
		s.ringLen++
	}
}

// raisePeak lifts the peak risk score if score is higher.
//
// NaN is ignored rather than compared: every comparison against NaN is false,
// so a NaN reaching the peak would be a score that can never be displaced.
func (s *MemoryState) raisePeak(score float64) {
	if math.IsNaN(score) || score <= 0 {
		return
	}
	for {
		cur := s.peakRiskBits.Load()
		if score <= math.Float64frombits(cur) {
			return
		}
		if s.peakRiskBits.CompareAndSwap(cur, math.Float64bits(score)) {
			return
		}
	}
}
