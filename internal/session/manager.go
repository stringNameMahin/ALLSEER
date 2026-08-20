package session

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/stringNameMahin/ALLSEER/internal/policy"
	"github.com/stringNameMahin/ALLSEER/internal/validator"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
)

// This file holds the session lifecycle state machine: which transitions are
// legal, who may take them, and what each one changes.
//
// # Why a table rather than a switch
//
// The legal transitions are declared once, in transitions below, and every
// method consults it. A switch statement per method would spread the same
// specification across six places, and the interesting property of a lifecycle
// is not what any one method does but what the whole graph forbids — that a
// terminated session cannot restart, that an unapproved envelope cannot govern
// a running agent, that a session cannot be started twice under two PIDs. Those
// are properties of the graph, and a table is the only form in which they can be
// read, tested exhaustively, and shown to a reviewer.
//
// TestEveryTransitionPairIsClassified walks all States x Actions and requires
// each pair to be explicitly legal or explicitly refused, so a state added to
// the enum cannot quietly inherit permissive behavior.
//
// # An illegal transition is an error, never a no-op
//
// This is the security-relevant half. A no-op Start on an ended session, or a
// silently ignored Seal, produces a session whose recorded state disagrees with
// what actually happened — and every conclusion drawn from the audit record
// afterwards is a conclusion about the wrong session. Refusing loudly is the
// only behavior that keeps the record and the world in agreement.
//
// # What this manager does NOT own
//
// It owns session identity, lifecycle, and per-session State_. It does **not**
// own pipelines. A manager that constructed and held an EventPipeline per
// session would be the "session registry with a stage list attached" that
// internal/pipeline explicitly refused to become; the caller builds a pipeline
// for a session and asks the manager for that session's State_ to wire into it.
// Cross-session event dispatch — routing an event to the right pipeline — is
// the next thing to build on top of this, and is deliberately not here.

// Action is a lifecycle transition request.
//
// Named as a type so an illegal transition can report which one was attempted,
// and so the transition table can be enumerated in a test rather than trusted.
type Action string

const (
	ActionSeal    Action = "seal"
	ActionApprove Action = "approve"
	ActionStart   Action = "start"
	ActionSuspend Action = "suspend"
	ActionResume  Action = "resume"
	ActionEnd     Action = "end"
)

// AllActions returns every lifecycle transition. Vocabulary, not behavior —
// the same role AllVerdicts plays in pkg/decision, and what lets the transition
// table be checked for completeness.
func AllActions() []Action {
	return []Action{ActionSeal, ActionApprove, ActionStart, ActionSuspend, ActionResume, ActionEnd}
}

// AllStates returns every lifecycle state, roughly in the order a session
// passes through them.
func AllStates() []State {
	return []State{
		StatePending,
		StateAwaitingApproval,
		StateReady,
		StateActive,
		StateSuspended,
		StateCompleted,
		StateTerminated,
		StateFailed,
	}
}

// TerminalStates returns the states a session cannot leave.
//
// Terminal means terminal: there is no reopening. A session that ended and was
// then restarted would have one identity, one audit stream, and two
// incompatible stories in it, and no reader could tell which counters belonged
// to which run.
func TerminalStates() []State {
	return []State{StateCompleted, StateTerminated, StateFailed}
}

// IsTerminal reports whether s is a state a session cannot leave.
func IsTerminal(s State) bool {
	for _, t := range TerminalStates() {
		if s == t {
			return true
		}
	}
	return false
}

// transitions is the legal-transition table: for each action, the states it may
// be taken from.
//
// The destination is not in the table because three actions have more than one.
// Seal goes to awaiting_approval or ready depending on whether approval is
// outstanding, and End goes to completed, terminated, or failed depending on
// what the caller reports. Encoding a single destination per action would have
// meant either a lie or a second table, and the branch belongs where the
// evidence for it is.
//
//	  Create
//	    │
//	    ▼
//	pending ──Seal (approval outstanding)──▶ awaiting_approval
//	    │                                            │
//	    └──Seal (approval satisfied)──▶ ready ◀──Approve
//	                                      │
//	                                      │ Start(rootPID)
//	                                      ▼
//	                     suspended ◀──Suspend── active
//	                             └────Resume────▶
//	                                      │
//	                                      ▼  End
//	                   completed | terminated | failed
//
// End is legal from every non-terminal state, which is the one rule in here
// that is not about the happy path. A session can fail before it starts — an
// inadmissible envelope, a shim that never launched, a daemon shutting down
// mid-approval — and a lifecycle that could only end sessions that had begun
// would leave those stuck in a non-terminal state forever, holding their state
// and never appearing in a completed-session query.
var transitions = map[Action]map[State]bool{
	ActionSeal: {
		StatePending: true,
	},
	ActionApprove: {
		StateAwaitingApproval: true,
	},
	ActionStart: {
		StateReady: true,
	},
	ActionSuspend: {
		StateActive: true,
	},
	ActionResume: {
		StateSuspended: true,
	},
	ActionEnd: {
		StatePending:          true,
		StateAwaitingApproval: true,
		StateReady:            true,
		StateActive:           true,
		StateSuspended:        true,
	},
}

// Allowed reports whether action a may be taken from state from.
//
// Exported because the answer is useful outside this package — an IPC layer
// deciding whether to offer a command, a CLI rendering what a session can do
// next — and because a caller working it out from the state enum would be
// re-deriving the table.
func Allowed(a Action, from State) bool { return transitions[a][from] }

// Errors reported for lifecycle misuse.
//
// Each is a sentinel so a caller can branch on the reason. That matters most
// for ErrNotFound, which an IPC layer turns into a different status code from
// every other failure here.
var (
	// ErrNotFound means no session with that ID exists in this manager.
	ErrNotFound = errors.New("session: not found")

	// ErrExists means a session with that ID already exists. Refused rather
	// than overwritten: the second caller would silently take over the first
	// one's governance, and the first one's state would vanish mid-session.
	ErrExists = errors.New("session: already exists")

	// ErrNoEnvelope means Create was given no envelope. Generating one from a
	// prompt is intent analysis (M8) plus envelope generation (M9), neither of
	// which exists; this manager governs a session against an envelope the
	// caller supplies and refuses rather than inventing one.
	ErrNoEnvelope = errors.New("session: an envelope is required")

	// ErrNoSessionID means the supplied envelope carries no SessionID. The
	// session's identity is the envelope's, deliberately: two identifiers for
	// one governed execution is two things to keep in agreement, and a
	// generated one would make a replayed session produce a different record
	// each run.
	ErrNoSessionID = errors.New("session: the envelope carries no session_id")

	// ErrEnvelopeInadmissible means the envelope has a blocking lint issue.
	ErrEnvelopeInadmissible = errors.New("session: envelope is inadmissible")

	// ErrEnvelopeUnsealed means Start was reached with an unsealed envelope,
	// which should be unreachable through the state machine and is checked
	// anyway.
	ErrEnvelopeUnsealed = errors.New("session: envelope is not sealed")

	// ErrNoSupervisor means Suspend or Resume was called with no supervisor
	// wired. Refused rather than recorded: moving a session to suspended while
	// the agent keeps running would put a claim in the audit record that
	// nothing enforced, which is the same dishonesty Decision.Enforced exists
	// to prevent.
	ErrNoSupervisor = errors.New("session: no supervisor configured")

	// ErrNoRootPID means Start was given a PID that cannot identify a process.
	ErrNoRootPID = errors.New("session: a root PID is required")

	// ErrBadOutcome means End was given a Result that is not a terminal state.
	ErrBadOutcome = errors.New("session: outcome result must be a terminal state")
)

// TransitionError reports a refused lifecycle transition.
//
// It names the state the session was actually in, which is the thing the caller
// did not know. "Start failed" sends someone to the logs; "start refused:
// session s-1 is completed, not ready" does not.
type TransitionError struct {
	SessionID string
	Action    Action
	From      State
}

func (e *TransitionError) Error() string {
	return fmt.Sprintf("session: cannot %s session %q from state %q", e.Action, e.SessionID, e.From)
}

// Is lets errors.Is(err, ErrIllegalTransition) match any refused transition,
// so a caller that only needs the category does not have to type-assert.
func (e *TransitionError) Is(target error) bool { return target == ErrIllegalTransition }

// ErrIllegalTransition is the category every TransitionError matches.
var ErrIllegalTransition = errors.New("session: illegal transition")

// ManagerConfig configures a MemoryManager.
type ManagerConfig struct {
	// RequireApproval demands human sign-off on the envelope before a session
	// may start. Mirrors config.EnvelopeConfig.RequireApproval, passed in
	// rather than read, because internal/config has no loader yet and a
	// component that reached for global configuration would be untestable in
	// the one dimension that matters here.
	RequireApproval bool

	// DefaultMode is the enforcement posture for a session that names none.
	// Empty means policy.ModeMonitor: a system that starts out blocking is a
	// system that gets uninstalled before it is trusted.
	DefaultMode policy.Mode

	// Supervisor controls the governed process tree. Optional, and nil today
	// because no implementation exists (M7, M11). With it nil, Suspend and
	// Resume are refused rather than faked. Exactly the seam
	// pipeline.Config.Sink was before internal/audit existed.
	Supervisor Supervisor

	// StateConfig supplies the per-session tracking state's settings —
	// history depth, novelty ceiling, clock. SessionID, Envelope, and StartedAt
	// are filled in per session and anything set here for them is ignored.
	StateConfig Config

	// Now supplies the clock for creation, start, and end times. Nil means
	// time.Now. Injectable so lifecycle timestamps are testable without
	// sleeping, the same seam pipeline.Config.Now provides.
	Now func() time.Time
}

// MemoryManager is the in-memory session lifecycle state machine.
//
// Safe for concurrent use. Unlike MemoryState, which is single-writer by
// architectural guarantee, a manager is genuinely shared: a daemon's IPC
// handler creates sessions, a shim starts them, a supervisor ends them, and a
// status query lists them, all on different goroutines. The lock is coarse and
// held only for lifecycle operations, which happen once or twice per session
// rather than once per syscall — this is not on the hot path, and the hot path
// (State_) is deliberately not behind it.
//
// The zero value is not usable; use NewManager.
type MemoryManager struct {
	mu       sync.RWMutex
	sessions map[string]*managed

	cfg ManagerConfig
	now func() time.Time
}

// managed is a session plus the tracking state that belongs to it.
type managed struct {
	session Session

	// state is handed to the pipeline that processes this session and is
	// written by that pipeline's goroutine alone. The manager holds the
	// reference and never writes through it — see the ownership note in
	// state.go, and Summary's limitation in end().
	state *MemoryState
}

var _ Manager = (*MemoryManager)(nil)

// NewManager returns an empty session manager.
func NewManager(cfg ManagerConfig) *MemoryManager {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	if cfg.DefaultMode == "" {
		cfg.DefaultMode = policy.ModeMonitor
	}
	return &MemoryManager{
		sessions: make(map[string]*managed),
		cfg:      cfg,
		now:      now,
	}
}

// --- creation ------------------------------------------------------------------

// Create registers a new session in StatePending against a caller-supplied
// envelope.
//
// The envelope is required. CreateRequest still carries a Prompt because that
// is what a session is ultimately for, but turning a prompt into an envelope is
// intent analysis (M8) and envelope generation (M9); until those exist this
// refuses rather than fabricating a capability set. A manager that guessed an
// envelope would be granting capabilities nobody authorized, which is the one
// failure this whole system is arranged to prevent.
//
// The manager takes ownership of the envelope. Seal mutates it — that is what
// sealing is — so the caller must not hold it for another session or modify it
// afterwards. One envelope, one session, which is also what makes the session
// identity below unambiguous.
func (m *MemoryManager) Create(_ context.Context, req CreateRequest) (*Session, error) {
	if req.Envelope == nil {
		return nil, fmt.Errorf("%w: creating one from a prompt is intent analysis (M8) and "+
			"envelope generation (M9), neither of which is implemented", ErrNoEnvelope)
	}
	if req.Envelope.SessionID == "" {
		return nil, ErrNoSessionID
	}

	id := req.Envelope.SessionID
	mode := req.Mode
	if mode == "" {
		mode = m.cfg.DefaultMode
	}

	workspace := req.WorkspaceRoot
	if workspace == "" {
		// The envelope's own constraint is the authority on what the workspace
		// is; the request's field is an override for a caller that knows
		// better. Preferring the envelope keeps the session and the thing
		// governing it from disagreeing about where the work happens.
		workspace = req.Envelope.Constraints.WorkspaceRoot
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.sessions[id]; ok {
		return nil, fmt.Errorf("%w: %q", ErrExists, id)
	}

	stateCfg := m.cfg.StateConfig
	stateCfg.SessionID = id
	stateCfg.Envelope = req.Envelope
	if stateCfg.Now == nil {
		stateCfg.Now = m.now
	}
	// StartedAt stays zero until Start. MemoryState reads a zero StartedAt as
	// "put elapsed time on the stream clock", which is right for a session that
	// has not begun and is what a replayed session wants throughout.

	rec := &managed{
		session: Session{
			ID:            id,
			State:         StatePending,
			Envelope:      req.Envelope,
			Mode:          mode,
			WorkspaceRoot: workspace,
			CreatedAt:     m.now(),
		},
		state: NewStateWith(stateCfg),
	}
	m.sessions[id] = rec

	out := rec.session.clone()
	return &out, nil
}

// --- transitions ----------------------------------------------------------------

// Seal finalizes the envelope and moves the session out of pending.
//
// Two things happen here, and the order matters. The envelope is checked for
// admissibility first, using the same validator.BlockingIssues the daemon and
// the approval CLI use, so one definition of "inadmissible" serves all three: a
// session must not be governed by an envelope the system would refuse to load.
// Only then is it marked sealed.
//
// The destination depends on whether approval is outstanding. It is not when
// approval was never required, and it is not when the envelope already carries
// an ApprovalRecord — an envelope approved out of band is approved, and
// demanding a second sign-off for the same document would train operators to
// click through the prompt.
//
// What sealing does *not* do here is compute Envelope.Digest. Tamper evidence
// needs canonical serialization, which is an open decision in pkg/ece, and a
// digest over Go's map-ordered JSON would be a digest that fails to reproduce.
// Recording that gap is better than shipping a checksum nobody can verify.
func (m *MemoryManager) Seal(_ context.Context, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	rec, err := m.lookup(sessionID)
	if err != nil {
		return err
	}
	if err := m.check(ActionSeal, rec); err != nil {
		return err
	}

	env := rec.session.Envelope
	if blocking := validator.BlockingIssues(validator.LintEnvelope(env)); len(blocking) > 0 {
		return fmt.Errorf("%w: %s: %s", ErrEnvelopeInadmissible, blocking[0].Field, blocking[0].Message)
	}
	env.Sealed = true

	if m.cfg.RequireApproval && env.Approval == nil {
		rec.session.State = StateAwaitingApproval
	} else {
		rec.session.State = StateReady
	}
	return nil
}

// Approve records a human's sign-off and moves an awaiting session to ready.
//
// Recording an approval, not obtaining one. Routing a request to a person and
// waiting for the answer is decision.ApprovalBroker's job (M11); this is where
// the answer lands. Keeping them apart is what lets an approval arrive from a
// CLI, from a web prompt, or from an automatic policy without this state
// machine knowing the difference.
//
// Not part of the Manager interface, which declares no approval step at all —
// an omission that would make awaiting_approval a state only End can leave. It
// is on the concrete type rather than added to the interface because the
// interface is a shipped contract and one implementation's need is not a reason
// to widen it.
//
// The record is written onto the envelope rather than kept beside it, because
// ece.Envelope.Approval is where every other reader already looks, and an
// approval the envelope does not carry is one that will not survive being
// persisted or shipped.
func (m *MemoryManager) Approve(_ context.Context, sessionID string, rec ece.ApprovalRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, err := m.lookup(sessionID)
	if err != nil {
		return err
	}
	if err := m.check(ActionApprove, s); err != nil {
		return err
	}
	if rec.ApprovedBy == "" {
		return errors.New("session: an approval must name who gave it")
	}
	if rec.ApprovedAt.IsZero() {
		rec.ApprovedAt = m.now()
	}

	approval := rec
	s.session.Envelope.Approval = &approval
	s.session.State = StateReady
	return nil
}

// Start marks the session active under a supervised process tree.
//
// Reachable only from ready, which is the point: a session that skipped Seal
// has an unlinted envelope, and one that skipped Approve has an unapproved one.
// The envelope's sealed flag is checked again here even though the state
// machine makes an unsealed envelope unreachable — the check is one line and
// what it guards against is governing an agent with a document that was still
// being edited.
//
// StartedAt is stamped on both the session and its tracking state, so elapsed
// time in a session constraint and elapsed time in the audit record are the
// same measurement rather than two clocks started at slightly different moments.
func (m *MemoryManager) Start(_ context.Context, sessionID string, rootPID int32) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	rec, err := m.lookup(sessionID)
	if err != nil {
		return err
	}
	if err := m.check(ActionStart, rec); err != nil {
		return err
	}
	if rootPID <= 0 {
		return fmt.Errorf("%w: got %d", ErrNoRootPID, rootPID)
	}
	if !rec.session.Envelope.Sealed {
		return ErrEnvelopeUnsealed
	}

	now := m.now()
	rec.session.RootPID = rootPID
	rec.session.StartedAt = now
	rec.state.SetStartedAt(now)
	rec.session.State = StateActive
	return nil
}

// Suspend pauses the supervised process tree pending an approval decision.
//
// Refused outright with no supervisor wired. The alternative — recording the
// session as suspended while the agent keeps running — would put a claim in the
// lifecycle record that nothing enforced, and a reader would have no way to
// tell it from a suspension that worked.
//
// The supervisor is called before the state moves, so a failure to actually
// stop the tree leaves the session active, which is what it still is.
func (m *MemoryManager) Suspend(ctx context.Context, sessionID string, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	rec, err := m.lookup(sessionID)
	if err != nil {
		return err
	}
	if err := m.check(ActionSuspend, rec); err != nil {
		return err
	}
	if m.cfg.Supervisor == nil {
		return fmt.Errorf("%w: cannot suspend %q (%s); the supervisor is M7 and SIGSTOP handling is M11",
			ErrNoSupervisor, sessionID, reason)
	}
	if err := m.cfg.Supervisor.Suspend(ctx, sessionID); err != nil {
		return fmt.Errorf("session: suspending %q: %w", sessionID, err)
	}

	rec.session.State = StateSuspended
	return nil
}

// Resume continues a suspended session.
//
// Same shape as Suspend and for the same reason: the tree is continued first,
// and the state moves only if it worked. A session recorded as active whose
// process is still stopped is worse than one recorded as suspended, because
// every subsequent "no events observed" reads as good news.
func (m *MemoryManager) Resume(ctx context.Context, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	rec, err := m.lookup(sessionID)
	if err != nil {
		return err
	}
	if err := m.check(ActionResume, rec); err != nil {
		return err
	}
	if m.cfg.Supervisor == nil {
		return fmt.Errorf("%w: cannot resume %q; the supervisor is M7 and SIGSTOP handling is M11",
			ErrNoSupervisor, sessionID)
	}
	if err := m.cfg.Supervisor.Resume(ctx, sessionID); err != nil {
		return fmt.Errorf("session: resuming %q: %w", sessionID, err)
	}

	rec.session.State = StateActive
	return nil
}

// End moves the session to a terminal state and captures its summary.
//
// Outcome.Result names which terminal state, and the caller has to say. It
// cannot be inferred: "the agent finished", "policy stopped it", and "our
// telemetry failed" are three different findings about three different
// subjects, and deriving them from a reason string would make the audit record
// depend on how somebody worded a sentence. An empty Result means completed,
// which is the ordinary case and the only one that needs no explanation.
//
// The summary is snapshotted here and only here. Snapshot reads structures that
// belong to the session's writer goroutine, and End is the moment that
// goroutine has stopped — the pipeline has drained, nothing is processing. That
// is why Get on a *running* session reports a zero Summary rather than a live
// one; see the limitation note there.
func (m *MemoryManager) End(_ context.Context, sessionID string, outcome Outcome) error {
	final := outcome.Result
	if final == "" {
		final = StateCompleted
	}
	if !IsTerminal(final) {
		return fmt.Errorf("%w: got %q, want one of %v", ErrBadOutcome, final, TerminalStates())
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	rec, err := m.lookup(sessionID)
	if err != nil {
		return err
	}
	if err := m.check(ActionEnd, rec); err != nil {
		return err
	}

	ended := m.now()
	outcome.Result = final
	rec.session.State = final
	rec.session.EndedAt = &ended
	rec.session.Outcome = outcome
	rec.session.Summary = rec.state.Snapshot()
	return nil
}

// --- queries ---------------------------------------------------------------------

// Get returns a copy of the session.
//
// A copy, not the live record. Handing out a pointer into the manager's map
// would give every caller a read into state another goroutine is writing, which
// is a data race dressed as an accessor. The Envelope pointer is shared
// deliberately: it is sealed and immutable by the time anyone can observe it,
// and copying a capability set per status query would be expensive for no gain.
//
// Limitation: Summary is zero until End. It is captured there because Snapshot
// reads owner-goroutine-only structures, and a status query runs on a different
// goroutine. A live summary needs either a snapshot taken by the session's own
// writer or an atomic-safe subset of Summary, and choosing between those is a
// change to MemoryState rather than to this file.
func (m *MemoryManager) Get(_ context.Context, sessionID string) (*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	rec, err := m.lookup(sessionID)
	if err != nil {
		return nil, err
	}
	out := rec.session.clone()
	return &out, nil
}

// List returns copies of the sessions matching f, oldest first.
//
// Ordered by CreatedAt then ID. Deterministic on purpose: map iteration order
// would make a status listing shuffle between calls, and the ID tiebreak keeps
// two sessions created in the same clock tick from swapping places.
//
// Filter.Since and Filter.Until bound CreatedAt, not StartedAt. A session that
// never started has no StartedAt at all, and filtering on it would silently
// hide exactly the sessions someone querying a time window is most likely to be
// looking for — the ones that failed before they began. Since is inclusive,
// Until exclusive, and a zero value for either means unbounded.
func (m *MemoryManager) List(_ context.Context, f Filter) ([]*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]*Session, 0, len(m.sessions))
	for _, rec := range m.sessions {
		if !f.matches(&rec.session) {
			continue
		}
		s := rec.session.clone()
		out = append(out, &s)
	}

	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})

	if f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out, nil
}

// State returns the session's mutable tracking state.
//
// The one thing this manager hands out by reference rather than by copy, and
// deliberately: it is what a pipeline writes through, and a copy would be a
// pipeline recording into nothing. Everything about who may call it is in
// state.go's ownership note — in short, one writer per session, and that writer
// is the pipeline processing it.
func (m *MemoryManager) State(sessionID string) (State_, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	rec, ok := m.sessions[sessionID]
	if !ok {
		return nil, false
	}
	return rec.state, true
}

// Len reports how many sessions the manager holds, terminal ones included.
//
// A manager never forgets. Nothing here evicts an ended session, because the
// record is the point and dropping it would lose the audit trail the moment the
// agent stopped. Eviction belongs with session.Store, which is where persistence
// lands (M7) and where the question "how long do we keep this in memory" can be
// answered against somewhere to put it.
func (m *MemoryManager) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

// --- internals ---------------------------------------------------------------------

// lookup finds a session. Callers hold the lock.
func (m *MemoryManager) lookup(id string) (*managed, error) {
	rec, ok := m.sessions[id]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrNotFound, id)
	}
	return rec, nil
}

// check enforces the transition table. Callers hold the lock.
func (m *MemoryManager) check(a Action, rec *managed) error {
	if !Allowed(a, rec.session.State) {
		return &TransitionError{SessionID: rec.session.ID, Action: a, From: rec.session.State}
	}
	return nil
}

// matches reports whether a session satisfies the filter.
func (f Filter) matches(s *Session) bool {
	if f.State != "" && s.State != f.State {
		return false
	}
	if !f.Since.IsZero() && s.CreatedAt.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && !s.CreatedAt.Before(f.Until) {
		return false
	}
	return true
}

// clone returns a copy safe to hand to another goroutine.
//
// Deep for everything the manager keeps mutating — the summary's map and slices,
// the end-time pointer — and shallow for the envelope, which is sealed and read
// only. A shallow copy of the summary would hand out the same map the next End
// writes into.
func (s *Session) clone() Session {
	out := *s

	if s.EndedAt != nil {
		t := *s.EndedAt
		out.EndedAt = &t
	}
	if s.Summary.CapabilityUsage != nil {
		usage := make(map[capability.Kind]int, len(s.Summary.CapabilityUsage))
		for k, v := range s.Summary.CapabilityUsage {
			usage[k] = v
		}
		out.Summary.CapabilityUsage = usage
	}
	out.Summary.UnusedGrants = append([]capability.Kind(nil), s.Summary.UnusedGrants...)
	out.Summary.TopViolations = append([]string(nil), s.Summary.TopViolations...)
	return out
}

// Done: the lifecycle state machine is MemoryManager above, over a
// caller-supplied envelope, with the legal transitions declared once in
// `transitions` and every pair of (state, action) classified by a test. Create
// from a Prompt, Suspend, and Resume are all declared and all refuse rather
// than pretend: the first needs M8 and M9, the second and third need a
// Supervisor that is M7 and M11. Approve is on the concrete type only, because
// awaiting_approval would otherwise be a state nothing but End can leave.
// TODO(session): cross-session event dispatch — routing an event to the
// pipeline governing its session. This manager is the registry that made it
// possible; it is a separate change because a manager that also owned pipelines
// would be the shape internal/pipeline refused to become.
// TODO(session): implement the supervisor with pre-exec registration. On Linux
// that likely means fork, register the child PID, then exec, closing the window
// between fork and exec.
// TODO(session): define what happens to a suspended session if the daemon
// restarts. Leaving an agent SIGSTOPped forever is a bad failure mode, and
// nothing here can help: the manager is in memory, so a restart loses the
// record that the session was suspended at all.
// TODO(session): implement session persistence so audit records survive a
// restart, and decide whether active sessions can be recovered or must fail.
// Session.Store is the seam; MemoryManager deliberately implements no eviction
// until there is somewhere for an evicted session to go.
// TODO(session): report a live Summary from Get. Snapshot reads
// owner-goroutine-only structures, so it is captured at End today; a live one
// needs either a snapshot taken by the session's own writer or an atomic-safe
// subset, and that is a change to MemoryState.
