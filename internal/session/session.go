// Package session manages the lifecycle of a governed agent execution.
//
// A session is the unit of governance: one user request, one envelope, one
// supervised process tree, one audit record. It is the only stateful component
// on the decision path, which makes it the natural owner of everything the
// stateless stages read: accumulated counters, process membership, event
// history.
//
// Concentrating mutable state here is intentional. The validator and risk
// engine read session state through narrow interfaces but never write to it, so
// there is exactly one writer per session and the concurrency story stays
// simple enough to reason about.
package session

import (
	"context"
	"time"

	"github.com/stringNameMahin/ALLSEER/internal/policy"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// Session is one governed agent execution.
type Session struct {
	ID string `json:"id"`

	State State `json:"state"`

	// Envelope governs this session. Sealed before execution begins.
	Envelope *ece.Envelope `json:"envelope"`

	Mode policy.Mode `json:"mode"`

	// RootPID is the supervised process tree root.
	RootPID int32 `json:"root_pid"`

	WorkspaceRoot string `json:"workspace_root"`

	// CreatedAt is when the session was registered, which is the only time a
	// session that never started has. Added when the lifecycle state machine
	// was built: List orders and filters on it, and doing either on StartedAt
	// would silently hide the sessions that failed before they began — exactly
	// the ones a time-window query most wants to find.
	CreatedAt time.Time `json:"created_at"`

	// StartedAt is when the agent began running under supervision. Zero until
	// Start, and distinct from CreatedAt because the gap between them is
	// approval latency, which is the number that decides whether interactive
	// mode is usable.
	StartedAt time.Time  `json:"started_at"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`

	Outcome Outcome `json:"outcome"`

	// Summary is what a user reads afterwards, and for most sessions the only
	// part they will ever look at.
	Summary Summary `json:"summary"`
}

// State is a session's lifecycle position.
type State string

const (
	// StatePending: created, envelope not yet sealed or approved.
	StatePending State = "pending"

	// StateAwaitingApproval: the envelope needs human sign-off before the agent
	// may start.
	StateAwaitingApproval State = "awaiting_approval"

	// StateReady: sealed, approved if approval was required, and not yet
	// started.
	//
	// Added when the lifecycle state machine was built, because the Manager
	// interface implied this state without naming it. Seal is documented as
	// moving to "StateAwaitingApproval or StateActive", and StateActive means
	// "the agent is running" — which it is not, since Start is what supplies
	// the root PID. Without a name for the gap, a sealed and approved session
	// would be indistinguishable from one just created, and Start would have no
	// state to guard against.
	StateReady State = "ready"

	// StateActive: the agent is running and being governed.
	StateActive State = "active"

	// StateSuspended: the agent is paused awaiting an approval decision.
	StateSuspended State = "suspended"

	// StateCompleted: the agent finished normally.
	StateCompleted State = "completed"

	// StateTerminated: the session was ended by policy.
	StateTerminated State = "terminated"

	// StateFailed: the session ended on a governance failure, such as telemetry
	// loss under fail-closed configuration. Distinct from Terminated because
	// the agent did nothing wrong; the system did.
	StateFailed State = "failed"
)

// Outcome describes how a session ended.
type Outcome struct {
	// Result is the terminal state to land in: completed, terminated, or
	// failed. Empty means completed, the ordinary case.
	//
	// Carried here rather than derived, because Manager.End takes only an
	// Outcome and the three terminal states are three different findings about
	// three different subjects — the agent finished, policy stopped it, our own
	// telemetry failed. Inferring which from Reason would make the audit record
	// depend on how somebody worded a sentence.
	Result State `json:"result"`

	Reason string `json:"reason"`

	ViolationCount int `json:"violation_count"`

	// BlockedCount is how many operations were actually prevented.
	BlockedCount int `json:"blocked_count"`

	// TelemetryComplete reports whether the event stream had no gaps. False
	// qualifies every conclusion drawn from this session, including the
	// conclusion that nothing bad happened.
	TelemetryComplete bool `json:"telemetry_complete"`
}

// Summary aggregates what happened during a session.
type Summary struct {
	EventsObserved  uint64 `json:"events_observed"`
	DecisionsIssued uint64 `json:"decisions_issued"`

	// CapabilityUsage counts exercises per capability.
	CapabilityUsage map[capability.Kind]int `json:"capability_usage"`

	// UnusedGrants lists non-optional grants never exercised. Worth surfacing:
	// it means either the envelope was too broad, or the task did not do what
	// the user asked.
	UnusedGrants []capability.Kind `json:"unused_grants,omitempty"`

	// TopViolations lists the most significant departures from the envelope.
	TopViolations []string `json:"top_violations,omitempty"`

	PeakRiskScore float64 `json:"peak_risk_score"`
}

// Manager owns session lifecycle.
type Manager interface {
	// Create makes a new session in StatePending.
	Create(ctx context.Context, req CreateRequest) (*Session, error)

	// Seal finalizes the envelope and moves to StateAwaitingApproval or
	// StateActive depending on whether approval is required.
	Seal(ctx context.Context, sessionID string) error

	// Start marks the session active and begins telemetry collection.
	Start(ctx context.Context, sessionID string, rootPID int32) error

	// Suspend pauses the supervised process tree pending approval.
	Suspend(ctx context.Context, sessionID string, reason string) error

	// Resume continues a suspended session.
	Resume(ctx context.Context, sessionID string) error

	// End terminates a session with the given outcome.
	End(ctx context.Context, sessionID string, outcome Outcome) error

	Get(ctx context.Context, sessionID string) (*Session, error)
	List(ctx context.Context, f Filter) ([]*Session, error)

	// State returns the mutable tracking state for a session.
	State(sessionID string) (State_, bool)
}

// CreateRequest is the input to session creation.
type CreateRequest struct {
	// Envelope governs the session. Required.
	//
	// Caller-supplied, because deriving one from Prompt is intent analysis (M8)
	// plus envelope generation (M9) and neither exists. MemoryManager refuses a
	// request without one rather than inventing a capability set, which would be
	// granting capabilities nobody authorized. Its SessionID is the session's
	// identity: one identifier for one governed execution, and a generated one
	// would make a replayed session produce a different record every run.
	Envelope *ece.Envelope

	// Prompt is the user request that motivates this session. Descriptive
	// today; it becomes load-bearing at M8, where it is what an analyzer reads
	// to produce the envelope above.
	Prompt string

	WorkspaceRoot string

	// Mode overrides the configured default enforcement mode.
	Mode policy.Mode

	// AgentIdentity names the agent that will execute the task.
	AgentIdentity string
}

// Filter narrows session queries.
type Filter struct {
	State State
	Since time.Time
	Until time.Time
	Limit int
}

// State_ is the mutable per-session tracking state.
//
// The trailing underscore avoids colliding with the State lifecycle enum, which
// owns the better name. It satisfies validator.SessionState and risk.History,
// so those modules read what they need through their own narrow interfaces
// without depending on this package's concrete type.
//
// Implemented by MemoryState in state.go. Every method here is a write, and all
// of them belong to one goroutine per session; the ownership rules and what the
// read side may assume are documented there.
//
// Callers must record *after* validating and deciding an event, never before.
// The counters a validator reads describe the session up to but excluding the
// event under judgment, which is what keeps an inclusive limit inclusive.
type State_ interface {
	// RecordEvent updates counters and history. The single writer for a
	// session's mutable state.
	RecordEvent(e *event.Event)

	// RecordDecision updates decision counters.
	RecordDecision(d *decision.Decision)

	// RecordGrantUse marks a grant as exercised, supporting MaxCount. The index
	// is validator.Result.MatchedGrantIndex, valid when MatchedGrant is set.
	RecordGrantUse(grantIndex int)

	// Snapshot returns an immutable view for reporting.
	Snapshot() Summary
}

// Supervisor launches and controls the governed process tree.
//
// This is the mechanism behind the shim: the agent starts as a child of a
// supervisor that registers it for telemetry before exec, so there is no window
// in which the agent runs unobserved. Attaching after the fact would miss
// exactly the early actions most worth watching.
type Supervisor interface {
	// Launch starts a command under supervision and returns its PID. The
	// process must be registered for collection before its first instruction
	// executes.
	Launch(ctx context.Context, sessionID string, cmd Command) (int32, error)

	// Suspend stops the process tree, typically via SIGSTOP.
	Suspend(ctx context.Context, sessionID string) error

	// Resume continues a stopped tree.
	Resume(ctx context.Context, sessionID string) error

	// Terminate ends the tree, escalating from SIGTERM to SIGKILL.
	Terminate(ctx context.Context, sessionID string, grace time.Duration) error

	// Wait blocks until the tree exits and returns the root's exit code.
	Wait(ctx context.Context, sessionID string) (exitCode int, err error)
}

// Command describes a process to launch.
type Command struct {
	Path string
	Args []string
	Env  []string
	Dir  string
}

// Store persists sessions for audit and later inspection.
type Store interface {
	Put(ctx context.Context, s *Session) error
	Get(ctx context.Context, id string) (*Session, error)
	List(ctx context.Context, f Filter) ([]*Session, error)
}

// Done: the in-memory State_ is MemoryState in state.go — atomic counters, a
// bounded event ring, and a bounded seen-targets set, satisfying
// validator.SessionState and risk.History. It has exactly one writer per
// session and takes no lock on the hot path, because per-session serial
// processing is an architectural guarantee rather than a hope; counter reads
// are still safe from any goroutine, which is what a daemon status query needs.
// The filesystem and process budgets are charged through
// validator.ModifiesFilesystem and validator.SpawnsProcess, so the counted set
// and the checked set are one definition rather than two that can drift.
// Done: the history retention bound is DefaultHistorySize, 256 events, with the
// reasoning recorded at the constant: the window has to be long enough for the
// credential-access-then-egress detector to see both ends across a build's file
// traffic, and short enough that memory is not a function of how long the user
// waited. The seen-targets set is bounded separately and saturates toward
// "novel" rather than toward "familiar".
// TODO(session): implement the supervisor with pre-exec registration. On Linux
// that likely means fork, register the child PID, then exec, closing the window
// between fork and exec.
// TODO(session): define what happens to a suspended session if the daemon
// restarts. Leaving an agent SIGSTOPped forever is a bad failure mode.
// TODO(session): implement session persistence so audit records survive a
// restart, and decide whether active sessions can be recovered or must fail.
