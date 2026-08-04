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
	// Prompt is the user request that motivates this session.
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
type State_ interface {
	// RecordEvent updates counters and history. The single writer for a
	// session's mutable state.
	RecordEvent(e *event.Event)

	// RecordDecision updates decision counters.
	RecordDecision(d *decision.Decision)

	// RecordGrantUse marks a grant as exercised, supporting MaxCount.
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

// TODO(session): implement the in-memory State_ with counters, a bounded event
// ring for history, and a seen-targets set.
// TODO(session): decide the history retention bound. Unbounded history leaks on
// long sessions; too short and sequence detection stops working.
// TODO(session): implement the supervisor with pre-exec registration. On Linux
// that likely means fork, register the child PID, then exec, closing the window
// between fork and exec.
// TODO(session): define what happens to a suspended session if the daemon
// restarts. Leaving an agent SIGSTOPped forever is a bad failure mode.
// TODO(session): implement session persistence so audit records survive a
// restart, and decide whether active sessions can be recovered or must fail.
