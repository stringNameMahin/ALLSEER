// Package ipc defines the control protocol between the daemon and its clients.
//
// ALLSEER runs as three cooperating binaries:
//
//	allseerd     the privileged daemon. Owns eBPF, envelopes, and decisions.
//	allseerctl   the operator CLI. Inspects state, answers approvals.
//	allseer-shim the agent supervisor. Registers a session, launches the agent
//	             under it, and reports exit.
//
// The split exists so the component being governed is not the component doing
// the governing. The shim runs alongside the agent with ordinary privileges;
// the daemon holds the kernel capabilities and makes every decision. An agent
// that subverts its shim can only prevent a session from starting, not widen
// what it is allowed to do.
//
// Transport is a Unix domain socket. Its filesystem permissions are the primary
// access control: anyone who can write to it can create sessions. There is no
// network listener by design, since a governance daemon should not be remotely
// reachable.
package ipc

import (
	"context"

	"github.com/stringNameMahin/ALLSEER/internal/policy"
	"github.com/stringNameMahin/ALLSEER/internal/session"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
)

// ProtocolVersion is the control protocol version. Clients and daemon exchange
// it on connect and refuse to proceed on mismatch, because a shim that
// misunderstands the daemon could silently run an agent ungoverned.
const ProtocolVersion = "1"

// Client is the daemon-facing API used by allseerctl and allseer-shim.
type Client interface {
	// --- Session lifecycle --------------------------------------------------

	// CreateSession analyzes intent, generates an envelope, and creates a
	// pending session. Does not start the agent.
	CreateSession(ctx context.Context, req CreateSessionRequest) (*CreateSessionResponse, error)

	// ApproveEnvelope records human approval of a generated envelope.
	ApproveEnvelope(ctx context.Context, req ApproveEnvelopeRequest) error

	// StartSession activates governance and registers the process tree root.
	// The shim calls this before exec'ing the agent, so no instruction runs
	// unobserved.
	StartSession(ctx context.Context, sessionID string, rootPID int32) error

	// EndSession finalizes a session and returns its summary.
	EndSession(ctx context.Context, sessionID string, exitCode int) (*session.Summary, error)

	// --- Inspection ---------------------------------------------------------

	GetSession(ctx context.Context, sessionID string) (*session.Session, error)
	ListSessions(ctx context.Context, f session.Filter) ([]*session.Session, error)
	GetEnvelope(ctx context.Context, sessionID string) (*ece.Envelope, error)

	// StreamDecisions returns a live decision feed, which is what drives the
	// CLI's real-time view.
	StreamDecisions(ctx context.Context, sessionID string) (<-chan decision.Decision, error)

	// --- Approvals ----------------------------------------------------------

	// PendingApprovals lists outstanding approval requests.
	PendingApprovals(ctx context.Context) ([]decision.ApprovalRequest, error)

	// RespondApproval answers a pending request.
	RespondApproval(ctx context.Context, resp decision.ApprovalResponse) error

	// StreamApprovals delivers approval requests as they are raised.
	StreamApprovals(ctx context.Context) (<-chan decision.ApprovalRequest, error)

	// --- Administration -----------------------------------------------------

	// Status reports daemon health.
	Status(ctx context.Context) (*StatusResponse, error)

	// ReloadPolicy reloads the rule set from disk.
	ReloadPolicy(ctx context.Context) error

	// Close releases the connection.
	Close() error
}

// Server handles client requests. Implemented by the daemon.
type Server interface {
	// Serve accepts connections until ctx is cancelled.
	Serve(ctx context.Context) error

	// Shutdown stops accepting and drains in-flight requests.
	Shutdown(ctx context.Context) error
}

// CreateSessionRequest asks the daemon to prepare a governed session.
type CreateSessionRequest struct {
	Prompt        string `json:"prompt"`
	WorkspaceRoot string `json:"workspace_root"`

	// Mode overrides the configured default enforcement mode. The daemon may
	// refuse to weaken its configured mode; a client asking for monitor mode on
	// an enforce-configured daemon must not get it.
	Mode policy.Mode `json:"mode,omitempty"`

	// AgentIdentity names the agent that will run.
	AgentIdentity string `json:"agent_identity,omitempty"`

	// Profile requests a specific envelope profile.
	Profile string `json:"profile,omitempty"`
}

// CreateSessionResponse returns the prepared session.
type CreateSessionResponse struct {
	SessionID string `json:"session_id"`

	// Envelope is the generated envelope, returned so the caller can show it to
	// a human before approval.
	Envelope *ece.Envelope `json:"envelope"`

	// RequiresApproval reports whether execution is blocked pending sign-off.
	RequiresApproval bool `json:"requires_approval"`

	// Warnings are non-fatal concerns raised during generation: low analyzer
	// confidence, ambiguities, or grants for capabilities no probe can observe.
	Warnings []string `json:"warnings,omitempty"`
}

// ApproveEnvelopeRequest records human sign-off.
type ApproveEnvelopeRequest struct {
	SessionID string `json:"session_id"`
	Approved  bool   `json:"approved"`

	// Modifications lists edits the approver made to the envelope. Tracked
	// because systematic edits are the clearest signal that generation is
	// miscalibrated.
	Modifications []string `json:"modifications,omitempty"`

	Reason string `json:"reason,omitempty"`
}

// StatusResponse reports daemon health.
type StatusResponse struct {
	Version         string `json:"version"`
	ProtocolVersion string `json:"protocol_version"`

	// Uptime in seconds.
	Uptime float64 `json:"uptime"`

	// ActiveSessions is the current governed session count.
	ActiveSessions int `json:"active_sessions"`

	// Mode is the configured default enforcement mode.
	Mode policy.Mode `json:"mode"`

	// TelemetryHealthy reports whether probes are attached and events flowing.
	// False means the daemon is running but governing nothing, the most
	// dangerous state the system can be in because it looks fine.
	TelemetryHealthy bool `json:"telemetry_healthy"`

	ProbesAttached int `json:"probes_attached"`

	// EnforcerMechanism names the active enforcement method, so an operator can
	// tell at a glance whether "block" actually blocks.
	EnforcerMechanism string `json:"enforcer_mechanism"`

	// DroppedEvents is the cumulative telemetry loss count.
	DroppedEvents uint64 `json:"dropped_events"`
}

// Error is a structured protocol error.
type Error struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
	Details string    `json:"details,omitempty"`
}

func (e *Error) Error() string { return e.Message }

// ErrorCode classifies protocol errors.
type ErrorCode string

const (
	ErrCodeInvalidRequest   ErrorCode = "invalid_request"
	ErrCodeSessionNotFound  ErrorCode = "session_not_found"
	ErrCodeEnvelopeNotFound ErrorCode = "envelope_not_found"
	ErrCodeNotApproved      ErrorCode = "not_approved"
	ErrCodeAlreadyStarted   ErrorCode = "already_started"
	ErrCodeAnalysisFailed   ErrorCode = "analysis_failed"
	ErrCodeTelemetryFailed  ErrorCode = "telemetry_failed"
	ErrCodePermissionDenied ErrorCode = "permission_denied"
	ErrCodeVersionMismatch  ErrorCode = "version_mismatch"
	ErrCodeInternal         ErrorCode = "internal"
)

// TODO(ipc): choose the wire format. Leaning newline-delimited JSON over the
// Unix socket: no dependency, debuggable with socat, and the request rate is
// low because only session lifecycle crosses this boundary, never events.
// TODO(ipc): implement SO_PEERCRED peer identification so the daemon knows
// which user made a request rather than trusting the request to say.
// TODO(ipc): define the streaming protocol for decisions and approvals,
// including what happens when a slow client stalls a stream.
// TODO(ipc): decide whether the shim must authenticate beyond socket
// permissions. On a single-user workstation permissions are probably enough; on
// a shared host they are not.
// TODO(ipc): specify daemon-unavailable behavior for the shim. Refusing to
// launch is fail-closed and correct; launching ungoverned would quietly undo
// the entire system.
