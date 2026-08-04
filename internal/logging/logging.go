// Package logging provides structured, leveled diagnostic logging.
//
// This is for diagnostics only: what the daemon is doing and whether it is
// healthy. It is not the audit trail. Governance decisions go to the audit sink
// in pkg/decision, which has different requirements around durability,
// completeness, and tamper evidence. Conflating the two produces an audit trail
// that can be silenced by a log level, which is not an audit trail.
//
// The interface wraps log/slog rather than exposing it, for one reason worth
// the indirection: redaction. Events carry file paths, command arguments, and
// hostnames, some of it sensitive, and a boundary the project controls is where
// that policy can be enforced.
package logging

import (
	"context"
	"log/slog"
)

// Logger is the diagnostic logging interface.
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)

	// With returns a logger with additional persistent attributes, used to bind
	// a session ID once rather than repeating it at every call site.
	With(args ...any) Logger

	// WithContext returns a logger that extracts trace context from ctx.
	WithContext(ctx context.Context) Logger

	// Enabled reports whether a level would be logged, so expensive message
	// construction can be skipped.
	Enabled(level slog.Level) bool
}

// Redactor removes or masks sensitive data before it is logged.
//
// An agent's command line may contain a token, and a file path may contain a
// username or a customer identifier. Redaction is applied at the boundary so no
// individual call site has to remember.
type Redactor interface {
	// Redact returns a safe version of a value for a given field name.
	Redact(field string, value any) any

	// ShouldRedact reports whether a field requires redaction.
	ShouldRedact(field string) bool
}

// Factory builds loggers from configuration.
type Factory interface {
	// New creates a named logger. The name identifies the subsystem and is
	// attached to every record.
	New(name string) Logger

	// SetLevel adjusts the level at runtime, which is how a user turns on debug
	// logging during an incident without a restart.
	SetLevel(level slog.Level)
}

// Standard attribute keys, defined as constants so log records are queryable.
// Ad-hoc key naming makes structured logging no better than printf.
const (
	KeySessionID  = "session_id"
	KeyEventID    = "event_id"
	KeyDecisionID = "decision_id"
	KeyEnvelopeID = "envelope_id"
	KeyPID        = "pid"
	KeyCapability = "capability"
	KeyVerdict    = "verdict"
	KeyAction     = "action"
	KeyRiskScore  = "risk_score"
	KeyStage      = "stage"
	KeyDuration   = "duration_ms"
	KeyError      = "error"
)

// TODO(logging): implement the slog-backed Logger with a redacting handler.
// TODO(logging): define the redaction rule set: environment variable values,
// anything matching a credential pattern, home directory paths.
// TODO(logging): add sampling for high-frequency debug records. Per-event debug
// logging becomes a performance problem of its own at realistic event rates.
// TODO(logging): decide whether to emit OpenTelemetry traces. Valuable for
// latency analysis, but a substantial dependency for a project trying to keep
// them at zero.
