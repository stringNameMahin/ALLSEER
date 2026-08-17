// Package decision defines the output of the governance pipeline: the verdict
// rendered for an observed event and the reasoning behind it.
//
// A Decision is the system's public product. Everything upstream exists to
// produce it and everything downstream consumes it. Because it is the record a
// human reads when asking why their agent was stopped, it carries the full
// reasoning chain rather than just the outcome.
package decision

import (
	"context"
	"time"

	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// Decision is the verdict for a single observed event.
type Decision struct {
	ID        string    `json:"id"`
	SessionID string    `json:"session_id"`
	EventID   string    `json:"event_id"`
	Timestamp time.Time `json:"timestamp"`

	// Action is what the enforcement layer acts on.
	Action ece.Action `json:"action"`

	// Verdict is the validator's classification with respect to the envelope.
	Verdict Verdict `json:"verdict"`

	// Risk is the scored assessment that informed the action.
	Risk RiskAssessment `json:"risk"`

	// Reasoning is the ordered chain of steps that produced the action. It is
	// what makes the system explainable: a user must be able to follow
	// validation to risk to policy without reading source code.
	Reasoning []ReasoningStep `json:"reasoning"`

	MatchedGrant *capability.Grant `json:"matched_grant,omitempty"`
	MatchedRule  string            `json:"matched_rule,omitempty"`

	// Latency is event receipt to decision. Tracked because in enforce mode
	// this delay is charged directly to the agent's syscall, and a slow
	// decision path is a usability failure.
	Latency time.Duration `json:"latency"`

	// Enforced reports whether the action was actually applied. False means the
	// decision was advisory: monitor mode, or an enforcement failure. The
	// distinction is critical for audit, since a "block" that was never
	// enforced must not read as if it stopped something.
	Enforced bool `json:"enforced"`
}

// Verdict classifies an observation against the envelope.
type Verdict string

const (
	// VerdictWithinEnvelope: matched a grant. Expected behavior.
	VerdictWithinEnvelope Verdict = "within_envelope"

	// VerdictOutsideEnvelope: no grant covered it. The core finding this system
	// exists to produce.
	VerdictOutsideEnvelope Verdict = "outside_envelope"

	// VerdictExplicitlyDenied: a denial matched. Stronger than merely
	// ungranted, since the envelope anticipated this and forbade it.
	VerdictExplicitlyDenied Verdict = "explicitly_denied"

	// VerdictConstraintViolation: individually granted, but over a
	// session-wide budget such as a write or byte count.
	VerdictConstraintViolation Verdict = "constraint_violation"

	// VerdictGrantExceeded: the capability was granted but the selector did not
	// match, e.g. a write outside the granted glob. Kept apart from
	// OutsideEnvelope because "right capability, wrong target" is a different
	// story from "capability never expected at all".
	VerdictGrantExceeded Verdict = "grant_exceeded"

	// VerdictIndeterminate: validation could not conclude, typically because
	// enrichment failed on an unresolvable path or an uncorrelated IP. Never
	// treat this as allowed; unresolved is not safe.
	VerdictIndeterminate Verdict = "indeterminate"
)

// AllVerdicts returns every verdict the validator can produce.
//
// Vocabulary, not behavior: the same role capability.AllKinds plays for Kind.
// It exists because a policy rule naming a verdict outside this set can never
// match, and the rule set linter has no other way to prove that. Append-only,
// like every wire-contract enum here.
func AllVerdicts() []Verdict {
	return []Verdict{
		VerdictWithinEnvelope,
		VerdictOutsideEnvelope,
		VerdictExplicitlyDenied,
		VerdictConstraintViolation,
		VerdictGrantExceeded,
		VerdictIndeterminate,
	}
}

// ValidVerdict reports whether v is a verdict this build can produce.
func ValidVerdict(v Verdict) bool {
	for _, known := range AllVerdicts() {
		if known == v {
			return true
		}
	}
	return false
}

// AllLevels returns every risk level, from lowest to highest.
func AllLevels() []Level {
	return []Level{LevelNone, LevelLow, LevelMedium, LevelHigh, LevelCritical}
}

// ValidLevel reports whether l is a level the risk engine can assign.
func ValidLevel(l Level) bool {
	for _, known := range AllLevels() {
		if known == l {
			return true
		}
	}
	return false
}

// RiskAssessment is the scored evaluation of an observation.
type RiskAssessment struct {
	// Score is normalized to [0,100]. Normalization matters because thresholds
	// are user-configurable and nobody can reason about an unbounded scale.
	Score float64 `json:"score"`

	// Level is the bucketed score, for humans and for coarse policy matching.
	Level Level `json:"level"`

	// Factors are the individual contributions, kept so a surprising score can
	// be traced to its cause instead of taken on faith.
	Factors []Factor `json:"factors"`

	// Confidence in [0,1] reflects how much evidence backed the assessment. A
	// high score with low confidence is a candidate for human review rather
	// than an automatic block.
	Confidence float64 `json:"confidence"`
}

// Level is a bucketed risk score.
type Level string

const (
	LevelNone     Level = "none"
	LevelLow      Level = "low"
	LevelMedium   Level = "medium"
	LevelHigh     Level = "high"
	LevelCritical Level = "critical"
)

// Factor is one contribution to a risk score.
type Factor struct {
	// Name identifies the heuristic, e.g. "sensitive_path", "novel_egress".
	Name string `json:"name"`

	// Weight is signed: factors may reduce risk as well as raise it.
	Weight float64 `json:"weight"`

	Description string `json:"description"`

	// Evidence points at the concrete data behind the factor.
	Evidence map[string]string `json:"evidence,omitempty"`
}

// ReasoningStep is one link in the explanation chain.
type ReasoningStep struct {
	// Stage names the module that produced this step.
	Stage string `json:"stage"`

	Conclusion string `json:"conclusion"`
	Detail     string `json:"detail,omitempty"`
}

// Sink receives decisions for persistence, display, or forwarding.
//
// Separate from enforcement: recording what was decided and acting on it are
// different responsibilities with different failure modes, and an audit sink
// that fails must not prevent a block.
type Sink interface {
	// Emit records a decision. Implementations must not block the pipeline;
	// buffer or drop with a counter instead.
	Emit(ctx context.Context, d Decision) error

	// Flush makes buffered decisions durable. Called at session end and on
	// shutdown.
	Flush(ctx context.Context) error
}

// Enforcer applies a decision to the running system.
//
// Implementations vary sharply in what they can do, which is why this is an
// interface rather than a function. A monitor-mode enforcer only logs; a
// signal-based one can SIGSTOP a process pending approval; an LSM- or
// seccomp-based one can deny the syscall before it takes effect. The pipeline
// need not care which is in use, but the audit record must, via
// Decision.Enforced.
type Enforcer interface {
	// Enforce applies the decision, reporting whether it was actually applied.
	Enforce(ctx context.Context, d Decision, e *event.Event) (applied bool, err error)

	// Capabilities reports what this enforcer can really do, so the daemon can
	// warn at startup when policy demands blocking the active enforcer cannot
	// deliver. Promising enforcement that will not happen is worse than
	// admitting monitor-only operation.
	Capabilities() EnforcerCapabilities
}

// EnforcerCapabilities describes an enforcer's real powers.
type EnforcerCapabilities struct {
	// CanBlock reports whether operations can be prevented before they take
	// effect, as opposed to detected after.
	CanBlock bool `json:"can_block"`

	// CanSuspend reports whether a process can be paused for approval.
	CanSuspend bool `json:"can_suspend"`

	CanTerminate bool `json:"can_terminate"`

	// Mechanism names the underlying method: "monitor", "signal", "seccomp",
	// "lsm-bpf".
	Mechanism string `json:"mechanism"`
}

// ApprovalRequest is raised when a decision requires human judgment.
type ApprovalRequest struct {
	ID        string      `json:"id"`
	SessionID string      `json:"session_id"`
	Decision  Decision    `json:"decision"`
	Event     event.Event `json:"event"`
	CreatedAt time.Time   `json:"created_at"`

	// Deadline is when the request times out. What happens then is policy, and
	// the safe default is deny, but a deny-on-timeout that fires while the user
	// is at lunch kills long-running tasks. The operator has to make that call
	// consciously.
	Deadline time.Time `json:"deadline"`

	// Summary is the plain-language description shown to the human. Approval
	// prompts are only useful if they can be understood in seconds; a prompt
	// showing raw syscall arguments gets reflexively approved, which is worse
	// than not asking.
	Summary string `json:"summary"`
}

// ApprovalBroker routes approval requests to a human and returns the answer.
type ApprovalBroker interface {
	// Request blocks until answered, the deadline passes, or ctx is cancelled.
	Request(ctx context.Context, req ApprovalRequest) (ApprovalResponse, error)

	// Pending lists outstanding requests.
	Pending(ctx context.Context) ([]ApprovalRequest, error)
}

// ApprovalResponse is a human's answer.
type ApprovalResponse struct {
	RequestID   string    `json:"request_id"`
	Approved    bool      `json:"approved"`
	RespondedBy string    `json:"responded_by"`
	RespondedAt time.Time `json:"responded_at"`
	Reason      string    `json:"reason,omitempty"`

	// Remember applies this answer to similar future events in the session,
	// trading precision for a tolerable number of prompts.
	Remember bool `json:"remember,omitempty"`

	// TimedOut reports that no human answered and the default was applied.
	TimedOut bool `json:"timed_out,omitempty"`
}

// TODO(decision): define the similarity relation behind Remember. Too loose and
// one approval authorizes far more than intended; too strict and it does not
// reduce prompting at all.
// TODO(decision): specify audit log durability. A decision that was enforced
// but never recorded is indistinguishable from one that never happened.
// TODO(decision): decide whether decisions should be hash-chained for tamper
// evidence, given the agent may run as the same user as the daemon in the
// single-user development case.
