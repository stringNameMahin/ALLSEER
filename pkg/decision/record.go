package decision

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
)

// RecordKind names what one line of the audit log holds.
//
// Every line carries it in its "record" field, decisions included, so a reader
// dispatches on one field and never infers a line's type from which other
// fields happen to be present. The kind is written by each type's own JSON
// encoding, so no producer can forget it.
type RecordKind string

const (
	// RecordDecision is a Decision: the verdict for one observed event.
	RecordDecision RecordKind = "decision"

	// RecordSessionStart is a SessionStart.
	RecordSessionStart RecordKind = "session_start"

	// RecordApproval is an Approval.
	RecordApproval RecordKind = "approval"

	// RecordControlRefused is a ControlRefused.
	RecordControlRefused RecordKind = "control_refused"

	// RecordSessionEnd is a SessionEnd.
	RecordSessionEnd RecordKind = "session_end"

	// RecordLeftover is a Leftover.
	RecordLeftover RecordKind = "leftover"
)

// AllRecordKinds returns every kind of audit line this build writes.
// Append-only, like every wire-contract enum here.
func AllRecordKinds() []RecordKind {
	return []RecordKind{
		RecordDecision,
		RecordSessionStart,
		RecordApproval,
		RecordControlRefused,
		RecordSessionEnd,
		RecordLeftover,
	}
}

// ErrNoRecordKind means an audit line has no "record" field.
var ErrNoRecordKind = errors.New("decision: audit line has no record kind")

// KindOf reads the discriminator of one audit line without decoding the rest.
func KindOf(line []byte) (RecordKind, error) {
	var head struct {
		Record RecordKind `json:"record"`
	}
	if err := json.Unmarshal(line, &head); err != nil {
		return "", err
	}
	if head.Record == "" {
		return "", ErrNoRecordKind
	}
	return head.Record, nil
}

// checkKind refuses a line that names a different kind than want. A line with
// no kind is let through: only a reader that dispatched first can tell, and a
// decision written before the discriminator existed has none.
func checkKind(data []byte, want RecordKind) error {
	var head struct {
		Record RecordKind `json:"record"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return err
	}
	if head.Record != "" && head.Record != want {
		return fmt.Errorf("decision: audit line is a %q record, not %q", head.Record, want)
	}
	return nil
}

// Record is a session-level audit line: one that frames decisions rather than
// being one.
type Record interface {
	RecordKind() RecordKind
}

// RecordSink receives session-level records. internal/audit.JSONLSink writes
// them into the same stream as decisions, so the facts that qualify a
// session's decisions cannot be separated from them.
type RecordSink interface {
	EmitRecord(ctx context.Context, r Record) error
}

// SessionStart is written when an agent begins running under governance. It
// carries what every later decision in the session is judged against.
type SessionStart struct {
	SessionID string    `json:"session_id"`
	Timestamp time.Time `json:"timestamp"`

	// Owner is the user the session acts for.
	Owner    string `json:"owner"`
	OwnerUID uint32 `json:"owner_uid"`

	Mode     string `json:"mode"`
	RootPID  int32  `json:"root_pid"`
	CgroupID uint64 `json:"cgroup_id"`

	// Envelope is the sealed envelope, approval included. Sessions do not
	// survive a daemon restart, so this is the only durable copy.
	Envelope *ece.Envelope `json:"envelope"`

	Coverage Coverage `json:"coverage"`

	DaemonVersion string `json:"daemon_version,omitempty"`
}

// Coverage is what the attached probes could observe for a session. A missing
// record for an operation the probes could not see is not evidence that the
// operation did not happen.
type Coverage struct {
	// Observable is every capability the attached probes report.
	Observable []capability.Kind `json:"observable"`

	// Unobservable is what this build can watch and this load could not.
	Unobservable []capability.Kind `json:"unobservable,omitempty"`

	// Degraded means this load lost something this build can watch.
	Degraded bool `json:"degraded"`

	// EntryPoints lists observable kinds that some entry point is not
	// watched for, whether this build never watches it or this load lost it.
	EntryPoints []EntryPointGap `json:"entry_points,omitempty"`
}

// EntryPointGap is one capability's unwatched entry points.
type EntryPointGap struct {
	Kind capability.Kind `json:"kind"`

	// Missing entry points produce no record at all.
	Missing []string `json:"missing,omitempty"`

	// SuccessOnly entry points are recorded only when the kernel permitted
	// the operation; a refused attempt produces no record.
	SuccessOnly []string `json:"success_only,omitempty"`
}

// ApprovalEffect is what an approval answer did to its session.
type ApprovalEffect string

const (
	// EffectResume: the last open request was approved; the session resumes.
	EffectResume ApprovalEffect = "resume"

	// EffectWait: approved, but other requests for the session are still open,
	// so it stays frozen.
	EffectWait ApprovalEffect = "wait"

	// EffectTerminate: denied or timed out under deny; the session is killed
	// and its other open requests are withdrawn.
	EffectTerminate ApprovalEffect = "terminate"

	// EffectNone: approved, but an earlier denial is already terminating the
	// session, so nothing is resumed.
	EffectNone ApprovalEffect = "none"
)

// Approval is the answer to a request a frozen session was waiting on: a
// human's, or the configured default when nobody answered in time.
type Approval struct {
	SessionID string    `json:"session_id"`
	Timestamp time.Time `json:"timestamp"`

	RequestID string `json:"request_id"`

	// DecisionID is the request_approval decision this answers.
	DecisionID string `json:"decision_id"`

	Approved bool `json:"approved"`

	// RespondedBy is the answering user's name, or "timeout".
	RespondedBy string `json:"responded_by"`
	TimedOut    bool   `json:"timed_out"`
	Reason      string `json:"reason,omitempty"`

	Effect ApprovalEffect `json:"effect"`
}

// ControlRefused is a control-socket request the daemon turned down because
// the caller was inside a governed session, or could not be located.
type ControlRefused struct {
	Timestamp time.Time `json:"timestamp"`
	Method    string    `json:"method"`
	PID       int32     `json:"pid"`
	UID       uint32    `json:"uid"`

	// SessionID is the session whose cgroup holds the caller, when known.
	SessionID string `json:"session_id,omitempty"`

	Reason string `json:"reason"`
}

// SessionEnd is written once, when a session reaches a terminal state, whether
// or not it ever started.
type SessionEnd struct {
	SessionID string    `json:"session_id"`
	Timestamp time.Time `json:"timestamp"`

	// Result is completed, terminated (policy stopped the agent) or failed
	// (governance itself broke).
	Result string `json:"result"`
	Reason string `json:"reason"`

	// TelemetryComplete false qualifies every conclusion drawn from the
	// session, including that nothing bad happened.
	TelemetryComplete bool `json:"telemetry_complete"`

	ViolationCount  int     `json:"violation_count"`
	BlockedCount    int     `json:"blocked_count"`
	EventsObserved  uint64  `json:"events_observed"`
	DecisionsIssued uint64  `json:"decisions_issued"`
	PeakRiskScore   float64 `json:"peak_risk_score"`

	CapabilityUsage map[capability.Kind]int `json:"capability_usage,omitempty"`
	UnusedGrants    []capability.Kind       `json:"unused_grants,omitempty"`
	TopViolations   []string                `json:"top_violations,omitempty"`
}

// LeftoverAction is what happened to a leftover session cgroup.
type LeftoverAction string

// The actions on a leftover. Append-only.
const (
	// LeftoverFrozen: the startup sweep froze it.
	LeftoverFrozen LeftoverAction = "frozen"
	// LeftoverFreezeFailed: the startup sweep could not freeze it, so its
	// processes are still running with nothing governing them.
	LeftoverFreezeFailed LeftoverAction = "freeze_failed"
	// LeftoverThawed: an operator resumed it. Its processes run ungoverned.
	LeftoverThawed LeftoverAction = "thawed"
	// LeftoverKilled: an operator killed every process in it.
	LeftoverKilled LeftoverAction = "killed"
)

// Leftover is an action on a session cgroup a previous daemon left behind
// with processes still in it. The cgroup is named after the dead session, so
// these lines follow that session's start record, which has no end record.
type Leftover struct {
	SessionID string    `json:"session_id"`
	Timestamp time.Time `json:"timestamp"`

	Action LeftoverAction `json:"action"`

	// PIDs are the processes in the group when the action was taken.
	PIDs []int32 `json:"pids,omitempty"`

	// By is the user who acted, or "startup" for the sweep.
	By     string `json:"by"`
	Reason string `json:"reason,omitempty"`
}

// RecordKind implements Record.
func (SessionStart) RecordKind() RecordKind { return RecordSessionStart }

// RecordKind implements Record.
func (Approval) RecordKind() RecordKind { return RecordApproval }

// RecordKind implements Record.
func (ControlRefused) RecordKind() RecordKind { return RecordControlRefused }

// RecordKind implements Record.
func (SessionEnd) RecordKind() RecordKind { return RecordSessionEnd }

// RecordKind implements Record.
func (Leftover) RecordKind() RecordKind { return RecordLeftover }

// The wire types below have no methods, so marshalling one does not re-enter
// the method that called it. Embedding puts the kind first on the line.

// MarshalJSON writes the record with its kind.
func (r SessionStart) MarshalJSON() ([]byte, error) {
	type wire SessionStart
	return json.Marshal(struct {
		Record RecordKind `json:"record"`
		wire
	}{RecordSessionStart, wire(r)})
}

// UnmarshalJSON refuses a line of another kind.
func (r *SessionStart) UnmarshalJSON(data []byte) error {
	type wire SessionStart
	if err := checkKind(data, RecordSessionStart); err != nil {
		return err
	}
	return json.Unmarshal(data, (*wire)(r))
}

// MarshalJSON writes the record with its kind.
func (r Approval) MarshalJSON() ([]byte, error) {
	type wire Approval
	return json.Marshal(struct {
		Record RecordKind `json:"record"`
		wire
	}{RecordApproval, wire(r)})
}

// UnmarshalJSON refuses a line of another kind.
func (r *Approval) UnmarshalJSON(data []byte) error {
	type wire Approval
	if err := checkKind(data, RecordApproval); err != nil {
		return err
	}
	return json.Unmarshal(data, (*wire)(r))
}

// MarshalJSON writes the record with its kind.
func (r ControlRefused) MarshalJSON() ([]byte, error) {
	type wire ControlRefused
	return json.Marshal(struct {
		Record RecordKind `json:"record"`
		wire
	}{RecordControlRefused, wire(r)})
}

// UnmarshalJSON refuses a line of another kind.
func (r *ControlRefused) UnmarshalJSON(data []byte) error {
	type wire ControlRefused
	if err := checkKind(data, RecordControlRefused); err != nil {
		return err
	}
	return json.Unmarshal(data, (*wire)(r))
}

// MarshalJSON writes the record with its kind.
func (r SessionEnd) MarshalJSON() ([]byte, error) {
	type wire SessionEnd
	return json.Marshal(struct {
		Record RecordKind `json:"record"`
		wire
	}{RecordSessionEnd, wire(r)})
}

// UnmarshalJSON refuses a line of another kind.
func (r *SessionEnd) UnmarshalJSON(data []byte) error {
	type wire SessionEnd
	if err := checkKind(data, RecordSessionEnd); err != nil {
		return err
	}
	return json.Unmarshal(data, (*wire)(r))
}

// MarshalJSON writes the record with its kind.
func (r Leftover) MarshalJSON() ([]byte, error) {
	type wire Leftover
	return json.Marshal(struct {
		Record RecordKind `json:"record"`
		wire
	}{RecordLeftover, wire(r)})
}

// UnmarshalJSON refuses a line of another kind.
func (r *Leftover) UnmarshalJSON(data []byte) error {
	type wire Leftover
	if err := checkKind(data, RecordLeftover); err != nil {
		return err
	}
	return json.Unmarshal(data, (*wire)(r))
}
