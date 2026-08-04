// Package ece defines the Expected Capability Envelope: the structured,
// task-specific specification of what an agent is expected to do.
//
// The ECE is the central artifact. It is derived from user intent before the
// agent runs, and every subsequent decision compares observed behavior against
// it. Its quality bounds the system's quality: an envelope that is too broad
// enforces nothing, and one that is too narrow buries the user in false
// positives.
//
// Two properties are non-negotiable:
//
//   - Immutability. An envelope is frozen once sealed. If the task changes,
//     that is a new envelope requiring fresh authorization, never an edit to
//     the current one. A mutable envelope could be widened by the very agent it
//     constrains.
//   - Auditability. Every envelope records what prompt produced it, which
//     analyzer built it, and who approved it. When a decision is questioned
//     months later the envelope must explain itself without external context.
package ece

import (
	"context"
	"time"

	"github.com/stringNameMahin/ALLSEER/pkg/capability"
)

// SchemaVersion is the current ECE format version. Envelopes carry their
// version so a daemon can reject documents it cannot faithfully interpret;
// silently ignoring an unknown restriction field would be a security failure,
// not a compatibility nicety.
const SchemaVersion = "allseer.dev/ece/v1alpha1"

// Envelope is the complete expected capability specification for one task.
type Envelope struct {
	SchemaVersion string `json:"schema_version"`

	ID string `json:"id"`

	// SessionID ties the envelope to the session it governs.
	SessionID string `json:"session_id"`

	CreatedAt time.Time `json:"created_at"`

	// ExpiresAt bounds validity. An envelope is a statement about one task, and
	// tasks end; an unexpiring envelope becomes a standing grant, which is what
	// this system exists to avoid.
	ExpiresAt time.Time `json:"expires_at,omitempty"`

	// --- Provenance ---------------------------------------------------------

	// Intent records the user request and its analysis, which is what makes an
	// envelope reviewable: a human can ask whether this set of grants actually
	// follows from what they asked for.
	Intent IntentRecord `json:"intent"`

	// --- Content ------------------------------------------------------------

	// Grants enumerate expected capabilities. The absence of a grant is the
	// enforcement mechanism: anything not granted is by construction outside
	// the envelope.
	Grants []capability.Grant `json:"grants"`

	// Denials override any grant. They exist for carve-outs a broad grant would
	// otherwise swallow, such as granting fs.write across a repo while denying
	// writes to .git/ or CI configuration. Denials always win.
	Denials []capability.Grant `json:"denials,omitempty"`

	// Constraints bound the session as a whole, independent of any one grant.
	Constraints Constraints `json:"constraints"`

	// DefaultAction applies to observations matching no grant and no denial. It
	// is the envelope's posture: fail-closed or fail-open.
	DefaultAction Action `json:"default_action"`

	// --- Authorization ------------------------------------------------------

	// Approval records human sign-off, when the configured trust model requires
	// it before an envelope may take effect.
	Approval *ApprovalRecord `json:"approval,omitempty"`

	// Sealed marks the envelope immutable. The daemon must refuse to enforce an
	// unsealed envelope, and refuse to modify a sealed one.
	Sealed bool `json:"sealed"`

	// Digest is a content hash over the canonical serialization, excluding this
	// field. It detects tampering between generation and enforcement.
	Digest string `json:"digest,omitempty"`
}

// IntentRecord captures how an envelope came to exist.
type IntentRecord struct {
	// RawPrompt is the user's request verbatim, never normalized. The exact
	// text is what a reviewer needs to judge whether the grants follow from it.
	RawPrompt string `json:"raw_prompt"`

	// Summary restates the task in the analyzer's words. Divergence from
	// RawPrompt is a warning sign: it means the system is governing a task the
	// user did not ask for.
	Summary string `json:"summary"`

	// TaskType classifies the request, e.g. "refactor", "dependency-upgrade".
	TaskType string `json:"task_type,omitempty"`

	// Analyzer identifies which implementation produced this analysis, e.g.
	// "llm:claude-sonnet-5" or "rules:v3", so a systematically bad analyzer can
	// be traced from the envelopes it produced.
	Analyzer string `json:"analyzer"`

	// Confidence is the analyzer's self-reported certainty in [0,1]. Low
	// confidence should route to human approval rather than quietly producing a
	// permissive envelope.
	Confidence float64 `json:"confidence"`

	// Ambiguities lists what the analyzer could not resolve. These are the
	// questions worth asking the user before execution starts.
	Ambiguities []string `json:"ambiguities,omitempty"`
}

// Constraints bound the whole session regardless of individual grants.
//
// They are the backstop for envelopes that are individually reasonable but
// collectively excessive: every grant may be justified while the session as a
// whole still runs far longer or touches far more than the task warranted.
type Constraints struct {
	MaxDuration  time.Duration `json:"max_duration,omitempty"`
	MaxProcesses int           `json:"max_processes,omitempty"`

	MaxFileWrites int `json:"max_file_writes,omitempty"`

	// MaxNetworkBytes caps total egress. Volume is the clearest exfiltration
	// signal available without inspecting payloads.
	MaxNetworkBytes int64 `json:"max_network_bytes,omitempty"`

	// WorkspaceRoot is the directory the task is scoped to. Filesystem grants
	// are interpreted relative to it, and escaping it is significant on its own.
	WorkspaceRoot string `json:"workspace_root,omitempty"`

	// AllowNetworkByDefault inverts network posture. Defaults to false: for a
	// coding agent, egress should be the exception.
	AllowNetworkByDefault bool `json:"allow_network_by_default,omitempty"`
}

// Action is the enforcement outcome the envelope prescribes.
type Action string

const (
	// ActionAllow permits the operation and records it.
	ActionAllow Action = "allow"

	// ActionWarn permits but flags for review. The operation still happens, so
	// warn is an observability outcome rather than a control.
	ActionWarn Action = "warn"

	// ActionRequestApproval suspends the actor and asks a human. The
	// distinctive middle ground: it converts an uncertain automated judgment
	// into an informed human one, at the cost of latency.
	ActionRequestApproval Action = "request_approval"

	// ActionBlock prevents or terminates the operation.
	ActionBlock Action = "block"
)

// ApprovalRecord captures human authorization of an envelope.
type ApprovalRecord struct {
	ApprovedBy string    `json:"approved_by"`
	ApprovedAt time.Time `json:"approved_at"`

	// Method records how approval was obtained ("cli", "auto:trusted-workspace").
	// An auto-approval is still an approval and must be as visible as a human one.
	Method string `json:"method"`

	// Modifications lists changes the approver made to the generated envelope.
	// Systematic edits are the strongest available feedback that the analyzer
	// is miscalibrated.
	Modifications []string `json:"modifications,omitempty"`
}

// Generator produces an envelope from analyzed intent.
//
// Separate from the Analyzer, which interprets language, because the two have
// different failure modes and testing needs. Generation should be deterministic
// and auditable given a fixed analysis, even when the analysis came from a
// model.
type Generator interface {
	Generate(ctx context.Context, req GenerateRequest) (*Envelope, error)
}

// GenerateRequest is the input to envelope generation.
type GenerateRequest struct {
	SessionID string
	Intent    IntentRecord

	// WorkspaceRoot scopes filesystem grants.
	WorkspaceRoot string

	// Catalog constrains generation to observable capabilities, so the
	// generator cannot grant something this build has no probe for.
	Catalog capability.Catalog

	// BaseProfile names an optional starting template ("go-build",
	// "npm-install") that grounds generation in known-good envelopes rather
	// than building from scratch each time.
	BaseProfile string
}

// Store persists envelopes for audit and retrieval.
type Store interface {
	Put(ctx context.Context, env *Envelope) error
	Get(ctx context.Context, id string) (*Envelope, error)
	GetBySession(ctx context.Context, sessionID string) (*Envelope, error)
	List(ctx context.Context, filter ListFilter) ([]*Envelope, error)
}

// ListFilter narrows envelope queries.
type ListFilter struct {
	SessionID string
	Since     time.Time
	Until     time.Time
	TaskType  string
	Limit     int
}

// Validator checks an envelope for structural and semantic soundness before it
// is sealed.
//
// A distinct concern from validating agent behavior. The question here is
// whether the envelope itself is coherent: does it reference only known
// capabilities, are its selectors well-formed, is it dangerously broad, does a
// denial contradict a grant it was meant to narrow?
type Validator interface {
	Validate(ctx context.Context, env *Envelope) ([]Issue, error)
}

// Issue is a problem found in an envelope.
type Issue struct {
	Severity capability.Severity `json:"severity"`
	Field    string              `json:"field"`
	Message  string              `json:"message"`

	// Suggestion is a concrete remediation where one exists.
	Suggestion string `json:"suggestion,omitempty"`
}

// TODO(ece): define canonical serialization for Digest. JSON key order and
// number formatting must be pinned or the hash is not reproducible.
// TODO(ece): decide whether to sign envelopes rather than only hash them. A
// digest catches accidental corruption; a signature is what stops a compromised
// agent forging a permissive envelope.
// TODO(ece): design envelope amendment. Long tasks legitimately discover new
// needs mid-run, but an amendment must be a new authorized envelope chained to
// the old one, never an in-place edit.
// TODO(ece): build a corpus of hand-written reference envelopes for common
// tasks, usable as both regression tests and few-shot examples.
