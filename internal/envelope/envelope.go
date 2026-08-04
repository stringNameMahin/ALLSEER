// Package envelope generates Expected Capability Envelopes from analyzed
// intent.
//
// Generation is separated from intent analysis. Analysis interprets language
// and may involve a model; generation maps a structured analysis onto
// capabilities and must be deterministic, bounded, and auditable. That split is
// the module's main security property: even if analysis is wrong or
// manipulated, generation only ever issues capabilities from a known catalog,
// narrowed by policy limits it cannot exceed.
//
// The central tension is breadth versus precision. Too broad and the envelope
// enforces nothing; too narrow and the user drowns in false positives and
// learns to approve everything reflexively, which is worse than no governance
// because it looks like governance.
//
// The approach is profile-grounded generation: start from a curated template
// for the task type, then narrow it with the specifics of the request.
// Templates encode what a task class actually needs, so the model specializes a
// known-good envelope instead of inventing one.
package envelope

import (
	"context"

	"github.com/stringNameMahin/ALLSEER/internal/intent"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
)

// Generator builds envelopes. It implements ece.Generator.
type Generator interface {
	ece.Generator

	// GenerateFromAnalysis builds an envelope directly from an intent analysis,
	// which is the path the daemon uses.
	GenerateFromAnalysis(ctx context.Context, req AnalysisRequest) (*ece.Envelope, error)
}

// AnalysisRequest is the input to generation.
type AnalysisRequest struct {
	SessionID string
	Analysis  *intent.Analysis

	WorkspaceRoot string

	// Catalog bounds generation to observable capabilities. A grant for
	// something no probe watches is a blind spot dressed as a control.
	Catalog capability.Catalog

	// Profile is an optional base template. When empty the generator selects
	// one from the analysis's task type.
	Profile *Profile

	// Limits are hard policy ceilings the generator may not exceed whatever the
	// analysis asked for. This is the backstop against a manipulated analysis:
	// an injected prompt cannot produce an envelope wider than the operator
	// permits.
	Limits Limits
}

// Profile is a reusable envelope template for a class of task.
//
// Profiles are the main mechanism for making envelopes both accurate and
// reviewable. "Run the Go test suite" needs a well-understood set of
// capabilities, and encoding that once as a reviewed template is far more
// reliable than deriving it from scratch on every request.
type Profile struct {
	Name        string `json:"name" yaml:"name"`
	Description string `json:"description" yaml:"description"`

	// TaskTypes this profile applies to.
	TaskTypes []string `json:"task_types" yaml:"task_types"`

	// BaseGrants are always included when the profile is selected.
	BaseGrants []capability.Grant `json:"base_grants" yaml:"base_grants"`

	// ConditionalGrants are included only when the analysis indicates the
	// corresponding need, keeping envelopes tight for the common case.
	ConditionalGrants []ConditionalGrant `json:"conditional_grants,omitempty" yaml:"conditional_grants,omitempty"`

	// BaseDenials are always included, for carve-outs a broad base grant would
	// otherwise swallow, such as denying writes to .git.
	BaseDenials []capability.Grant `json:"base_denials,omitempty" yaml:"base_denials,omitempty"`

	// DefaultConstraints seed the envelope's session constraints.
	DefaultConstraints ece.Constraints `json:"default_constraints" yaml:"default_constraints"`
}

// ConditionalGrant is a grant included only when a condition holds.
type ConditionalGrant struct {
	// Condition names the trigger, e.g. "requires_network", "has_vcs".
	Condition string `json:"condition" yaml:"condition"`

	Grant capability.Grant `json:"grant" yaml:"grant"`
}

// Limits are hard ceilings on what generation may produce.
//
// Operator-controlled and outside the model's reach entirely, so even a fully
// compromised analyzer cannot produce an envelope exceeding them.
type Limits struct {
	// MaxGrants caps envelope size. An envelope with fifty grants is not
	// constraining anything.
	MaxGrants int `json:"max_grants" yaml:"max_grants"`

	// ForbiddenKinds may never be granted whatever the intent.
	ForbiddenKinds []capability.Kind `json:"forbidden_kinds" yaml:"forbidden_kinds"`

	// RequireApprovalKinds always route the envelope to human approval.
	RequireApprovalKinds []capability.Kind `json:"require_approval_kinds" yaml:"require_approval_kinds"`

	// MaxSeverity caps the baseline severity of any grant.
	MaxSeverity capability.Severity `json:"max_severity" yaml:"max_severity"`

	// AllowUnboundedSelectors permits grants with no selector. Defaults to
	// false: an unbounded grant is nearly always a generation failure rather
	// than a genuine requirement.
	AllowUnboundedSelectors bool `json:"allow_unbounded_selectors" yaml:"allow_unbounded_selectors"`

	// MinConfidence is the analysis confidence below which generation must
	// escalate to a human instead of proceeding.
	MinConfidence float64 `json:"min_confidence" yaml:"min_confidence"`
}

// ProfileStore holds available profiles.
type ProfileStore interface {
	// Get returns a profile by name.
	Get(ctx context.Context, name string) (*Profile, error)

	// SelectForTaskType returns the best profile for a task type, and false
	// when none matches. The caller must then fall back to a minimal envelope
	// rather than an empty one: no profile means less confidence, not more
	// freedom.
	SelectForTaskType(ctx context.Context, taskType string) (*Profile, bool)

	// List returns all profiles.
	List(ctx context.Context) ([]*Profile, error)
}

// Narrower tightens grants using specifics from the analysis.
//
// This is where a profile's generic "may write source files" becomes "may write
// ./internal/parser/**", using the paths the user actually named. Isolated
// because it is the step most likely to be improved iteratively, and the one
// whose quality most directly sets the false-positive rate.
type Narrower interface {
	// Narrow returns a tightened copy of the grant. It must only restrict;
	// widening here would let the analysis escape the profile's bounds.
	Narrow(g capability.Grant, an *intent.Analysis, workspaceRoot string) capability.Grant
}

// Sealer finalizes an envelope: computing its digest and marking it immutable.
type Sealer interface {
	// Seal computes the digest and sets Sealed. Returns an error if the
	// envelope is already sealed, since re-sealing a modified envelope is
	// exactly the attack this guards against.
	Seal(env *ece.Envelope) error

	// Verify checks that a sealed envelope's digest matches its content.
	Verify(env *ece.Envelope) error
}

// TODO(envelope): write the initial profile set: go-build, go-test,
// npm-install, python-test, git-operations, refactor, docs-edit. Curate them by
// hand and review them as carefully as code; they are effectively policy.
// TODO(envelope): implement canonical JSON serialization for sealing, with
// pinned key ordering and number formatting so digests are reproducible.
// TODO(envelope): decide how conditional grants are evaluated. A small
// expression language is flexible and is also a new attack surface; a fixed set
// of named conditions is probably right for v1.
// TODO(envelope): implement path narrowing against the workspace, including
// symlinked workspace roots.
// TODO(envelope): add an envelope diff tool so a user can see how a generated
// envelope differs from the profile it came from. That diff is the most useful
// thing to put in front of a human approver.
