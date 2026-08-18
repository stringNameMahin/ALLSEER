package pipeline

import (
	"context"
	"errors"
	"fmt"

	"github.com/stringNameMahin/ALLSEER/internal/policy"
	"github.com/stringNameMahin/ALLSEER/internal/risk"
	"github.com/stringNameMahin/ALLSEER/internal/validator"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
)

// The stages are adapters and nothing more. Each one calls exactly one existing
// engine, copies its answer onto the ProcessingContext, and returns. No stage
// interprets a verdict, weighs a violation, or decides what an action should
// be: doing any of that here would be a second implementation of a module that
// already exists, and the second implementation is the one nobody tests against
// the corpus.
//
// The engines are taken as narrow interfaces declared here rather than as the
// concrete types, so a test can drive a stage with a stub without standing up a
// rule set — and so this package cannot reach past the one method it uses.

// Validator is the validation the pipeline needs. Satisfied by
// validator.DefaultValidator.
type Validator interface {
	Validate(ctx context.Context, req validator.ValidateRequest) (*validator.Result, error)
}

// RiskEngine is the scoring the pipeline needs. Satisfied by
// risk.BaselineEngine.
//
// Only Score, not ScoreSession: the hot path scores events, and session-level
// scoring is answered at session end by whoever owns the session rather than on
// every syscall.
type RiskEngine interface {
	Score(ctx context.Context, req risk.ScoreRequest) (*decision.RiskAssessment, error)
}

// PolicyEngine is the evaluation the pipeline needs. Satisfied by
// policy.RuleEngine.
type PolicyEngine interface {
	Evaluate(ctx context.Context, req policy.EvaluateRequest) (*policy.Outcome, error)
}

// ValidateStage compares the event against the envelope.
type ValidateStage struct{ v Validator }

var _ Stage = (*ValidateStage)(nil)

// NewValidateStage wraps a validator as a pipeline stage.
func NewValidateStage(v Validator) *ValidateStage { return &ValidateStage{v: v} }

// Name identifies the stage in metrics and reasoning chains.
func (s *ValidateStage) Name() string { return "validate" }

// Execute validates the event and records the result on the context.
//
// The session state is passed through as the validator's read side. The
// validator reads counters and never advances them, which is what keeps it a
// pure function of its inputs and what makes the pipeline's write-last ordering
// meaningful.
func (s *ValidateStage) Execute(ctx context.Context, pc *ProcessingContext) error {
	if s.v == nil {
		return errors.New("validate: no validator configured")
	}

	res, err := s.v.Validate(ctx, validator.ValidateRequest{
		Envelope: pc.Envelope,
		Event:    pc.Event,
		State:    pc.State,
	})
	if err != nil {
		return fmt.Errorf("validate: %w", err)
	}
	if res == nil {
		// The interface promises a non-nil result alongside a nil error. A nil
		// here would otherwise surface as a nil dereference in the decide
		// stage, one stage away from the code that broke the contract.
		return errors.New("validate: validator returned no result")
	}

	pc.Validation = res
	return nil
}

// ScoreStage assesses how serious the validated event is.
//
// Sits between validate and decide, which is the position the whole pipeline
// ordering was built around: it reads the validator's answer, and it reads the
// session history *before* the pipeline commits this event, so a target the
// agent is touching for the first time still reads as novel. Moving the commit
// earlier would make every target familiar by the time this stage asked.
type ScoreStage struct{ e RiskEngine }

var _ Stage = (*ScoreStage)(nil)

// NewScoreStage wraps a risk engine as a pipeline stage.
func NewScoreStage(e RiskEngine) *ScoreStage { return &ScoreStage{e: e} }

// Name identifies the stage in metrics and reasoning chains.
func (s *ScoreStage) Name() string { return "score" }

// Execute scores the event and records the assessment on the context.
//
// It refuses to run without a validation result for the same reason the decide
// stage does: every factor in the baseline model reads the validator's answer,
// and a score computed against an absent verdict would be a number with nothing
// behind it — which is precisely the fabricated evidence policy's no-evidence
// rule exists to keep out.
//
// A scoring failure is an error, never a zero assessment. The pipeline turns it
// into an explicit indeterminate decision; substituting a score would hand
// policy a reassuring value the engine never produced.
func (s *ScoreStage) Execute(ctx context.Context, pc *ProcessingContext) error {
	if s.e == nil {
		return errors.New("score: no risk engine configured")
	}
	if pc.Validation == nil {
		return errors.New("score: no validation result; an event that was never validated cannot be scored")
	}

	// pc.State is passed as the history. It may be nil — a pipeline is built
	// with state, but the field is an interface and a nil one is the honest
	// "no history" input the engine already handles by withholding the
	// history-derived factors and lowering confidence.
	var history risk.History
	if pc.State != nil {
		history = pc.State
	}

	assessment, err := s.e.Score(ctx, risk.ScoreRequest{
		Event:      pc.Event,
		Validation: pc.Validation,
		Envelope:   pc.Envelope,
		History:    history,
	})
	if err != nil {
		return fmt.Errorf("score: %w", err)
	}
	if assessment == nil {
		// The interface promises a non-nil assessment alongside a nil error. A
		// nil here would reach policy as "risk did not run", which is a
		// different and much quieter claim than "risk ran and found nothing".
		return errors.New("score: risk engine returned no assessment")
	}

	pc.Risk = assessment
	return nil
}

// DecideStage turns the validated event into an action.
type DecideStage struct{ e PolicyEngine }

var _ Stage = (*DecideStage)(nil)

// NewDecideStage wraps a policy engine as a pipeline stage.
func NewDecideStage(e PolicyEngine) *DecideStage { return &DecideStage{e: e} }

// Name identifies the stage in metrics and reasoning chains.
func (s *DecideStage) Name() string { return "decide" }

// Execute evaluates policy against what the earlier stages established.
//
// It refuses to run without a validation result rather than evaluating against
// an absent verdict. Policy conditions read the verdict and the violation list;
// with neither, every condition that mentions them would fail to match and the
// event would quietly fall through to the rule set's default action, which
// would look exactly like a considered decision. That is the policy engine's
// own rule about evidence, applied one stage earlier.
//
// Risk is passed through as-is, nil included. Nil is the honest state for a
// pipeline built without a score stage, and the policy engine already treats a
// condition with no evidence behind it as not matching.
func (s *DecideStage) Execute(ctx context.Context, pc *ProcessingContext) error {
	if s.e == nil {
		return errors.New("decide: no policy engine configured")
	}
	if pc.Validation == nil {
		return errors.New("decide: no validation result; policy cannot evaluate an event that was never validated")
	}

	out, err := s.e.Evaluate(ctx, policy.EvaluateRequest{
		Event:      pc.Event,
		Validation: pc.Validation,
		Risk:       pc.Risk,
		Envelope:   pc.Envelope,
		Mode:       pc.Mode,
	})
	if err != nil {
		return fmt.Errorf("decide: %w", err)
	}
	if out == nil {
		return errors.New("decide: policy returned no outcome")
	}

	pc.Outcome = out
	return nil
}

// --- error handling ------------------------------------------------------------

// IndeterminateHandler is the default ErrorHandler.
//
// It implements the rule the architecture states plainly: a stage failure must
// never silently allow. Every failure becomes an explicit decision carrying the
// indeterminate verdict, so a dropped stage is visible in the audit stream
// rather than absent from it — an event that produced no record is
// indistinguishable from an event that never happened.
//
// The verdict is indeterminate rather than any of the envelope-relative ones
// because none of those would be true. "Outside envelope" is a finding about
// the agent, and the pipeline failing to evaluate an event is not evidence of
// anything the agent did.
type IndeterminateHandler struct {
	action ece.Action
}

var _ ErrorHandler = (*IndeterminateHandler)(nil)

// NewErrorHandler returns the default handler, which asks a human.
func NewErrorHandler() *IndeterminateHandler {
	return &IndeterminateHandler{action: ActionForFailure}
}

// NewErrorHandlerWithAction returns a handler assigning a specific action.
//
// Exposed because the right answer is deployment-specific in a way the pipeline
// cannot settle: an unattended CI run has no human to ask, and whether it
// should block or proceed on a governance fault is exactly the kind of judgment
// this project keeps in configuration rather than in code.
func NewErrorHandlerWithAction(a ece.Action) *IndeterminateHandler {
	return &IndeterminateHandler{action: a}
}

// Handle produces the indeterminate decision for a failed stage.
func (h *IndeterminateHandler) Handle(_ context.Context, pc *ProcessingContext, stage string, err error) *decision.Decision {
	d := &decision.Decision{
		ID:        decisionID(pc),
		SessionID: pc.SessionID,
		Timestamp: pc.Started,
		Action:    h.action,
		Verdict:   decision.VerdictIndeterminate,

		// No MatchedGrant, even when validation had already found one. That
		// field is read downstream as "what covered this", and a run that could
		// not finish has not established that anything did.
		Enforced: false,
	}
	if pc.Event != nil {
		d.EventID = pc.Event.ID
		if !pc.Event.WallClock.IsZero() {
			d.Timestamp = pc.Event.WallClock
		}
	}

	// Whatever the earlier stages did conclude is kept. A partial explanation
	// is worth more than none to whoever has to work out why an event came back
	// indeterminate.
	if pc.Validation != nil {
		d.Reasoning = append(d.Reasoning, pc.Validation.Reasoning...)
	}
	d.Reasoning = append(d.Reasoning, decision.ReasoningStep{
		Stage:      "pipeline",
		Conclusion: fmt.Sprintf("stage %q failed", stage),
		Detail: fmt.Sprintf("%v; the event could not be classified, and an unclassified event is "+
			"reported rather than dropped", err),
	})
	return d
}
