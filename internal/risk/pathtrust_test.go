package risk

import (
	"context"
	"testing"

	"github.com/stringNameMahin/ALLSEER/internal/validator"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

func indeterminateReq(e *event.Event) ScoreRequest {
	return ScoreRequest{
		Event: e,
		Validation: result(decision.VerdictIndeterminate,
			viol(validator.ViolationUnresolvable, capability.SeverityMedium)),
		Envelope: envelope(),
		History:  history(),
	}
}

func TestUnverifiablePathChargesWhatTheKernelCouldNotVouchFor(t *testing.T) {
	cases := map[string]func(*event.Event){
		"truncated path": func(e *event.Event) { e.File.Truncated = true },
		"dir truncated":  func(e *event.Event) { e.File.Path, e.File.DirStatus = "x", "truncated" },
		"dir deleted":    func(e *event.Event) { e.File.Path, e.File.DirStatus = "x", "deleted" },
		"dir unavail":    func(e *event.Event) { e.File.Path, e.File.DirStatus = "x", "unavailable" },
	}
	for name, mod := range cases {
		e := fileEvent(capability.KindFileRead, "")
		e.File.ResolvedPath = ""
		mod(e)
		f, err := UnverifiablePathScorer{}.Evaluate(context.Background(), indeterminateReq(e))
		if err != nil || f == nil || f.Weight != UnverifiablePathPoints || f.Evidence[EvidencePathProblem] == "" {
			t.Errorf("%s: factor %+v, err %v", name, f, err)
		}
	}

	x := &event.Event{Capability: capability.KindProcessExec, Domain: capability.DomainProcess,
		Exec: &event.ExecPayload{Filename: "/usr/bin/long", Truncated: true}}
	if f, _ := (UnverifiablePathScorer{}).Evaluate(context.Background(), indeterminateReq(x)); f == nil {
		t.Error("a truncated exec filename was not charged")
	}
}

// A file opened and removed before enrichment is ordinary, not evasion.
func TestUnverifiablePathIgnoresOrdinaryUnresolved(t *testing.T) {
	e := fileEvent(capability.KindFileRead, "")
	e.File.Path, e.File.Dir, e.File.DirStatus = "a.out", "/tmp/b", "complete"
	if f, _ := (UnverifiablePathScorer{}).Evaluate(context.Background(), indeterminateReq(e)); f != nil {
		t.Errorf("charged an ordinary unresolved path: %+v", f)
	}
	// An absolute path ignores DirStatus.
	e = fileEvent(capability.KindFileRead, "/etc/x")
	e.File.DirStatus = "deleted"
	if f, _ := (UnverifiablePathScorer{}).Evaluate(context.Background(), indeterminateReq(e)); f != nil {
		t.Errorf("charged an absolute path on a directory status: %+v", f)
	}
}

// The point of the factor: an unverifiable path reaches the rule set's
// indeterminate-high-risk band (50 and above), an ordinary one does not.
func TestUnverifiablePathCrossesTheIndeterminateBoundary(t *testing.T) {
	plain := fileEvent(capability.KindFileRead, "")
	padded := fileEvent(capability.KindFileRead, "")
	padded.File.Truncated = true

	low := score(t, indeterminateReq(plain))
	high := score(t, indeterminateReq(padded))
	if low.Score >= 50 || high.Score < 50 {
		t.Fatalf("scores = %v (ordinary) and %v (truncated); want below and at or above 50", low.Score, high.Score)
	}
}
