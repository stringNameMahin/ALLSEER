package decision

import (
	"encoding/json"
	"strings"
	"testing"
)

// The wire form of a risk assessment is a contract with external tooling -
// api/schema/decision.v1alpha1.schema.json is the published half of it - so the
// cases below are about bytes rather than about Go values.

// An assessment nobody made must render in the one form the schema admits, and
// must not borrow a band from one that was made.
func TestZeroRiskAssessmentRendersAsUnscored(t *testing.T) {
	b, err := json.Marshal(RiskAssessment{})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got := string(b)

	for _, rejected := range []string{`"level":""`, `"factors":null`} {
		if strings.Contains(got, rejected) {
			t.Errorf("the zero assessment carries %s, which the schema rejects\ngot: %s", rejected, got)
		}
	}
	if !strings.Contains(got, `"level":"unscored"`) {
		t.Errorf("the zero assessment did not name its absence\ngot: %s", got)
	}
	if !strings.Contains(got, `"factors":[]`) {
		t.Errorf("the zero assessment did not render an empty factor array\ngot: %s", got)
	}
	// Score and confidence are not normalized. Zero confidence is the honest
	// reading of no evidence, and inventing a score would be the substitution
	// this whole change exists to avoid.
	if !strings.Contains(got, `"score":0`) || !strings.Contains(got, `"confidence":0`) {
		t.Errorf("score or confidence was rewritten\ngot: %s", got)
	}
}

// A real assessment must pass through untouched. The golden decision streams
// are byte-asserted, so a marshaler that reformatted a scored record would
// rewrite every one of them.
func TestScoredAssessmentIsNotRewritten(t *testing.T) {
	in := RiskAssessment{
		Score:      55,
		Level:      LevelHigh,
		Factors:    []Factor{{Name: "verdict", Weight: 30, Description: "outside envelope"}},
		Confidence: 0.6,
	}

	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var back RiskAssessment
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if back.Score != in.Score || back.Level != in.Level || back.Confidence != in.Confidence {
		t.Errorf("scalar fields changed: %+v -> %+v", in, back)
	}
	if len(back.Factors) != 1 || back.Factors[0].Name != "verdict" {
		t.Errorf("factors changed: %+v", back.Factors)
	}
}

// Field order is part of the byte-level contract the golden streams assert.
func TestAssessmentFieldOrderIsStable(t *testing.T) {
	b, err := json.Marshal(RiskAssessment{Level: LevelNone, Factors: []Factor{}})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if want := `{"score":0,"level":"none","factors":[],"confidence":0}`; string(b) != want {
		t.Errorf("wire form changed\n got: %s\nwant: %s", b, want)
	}
}

// Once a decision is in its canonical form, writing and reading it must be the
// identity. The normalization happens on the way out of a zero value, not on
// every trip.
func TestCanonicalUnscoredFormRoundTrips(t *testing.T) {
	in := RiskAssessment{Level: LevelUnscored, Factors: []Factor{}}

	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var back RiskAssessment
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if back.Level != LevelUnscored {
		t.Errorf("Level = %q, want %q", back.Level, LevelUnscored)
	}
	if back.Factors == nil || len(back.Factors) != 0 {
		t.Errorf("Factors = %+v, want an empty array", back.Factors)
	}
}

// LevelUnscored must stay outside the assignable set. That is what keeps
// "nothing ran" distinguishable from "the engine ran and found nothing", and
// what stops internal/policy accepting it as a rule condition.
func TestUnscoredIsNotAnAssignableLevel(t *testing.T) {
	if ValidLevel(LevelUnscored) {
		t.Error("ValidLevel accepts LevelUnscored; unscored is no longer distinct from scored")
	}
	for _, l := range AllLevels() {
		if l == LevelUnscored {
			t.Fatal("LevelUnscored is a member of AllLevels, which orders severity bands")
		}
	}
	// The empty level is not assignable either, and never was. It is now only
	// an in-memory state that the marshaler names on the way out.
	if ValidLevel(Level("")) {
		t.Error("ValidLevel accepts the empty level")
	}
}

// A decision carrying an unset assessment is schema-valid as a whole, not just
// in its risk field. This is the shape that reached disk before the wire format
// was settled.
func TestUnscoredDecisionCarriesNoRejectedShape(t *testing.T) {
	b, err := json.Marshal(Decision{ID: "d-1", Verdict: VerdictIndeterminate})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got := string(b)
	if strings.Contains(got, `"level":""`) || strings.Contains(got, `"factors":null`) {
		t.Errorf("a decision with no risk stage still publishes a rejected shape\ngot: %s", got)
	}
}
