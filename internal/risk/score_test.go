package risk

import (
	"context"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/stringNameMahin/ALLSEER/internal/validator"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// --- fixtures -------------------------------------------------------------------

const ws = "/ws"

// fakeHistory is a History with everything set by the test and every read
// recorded, so a test can assert not only what the scorer concluded but what it
// asked.
type fakeHistory struct {
	seen       map[string]bool
	violations int
	capCounts  map[capability.Kind]int
	recent     []event.Event
	duration   float64
	saturated  bool

	// asked records every TargetSeen query in order. Used to pin that history is
	// consulted at all, and by the pipeline test to pin *when*.
	asked []string
}

func (h *fakeHistory) CapabilityCount(k capability.Kind) int { return h.capCounts[k] }

func (h *fakeHistory) TargetSeen(k capability.Kind, target string) bool {
	h.asked = append(h.asked, string(k)+"|"+target)
	return h.seen[string(k)+"|"+target]
}

func (h *fakeHistory) ViolationCount() int { return h.violations }

// RecentEvents mirrors session.MemoryState's contract rather than approximating
// it: up to the last n events, oldest first. A fake that returned the *first* n
// would let a sequence test pass against a scorer that walks history the wrong
// way round, which is the one thing those tests exist to catch.
func (h *fakeHistory) RecentEvents(n int) []event.Event {
	if n <= 0 || len(h.recent) == 0 {
		return nil
	}
	if n > len(h.recent) {
		n = len(h.recent)
	}
	return h.recent[len(h.recent)-n:]
}

func (h *fakeHistory) SessionDurationSeconds() float64 { return h.duration }

// saturatingHistory adds the optional saturation reporter session.MemoryState
// carries, so the qualification path is covered without importing that package.
type saturatingHistory struct{ *fakeHistory }

func (h saturatingHistory) SeenTargetsSaturated() bool { return h.saturated }

func history() *fakeHistory {
	return &fakeHistory{seen: map[string]bool{}, capCounts: map[capability.Kind]int{}}
}

func (h *fakeHistory) withSeen(k capability.Kind, target string) *fakeHistory {
	h.seen[string(k)+"|"+target] = true
	return h
}

func (h *fakeHistory) withViolations(n int) *fakeHistory {
	h.violations = n
	return h
}

// withRecent sets the session's event history, oldest first -- the order
// RecentEvents promises and the order a sequence is only recognizable in.
func (h *fakeHistory) withRecent(events ...event.Event) *fakeHistory {
	h.recent = events
	return h
}

func fileEvent(kind capability.Kind, path string) *event.Event {
	domain, _ := capability.DomainOf(kind)
	return &event.Event{
		ID:         "e-1",
		SessionID:  "s-1",
		Capability: kind,
		Domain:     domain,
		File:       &event.FilePayload{Path: path, ResolvedPath: path},
		Observation: capability.Observation{
			Kind: kind, Domain: domain, Target: path,
		},
	}
}

// unresolvableEvent carries a payload enrichment never resolved, which is the
// state the validator reports as indeterminate.
func unresolvableEvent() *event.Event {
	return &event.Event{
		ID:         "e-unres",
		SessionID:  "s-1",
		Capability: capability.KindFileWrite,
		Domain:     capability.DomainFilesystem,
		File:       &event.FilePayload{Path: "../escape/a.go"},
	}
}

func viol(t validator.ViolationType, s capability.Severity) validator.Violation {
	return validator.Violation{
		Type:     t,
		Severity: s,
		Expected: "expected",
		Observed: "observed",
	}
}

func result(v decision.Verdict, vs ...validator.Violation) *validator.Result {
	return &validator.Result{Verdict: v, Violations: vs}
}

func envelope() *ece.Envelope {
	return &ece.Envelope{
		SchemaVersion: ece.SchemaVersion,
		ID:            "env-1",
		SessionID:     "s-1",
		Constraints:   ece.Constraints{WorkspaceRoot: ws},
		Sealed:        true,
	}
}

func score(t *testing.T, req ScoreRequest) *decision.RiskAssessment {
	t.Helper()
	a, err := NewEngine().Score(context.Background(), req)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if a == nil {
		t.Fatal("Score returned a nil assessment with a nil error")
	}
	return a
}

// factor returns the named factor, or nil when the assessment does not carry it.
func factor(a *decision.RiskAssessment, name string) *decision.Factor {
	for i := range a.Factors {
		if a.Factors[i].Name == name {
			return &a.Factors[i]
		}
	}
	return nil
}

func names(a *decision.RiskAssessment) []string {
	out := make([]string, 0, len(a.Factors))
	for _, f := range a.Factors {
		out = append(out, f.Name)
	}
	return out
}

// --- 1. the lowest-risk ordinary event --------------------------------------------

// An event a grant covered is the overwhelming majority of a session, and it has
// to score exactly zero. Not "close to zero": LevelNone is what distinguishes an
// assessed-and-clean event from one the risk stage never saw, and a baseline
// that drifted above zero on routine work would make every max_risk_score rule
// in a policy fire on ordinary builds.
func TestOrdinaryEventScoresZero(t *testing.T) {
	a := score(t, ScoreRequest{
		Event:      fileEvent(capability.KindFileWrite, ws+"/main.go"),
		Validation: result(decision.VerdictWithinEnvelope),
		Envelope:   envelope(),
		History:    history().withViolations(7),
	})

	if a.Score != 0 {
		t.Errorf("Score = %v, want 0", a.Score)
	}
	if a.Level != decision.LevelNone {
		t.Errorf("Level = %q, want %q", a.Level, decision.LevelNone)
	}
	if a.Confidence != 0.9 {
		t.Errorf("Confidence = %v, want 0.9", a.Confidence)
	}

	// The zero is a stated finding, not an empty assessment: the verdict factor
	// is present and says which verdict produced it.
	if got := names(a); !reflect.DeepEqual(got, []string{FactorVerdict, FactorEvidenceBasis}) {
		t.Errorf("factors = %v, want just the verdict and the evidence basis", got)
	}
	if f := factor(a, FactorVerdict); f == nil || f.Evidence["verdict"] != string(decision.VerdictWithinEnvelope) {
		t.Errorf("verdict factor = %+v, want evidence naming within_envelope", f)
	}

	// The two history-reading factors are withheld from a covered event even
	// though the session has seven violations on record and the target is new.
	// That is the rule that keeps the common path at zero and history-free.
	if f := factor(a, FactorViolationHistory); f != nil {
		t.Errorf("violation_history fired on a within-envelope event: %+v", f)
	}
	if f := factor(a, FactorNovelTarget); f != nil {
		t.Errorf("novel_target fired on a within-envelope event: %+v", f)
	}
}

// --- 2. a denied event ----------------------------------------------------------------

func TestDeniedEvent(t *testing.T) {
	a := score(t, ScoreRequest{
		Event:      fileEvent(capability.KindFileWrite, ws+"/.github/workflows/ci.yml"),
		Validation: result(decision.VerdictExplicitlyDenied, viol(validator.ViolationExplicitDenial, capability.SeverityHigh)),
		Envelope:   envelope(),
		History:    history(),
	})

	// 55 denial + 15 high severity + 5 novel target.
	if a.Score != 75 {
		t.Errorf("Score = %v, want 75", a.Score)
	}
	if a.Level != decision.LevelHigh {
		t.Errorf("Level = %q, want %q", a.Level, decision.LevelHigh)
	}
	if f := factor(a, FactorVerdict); f == nil || f.Weight != 55 {
		t.Errorf("verdict factor = %+v, want weight 55", f)
	}

	// A denial is the heaviest single verdict, and it must stay heavier than any
	// other, or "the envelope's author forbade this" would rank below an
	// unanticipated departure.
	for v, pts := range verdictPoints {
		if v != decision.VerdictExplicitlyDenied && pts >= verdictPoints[decision.VerdictExplicitlyDenied] {
			t.Errorf("verdict %q scores %v, which is not below an explicit denial", v, pts)
		}
	}
}

// --- 3. an indeterminate event --------------------------------------------------------

// The event the whole no-fabrication rule exists for. Validation could not
// conclude, so the score has to be non-zero (unresolved is not safe) and the
// confidence has to fall (there is genuinely less behind it).
func TestIndeterminateEvent(t *testing.T) {
	a := score(t, ScoreRequest{
		Event:      unresolvableEvent(),
		Validation: result(decision.VerdictIndeterminate, viol(validator.ViolationUnresolvable, capability.SeverityMedium)),
		Envelope:   envelope(),
		History:    history(),
	})

	// 20 indeterminate + 10 medium severity. No novelty: there is no resolved
	// target to have seen before, which is an absent input rather than a
	// familiar one.
	if a.Score != 30 {
		t.Errorf("Score = %v, want 30", a.Score)
	}
	if a.Level != decision.LevelMedium {
		t.Errorf("Level = %q, want %q", a.Level, decision.LevelMedium)
	}
	if a.Score == 0 {
		t.Error("an indeterminate event scored zero; unresolved is not safe")
	}

	// One basis input of three: history was available, the verdict was not
	// conclusive and no target resolved.
	if a.Confidence != 0.3 {
		t.Errorf("Confidence = %v, want 0.3", a.Confidence)
	}
	basis := factor(a, FactorEvidenceBasis)
	if basis == nil {
		t.Fatal("no evidence basis factor")
	}
	for key, want := range map[string]string{
		BasisVerdictConclusive: "false",
		BasisTargetResolved:    "false",
		BasisHistoryAvailable:  "true",
	} {
		if got := basis.Evidence[key]; got != want {
			t.Errorf("basis[%s] = %q, want %q", key, got, want)
		}
	}
	if f := factor(a, FactorNovelTarget); f != nil {
		t.Errorf("novel_target fired with no resolved target: %+v", f)
	}
}

// --- 4. workspace escape ---------------------------------------------------------------

func TestWorkspaceEscape(t *testing.T) {
	esc := viol(validator.ViolationWorkspaceEscape, capability.SeverityHigh)
	esc.Expected = "within " + ws
	esc.Observed = "/etc/hosts"

	a := score(t, ScoreRequest{
		Event: fileEvent(capability.KindFileRead, "/etc/hosts"),
		Validation: result(decision.VerdictGrantExceeded,
			viol(validator.ViolationSelectorMismatch, capability.SeverityMedium), esc),
		Envelope: envelope(),
		History:  history(),
	})

	// 25 grant_exceeded + 15 (the escape's high severity, not the mismatch's
	// medium) + 10 escape + 5 novel.
	if a.Score != 55 {
		t.Errorf("Score = %v, want 55", a.Score)
	}

	f := factor(a, FactorWorkspaceEscape)
	if f == nil {
		t.Fatal("no workspace_escape factor")
	}
	if f.Weight != WorkspaceEscapePoints {
		t.Errorf("workspace_escape weight = %v, want %v", f.Weight, WorkspaceEscapePoints)
	}
	// The evidence has to name the boundary, or the factor is an assertion
	// rather than a finding.
	if f.Evidence["expected"] != "within "+ws || f.Evidence["observed"] != "/etc/hosts" {
		t.Errorf("workspace_escape evidence = %v, want the validator's own expected/observed", f.Evidence)
	}

	// Severity is the maximum across the violations, never their sum: two
	// findings about one operation are two descriptions of one act.
	if sf := factor(a, FactorViolationSeverity); sf == nil || sf.Weight != severityPoints[capability.SeverityHigh] {
		t.Errorf("violation_severity = %+v, want the high-severity weight alone", sf)
	}

	// And without an escape violation the factor stays silent, even though the
	// envelope declares a workspace root and the path is outside it. The
	// validator owns containment; a second check here could disagree with it.
	b := score(t, ScoreRequest{
		Event:      fileEvent(capability.KindFileRead, "/etc/hosts"),
		Validation: result(decision.VerdictGrantExceeded, viol(validator.ViolationSelectorMismatch, capability.SeverityMedium)),
		Envelope:   envelope(),
		History:    history(),
	})
	if f := factor(b, FactorWorkspaceEscape); f != nil {
		t.Errorf("workspace_escape fired without the validator reporting one: %+v", f)
	}
}

// --- 5. novel versus previously seen ------------------------------------------------------

func TestNovelVersusSeenTarget(t *testing.T) {
	const target = "/etc/hosts"
	req := func(h History) ScoreRequest {
		return ScoreRequest{
			Event:      fileEvent(capability.KindFileRead, target),
			Validation: result(decision.VerdictOutsideEnvelope, viol(validator.ViolationUngrantedCapability, capability.SeverityMedium)),
			Envelope:   envelope(),
			History:    h,
		}
	}

	novel := score(t, req(history()))
	seen := score(t, req(history().withSeen(capability.KindFileRead, target)))

	if novel.Score-seen.Score != NovelTargetPoints {
		t.Errorf("novel %v vs seen %v; the difference should be exactly %v",
			novel.Score, seen.Score, NovelTargetPoints)
	}
	if f := factor(novel, FactorNovelTarget); f == nil || f.Evidence["target"] != target {
		t.Errorf("novel factor = %+v, want evidence naming the target", f)
	}
	if f := factor(seen, FactorNovelTarget); f != nil {
		t.Errorf("novel_target fired for a target already seen: %+v", f)
	}

	// Novelty is per (capability, target). The same path read before is not the
	// same path written before.
	h := history().withSeen(capability.KindFileRead, target)
	other := score(t, ScoreRequest{
		Event:      fileEvent(capability.KindFileWrite, target),
		Validation: result(decision.VerdictOutsideEnvelope, viol(validator.ViolationUngrantedCapability, capability.SeverityMedium)),
		Envelope:   envelope(),
		History:    h,
	})
	if factor(other, FactorNovelTarget) == nil {
		t.Error("a write to a path only ever read before did not read as novel")
	}
}

// A saturated novelty set still reports novel -- the safe direction -- but says so,
// because past the ceiling "unseen" stops being evidence of anything.
func TestSaturatedNoveltySetIsQualified(t *testing.T) {
	h := history()
	h.saturated = true

	a := score(t, ScoreRequest{
		Event:      fileEvent(capability.KindFileRead, "/etc/hosts"),
		Validation: result(decision.VerdictOutsideEnvelope, viol(validator.ViolationUngrantedCapability, capability.SeverityMedium)),
		Envelope:   envelope(),
		History:    saturatingHistory{h},
	})

	f := factor(a, FactorNovelTarget)
	if f == nil {
		t.Fatal("no novel_target factor")
	}
	if f.Evidence["novelty_set_saturated"] != "true" {
		t.Errorf("evidence = %v, want the saturation qualified", f.Evidence)
	}
	if f.Weight != NovelTargetPoints {
		t.Errorf("weight = %v; saturation qualifies the factor, it does not soften it", f.Weight)
	}
}

// --- 6. several factors at once -------------------------------------------------------------

func TestMultipleFactorsStack(t *testing.T) {
	a := score(t, ScoreRequest{
		Event: fileEvent(capability.KindFileDelete, "/etc/shadow"),
		Validation: result(decision.VerdictOutsideEnvelope,
			viol(validator.ViolationUngrantedCapability, capability.SeverityMedium),
			viol(validator.ViolationWorkspaceEscape, capability.SeverityHigh)),
		Envelope: envelope(),
		History:  history().withViolations(4),
	})

	// 30 outside_envelope + 15 high + 10 escape + 5 novel + 4 prior violations.
	if a.Score != 64 {
		t.Errorf("Score = %v, want 64", a.Score)
	}
	want := []string{
		FactorVerdict, FactorViolationSeverity, FactorWorkspaceEscape,
		FactorNovelTarget, FactorViolationHistory, FactorEvidenceBasis,
	}
	if got := names(a); !reflect.DeepEqual(got, want) {
		t.Errorf("factors = %v, want %v", got, want)
	}

	// Stacking is a plain sum of the factor weights and nothing else, which is
	// the property that lets the number be checked by hand from the record.
	var sum float64
	for _, f := range a.Factors {
		sum += f.Weight
	}
	if sum != a.Score {
		t.Errorf("factors sum to %v but the score is %v", sum, a.Score)
	}
}

// --- 7. score boundaries ----------------------------------------------------------------------

// The whole model in one table. Every row is checkable by hand against the point
// tables, which is the point of keeping the model additive.
func TestScoreTable(t *testing.T) {
	novelReadOf := func(p string) *event.Event { return fileEvent(capability.KindFileRead, p) }

	cases := []struct {
		name    string
		event   *event.Event
		res     *validator.Result
		hist    History
		want    float64
		wantLvl decision.Level
	}{
		{
			name:  "within envelope",
			event: novelReadOf(ws + "/a.go"),
			res:   result(decision.VerdictWithinEnvelope),
			hist:  history(), want: 0, wantLvl: decision.LevelNone,
		},
		{
			name:  "bare indeterminate, no violations recorded",
			event: unresolvableEvent(),
			res:   result(decision.VerdictIndeterminate),
			hist:  history(), want: 20, wantLvl: decision.LevelLow,
		},
		{
			name:  "constraint violation, medium",
			event: novelReadOf(ws + "/a.go"),
			res:   result(decision.VerdictConstraintViolation, viol(validator.ViolationConstraintExceeded, capability.SeverityMedium)),
			hist:  history().withSeen(capability.KindFileRead, ws+"/a.go"),
			want:  35, wantLvl: decision.LevelMedium,
		},
		{
			name:  "grant exceeded, medium, novel",
			event: novelReadOf("/usr/lib/x.so"),
			res:   result(decision.VerdictGrantExceeded, viol(validator.ViolationSelectorMismatch, capability.SeverityMedium)),
			hist:  history(),
			want:  40, wantLvl: decision.LevelMedium,
		},
		{
			name:  "ordinary workspace-escape read",
			event: novelReadOf("/usr/lib/x.so"),
			res: result(decision.VerdictGrantExceeded,
				viol(validator.ViolationSelectorMismatch, capability.SeverityMedium),
				viol(validator.ViolationWorkspaceEscape, capability.SeverityHigh)),
			hist: history(),
			want: 55, wantLvl: decision.LevelHigh,
		},
		{
			name:  "ungranted critical capability",
			event: novelReadOf("/sys/kernel/btf/vmlinux"),
			res:   result(decision.VerdictOutsideEnvelope, viol(validator.ViolationUngrantedCapability, capability.SeverityCritical)),
			hist:  history(),
			want:  65, wantLvl: decision.LevelHigh,
		},
		{
			name:  "denied critical capability late in a bad session",
			event: novelReadOf("/sys/kernel/btf/vmlinux"),
			res:   result(decision.VerdictExplicitlyDenied, viol(validator.ViolationExplicitDenial, capability.SeverityCritical)),
			hist:  history().withViolations(30),
			want:  100, wantLvl: decision.LevelCritical,
		},
		{
			name:  "no history at all",
			event: novelReadOf("/etc/hosts"),
			res:   result(decision.VerdictOutsideEnvelope, viol(validator.ViolationUngrantedCapability, capability.SeverityMedium)),
			hist:  nil,
			want:  40, wantLvl: decision.LevelMedium,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := score(t, ScoreRequest{Event: c.event, Validation: c.res, Envelope: envelope(), History: c.hist})
			if a.Score != c.want {
				t.Errorf("Score = %v, want %v (factors %+v)", a.Score, c.want, a.Factors)
			}
			if a.Level != c.wantLvl {
				t.Errorf("Level = %q, want %q", a.Level, c.wantLvl)
			}
			if a.Score < ScoreMin || a.Score > ScoreMax {
				t.Errorf("Score %v left the declared bounds", a.Score)
			}
		})
	}
}

// The violation-history factor is one point per prior violation up to a cap, and
// the cap is what stops a long noisy session scoring every later event critical
// for arriving late.
func TestViolationHistoryIsCapped(t *testing.T) {
	for _, c := range []struct {
		prior int
		want  float64
	}{
		{0, 0}, {1, 1}, {9, 9}, {10, 10}, {11, 10}, {1000, 10},
	} {
		a := score(t, ScoreRequest{
			Event:      fileEvent(capability.KindFileRead, "/etc/hosts"),
			Validation: result(decision.VerdictOutsideEnvelope, viol(validator.ViolationUngrantedCapability, capability.SeverityMedium)),
			Envelope:   envelope(),
			History:    history().withSeen(capability.KindFileRead, "/etc/hosts").withViolations(c.prior),
		})
		var got float64
		if f := factor(a, FactorViolationHistory); f != nil {
			got = f.Weight
		}
		if got != c.want {
			t.Errorf("%d prior violations contributed %v, want %v", c.prior, got, c.want)
		}
	}
}

// --- 8. risk-level boundaries -----------------------------------------------------------------

// Minimum inclusive, maximum exclusive, matching internal/policy's convention so
// adjacent bands partition the scale rather than overlapping on a threshold.
func TestLevelBoundaries(t *testing.T) {
	cases := []struct {
		score float64
		want  decision.Level
	}{
		{0, decision.LevelNone},
		{0.0001, decision.LevelLow},
		{24.9999, decision.LevelLow},
		{LevelBoundaryMedium, decision.LevelMedium},
		{54.9999, decision.LevelMedium},
		{LevelBoundaryHigh, decision.LevelHigh},
		{84.9999, decision.LevelHigh},
		{LevelBoundaryCritical, decision.LevelCritical},
		{100, decision.LevelCritical},
	}
	for _, c := range cases {
		if got := LevelFor(c.score); got != c.want {
			t.Errorf("LevelFor(%v) = %q, want %q", c.score, got, c.want)
		}
	}

	// Every level the mapping can produce has to be a level the enum declares,
	// or a policy rule naming it could never match.
	for _, c := range cases {
		if !decision.ValidLevel(LevelFor(c.score)) {
			t.Errorf("LevelFor(%v) produced %q, which is not in decision.AllLevels", c.score, LevelFor(c.score))
		}
	}

	// The mapping is monotonic: a higher score never buckets lower.
	prev := -1
	rank := map[decision.Level]int{}
	for i, l := range decision.AllLevels() {
		rank[l] = i
	}
	for s := 0.0; s <= 100.0; s += 0.5 {
		if r := rank[LevelFor(s)]; r < prev {
			t.Fatalf("LevelFor(%v) = %q ranks below the level of a lower score", s, LevelFor(s))
		} else {
			prev = r
		}
	}
}

// --- 9. clamping ------------------------------------------------------------------------------

func TestScoreClamps(t *testing.T) {
	// The unrated model's theoretical maximum is 140 -- every factor at its
	// ceiling -- and it has to land on 100 rather than run off the scale a policy
	// threshold is expressed on. Asserted as an inequality rather than a number,
	// because what this test needs is that clamping is reachable at all.
	var ceiling float64
	for _, s := range NewEngine().Scorers() {
		ceiling += s.Weight()
	}
	if ceiling <= ScoreMax {
		t.Fatalf("the scorer set can only reach %v, so clamping is untested by construction", ceiling)
	}

	a := score(t, ScoreRequest{
		Event: fileEvent(capability.KindFileDelete, "/etc/shadow"),
		Validation: result(decision.VerdictExplicitlyDenied,
			viol(validator.ViolationExplicitDenial, capability.SeverityCritical),
			viol(validator.ViolationWorkspaceEscape, capability.SeverityHigh)),
		Envelope: envelope(),
		History:  history().withViolations(50),
	})
	if a.Score != ScoreMax {
		t.Errorf("Score = %v, want it clamped to %v", a.Score, ScoreMax)
	}
	if a.Level != decision.LevelCritical {
		t.Errorf("Level = %q, want %q", a.Level, decision.LevelCritical)
	}

	// Directly, at both ends and past them, including the values a float can
	// carry that no factor can produce.
	agg := BoundedSumAggregator{}
	for _, c := range []struct{ in, want float64 }{
		{-500, ScoreMin}, {-0.5, ScoreMin}, {0, ScoreMin},
		{50, 50}, {100, ScoreMax}, {5000, ScoreMax},
		{math.Inf(1), ScoreMax}, {math.Inf(-1), ScoreMin},
	} {
		got, _ := agg.Aggregate([]decision.Factor{{Name: "x", Weight: c.in}})
		if got != c.want {
			t.Errorf("Aggregate(%v) = %v, want %v", c.in, got, c.want)
		}
	}

	// NaN is a fault in scoring, not a low score, and must not present as the
	// reassuring end of the scale.
	if got, _ := agg.Aggregate([]decision.Factor{{Name: "x", Weight: math.NaN()}}); got != ScoreMax {
		t.Errorf("Aggregate(NaN) = %v, want %v", got, ScoreMax)
	}
	if LevelFor(math.NaN()) != decision.LevelCritical {
		t.Errorf("LevelFor(NaN) = %q, want %q", LevelFor(math.NaN()), decision.LevelCritical)
	}
}

// --- 10. determinism ---------------------------------------------------------------------------

// Two runs of one recording have to produce the same audit record, or replay
// stops being a regression test and the evaluation corpus stops meaning
// anything. Map iteration order is the usual way that breaks, which is why the
// factor list is built from an ordered slice.
func TestDeterministic(t *testing.T) {
	req := ScoreRequest{
		Event: fileEvent(capability.KindFileDelete, "/etc/shadow"),
		Validation: result(decision.VerdictOutsideEnvelope,
			viol(validator.ViolationUngrantedCapability, capability.SeverityMedium),
			viol(validator.ViolationWorkspaceEscape, capability.SeverityHigh)),
		Envelope: envelope(),
		History:  history().withViolations(3),
	}

	first := score(t, req)
	for i := 0; i < 50; i++ {
		// A fresh engine each time as well, so nothing accumulated between runs
		// can hide behind a shared instance.
		got := score(t, req)
		if !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d diverged\n got %+v\nwant %+v", i, got, first)
		}
	}
}

// --- 11. missing evidence is never fabricated ------------------------------------------------

// The rule the package is built around, checked from the outside: every input
// this model has can be absent, and no absence may turn into a value.
func TestMissingEvidenceIsNotFabricated(t *testing.T) {
	t.Run("no history withholds the history factors and lowers confidence", func(t *testing.T) {
		with := score(t, ScoreRequest{
			Event:      fileEvent(capability.KindFileRead, "/etc/hosts"),
			Validation: result(decision.VerdictOutsideEnvelope, viol(validator.ViolationUngrantedCapability, capability.SeverityMedium)),
			Envelope:   envelope(),
			History:    history(),
		})
		without := score(t, ScoreRequest{
			Event:      fileEvent(capability.KindFileRead, "/etc/hosts"),
			Validation: result(decision.VerdictOutsideEnvelope, viol(validator.ViolationUngrantedCapability, capability.SeverityMedium)),
			Envelope:   envelope(),
			History:    nil,
		})

		if factor(without, FactorNovelTarget) != nil || factor(without, FactorViolationHistory) != nil {
			t.Error("a history-derived factor fired with no history behind it")
		}
		if without.Confidence >= with.Confidence {
			t.Errorf("confidence without history (%v) is not below confidence with it (%v)",
				without.Confidence, with.Confidence)
		}
		if f := factor(without, FactorEvidenceBasis); f == nil || f.Evidence[BasisHistoryAvailable] != "false" {
			t.Errorf("the evidence basis did not record the missing history: %+v", f)
		}
	})

	t.Run("no validation is an error, not a zero", func(t *testing.T) {
		if _, err := NewEngine().Score(context.Background(), ScoreRequest{
			Event: fileEvent(capability.KindFileRead, "/etc/hosts"),
		}); err == nil {
			t.Error("scoring an unvalidated event succeeded; it must refuse rather than return 0")
		}
		if _, err := NewEngine().Score(context.Background(), ScoreRequest{
			Validation: result(decision.VerdictWithinEnvelope),
		}); err == nil {
			t.Error("scoring with no event succeeded")
		}
	})

	t.Run("an unknown verdict is refused rather than guessed", func(t *testing.T) {
		_, err := NewEngine().Score(context.Background(), ScoreRequest{
			Event:      fileEvent(capability.KindFileRead, "/etc/hosts"),
			Validation: result(decision.Verdict("invented_by_a_future_build")),
			History:    history(),
		})
		if err == nil {
			t.Fatal("an unknown verdict was scored")
		}
		if !strings.Contains(err.Error(), "unknown verdict") {
			t.Errorf("error = %v, want it to name the unknown verdict", err)
		}
	})

	t.Run("every verdict this build can produce is scorable", func(t *testing.T) {
		// The counterpart: an enum member with no entry in the table would make
		// the refusal above fire on an ordinary event.
		for _, v := range decision.AllVerdicts() {
			if _, ok := verdictPoints[v]; !ok {
				t.Errorf("verdict %q has no point value", v)
			}
		}
	})

	t.Run("an unknown severity is not scored as harmless", func(t *testing.T) {
		a := score(t, ScoreRequest{
			Event:      fileEvent(capability.KindFileRead, "/etc/hosts"),
			Validation: result(decision.VerdictOutsideEnvelope, viol(validator.ViolationUngrantedCapability, capability.Severity("moderate"))),
			Envelope:   envelope(),
			History:    history(),
		})
		if f := factor(a, FactorViolationSeverity); f == nil || f.Weight != severityPoints[capability.SeverityMedium] {
			t.Errorf("unknown severity scored %+v, want the medium fallback", f)
		}
	})

	t.Run("confidence with no basis factor is zero, not assumed", func(t *testing.T) {
		if _, c := (BoundedSumAggregator{}).Aggregate([]decision.Factor{{Name: FactorVerdict, Weight: 30}}); c != 0 {
			t.Errorf("confidence = %v with nothing stating a basis, want 0", c)
		}
	})
}

// Confidence is a count of available inputs and can be checked by counting.
func TestConfidenceIsACountOfInputs(t *testing.T) {
	cases := []struct {
		name string
		req  ScoreRequest
		want float64
	}{
		{
			name: "all three inputs",
			req: ScoreRequest{
				Event:      fileEvent(capability.KindFileRead, "/etc/hosts"),
				Validation: result(decision.VerdictOutsideEnvelope),
				History:    history(),
			},
			want: 0.9,
		},
		{
			name: "conclusive verdict and target, no history",
			req: ScoreRequest{
				Event:      fileEvent(capability.KindFileRead, "/etc/hosts"),
				Validation: result(decision.VerdictOutsideEnvelope),
			},
			want: 0.6,
		},
		{
			name: "history only",
			req: ScoreRequest{
				Event:      unresolvableEvent(),
				Validation: result(decision.VerdictIndeterminate),
				History:    history(),
			},
			want: 0.3,
		},
		{
			name: "nothing",
			req: ScoreRequest{
				Event:      unresolvableEvent(),
				Validation: result(decision.VerdictIndeterminate),
			},
			want: 0,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := score(t, c.req)
			if a.Confidence != c.want {
				t.Errorf("Confidence = %v, want %v (basis %v)", a.Confidence, c.want, factor(a, FactorEvidenceBasis).Evidence)
			}
			if a.Confidence < 0 || a.Confidence > 1 {
				t.Errorf("Confidence %v left [0,1]", a.Confidence)
			}
			if a.Confidence > ConfidenceCeiling {
				t.Errorf("Confidence %v exceeded the ceiling this model is allowed to claim", a.Confidence)
			}
		})
	}
}

// --- 12. history is read, and read before the event is committed ---------------------------

// The engine's half of the ordering guarantee: it asks the history about this
// event's target, so a caller that recorded first would see the factor go
// silent. The pipeline's half -- that the recording really does happen after --
// is pinned by TestRiskStageSeesHistoryBeforeCommit in internal/pipeline.
func TestHistoryIsQueriedForTheCurrentTarget(t *testing.T) {
	h := history()
	score(t, ScoreRequest{
		Event:      fileEvent(capability.KindFileRead, "/etc/hosts"),
		Validation: result(decision.VerdictOutsideEnvelope, viol(validator.ViolationUngrantedCapability, capability.SeverityMedium)),
		Envelope:   envelope(),
		History:    h,
	})

	want := []string{string(capability.KindFileRead) + "|/etc/hosts"}
	if !reflect.DeepEqual(h.asked, want) {
		t.Errorf("history queries = %v, want exactly %v", h.asked, want)
	}

	// And the same target, already recorded, silences the factor -- which is what
	// makes the ordering observable at all.
	h2 := history().withSeen(capability.KindFileRead, "/etc/hosts")
	a := score(t, ScoreRequest{
		Event:      fileEvent(capability.KindFileRead, "/etc/hosts"),
		Validation: result(decision.VerdictOutsideEnvelope, viol(validator.ViolationUngrantedCapability, capability.SeverityMedium)),
		Envelope:   envelope(),
		History:    h2,
	})
	if factor(a, FactorNovelTarget) != nil {
		t.Error("novelty survived a target the history already knew")
	}
}

// --- construction and composition ------------------------------------------------------------

func TestEngineAdmission(t *testing.T) {
	cases := []struct {
		name    string
		scorers []Scorer
		wantErr string
	}{
		{"no scorers", nil, "at least one"},
		{"nil scorer", []Scorer{VerdictScorer{}, nil}, "is nil"},
		{"duplicate name", []Scorer{VerdictScorer{}, VerdictScorer{}}, "duplicate"},
		{"unnamed", []Scorer{unnamedScorer{}}, "no name"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := NewEngineWith(c.scorers, nil)
			if err == nil {
				t.Fatalf("accepted %s", c.name)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("error = %v, want it to mention %q", err, c.wantErr)
			}
		})
	}

	// A swapped scorer set really is the set that runs, which is the whole point
	// of the interface being an interface.
	e, err := NewEngineWith([]Scorer{VerdictScorer{}}, nil)
	if err != nil {
		t.Fatalf("NewEngineWith: %v", err)
	}
	a, err := e.Score(context.Background(), ScoreRequest{
		Event:      fileEvent(capability.KindFileRead, "/etc/hosts"),
		Validation: result(decision.VerdictOutsideEnvelope, viol(validator.ViolationUngrantedCapability, capability.SeverityHigh)),
		History:    history(),
	})
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if a.Score != 30 || len(a.Factors) != 1 {
		t.Errorf("a verdict-only engine produced %v from %d factors, want 30 from 1", a.Score, len(a.Factors))
	}
	// With no evidence basis in the set, confidence is zero rather than assumed.
	if a.Confidence != 0 {
		t.Errorf("Confidence = %v, want 0 when nothing stated a basis", a.Confidence)
	}
}

type unnamedScorer struct{}

func (unnamedScorer) Name() string    { return "" }
func (unnamedScorer) Weight() float64 { return 0 }
func (unnamedScorer) Evaluate(context.Context, ScoreRequest) (*decision.Factor, error) {
	return nil, nil
}

// Each scorer must produce what it claims to produce, or the factor names in an
// audit record stop matching the scorer that wrote them.
// The scorer set is domain-partitioned, so no single request can trigger every
// scorer any more: an event has a path, a destination, or a privilege change,
// and never two of them. The check is therefore that each scorer fires on at
// least one of the three shapes and agrees with its own metadata when it does --
// which is a stronger claim than the single-request form it replaces, because it
// also asserts that every scorer in the set is reachable at all.
func TestScorersAgreeWithTheirOwnMetadata(t *testing.T) {
	req := ScoreRequest{
		Event: fileEvent(capability.KindFileDelete, "/etc/shadow"),
		Validation: result(decision.VerdictExplicitlyDenied,
			viol(validator.ViolationExplicitDenial, capability.SeverityCritical),
			viol(validator.ViolationWorkspaceEscape, capability.SeverityHigh)),
		Envelope: envelope(),
		History:  history().withViolations(100),
	}

	// The network counterpart: an ungranted connection to an address no name was
	// correlated to, which is what reaches the destination-scoped scorers.
	netReq := ScoreRequest{
		Event: uncorrelatedEvent(capability.KindNetConnect, "203.0.113.10:8443"),
		Validation: result(decision.VerdictOutsideEnvelope,
			viol(validator.ViolationUngrantedCapability, capability.SeverityHigh)),
		Envelope: envelope(),
		History:  history().withViolations(100),
	}

	// The privilege counterpart: an ungranted privilege change, which is the
	// only shape that reaches privilege_change. It carries no target at all, so
	// it reaches nothing that reads one.
	privReq := ScoreRequest{
		Event: privEvent(capability.KindPrivEscalate, setuidPayload()),
		Validation: result(decision.VerdictOutsideEnvelope,
			viol(validator.ViolationUngrantedCapability, capability.SeverityCritical)),
		Envelope: envelope(),
		History:  history().withViolations(100),
	}

	for _, s := range NewEngine().Scorers() {
		var fired bool
		for _, r := range []ScoreRequest{req, netReq, privReq} {
			f, err := s.Evaluate(context.Background(), r)
			if err != nil {
				t.Fatalf("%s: %v", s.Name(), err)
			}
			if f == nil {
				continue
			}
			fired = true
			if f.Name != s.Name() {
				t.Errorf("scorer %q produced a factor named %q", s.Name(), f.Name)
			}
			if f.Weight > s.Weight() {
				t.Errorf("scorer %q contributed %v, above its declared ceiling of %v", s.Name(), f.Weight, s.Weight())
			}
			if f.Description == "" {
				t.Errorf("scorer %q produced a factor with no description", s.Name())
			}
		}
		if !fired {
			t.Errorf("%s produced no factor on a filesystem, a network, or a privilege "+
				"departure; a scorer nothing can reach is a scorer nothing tests", s.Name())
		}
	}

	// The interface path and the engine's internal fast path have to agree, or a
	// scorer would behave differently depending on who called it.
	e := NewEngine()
	viaEngine, err := e.Score(context.Background(), req)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	var sum float64
	for _, s := range e.Scorers() {
		f, err := s.Evaluate(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if f != nil {
			sum += f.Weight
		}
	}
	if clampScore(sum) != viaEngine.Score {
		t.Errorf("scorers called directly sum to %v, the engine produced %v", clampScore(sum), viaEngine.Score)
	}
}

// --- session scoring ---------------------------------------------------------------------------

// Narrow by design, and honest about it: two evidence inputs, so confidence
// tops out at 0.6 and never claims what the event scorer can claim.
func TestScoreSession(t *testing.T) {
	e := NewEngine()

	empty, err := e.ScoreSession(context.Background(), SessionScoreRequest{})
	if err != nil {
		t.Fatalf("ScoreSession: %v", err)
	}
	if empty.Score != 0 || empty.Level != decision.LevelNone {
		t.Errorf("a session with nothing recorded scored %v (%q), want 0 / none", empty.Score, empty.Level)
	}
	if empty.Confidence != 0 {
		t.Errorf("Confidence = %v with no violations and no history, want 0", empty.Confidence)
	}

	a, err := e.ScoreSession(context.Background(), SessionScoreRequest{
		Envelope: envelope(),
		History:  history().withViolations(6),
		Violations: []validator.Violation{
			viol(validator.ViolationSelectorMismatch, capability.SeverityMedium),
			viol(validator.ViolationExplicitDenial, capability.SeverityHigh),
		},
	})
	if err != nil {
		t.Fatalf("ScoreSession: %v", err)
	}
	// 15 for the worst severity + 6 for the session's own violation count, which
	// is preferred over the length of the slice the caller passed.
	if a.Score != 21 {
		t.Errorf("Score = %v, want 21", a.Score)
	}
	if a.Confidence != 0.6 {
		t.Errorf("Confidence = %v, want 0.6 -- session scoring has two inputs, not three", a.Confidence)
	}
	if a.Confidence >= ConfidenceCeiling {
		t.Error("session scoring claimed the confidence event scoring is allowed")
	}

	// With no history the slice is the fallback, since something counted is
	// better than nothing counted -- but the basis says which it was.
	b, err := e.ScoreSession(context.Background(), SessionScoreRequest{
		Violations: []validator.Violation{viol(validator.ViolationSelectorMismatch, capability.SeverityLow)},
	})
	if err != nil {
		t.Fatalf("ScoreSession: %v", err)
	}
	if b.Score != 6 {
		t.Errorf("Score = %v, want 6 (5 low severity + 1 violation)", b.Score)
	}
	if f := factor(b, FactorEvidenceBasis); f == nil || f.Evidence[BasisHistoryAvailable] != "false" {
		t.Errorf("basis = %+v, want the missing history recorded", f)
	}
}

// --- shared evidence maps -----------------------------------------------------------------------

// The preallocated evidence maps are shared between assessments, which is only
// safe because nothing mutates them. Pin the invariant rather than trusting it:
// two assessments of the same shape must carry equal evidence, and the tables
// must cover their whole vocabulary so the allocating fallback stays unreachable
// in practice.
func TestSharedEvidenceTablesCoverTheVocabulary(t *testing.T) {
	for _, v := range decision.AllVerdicts() {
		if _, ok := verdictEvidenceTable[v]; !ok {
			t.Errorf("no preallocated evidence for verdict %q", v)
		}
	}
	for s := range severityPoints {
		if _, ok := severityEvidenceTable[s]; !ok {
			t.Errorf("no preallocated evidence for severity %q", s)
		}
	}
	for i, m := range eventBasisTable {
		if len(m) != 3 {
			t.Errorf("event basis %d has %d keys, want 3", i, len(m))
		}
	}
	for i, m := range sessionBasisTable {
		if len(m) != 2 {
			t.Errorf("session basis %d has %d keys, want 2", i, len(m))
		}
	}

	req := ScoreRequest{
		Event:      fileEvent(capability.KindFileRead, "/etc/hosts"),
		Validation: result(decision.VerdictOutsideEnvelope, viol(validator.ViolationUngrantedCapability, capability.SeverityMedium)),
		History:    history(),
	}
	a, b := score(t, req), score(t, req)
	if !reflect.DeepEqual(a.Factors, b.Factors) {
		t.Error("two assessments of the same request carry different factors")
	}
}

// A Scorer this package did not write must reach the same score through the
// engine as it does called directly.
//
// The engine has a fast path for its own scorers that returns factors by value
// to avoid an allocation per factor; a third-party scorer takes the plain
// interface call. Two paths through one loop is exactly where a swappable
// interface stops being swappable, so both are driven here.
func TestAThirdPartyScorerIsComposed(t *testing.T) {
	e, err := NewEngineWith([]Scorer{VerdictScorer{}, constantScorer{}, EvidenceBasisScorer{}}, nil)
	if err != nil {
		t.Fatalf("NewEngineWith: %v", err)
	}

	a, err := e.Score(context.Background(), ScoreRequest{
		Event:      fileEvent(capability.KindFileRead, "/etc/hosts"),
		Validation: result(decision.VerdictOutsideEnvelope),
		History:    history(),
	})
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if a.Score != 37 {
		t.Errorf("Score = %v, want 37 (30 verdict + 7 from the custom scorer)", a.Score)
	}
	if f := factor(a, "constant"); f == nil || f.Weight != 7 {
		t.Errorf("the custom factor = %+v, want weight 7", f)
	}
	// It still lands in the ordered position the scorer set declares.
	if got := names(a); !reflect.DeepEqual(got, []string{FactorVerdict, "constant", FactorEvidenceBasis}) {
		t.Errorf("factors = %v, want the declared order", got)
	}

	// A third-party scorer that does not apply is dropped, not appended empty.
	e2, err := NewEngineWith([]Scorer{VerdictScorer{}, silentScorer{}}, nil)
	if err != nil {
		t.Fatalf("NewEngineWith: %v", err)
	}
	b, err := e2.Score(context.Background(), ScoreRequest{
		Event:      fileEvent(capability.KindFileRead, "/etc/hosts"),
		Validation: result(decision.VerdictOutsideEnvelope),
	})
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if len(b.Factors) != 1 {
		t.Errorf("factors = %v, want only the verdict", names(b))
	}

	// And one that fails stops the assessment rather than producing a partial
	// score, for the same reason an unknown verdict does.
	e3, err := NewEngineWith([]Scorer{VerdictScorer{}, failingScorer{}}, nil)
	if err != nil {
		t.Fatalf("NewEngineWith: %v", err)
	}
	if _, err := e3.Score(context.Background(), ScoreRequest{
		Event:      fileEvent(capability.KindFileRead, "/etc/hosts"),
		Validation: result(decision.VerdictOutsideEnvelope),
	}); err == nil {
		t.Error("a failing scorer produced an assessment anyway")
	}
}

type constantScorer struct{}

func (constantScorer) Name() string    { return "constant" }
func (constantScorer) Weight() float64 { return 7 }
func (constantScorer) Evaluate(context.Context, ScoreRequest) (*decision.Factor, error) {
	return &decision.Factor{Name: "constant", Weight: 7, Description: "a fixed contribution"}, nil
}

type silentScorer struct{}

func (silentScorer) Name() string    { return "silent" }
func (silentScorer) Weight() float64 { return 0 }
func (silentScorer) Evaluate(context.Context, ScoreRequest) (*decision.Factor, error) {
	return nil, nil
}

type failingScorer struct{}

func (failingScorer) Name() string    { return "failing" }
func (failingScorer) Weight() float64 { return 0 }
func (failingScorer) Evaluate(context.Context, ScoreRequest) (*decision.Factor, error) {
	return nil, errors.New("this scorer cannot evaluate")
}

// Every scorer refuses a request with no validation behind it, including when
// called directly rather than through the engine. A scorer reachable from
// outside this package is a scorer someone will call from outside it.
func TestEveryScorerRefusesAnUnvalidatedRequest(t *testing.T) {
	for _, s := range NewEngine().Scorers() {
		if _, err := s.Evaluate(context.Background(), ScoreRequest{
			Event: fileEvent(capability.KindFileRead, "/etc/hosts"),
		}); !errors.Is(err, ErrNoValidation) {
			t.Errorf("%s.Evaluate returned %v, want ErrNoValidation", s.Name(), err)
		}
	}
}

// confidenceFor is total: a count outside the table is clamped rather than
// panicking on an index, because a custom basis factor is free to carry more
// keys than this model names and must not be able to crash the hot path.
func TestConfidenceForIsTotal(t *testing.T) {
	for _, c := range []struct {
		in   int
		want float64
	}{
		{-3, 0}, {0, 0}, {1, 0.3}, {2, 0.6}, {3, ConfidenceCeiling},
		{4, ConfidenceCeiling}, {99, ConfidenceCeiling},
	} {
		if got := confidenceFor(c.in); got != c.want {
			t.Errorf("confidenceFor(%d) = %v, want %v", c.in, got, c.want)
		}
	}

	// Through the aggregator, with a basis carrying more trues than the model
	// has inputs.
	_, conf := BoundedSumAggregator{}.Aggregate([]decision.Factor{{
		Name:     FactorEvidenceBasis,
		Evidence: map[string]string{"a": "true", "b": "true", "c": "true", "d": "true"},
	}})
	if conf != ConfidenceCeiling {
		t.Errorf("confidence = %v, want it clamped to %v", conf, ConfidenceCeiling)
	}
}

// --- benchmarks -----------------------------------------------------------------------------------

// The number that matters: the within-envelope path, which is the overwhelming
// majority of a session and the one charged to the agent's syscall in enforce
// mode. It reads no history and allocates only the factor slice and the
// assessment.
func BenchmarkScoreWithinEnvelope(b *testing.B) {
	e := NewEngine()
	req := ScoreRequest{
		Event:      fileEvent(capability.KindFileWrite, ws+"/main.go"),
		Validation: result(decision.VerdictWithinEnvelope),
		Envelope:   envelope(),
		History:    history(),
	}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := e.Score(ctx, req); err != nil {
			b.Fatal(err)
		}
	}
}

// The departure path, where every factor fires and the history is read.
func BenchmarkScoreDeparture(b *testing.B) {
	e := NewEngine()
	req := ScoreRequest{
		Event: fileEvent(capability.KindFileDelete, "/etc/shadow"),
		Validation: result(decision.VerdictOutsideEnvelope,
			viol(validator.ViolationUngrantedCapability, capability.SeverityMedium),
			viol(validator.ViolationWorkspaceEscape, capability.SeverityHigh)),
		Envelope: envelope(),
		History:  history().withViolations(3),
	}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := e.Score(ctx, req); err != nil {
			b.Fatal(err)
		}
	}
}
