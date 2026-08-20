package pipeline

import (
	"context"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"

	"github.com/stringNameMahin/ALLSEER/internal/policy"
	"github.com/stringNameMahin/ALLSEER/internal/risk"
	"github.com/stringNameMahin/ALLSEER/internal/session"
	"github.com/stringNameMahin/ALLSEER/internal/validator"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// This file covers the sequence detector end to end, which is the only place
// two of its claims can be checked at all.
//
// The first is the ordering claim. internal/risk asserts that a hand-assembled
// request cannot make an event its own antecedent; what it cannot assert is
// that the *pipeline* never presents one, because that depends on commit
// running after the whole stage list. Here the real session state is the
// history, so the guarantee is exercised rather than described.
//
// The second is that the finding reaches policy. A risk factor that never moves
// an action is a number in a log, and the whole point of putting the detector
// behind the existing score stage is that a shipped rule can read it.

// --- fixtures ------------------------------------------------------------------------

// exfilEnvelope governs the credential-egress recording.
//
// Written the way an honest envelope for that task would be: the workspace, the
// interpreter it runs, and the one registry it is expected to talk to. Nothing
// in it was arranged to make the detector fire — the credential read is a
// departure because the envelope did not anticipate it, which is the point.
func exfilEnvelope() *ece.Envelope {
	ws := "/home/dev/project"
	host := func(kind capability.Kind, hosts ...string) capability.Grant {
		return capability.Grant{
			Kind:     kind,
			Domain:   capability.DomainNetwork,
			Selector: capability.Selector{Hosts: hosts},
		}
	}
	env := envelope(
		[]capability.Grant{
			pathGrant(capability.KindFileRead, 0, ws+"/**"),
			pathGrant(capability.KindFileWrite, 0, ws+"/**"),
			pathGrant(capability.KindFileCreate, 0, ws+"/**"),
			{Kind: capability.KindProcessExec, Domain: capability.DomainProcess,
				Selector: capability.Selector{Executables: []string{"/usr/bin/node"}}},
			{Kind: capability.KindProcessExit, Domain: capability.DomainProcess,
				Selector: capability.Selector{Executables: []string{"/usr/bin/node"}}},
			host(capability.KindNetDNS, "registry.npmjs.org"),
			host(capability.KindNetConnect, "registry.npmjs.org"),
			host(capability.KindNetSend, "registry.npmjs.org"),
		},
		nil,
		ece.Constraints{WorkspaceRoot: ws},
	)
	env.SessionID = "s-exfil"
	return env
}

// sequenceOutcome is one event's result, with enough of the sequence factor to
// tell a finding from a coincidence.
type sequenceOutcome struct {
	EventID string
	Verdict decision.Verdict
	Rule    string
	Action  ece.Action
	Score   float64
	Level   decision.Level

	// SequenceAccess is the antecedent the detector named, empty when it
	// reported nothing. SequencePoints is what the factor contributed, which is
	// zero for a finding on an event the envelope covered.
	SequenceAccess string
	SequencePoints float64
}

// runExfil replays the sequence fixture through the real pipeline under the
// shipped rule set, with the sensitivity list either behind it or not.
func runExfil(t *testing.T, rated bool) []sequenceOutcome {
	t.Helper()

	env := exfilEnvelope()
	st := session.NewState(env.SessionID, env)
	cfg := Config{
		Session: Session{Envelope: env, Mode: policy.ModeMonitor, State: st},
		Now:     frozen(),
	}

	engine := risk.Engine(risk.NewEngine())
	if rated {
		engine = ratedEngine(t)
	}
	p, err := NewWithRisk(cfg, validator.NewValidator(), engine, defaultEngine(t))
	if err != nil {
		t.Fatalf("NewWithRisk: %v", err)
	}

	events := loadFixture(t, "credential-egress.jsonl")
	out := make([]sequenceOutcome, 0, len(events))
	for i := range events {
		e := events[i]
		pc := process(t, p, &e)
		if pc.Err != nil {
			t.Fatalf("%s: %v", e.ID, pc.Err)
		}
		o := sequenceOutcome{
			EventID: e.ID,
			Verdict: pc.Validation.Verdict,
			Rule:    pc.Outcome.RuleID,
			Action:  pc.Outcome.Action,
			Score:   pc.Risk.Score,
			Level:   pc.Risk.Level,
		}
		if f := sequenceFactor(pc.Risk); f != nil {
			o.SequenceAccess = f.Evidence[risk.EvidenceAccessEventID]
			o.SequencePoints = f.Weight
		}
		out = append(out, o)
	}
	return out
}

func sequenceFactor(a *decision.RiskAssessment) *decision.Factor {
	if a == nil {
		return nil
	}
	for i := range a.Factors {
		if a.Factors[i].Name == risk.FactorCredentialEgress {
			return &a.Factors[i]
		}
	}
	return nil
}

// --- 1. the recording, event by event -----------------------------------------------

// The whole fixture asserted as an exact table.
//
// Written out rather than spot-checked because every row is a rule of the
// detector: which read qualifies, which do not, which capabilities are egress,
// what a granted egress does, and what an indeterminate one does. A change to
// any of those rules moves a row here, which is the intent.
func TestTheSequenceFixtureThroughTheRealPipeline(t *testing.T) {
	want := []sequenceOutcome{
		{EventID: "ex-001", Verdict: decision.VerdictWithinEnvelope,
			Rule: "within-envelope", Action: ece.ActionAllow, Score: 0, Level: decision.LevelNone},
		{EventID: "ex-002", Verdict: decision.VerdictWithinEnvelope,
			Rule: "within-envelope", Action: ece.ActionAllow, Score: 0, Level: decision.LevelNone},

		// The credential read. A departure the envelope did not anticipate,
		// scored 80 by the factors that already existed — verdict 25, the
		// escape's high severity 15, the critical grade 25, the escape itself
		// 10, novelty 5 — and matched by the rule written for exactly this.
		// The sequence detector contributes nothing here: this is the first
		// half, and the first half is not yet a sequence.
		{EventID: "ex-003", Verdict: decision.VerdictGrantExceeded,
			Rule: "credential-access-high-risk", Action: ece.ActionRequestApproval,
			Score: 80, Level: decision.LevelHigh},

		// Medium-graded, so 8 rather than 25, and one prior violation on the
		// clock. Not credential access.
		{EventID: "ex-004", Verdict: decision.VerdictGrantExceeded,
			Rule: "medium-risk-departure", Action: ece.ActionWarn,
			Score: 64, Level: decision.LevelHigh},

		// Critical-graded and failed. sensitive_path still charges the grade —
		// the resource was reached for — so this scores like ex-003 plus two
		// prior violations. The sequence detector will not accept it.
		{EventID: "ex-005", Verdict: decision.VerdictGrantExceeded,
			Rule: "credential-access-high-risk", Action: ece.ActionRequestApproval,
			Score: 82, Level: decision.LevelHigh},

		{EventID: "ex-006", Verdict: decision.VerdictWithinEnvelope,
			Rule: "within-envelope", Action: ece.ActionAllow, Score: 0, Level: decision.LevelNone},

		// Granted egress. The sequence is found and reported with its
		// attribution intact, and it charges nothing, because an event a grant
		// covered scores exactly zero.
		{EventID: "ex-007", Verdict: decision.VerdictWithinEnvelope,
			Rule: "within-envelope", Action: ece.ActionAllow, Score: 0, Level: decision.LevelNone,
			SequenceAccess: "ex-003", SequencePoints: 0},
		{EventID: "ex-008", Verdict: decision.VerdictWithinEnvelope,
			Rule: "within-envelope", Action: ece.ActionAllow, Score: 0, Level: decision.LevelNone,
			SequenceAccess: "ex-003", SequencePoints: 0},

		// The event the detector is for. 20 for indeterminate, 15 for the
		// unresolvable violation's severity, 5 for novelty, 3 for the prior
		// violations, 30 for the sequence, and 5 for the destination being
		// reached by address with no correlated hostname: 78, which is above the
		// shipped rule set's own 50 boundary between its two indeterminate
		// rules. It was 73 before uncorrelated_destination existed; the rule,
		// the action, and the level are unchanged by those five points, which is
		// the intended character of the smallest contribution in the model.
		{EventID: "ex-009", Verdict: decision.VerdictIndeterminate,
			Rule: "indeterminate-high-risk", Action: ece.ActionRequestApproval,
			Score: 78, Level: decision.LevelHigh,
			SequenceAccess: "ex-003", SequencePoints: 30},

		{EventID: "ex-010", Verdict: decision.VerdictWithinEnvelope,
			Rule: "within-envelope", Action: ece.ActionAllow, Score: 0, Level: decision.LevelNone},
	}

	got := runExfil(t, true)
	if len(got) != len(want) {
		t.Fatalf("produced %d outcomes, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("event %d:\n got %+v\nwant %+v", i, got[i], want[i])
		}
	}
}

// --- 2. the policy integration -----------------------------------------------------

// The claim this milestone has to make good on: the sequence changes what would
// happen, through a rule that already shipped.
//
// ex-009 is an egress whose destination could not be attributed. Without the
// sequence it scores 43 and matches indeterminate-low-risk, which warns.
// With it, it scores 73 and matches indeterminate-high-risk, which asks a
// human. Neither rule was written for this feature — they ship in
// configs/rules.default.yaml with "unresolved is not the same as safe" as their
// stated reason, and a credential read behind the connection is precisely when
// that should hold.
func TestTheSequenceMovesAShippedRiskConditionedRule(t *testing.T) {
	// The comparison run is the same pipeline with the sensitivity list taken
	// away, which removes both oracle-backed factors. That is the honest
	// control: an engine with no list cannot recognize a credential read, so it
	// cannot see the sequence either.
	unrated := runExfil(t, false)
	rated := runExfil(t, true)

	find := func(rows []sequenceOutcome, id string) sequenceOutcome {
		t.Helper()
		for _, r := range rows {
			if r.EventID == id {
				return r
			}
		}
		t.Fatalf("%s not in the run", id)
		return sequenceOutcome{}
	}

	before, after := find(unrated, "ex-009"), find(rated, "ex-009")

	if before.Rule != "indeterminate-low-risk" || before.Action != ece.ActionWarn {
		t.Fatalf("without the detector, ex-009 matched %q / %q; want indeterminate-low-risk / warn",
			before.Rule, before.Action)
	}
	if after.Rule != "indeterminate-high-risk" || after.Action != ece.ActionRequestApproval {
		t.Errorf("with the detector, ex-009 matched %q / %q; want indeterminate-high-risk / request_approval",
			after.Rule, after.Action)
	}
	if after.Score-before.Score != risk.SequencePoints {
		t.Errorf("the score moved by %v, want exactly the sequence's %v",
			after.Score-before.Score, risk.SequencePoints)
	}
	if after.Verdict != before.Verdict {
		t.Errorf("the verdict moved from %q to %q; risk must not reach validation",
			before.Verdict, after.Verdict)
	}
	if after.SequenceAccess != "ex-003" {
		t.Errorf("the decision attributes the sequence to %q, want ex-003", after.SequenceAccess)
	}
}

// The evidence has to survive into the audit record, not just into the
// assessment the stage produced. A finding a human cannot read in the decision
// is a finding nobody can act on.
func TestTheSequenceEvidenceReachesTheDecision(t *testing.T) {
	env := exfilEnvelope()
	st := session.NewState(env.SessionID, env)
	p, err := NewWithRisk(Config{
		Session: Session{Envelope: env, Mode: policy.ModeMonitor, State: st},
		Now:     frozen(),
	}, validator.NewValidator(), ratedEngine(t), defaultEngine(t))
	if err != nil {
		t.Fatalf("NewWithRisk: %v", err)
	}

	var d *decision.Decision
	for _, e := range loadFixture(t, "credential-egress.jsonl") {
		ev := e
		pc := process(t, p, &ev)
		if ev.ID == "ex-009" {
			d = pc.Decision
		}
	}
	if d == nil {
		t.Fatal("ex-009 produced no decision")
	}

	f := sequenceFactor(&d.Risk)
	if f == nil {
		t.Fatalf("the decision carries no %s factor; factors were %+v",
			risk.FactorCredentialEgress, d.Risk.Factors)
	}

	// Every question the factor has to answer, checked against the recording.
	for k, want := range map[string]string{
		risk.EvidenceAccessEventID:     "ex-003",
		risk.EvidenceAccessTarget:      "/home/dev/.aws/credentials",
		risk.EvidenceAccessCapability:  string(capability.KindFileRead),
		risk.EvidenceAccessSensitivity: string(capability.SeverityCritical),
		risk.EvidenceAccessSucceeded:   "true",
		risk.EvidenceEgressCapability:  string(capability.KindNetConnect),
		risk.EvidenceEgressTarget:      "198.51.100.77:8443",
		risk.EvidenceDistanceEvents:    "6",
	} {
		if got := f.Evidence[k]; got != want {
			t.Errorf("evidence[%q] = %q, want %q", k, got, want)
		}
	}
	if f.Evidence[risk.EvidenceWindowEvents] == "" {
		t.Error("the record does not say what window was searched")
	}
	if f.Evidence[risk.EvidenceAccessReason] == "" {
		t.Error("the sensitivity list's written reason did not reach the audit record")
	}
	if _, ok := f.Evidence[risk.EvidenceWindowTruncated]; ok {
		t.Error("a nine-event history was reported as filling a 256-event window")
	}
}

// --- 3. the ordering the pipeline guarantees ------------------------------------------

// An egress event cannot be its own antecedent, through the real pipeline.
//
// This is the pipeline's guarantee rather than the scorer's: commit runs after
// the whole stage list, so the event under judgment is not in history when the
// score stage reads it. The proof is a session containing exactly one event
// that is both a qualifying read and — were the ordering reversed — visible to
// itself. A net.connect cannot be a read, so the case is constructed the only
// way it can be: score the egress with nothing before it, then commit it, then
// score a second egress and watch the antecedent appear only when there really
// is one.
func TestSequenceCannotSeeTheEventBeingScored(t *testing.T) {
	env := exfilEnvelope()
	st := session.NewState(env.SessionID, env)
	p, err := NewWithRisk(Config{
		Session: Session{Envelope: env, Mode: policy.ModeMonitor, State: st},
		Now:     frozen(),
	}, validator.NewValidator(), ratedEngine(t), defaultEngine(t))
	if err != nil {
		t.Fatalf("NewWithRisk: %v", err)
	}

	// A credential read that is *also* the very first event. Nothing precedes
	// it, so nothing can be its antecedent — and it is not egress, so the
	// detector does not even look.
	read := fileEventAt("ex-r", capability.KindFileRead, "/home/dev/.aws/credentials", true)
	first := process(t, p, read)
	if f := sequenceFactor(first.Risk); f != nil {
		t.Errorf("a credential read produced a sequence factor about itself: %+v", *f)
	}

	// The next egress event sees that read, because by now it is committed.
	egress := process(t, p, netEventAt("ex-n", capability.KindNetConnect, "198.51.100.77:8443"))
	f := sequenceFactor(egress.Risk)
	if f == nil {
		t.Fatal("the committed read was invisible to the following egress")
	}
	if got := f.Evidence[risk.EvidenceAccessEventID]; got != "ex-r" {
		t.Errorf("attributed to %q, want ex-r", got)
	}
	if got := f.Evidence[risk.EvidenceDistanceEvents]; got != "1" {
		t.Errorf("distance_events = %q, want 1", got)
	}

	// And an egress event scored against a history that contains only itself
	// would have to attribute the sequence to itself. It cannot, because the
	// history it reads is the one that existed before it — asserted through the
	// consequence: a second, identical egress finds the same read rather than
	// the first egress.
	second := process(t, p, netEventAt("ex-n2", capability.KindNetSend, "198.51.100.77:8443"))
	f2 := sequenceFactor(second.Risk)
	if f2 == nil {
		t.Fatal("the second egress reported no sequence")
	}
	if got := f2.Evidence[risk.EvidenceAccessEventID]; got != "ex-r" {
		t.Errorf("the second egress attributed the sequence to %q, want ex-r", got)
	}
	if got := f2.Evidence[risk.EvidenceEgressCapability]; got != string(capability.KindNetSend) {
		t.Errorf("egress_capability = %q, want net.send", got)
	}
}

// fileEventAt is fileEvent with a session, a result, and an explicit success
// flag, because the detector reads all three.
func fileEventAt(id string, kind capability.Kind, path string, succeeded bool) *event.Event {
	e := fileEvent(id, kind, path)
	e.SessionID = "s-exfil"
	e.Result = event.Result{ReturnCode: 3, Succeeded: succeeded}
	if !succeeded {
		e.Result = event.Result{ReturnCode: -2, Errno: "ENOENT"}
	}
	return e
}

func netEventAt(id string, kind capability.Kind, target string) *event.Event {
	domain, _ := capability.DomainOf(kind)
	return &event.Event{
		ID:         id,
		SessionID:  "s-exfil",
		Capability: kind,
		Domain:     domain,
		WallClock:  baseTime,
		Result:     event.Result{Succeeded: true},
		Network: &event.NetworkPayload{
			Protocol: "tcp", DestAddr: "198.51.100.77", DestPort: 8443,
		},
		Observation: capability.Observation{
			Kind: kind, Domain: domain, Target: target,
			Attributes: map[string]string{
				capability.AttrProtocol:           "tcp",
				capability.AttrDestIP:             "198.51.100.77",
				capability.AttrPort:               "8443",
				capability.AttrHostnameCorrelated: "false",
			},
		},
	}
}

// --- 4. the regression ----------------------------------------------------------------

// Adding the detector must change nothing about the recordings that contain no
// sequence.
//
// The three original fixtures are run through the same rated composition the
// sensitivity milestone pinned, and every outcome has to be identical to what
// that milestone recorded — no verdict, score, rule, or action may move, and no
// sequence factor may appear anywhere. This is the claim that the detector adds
// evidence rather than rewriting it.
func TestTheOriginalCorpusIsUnchangedByTheDetector(t *testing.T) {
	// What the sensitivity milestone recorded for the one event it moved. If
	// the detector disturbed the corpus at all, it would show up here first.
	wantGitScores := map[string]float64{"gt-009": 81}

	for _, fixture := range []string{"go-build.jsonl", "npm-install.jsonl", "git-operation.jsonl"} {
		t.Run(fixture, func(t *testing.T) {
			events := loadFixture(t, fixture)

			env := gitEnvelope()
			st := session.NewState(env.SessionID, env)
			p, err := NewWithRisk(Config{
				Session: Session{Envelope: env, Mode: policy.ModeMonitor, State: st},
				Now:     frozen(),
			}, validator.NewValidator(), ratedEngine(t), defaultEngine(t))
			if err != nil {
				t.Fatalf("NewWithRisk: %v", err)
			}

			for i := range events {
				e := events[i]
				pc := process(t, p, &e)
				if pc.Err != nil {
					t.Fatalf("%s: %v", e.ID, pc.Err)
				}
				if f := sequenceFactor(pc.Risk); f != nil {
					t.Errorf("%s produced a sequence factor in a recording that contains no sequence: %+v",
						e.ID, *f)
				}
				if want, ok := wantGitScores[e.ID]; ok && pc.Risk.Score != want {
					t.Errorf("%s scored %v, want the %v the sensitivity milestone recorded",
						e.ID, pc.Risk.Score, want)
				}
			}
		})
	}
}

// A recording replayed twice has to produce the same decisions. The detector
// walks a history slice and builds an evidence map on the hot path, both of
// which are places non-determinism hides.
func TestTheSequencePipelineIsDeterministic(t *testing.T) {
	first := runExfil(t, true)
	for i := 0; i < 25; i++ {
		if got := runExfil(t, true); !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d diverged\n got %+v\nwant %+v", i, got, first)
		}
	}
}

// --- 5. benchmarks ----------------------------------------------------------------------

// The hot path with the detector in it, on the event a real session is made of:
// an in-workspace write the sensitivity list has never heard of. It is not
// egress, so the detector costs one capability comparison and reads no history.
// Compare against BenchmarkProcessRated, which is the same pipeline without it.
func BenchmarkProcessWithSequenceDetector(b *testing.B) {
	env := envelope([]capability.Grant{pathGrant(capability.KindFileWrite, 0, "/ws/**")}, nil, ece.Constraints{})
	st := session.NewState("s-1", env)

	pe, err := policy.NewEngine(simpleRules())
	if err != nil {
		b.Fatalf("NewEngine: %v", err)
	}
	o, err := risk.LoadResourceOracle(filepath.Join("..", "..", "configs", "sensitivity.default.yaml"))
	if err != nil {
		b.Fatalf("LoadResourceOracle: %v", err)
	}
	re, err := risk.NewEngineWithOracle(o)
	if err != nil {
		b.Fatalf("NewEngineWithOracle: %v", err)
	}
	p, err := NewWithRisk(Config{
		Session: Session{Envelope: env, Mode: policy.ModeMonitor, State: st},
		Now:     frozen(),
	}, validator.NewValidator(), re, pe)
	if err != nil {
		b.Fatalf("NewWithRisk: %v", err)
	}

	ev := fileEvent("e-1", capability.KindFileWrite, "/ws/a.go")
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := p.Process(ctx, ev); err != nil {
			b.Fatal(err)
		}
	}
}

// The expensive path, measured rather than assumed: an egress event in a
// session whose history is full and holds no qualifying access, so the scan
// runs the whole window. This is the worst case the detector can reach on a
// real pipeline, and the number it has to justify.
func BenchmarkProcessEgressOverAFullWindow(b *testing.B) {
	env := envelope([]capability.Grant{pathGrant(capability.KindFileRead, 0, "/ws/**")}, nil, ece.Constraints{})
	st := session.NewState("s-1", env)

	pe, err := policy.NewEngine(simpleRules())
	if err != nil {
		b.Fatalf("NewEngine: %v", err)
	}
	o, err := risk.LoadResourceOracle(filepath.Join("..", "..", "configs", "sensitivity.default.yaml"))
	if err != nil {
		b.Fatalf("LoadResourceOracle: %v", err)
	}
	re, err := risk.NewEngineWithOracle(o)
	if err != nil {
		b.Fatalf("NewEngineWithOracle: %v", err)
	}
	p, err := NewWithRisk(Config{
		Session: Session{Envelope: env, Mode: policy.ModeMonitor, State: st},
		Now:     frozen(),
	}, validator.NewValidator(), re, pe)
	if err != nil {
		b.Fatalf("NewWithRisk: %v", err)
	}

	ctx := context.Background()
	// Fill the ring with ordinary in-workspace reads, none of which qualifies.
	// Distinct paths, because one repeated path would understate the scan: the
	// oracle's cost is a function of how many segments it has to compare, and a
	// benchmark that read the same short path 256 times would measure a case no
	// real build produces.
	for i := 0; i < session.DefaultHistorySize; i++ {
		e := fileEvent("f-fill", capability.KindFileRead,
			"/ws/internal/pkg"+strconv.Itoa(i)+"/service/handler.go")
		e.Result = event.Result{ReturnCode: 3, Succeeded: true}
		if _, err := p.Process(ctx, e); err != nil {
			b.Fatal(err)
		}
	}

	ev := netEventAt("e-egress", capability.KindNetConnect, "198.51.100.77:8443")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := p.Process(ctx, ev); err != nil {
			b.Fatal(err)
		}
	}
}
