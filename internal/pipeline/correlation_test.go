package pipeline

import (
	"testing"

	"github.com/stringNameMahin/ALLSEER/internal/policy"
	"github.com/stringNameMahin/ALLSEER/internal/risk"
	"github.com/stringNameMahin/ALLSEER/internal/session"
	"github.com/stringNameMahin/ALLSEER/internal/validator"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
)

// The corpus is where uncorrelated_destination has to prove it is cheap
// evidence rather than a new opinion: it may add points to the two recorded
// events that are genuinely reached by address, and it may not move a verdict,
// a rule, an action, or a level anywhere.

// engineWithoutCorrelation is the shipped rated engine with the correlation
// scorer removed, and it is the control for every comparison here.
//
// Built by filtering the real scorer set through the exported NewEngineWith
// rather than by standing up a second engine, so the control differs from the
// subject in exactly one scorer and in nothing else.
func engineWithoutCorrelation(t *testing.T) *risk.BaselineEngine {
	t.Helper()

	full := ratedEngine(t)
	kept := make([]risk.Scorer, 0, len(full.Scorers()))
	for _, s := range full.Scorers() {
		if s.Name() == risk.FactorUncorrelatedDestination {
			continue
		}
		kept = append(kept, s)
	}
	if len(kept) == len(full.Scorers()) {
		t.Fatal("the rated engine does not carry the correlation scorer, so this control tests nothing")
	}

	e, err := risk.NewEngineWith(kept, nil)
	if err != nil {
		t.Fatalf("NewEngineWith: %v", err)
	}
	return e
}

// corpusFixtures is every recording, with the envelope each is governed by.
func corpusFixtures() map[string]func() *ece.Envelope {
	return map[string]func() *ece.Envelope{
		"go-build.jsonl":          gitEnvelope,
		"npm-install.jsonl":       gitEnvelope,
		"git-operation.jsonl":     gitEnvelope,
		"credential-egress.jsonl": exfilEnvelope,
	}
}

// runCorpusWith replays a fixture through the real pipeline under the shipped
// rule set and the given risk engine.
func runCorpusWith(t *testing.T, fixture string, env *ece.Envelope, e risk.Engine) []sequenceOutcome {
	t.Helper()

	st := session.NewState(env.SessionID, env)
	p, err := NewWithRisk(Config{
		Session: Session{Envelope: env, Mode: policy.ModeMonitor, State: st},
		Now:     frozen(),
	}, validator.NewValidator(), e, defaultEngine(t))
	if err != nil {
		t.Fatalf("NewWithRisk: %v", err)
	}

	events := loadFixture(t, fixture)
	out := make([]sequenceOutcome, 0, len(events))
	for i := range events {
		ev := events[i]
		pc := process(t, p, &ev)
		if pc.Err != nil {
			t.Fatalf("%s: %v", ev.ID, pc.Err)
		}
		out = append(out, sequenceOutcome{
			EventID: ev.ID,
			Verdict: pc.Validation.Verdict,
			Rule:    pc.Outcome.RuleID,
			Action:  pc.Outcome.Action,
			Score:   pc.Risk.Score,
			Level:   pc.Risk.Level,
		})
	}
	return out
}

// --- 1. the corpus, event by event ---------------------------------------------------

// The whole regression, asserted as an exact map of score changes.
//
// Two events in the corpus are reached by address with no correlated hostname,
// and they are the only two the factor may touch. Both are listed with their
// exact before and after; an unlisted change and a lost one both fail.
func TestUncorrelatedDestinationChangesExactlyTwoEventsInTheCorpus(t *testing.T) {
	want := map[string]map[string]scoreChange{
		// No network events at all.
		"go-build.jsonl":      {},
		"git-operation.jsonl": {},

		// np-032 connects to 151.101.1.162 with no correlated hostname -- the
		// event the fixture's own README describes as "standing in for
		// DNS-over-HTTPS and hardcoded addresses". It is exactly what this
		// factor is for, and it was previously scored as though the missing name
		// were not a fact about it.
		"npm-install.jsonl": {
			"np-032": {from: 57, to: 62},
		},

		// ex-009 is the same shape, and already carried the credential-egress
		// sequence. The five points are additive with it.
		"credential-egress.jsonl": {
			"ex-009": {from: 73, to: 78},
		},
	}

	for fixture, envFor := range corpusFixtures() {
		t.Run(fixture, func(t *testing.T) {
			env := envFor()

			before := runCorpusWith(t, fixture, env, engineWithoutCorrelation(t))
			after := runCorpusWith(t, fixture, env, ratedEngine(t))

			if len(before) != len(after) {
				t.Fatalf("event counts diverged: %d before, %d after", len(before), len(after))
			}

			got := map[string]scoreChange{}
			for i := range after {
				b, a := before[i], after[i]

				if a.EventID != b.EventID {
					t.Fatalf("event %d: %q after, %q before", i, a.EventID, b.EventID)
				}
				// Nothing but the score may move. The factor is evidence, and
				// evidence that changed a verdict would mean risk had reached
				// validation.
				if a.Verdict != b.Verdict {
					t.Errorf("%s: verdict %q -> %q", a.EventID, b.Verdict, a.Verdict)
				}
				if a.Rule != b.Rule {
					t.Errorf("%s: rule %q -> %q", a.EventID, b.Rule, a.Rule)
				}
				if a.Action != b.Action {
					t.Errorf("%s: action %q -> %q", a.EventID, b.Action, a.Action)
				}
				if a.Level != b.Level {
					t.Errorf("%s: level %q -> %q", a.EventID, b.Level, a.Level)
				}
				// And the score may only rise, by exactly the one value this
				// scorer can contribute.
				if a.Score < b.Score {
					t.Errorf("%s: score fell from %v to %v", a.EventID, b.Score, a.Score)
				}
				if a.Score != b.Score {
					if d := a.Score - b.Score; d != risk.UncorrelatedDestinationPoints {
						t.Errorf("%s: score moved by %v, want exactly %v",
							a.EventID, d, risk.UncorrelatedDestinationPoints)
					}
					got[a.EventID] = scoreChange{from: b.Score, to: a.Score}
				}
			}

			w := want[fixture]
			if len(got) != len(w) {
				t.Errorf("changed events\n got %+v\nwant %+v", got, w)
			}
			for id, c := range w {
				if got[id] != c {
					t.Errorf("%s: change %+v, want %+v", id, got[id], c)
				}
			}
		})
	}
}

type scoreChange struct{ from, to float64 }

// --- 2. the event, in detail -------------------------------------------------------------

// np-032 is the corpus's own uncorrelated destination, and this is what the
// factor says about it. The evidence has to be checkable against the recording
// by hand, which is the whole standard for a factor in this project.
func TestTheCorpusUncorrelatedEventCarriesItsEvidence(t *testing.T) {
	env := gitEnvelope()
	st := session.NewState(env.SessionID, env)
	p, err := NewWithRisk(Config{
		Session: Session{Envelope: env, Mode: policy.ModeMonitor, State: st},
		Now:     frozen(),
	}, validator.NewValidator(), ratedEngine(t), defaultEngine(t))
	if err != nil {
		t.Fatalf("NewWithRisk: %v", err)
	}

	var target, correlated *decision.Decision
	for _, e := range loadFixture(t, "npm-install.jsonl") {
		ev := e
		pc := process(t, p, &ev)
		switch ev.ID {
		case "np-032":
			target = pc.Decision
		case "np-004":
			correlated = pc.Decision
		}
	}
	if target == nil || correlated == nil {
		t.Fatal("the fixture no longer carries np-004 and np-032")
	}

	f := correlationFactor(&target.Risk)
	if f == nil {
		t.Fatalf("np-032 carries no %s factor; factors were %+v",
			risk.FactorUncorrelatedDestination, target.Risk.Factors)
	}
	for k, wantV := range map[string]string{
		risk.EvidenceCapability:  string(capability.KindNetConnect),
		risk.EvidenceTarget:      "151.101.1.162:443",
		risk.EvidenceHost:        "151.101.1.162",
		risk.EvidenceHostKind:    risk.HostKindLabelAddress,
		risk.EvidenceDestIP:      "151.101.1.162",
		risk.EvidenceCorrelation: risk.CorrelationLabelMissing,
	} {
		if got := f.Evidence[k]; got != wantV {
			t.Errorf("evidence[%q] = %q, want %q", k, got, wantV)
		}
	}
	if f.Weight != risk.UncorrelatedDestinationPoints {
		t.Errorf("Weight = %v, want %v", f.Weight, risk.UncorrelatedDestinationPoints)
	}

	// np-004 reaches the same registry over a correlated name in the same
	// session, and says nothing. The pair is what makes the factor a statement
	// about correlation rather than about the network domain.
	if cf := correlationFactor(&correlated.Risk); cf != nil {
		t.Errorf("np-004 is correlated and produced %+v", *cf)
	}
}

// Every network event in the corpus is accounted for: correlated ones are
// silent, uncorrelated ones fire, and DNS never speaks whichever it is.
func TestEveryCorpusNetworkEventIsAccountedFor(t *testing.T) {
	// Every network event in the corpus, and what the factor must say about it.
	want := map[string]bool{
		"np-003": false, // net.dns, correlated name -- and DNS is excluded anyway
		"np-004": false, // net.connect, correlated
		"np-005": false, // net.receive -- not a destination-naming capability
		"np-032": true,  // net.connect, uncorrelated
		"ex-006": false, // net.dns
		"ex-007": false, // net.connect, correlated
		"ex-008": false, // net.send, correlated
		"ex-009": true,  // net.connect, uncorrelated
	}

	seen := map[string]bool{}
	for fixture, envFor := range corpusFixtures() {
		env := envFor()
		st := session.NewState(env.SessionID, env)
		p, err := NewWithRisk(Config{
			Session: Session{Envelope: env, Mode: policy.ModeMonitor, State: st},
			Now:     frozen(),
		}, validator.NewValidator(), ratedEngine(t), defaultEngine(t))
		if err != nil {
			t.Fatalf("NewWithRisk: %v", err)
		}

		for _, e := range loadFixture(t, fixture) {
			ev := e
			pc := process(t, p, &ev)

			domain, ok := capability.DomainOf(ev.Capability)
			fired := correlationFactor(pc.Risk) != nil

			if !ok || domain != capability.DomainNetwork {
				if fired {
					t.Errorf("%s: a %s event produced a correlation factor", ev.ID, ev.Capability)
				}
				continue
			}

			seen[ev.ID] = true
			if w, listed := want[ev.ID]; !listed {
				t.Errorf("%s is a network event this test does not account for", ev.ID)
			} else if fired != w {
				t.Errorf("%s (%s): factor produced = %v, want %v", ev.ID, ev.Capability, fired, w)
			}
		}
	}

	for id := range want {
		if !seen[id] {
			t.Errorf("%s is no longer in the corpus", id)
		}
	}
}

func correlationFactor(a *decision.RiskAssessment) *decision.Factor {
	if a == nil {
		return nil
	}
	for i := range a.Factors {
		if a.Factors[i].Name == risk.FactorUncorrelatedDestination {
			return &a.Factors[i]
		}
	}
	return nil
}
