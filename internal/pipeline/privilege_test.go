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
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// This file covers the privilege_change factor end to end, against the rule set
// the project actually ships. Two claims live here and nowhere else:
//
//  1. The factor changes an action on priv.namespace. That is a statement about
//     risk and policy together and is unobservable from either package alone.
//  2. The factor changes no action on priv.escalate, priv.setuid, or
//     priv.capset, because configs/rules.default.yaml already blocks those
//     terminally at priority 990 and a terminal block is not something a score
//     may loosen. The second claim matters as much as the first: a risk factor
//     that could talk an event out of a block would be a hole rather than a
//     feature.

// --- fixtures ---------------------------------------------------------------------

// privEvent is a privilege event as telemetry.resolve produces one: the
// observation carries the kind and the domain and no target at all.
func privEvent(id string, kind capability.Kind, p *event.PrivPayload) *event.Event {
	domain, _ := capability.DomainOf(kind)
	return &event.Event{
		ID:         id,
		SessionID:  "s-1",
		Capability: kind,
		Domain:     domain,
		WallClock:  baseTime,
		Privil:     p,
		Result:     event.Result{Succeeded: true},
		Observation: capability.Observation{
			Kind: kind, Domain: domain,
		},
	}
}

// workspaceEnvelope grants ordinary filesystem work and no privilege at all,
// which is what an honest coding envelope looks like: pkg/capability's table
// says a privilege grant to a coding agent "is a generation failure rather than
// a requirement".
func workspaceEnvelope() *ece.Envelope {
	return envelope(
		[]capability.Grant{pathGrant(capability.KindFileRead, 0, "/ws/**")},
		nil,
		ece.Constraints{WorkspaceRoot: "/ws"},
	)
}

// unprivilegedEngine is the shipped scorer set with privilege_change removed,
// standing in for the build before this milestone. Hand-assembled through
// NewEngineWith, which exists precisely so a scorer set can be varied and
// measured.
func unprivilegedEngine(t *testing.T) *risk.BaselineEngine {
	t.Helper()

	var scorers []risk.Scorer
	for _, s := range risk.NewEngine().Scorers() {
		if s.Name() == risk.FactorPrivilegeChange {
			continue
		}
		scorers = append(scorers, s)
	}
	e, err := risk.NewEngineWith(scorers, nil)
	if err != nil {
		t.Fatalf("NewEngineWith: %v", err)
	}
	return e
}

// buildPrivPipeline is the full deterministic pipeline under the shipped rule
// set, with or without the privilege factor behind it.
func buildPrivPipeline(t *testing.T, env *ece.Envelope, st State, scored bool) *EventPipeline {
	t.Helper()

	engine := risk.Engine(unprivilegedEngine(t))
	if scored {
		engine = risk.NewEngine()
	}
	p, err := NewWithRisk(Config{
		Session: Session{Envelope: env, Mode: policy.ModeMonitor, State: st},
		Now:     frozen(),
	}, validator.NewValidator(), engine, defaultEngine(t))
	if err != nil {
		t.Fatalf("NewWithRisk: %v", err)
	}
	return p
}

func runPriv(t *testing.T, e *event.Event, scored bool) *ProcessingContext {
	t.Helper()
	env := workspaceEnvelope()
	return process(t, buildPrivPipeline(t, env, session.NewState(env.SessionID, env), scored), e)
}

// --- 1. the claim that justified building this ---------------------------------------

// The reason the milestone was not deferred. configs/rules.default.yaml's
// privilege-escalation rule matches `capabilities: [priv.escalate, priv.setuid,
// priv.capset]` and does not name priv.namespace — the capability the catalog
// describes as "how a process escapes the attribution the collector depends
// on". An ungranted namespace change therefore falls past that rule, past ten
// others, and lands on medium-risk-departure, which warns.
//
// With the factor the same event reaches high-risk-departure, which asks a
// human. The rule was not written for this feature; it ships with a stated
// confidence floor so "a shaky score" cannot trigger an interruption, and the
// score here clears it on a conclusive verdict and a real session history.
func TestPrivilegeScoringMovesAShippedRuleForNamespaceChanges(t *testing.T) {
	e := privEvent("p-ns", capability.KindPrivNamespace,
		&event.PrivPayload{Operation: "unshare", NamespaceType: "user"})

	before, after := runPriv(t, e, false), runPriv(t, e, true)

	if before.Validation.Verdict != decision.VerdictOutsideEnvelope {
		t.Fatalf("verdict = %q, want outside_envelope; the envelope grants no privilege",
			before.Validation.Verdict)
	}
	if before.Outcome.RuleID != "medium-risk-departure" || before.Outcome.Action != ece.ActionWarn {
		t.Fatalf("without the factor the event matched %q / %q; want medium-risk-departure / warn",
			before.Outcome.RuleID, before.Outcome.Action)
	}
	if after.Outcome.RuleID != "high-risk-departure" || after.Outcome.Action != ece.ActionRequestApproval {
		t.Errorf("with the factor the event matched %q / %q; want high-risk-departure / request_approval",
			after.Outcome.RuleID, after.Outcome.Action)
	}

	// The score moved by exactly the catalog's grade for the kind, and by
	// nothing else.
	if got := after.Risk.Score - before.Risk.Score; got != 25 {
		t.Errorf("score moved by %v, want exactly the critical grade's 25", got)
	}
	// And risk did not reach validation, which is the boundary the whole
	// architecture rests on.
	if after.Validation.Verdict != before.Validation.Verdict {
		t.Errorf("the verdict moved from %q to %q", before.Validation.Verdict, after.Validation.Verdict)
	}
}

// The other half of the claim, and the more important one to pin: for the three
// capabilities the rule set does block, the factor changes the score and
// changes nothing else. A terminal block at priority 990 is decided before any
// risk condition is read, and a risk factor that could move it would be a hole.
func TestPrivilegeScoringCannotLoosenTheBlockRule(t *testing.T) {
	for _, k := range []capability.Kind{
		capability.KindPrivEscalate, capability.KindPrivSetuid, capability.KindPrivCapSet,
	} {
		t.Run(string(k), func(t *testing.T) {
			e := privEvent("p-blocked", k, &event.PrivPayload{Operation: "setuid", OldUID: 1000, NewUID: 33})
			before, after := runPriv(t, e, false), runPriv(t, e, true)

			for _, pc := range []*ProcessingContext{before, after} {
				if pc.Outcome.RuleID != "privilege-escalation" {
					t.Fatalf("matched %q, want privilege-escalation", pc.Outcome.RuleID)
				}
				if pc.Outcome.Action != ece.ActionBlock || !pc.Outcome.Terminal {
					t.Errorf("action = %q terminal = %v, want block / true",
						pc.Outcome.Action, pc.Outcome.Terminal)
				}
			}
			// The score still moves. The record is more informative even where
			// the action is not, which is the auditability half of the case for
			// the factor.
			if after.Risk.Score <= before.Risk.Score {
				t.Errorf("score did not move: %v to %v", before.Risk.Score, after.Risk.Score)
			}
		})
	}
}

// --- 2. the evidence reaches the audit record ------------------------------------------

// A factor a human cannot read in the decision is a factor nobody can act on.
// Everything the payload carried has to survive the whole pipeline, including
// the two labels that say how far it can be trusted.
func TestPrivilegeEvidenceReachesTheDecision(t *testing.T) {
	pc := runPriv(t, privEvent("p-caps", capability.KindPrivCapSet, &event.PrivPayload{
		Operation:         "capset",
		OldUID:            1000,
		NewUID:            1000,
		CapabilitiesAdded: []string{"CAP_SYS_ADMIN"},
	}), true)

	var f *decision.Factor
	for i := range pc.Decision.Risk.Factors {
		if pc.Decision.Risk.Factors[i].Name == risk.FactorPrivilegeChange {
			f = &pc.Decision.Risk.Factors[i]
		}
	}
	if f == nil {
		t.Fatalf("the decision carries no %s factor; factors were %+v",
			risk.FactorPrivilegeChange, pc.Decision.Risk.Factors)
	}

	for k, want := range map[string]string{
		risk.EvidenceCapability:        string(capability.KindPrivCapSet),
		risk.EvidenceBaselineSeverity:  string(capability.SeverityCritical),
		risk.EvidencePrivEvidence:      risk.PrivEvidenceRecorded,
		risk.EvidenceOperation:         "capset",
		risk.EvidenceCapabilitiesAdded: "CAP_SYS_ADMIN",
		risk.EvidenceCapabilityDelta:   risk.CapabilityDeltaAddedOnly,
		risk.EvidenceUIDTransition:     risk.UIDTransitionUnchanged,
	} {
		if got := f.Evidence[k]; got != want {
			t.Errorf("evidence[%q] = %q, want %q", k, got, want)
		}
	}
}

// --- 3. a granted privilege change ------------------------------------------------------

// An envelope that grants priv.setuid is not matched by the block rule, which
// reads only three of the six verdicts. The event is allowed — correctly, since
// the envelope's author said so — and the point of the factor here is that the
// record now names what was granted away instead of passing in silence.
//
// The score stays exactly zero, so the model's invariant that an expected event
// scores zero survives a domain the catalog grades critical.
func TestAGrantedPrivilegeChangeIsAllowedAndRecorded(t *testing.T) {
	env := envelope(
		[]capability.Grant{{Kind: capability.KindPrivSetuid, Domain: capability.DomainPrivilege}},
		nil,
		ece.Constraints{WorkspaceRoot: "/ws"},
	)
	pc := process(t, buildPrivPipeline(t, env, session.NewState(env.SessionID, env), true),
		privEvent("p-granted", capability.KindPrivSetuid,
			&event.PrivPayload{Operation: "setuid", OldUID: 1000, NewUID: 33}))

	if pc.Validation.Verdict != decision.VerdictWithinEnvelope {
		t.Fatalf("verdict = %q, want within_envelope", pc.Validation.Verdict)
	}
	if pc.Outcome.RuleID != "within-envelope" || pc.Outcome.Action != ece.ActionAllow {
		t.Fatalf("matched %q / %q; want within-envelope / allow — the shipped block rule reads "+
			"only three verdicts and within_envelope is not among them",
			pc.Outcome.RuleID, pc.Outcome.Action)
	}
	if pc.Risk.Score != 0 {
		t.Errorf("Score = %v, want 0; a covered event has to score exactly zero", pc.Risk.Score)
	}

	var f *decision.Factor
	for i := range pc.Decision.Risk.Factors {
		if pc.Decision.Risk.Factors[i].Name == risk.FactorPrivilegeChange {
			f = &pc.Decision.Risk.Factors[i]
		}
	}
	if f == nil {
		t.Fatal("a granted privilege change reached the audit record with nothing naming it")
	}
	if f.Evidence[risk.EvidenceNotCharged] == "" {
		t.Error("points were withheld with no not_charged reason in the record")
	}
}
