package risk

import (
	"context"
	"testing"

	"github.com/stringNameMahin/ALLSEER/internal/validator"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// These tests are about a factor whose points come from the capability catalog
// and whose evidence comes from a payload nothing in this build writes. The
// split runs through the file: section 2 pins the arithmetic against the
// catalog, and sections 3 to 5 pin the evidence against every shape
// event.PrivPayload can take, including the shapes that cannot be read.
//
// The claim in section 6 is the reason the milestone was not deferred, and it
// is checked against configs/rules.default.yaml's actual match clauses rather
// than against its prose.

// --- fixtures ---------------------------------------------------------------------

// privEvent is a privilege event as telemetry.resolve produces one: the
// observation carries the kind and the domain and no target at all, because
// exercising the capability is the whole observation.
func privEvent(kind capability.Kind, p *event.PrivPayload) *event.Event {
	domain, _ := capability.DomainOf(kind)
	return &event.Event{
		ID:         "e-priv",
		SessionID:  "s-1",
		Capability: kind,
		Domain:     domain,
		Privil:     p,
		Result:     event.Result{Succeeded: true},
		Observation: capability.Observation{
			Kind: kind, Domain: domain,
		},
	}
}

// privDeparture scores an ungranted privilege event, so the factor is charged
// rather than merely reported. Critical severity is what validator.severityFor
// returns for an ungranted capability the catalog grades critical.
func privDeparture(kind capability.Kind, p *event.PrivPayload) ScoreRequest {
	return ScoreRequest{
		Event: privEvent(kind, p),
		Validation: result(decision.VerdictOutsideEnvelope,
			viol(validator.ViolationUngrantedCapability, capability.SeverityCritical)),
		Envelope: envelope(),
		History:  history(),
	}
}

func priv(a *decision.RiskAssessment) *decision.Factor {
	return factor(a, FactorPrivilegeChange)
}

// setuidPayload is the shape a decoder would plausibly produce, used wherever
// the test is about something other than the payload itself.
func setuidPayload() *event.PrivPayload {
	return &event.PrivPayload{Operation: "setuid", OldUID: 1000, NewUID: 33}
}

// --- 1. which events the factor speaks about ----------------------------------------

// The factor is emitted for every capability the catalog places in the
// privilege domain, and for no other. Enumerated from the catalog rather than
// from a hand-written list, so a privilege capability added to table.go without
// a thought for scoring fails here rather than passing silently.
func TestEveryPrivilegeCapabilityProducesTheFactor(t *testing.T) {
	kinds := capability.KindsInDomain(capability.DomainPrivilege)
	if len(kinds) == 0 {
		t.Fatal("the catalog holds no privilege capabilities; this test is vacuous")
	}
	for _, k := range kinds {
		a := score(t, privDeparture(k, setuidPayload()))
		f := priv(a)
		if f == nil {
			t.Errorf("%s produced no %s factor; factors were %v", k, FactorPrivilegeChange, names(a))
			continue
		}
		if f.Evidence[EvidenceCapability] != string(k) {
			t.Errorf("%s: capability evidence = %q", k, f.Evidence[EvidenceCapability])
		}
	}
}

// No other domain produces the factor, and the scorer's silence is total: it
// does not emit a zero-weight "no privilege change" factor the way
// sensitive_path emits "unknown". The two are different claims. sensitive_path
// speaks because a resource exists and is unrated; here nothing happened.
func TestNonPrivilegeEventsProduceNoFactor(t *testing.T) {
	for _, d := range capability.AllDomains() {
		if d == capability.DomainPrivilege {
			continue
		}
		for _, k := range capability.KindsInDomain(d) {
			a := score(t, ScoreRequest{
				Event:      fileEvent(k, "/home/dev/project/main.go"),
				Validation: result(decision.VerdictOutsideEnvelope),
				Envelope:   envelope(),
				History:    history(),
			})
			if f := priv(a); f != nil {
				t.Errorf("%s (%s) produced %+v", k, d, *f)
			}
		}
	}
}

// The domain comes from the catalog and never from Event.Domain. A record
// claiming to be a filesystem event while carrying a privilege capability is
// scored as the privilege event its capability makes it, because Domain is a
// denormalized convenience the decoder writes and the catalog is the authority.
func TestTheDomainComesFromTheCatalogNotTheEvent(t *testing.T) {
	e := privEvent(capability.KindPrivEscalate, setuidPayload())
	e.Domain = capability.DomainFilesystem
	e.Observation.Domain = capability.DomainFilesystem

	a := score(t, ScoreRequest{
		Event: e,
		Validation: result(decision.VerdictOutsideEnvelope,
			viol(validator.ViolationUngrantedCapability, capability.SeverityCritical)),
		Envelope: envelope(),
		History:  history(),
	})
	if priv(a) == nil {
		t.Fatalf("a mis-labelled privilege event escaped the factor; factors were %v", names(a))
	}
}

// An event the resolver could not interpret produces no privilege finding, even
// when its capability field says privilege. The validator already reports that
// state as indeterminate, and inventing a finding from an uninterpretable
// record is the fabricated evidence this package refuses.
//
// The event below carries a capability the catalog does not know, which is how
// sc.kind ends up empty in practice.
func TestAnUnknownCapabilityProducesNoFactor(t *testing.T) {
	a := score(t, ScoreRequest{
		Event: &event.Event{
			ID: "e-unknown", SessionID: "s-1",
			Capability: capability.Kind("priv.invented"),
			Privil:     setuidPayload(),
		},
		Validation: result(decision.VerdictOutsideEnvelope),
		Envelope:   envelope(),
		History:    history(),
	})
	if f := priv(a); f != nil {
		t.Errorf("an unknown capability produced %+v", *f)
	}
}

// --- 2. the arithmetic, pinned against the catalog -----------------------------------

// The weight is the catalog's own grade for the kind, read through the same
// table sensitive_path and sensitive_host read. Derived here from the catalog
// rather than restated, so a regrade in table.go moves the test with the code
// and a change to sensitivityPoints moves all three factors together.
func TestTheWeightIsTheCatalogGrade(t *testing.T) {
	for _, k := range capability.KindsInDomain(capability.DomainPrivilege) {
		desc, ok := capability.Describe(k)
		if !ok {
			t.Fatalf("catalog does not describe %s", k)
		}
		want := sensitivityPoints[desc.BaselineSeverity]

		f := priv(score(t, privDeparture(k, setuidPayload())))
		if f == nil {
			t.Fatalf("%s produced no factor", k)
		}
		if f.Weight != want {
			t.Errorf("%s weight = %v, want %v (catalog grade %s)", k, f.Weight, want, desc.BaselineSeverity)
		}
		if f.Evidence[EvidenceBaselineSeverity] != string(desc.BaselineSeverity) {
			t.Errorf("%s: baseline_severity evidence = %q, want %q",
				k, f.Evidence[EvidenceBaselineSeverity], desc.BaselineSeverity)
		}
	}
}

// The point of the factor, stated as a test: before it, every privilege
// departure scored the same number, because validator.severityFor takes the
// maximum of the violation-type floor and the catalog baseline and that maximum
// saturates at critical. A seccomp filter and a capability-set change are not
// the same event, and the score now says so.
func TestPrivilegeChangesAreDistinguishableFromEachOther(t *testing.T) {
	// The severities the validator would actually assign: critical for a
	// capability the catalog grades critical, high for priv.seccomp.
	capset := score(t, privDeparture(capability.KindPrivCapSet, setuidPayload()))
	seccomp := score(t, ScoreRequest{
		Event: privEvent(capability.KindPrivSeccomp, &event.PrivPayload{Operation: "seccomp"}),
		Validation: result(decision.VerdictOutsideEnvelope,
			viol(validator.ViolationUngrantedCapability, capability.SeverityHigh)),
		Envelope: envelope(),
		History:  history(),
	})

	if capset.Score <= seccomp.Score {
		t.Errorf("capset scored %v and seccomp %v; a capability-set change is graded above a "+
			"seccomp filter in the catalog and the score has to reflect it",
			capset.Score, seccomp.Score)
	}
	if priv(capset).Weight <= priv(seccomp).Weight {
		t.Error("the two factors carry the same weight, so the score cannot be telling them apart")
	}
}

// The invariant the whole model rests on: an event the envelope covered scores
// exactly zero. The finding is still reported -- a granted privilege change is
// the one an auditor most needs to see -- and not_charged says why the points
// were withheld.
func TestAGrantedPrivilegeChangeScoresZeroAndIsStillReported(t *testing.T) {
	a := score(t, ScoreRequest{
		Event:      privEvent(capability.KindPrivSetuid, setuidPayload()),
		Validation: result(decision.VerdictWithinEnvelope),
		Envelope:   envelope(),
		History:    history(),
	})

	if a.Score != 0 {
		t.Errorf("Score = %v, want 0; a covered event has to score exactly zero", a.Score)
	}
	if a.Level != decision.LevelNone {
		t.Errorf("Level = %s, want %s", a.Level, decision.LevelNone)
	}

	f := priv(a)
	if f == nil {
		t.Fatal("a granted privilege change produced no factor; the finding has to survive the withholding")
	}
	if f.Weight != 0 {
		t.Errorf("Weight = %v, want 0", f.Weight)
	}
	if f.Evidence[EvidenceNotCharged] == "" {
		t.Error("points were withheld with no not_charged reason in the record")
	}
	// The grade is reported whether or not it was charged, which is what makes
	// the withholding auditable rather than invisible.
	if f.Evidence[EvidenceBaselineSeverity] == "" {
		t.Error("the catalog grade was dropped along with the points")
	}
}

// --- 3. the payload, reported and never charged --------------------------------------

// Every field PrivPayload carries reaches the record verbatim. None of them is
// interpreted, and none of them moves the weight -- the weight came from the
// catalog before the payload was opened.
func TestThePayloadReachesTheRecordVerbatim(t *testing.T) {
	p := &event.PrivPayload{
		Operation:         "capset",
		OldUID:            1000,
		NewUID:            33,
		CapabilitiesAdded: []string{"CAP_SYS_ADMIN", "CAP_NET_RAW"},
		NamespaceType:     "user",
	}
	f := priv(score(t, privDeparture(capability.KindPrivCapSet, p)))
	if f == nil {
		t.Fatal("no factor")
	}

	for key, want := range map[string]string{
		EvidencePrivEvidence:      PrivEvidenceRecorded,
		EvidenceOperation:         "capset",
		EvidenceNamespaceType:     "user",
		EvidenceCapabilitiesAdded: "CAP_SYS_ADMIN CAP_NET_RAW",
		EvidenceCapabilityDelta:   CapabilityDeltaAddedOnly,
		EvidenceUIDTransition:     UIDTransitionChanged,
		EvidenceOldUID:            "1000",
		EvidenceNewUID:            "33",
	} {
		if got := f.Evidence[key]; got != want {
			t.Errorf("evidence[%q] = %q, want %q", key, got, want)
		}
	}
}

// A payload that reports capabilities always says what kind of capability
// evidence it is. The list is one-sided -- pkg/event carries CapabilitiesAdded
// and nothing for removals -- and a reader who took it for a delta would read a
// gain as the whole change.
func TestReportedCapabilitiesAreLabelledOneSided(t *testing.T) {
	with := priv(score(t, privDeparture(capability.KindPrivCapSet,
		&event.PrivPayload{Operation: "capset", CapabilitiesAdded: []string{"CAP_SYS_ADMIN"}})))
	if with.Evidence[EvidenceCapabilityDelta] != CapabilityDeltaAddedOnly {
		t.Errorf("capability_delta = %q, want %q",
			with.Evidence[EvidenceCapabilityDelta], CapabilityDeltaAddedOnly)
	}

	// An empty list says nothing at all, and must not be recorded as though it
	// said "nothing was added". A capset that only dropped capabilities
	// produces exactly this shape.
	without := priv(score(t, privDeparture(capability.KindPrivCapSet,
		&event.PrivPayload{Operation: "capset"})))
	if _, ok := without.Evidence[EvidenceCapabilitiesAdded]; ok {
		t.Error("an empty capability list was reported as a finding")
	}
	if _, ok := without.Evidence[EvidenceCapabilityDelta]; ok {
		t.Error("capability_delta was claimed with no capability evidence behind it")
	}
	// And the points are unchanged: an empty added-list is not evidence that
	// nothing changed.
	if with.Weight != without.Weight {
		t.Errorf("weights differ (%v vs %v); the payload must not move the score",
			with.Weight, without.Weight)
	}
}

// A no-op change is recorded as one and charged in full. The capability was
// still exercised, and the observation cannot prove the change was empty: a
// capset moves no UID at all, so an unchanged UID says nothing about it.
func TestANoOpChangeIsRecordedAndStillCharged(t *testing.T) {
	noop := priv(score(t, privDeparture(capability.KindPrivSetuid,
		&event.PrivPayload{Operation: "setuid", OldUID: 1000, NewUID: 1000})))
	if noop.Evidence[EvidenceUIDTransition] != UIDTransitionUnchanged {
		t.Errorf("uid_transition = %q, want %q", noop.Evidence[EvidenceUIDTransition], UIDTransitionUnchanged)
	}
	if noop.Weight != sensitivityPoints[capability.SeverityCritical] {
		t.Errorf("Weight = %v; a no-op transition must not discount the exercised capability", noop.Weight)
	}
}

// --- 4. the UID ambiguity, stated rather than resolved --------------------------------

// OldUID and NewUID are omitempty on a field whose zero value is root, so three
// of the four states below are statements that the record cannot settle what
// happened. The table is the whole claim: a transition to root and a record
// that never carried a UID are the same two integers, and the scorer says so
// instead of picking.
func TestTheUIDPairIsClassifiedWithoutGuessing(t *testing.T) {
	for _, tc := range []struct {
		name           string
		oldUID, newUID int32
		want           string
	}{
		{"both absent, or root to root", 0, 0, UIDTransitionUnrecorded},
		{"to root, or new_uid never recorded", 1000, 0, UIDTransitionAmbiguous},
		{"from root, or old_uid never recorded", 0, 1000, UIDTransitionAmbiguous},
		{"a real transition between two non-root ids", 1000, 33, UIDTransitionChanged},
		{"a real no-op between two non-root ids", 1000, 1000, UIDTransitionUnchanged},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := priv(score(t, privDeparture(capability.KindPrivSetuid, &event.PrivPayload{
				Operation: "setuid", OldUID: tc.oldUID, NewUID: tc.newUID,
			})))
			if got := f.Evidence[EvidenceUIDTransition]; got != tc.want {
				t.Errorf("uid_transition = %q, want %q", got, tc.want)
			}
			// The literals travel beside the classification in every state,
			// including the two-zero one, so a reader can check the reading
			// against the same integers rather than take it on trust.
			if _, ok := f.Evidence[EvidenceOldUID]; !ok {
				t.Error("old_uid literal missing from the record")
			}
			if _, ok := f.Evidence[EvidenceNewUID]; !ok {
				t.Error("new_uid literal missing from the record")
			}
		})
	}
}

// --- 5. absent and malformed evidence -------------------------------------------------

// A privilege event with no payload is charged in full and says so. The weight
// never came from the payload, so losing the payload loses evidence and not
// points -- and the three-state key keeps "no payload attached" apart from "a
// payload that said nothing".
func TestAnAbsentPayloadIsChargedAndNamed(t *testing.T) {
	f := priv(score(t, privDeparture(capability.KindPrivEscalate, nil)))
	if f == nil {
		t.Fatal("a privilege event with no payload produced no factor")
	}
	if f.Evidence[EvidencePrivEvidence] != PrivEvidenceAbsent {
		t.Errorf("privilege_evidence = %q, want %q", f.Evidence[EvidencePrivEvidence], PrivEvidenceAbsent)
	}
	if f.Weight != sensitivityPoints[capability.SeverityCritical] {
		t.Errorf("Weight = %v; an absent payload must not discount the event", f.Weight)
	}
	// Nothing is invented to fill the gap. A uid_transition on a payload that
	// does not exist would be a reading of two fields nobody wrote.
	if _, ok := f.Evidence[EvidenceUIDTransition]; ok {
		t.Error("a uid_transition was reported for an event with no payload")
	}
}

// A payload without the Operation its own schema marks required is malformed,
// named as such, and charged in full.
func TestAMalformedPayloadIsChargedAndNamed(t *testing.T) {
	f := priv(score(t, privDeparture(capability.KindPrivEscalate,
		&event.PrivPayload{OldUID: 1000, NewUID: 33})))
	if f.Evidence[EvidencePrivEvidence] != PrivEvidenceMalformed {
		t.Errorf("privilege_evidence = %q, want %q", f.Evidence[EvidencePrivEvidence], PrivEvidenceMalformed)
	}
	if f.Weight != sensitivityPoints[capability.SeverityCritical] {
		t.Errorf("Weight = %v; a malformed payload must not discount the event", f.Weight)
	}
	// The fields that did arrive are still reported. A partial record is worth
	// more than none to whoever has to work out what the decoder is doing.
	if f.Evidence[EvidenceUIDTransition] != UIDTransitionChanged {
		t.Error("readable fields were dropped along with the unreadable one")
	}
}

// The security property behind the choice above, tested rather than asserted in
// a comment: neither an absent nor a malformed payload can make the scorer
// error. A scorer error becomes a pipeline stage failure, which
// pipeline.IndeterminateHandler turns into request_approval while bypassing the
// policy engine -- so an unreadable payload would downgrade a terminal block to
// a prompt, making a corrupt record the cheapest route past the privilege rule.
func TestUnreadableEvidenceNeverErrors(t *testing.T) {
	for _, p := range []*event.PrivPayload{
		nil,
		{},
		{Operation: "   "},
		{Operation: "setuid", OldUID: 0, NewUID: 0},
	} {
		for _, k := range capability.KindsInDomain(capability.DomainPrivilege) {
			req := privDeparture(k, p)
			if _, err := (PrivilegeChangeScorer{}).Evaluate(context.Background(), req); err != nil {
				t.Errorf("%s with payload %+v: Evaluate returned %v; an unreadable payload must "+
					"never become a stage failure", k, p, err)
			}
			if _, err := NewEngine().Score(context.Background(), req); err != nil {
				t.Errorf("%s with payload %+v: Score returned %v", k, p, err)
			}
		}
	}
}

// --- 6. the reason the milestone was not deferred --------------------------------------

// The claim that justified building this: configs/rules.default.yaml blocks
// priv.escalate, priv.setuid and priv.capset, and does not name priv.namespace
// or priv.seccomp. For those two the risk score is the only thing standing
// between an ungranted privilege change and default_action, so the factor
// changes an action rather than only a record.
//
// The arithmetic is checked here; whether the rule set then fires is
// internal/policy's business and is tested there. 75 is high-risk-departure's
// min_risk_score, and the confidence floor it carries is 0.5.
func TestAnUngrantedNamespaceChangeReachesTheApprovalBand(t *testing.T) {
	a := score(t, privDeparture(capability.KindPrivNamespace,
		&event.PrivPayload{Operation: "unshare", NamespaceType: "user"}))

	const highRiskDepartureMin = 75.0
	if a.Score < highRiskDepartureMin {
		t.Errorf("Score = %v, want at least %v; below it an ungranted namespace change "+
			"falls through to medium-risk-departure and is warned rather than escalated",
			a.Score, highRiskDepartureMin)
	}
	const highRiskDepartureMinConfidence = 0.5
	if a.Confidence < highRiskDepartureMinConfidence {
		t.Errorf("Confidence = %v, want at least %v; high-risk-departure carries a confidence "+
			"floor and a score that cannot clear it changes nothing",
			a.Confidence, highRiskDepartureMinConfidence)
	}
}

// Confidence is permanently capped at 0.6 for the whole privilege domain, and
// that is a property of the domain rather than of this factor. The model's
// three evidence inputs include a resolved observation target, and a privilege
// observation has none by construction -- telemetry.resolve leaves Target empty
// because exercising the capability is the whole observation.
//
// Pinned so nobody later "fixes" it by writing a synthetic target. A target
// invented to raise confidence would be the fabricated evidence the package
// exists to avoid, and it would raise a number an operator reads as "how much
// backed this".
func TestPrivilegeEventsCannotReachFullConfidence(t *testing.T) {
	a := score(t, privDeparture(capability.KindPrivEscalate, setuidPayload()))

	basis := factor(a, FactorEvidenceBasis)
	if basis == nil {
		t.Fatal("no evidence basis factor")
	}
	if basis.Evidence[BasisTargetResolved] != "false" {
		t.Errorf("target_resolved = %q, want false; a privilege observation names no resource",
			basis.Evidence[BasisTargetResolved])
	}
	if a.Confidence != 0.6 {
		t.Errorf("Confidence = %v, want 0.6 (a conclusive verdict and a history, and no target)",
			a.Confidence)
	}
}

// --- 7. wiring -------------------------------------------------------------------------

// The factor is in every engine, oracle or not, because its evidence is a grade
// the catalog already carries rather than a list somebody has to author. An
// engine that scored privilege changes only when a sensitivity list happened to
// be configured would make the domain's coverage an accident of deployment.
func TestTheFactorIsInEveryEngine(t *testing.T) {
	oracled := engineWith(t, defaultOracle(t))

	for name, e := range map[string]*BaselineEngine{
		"NewEngine":           NewEngine(),
		"NewEngineWithOracle": oracled,
	} {
		var found bool
		for _, s := range e.Scorers() {
			if s.Name() == FactorPrivilegeChange {
				found = true
			}
		}
		if !found {
			t.Errorf("%s does not carry the %s scorer", name, FactorPrivilegeChange)
		}
	}

	// And it produces the same weight through both, since neither the oracle
	// nor its absence is an input to it.
	bare := priv(score(t, privDeparture(capability.KindPrivEscalate, setuidPayload())))
	withOracle := priv(scoreWith(t, oracled, privDeparture(capability.KindPrivEscalate, setuidPayload())))
	if bare.Weight != withOracle.Weight {
		t.Errorf("weight differs by engine: %v without an oracle, %v with one",
			bare.Weight, withOracle.Weight)
	}
}
