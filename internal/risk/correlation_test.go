package risk

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/stringNameMahin/ALLSEER/internal/validator"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// These tests are about one field of one observation, so most of the work is in
// building the three shapes telemetry can produce and asserting which of them
// the scorer speaks about.
//
// The shapes come from telemetry/resolve.observeNetwork rather than from
// imagination: it writes AttrHostnameCorrelated: "false" exactly when
// NetworkPayload.Hostname is empty, and leaves the key off otherwise. Anything
// else is an observation this build did not produce, which is the indeterminate
// case and is tested as such.

// --- fixtures ---------------------------------------------------------------------

// correlatedEvent is what resolve produces when DNS correlation succeeded: the
// target names the host, and no correlation attribute is written.
func correlatedEvent(kind capability.Kind, hostPort, addr string) *event.Event {
	e := observedEvent(kind, hostPort)
	e.Result = event.Result{Succeeded: true}
	e.Observation.Attributes = map[string]string{
		capability.AttrProtocol: "tcp",
		capability.AttrDestIP:   addr,
	}
	return e
}

// uncorrelatedEvent is what resolve produces when correlation failed: the target
// carries the address, and the attribute says so.
func uncorrelatedEvent(kind capability.Kind, addrPort string) *event.Event {
	e := observedEvent(kind, addrPort)
	e.Result = event.Result{Succeeded: true}
	e.Observation.Attributes = map[string]string{
		capability.AttrProtocol:           "tcp",
		capability.AttrDestIP:             bareHost(addrPort),
		capability.AttrHostnameCorrelated: "false",
	}
	return e
}

// bareObservationEvent carries a target and no attributes at all — an
// observation this build's resolver never emits for the network domain, and
// therefore the shape whose correlation cannot be established.
func bareObservationEvent(kind capability.Kind, target string) *event.Event {
	e := observedEvent(kind, target)
	e.Result = event.Result{Succeeded: true}
	return e
}

// netDeparture scores an ungranted network event, so the factor is charged
// rather than merely reported.
func netDeparture(e *event.Event) ScoreRequest {
	return ScoreRequest{
		Event: e,
		Validation: result(decision.VerdictOutsideEnvelope,
			viol(validator.ViolationUngrantedCapability, capability.SeverityHigh)),
		Envelope: envelope(),
		History:  history(),
	}
}

func corr(a *decision.RiskAssessment) *decision.Factor {
	return factor(a, FactorUncorrelatedDestination)
}

// --- 1. the three correlation states -------------------------------------------------

// A destination reached by a correlated hostname is not this factor's business,
// and the factor stays silent rather than reporting a reassuring negative. The
// name in the target is itself the evidence that correlation succeeded.
func TestACorrelatedDestinationProducesNoFactor(t *testing.T) {
	a := score(t, netDeparture(correlatedEvent(capability.KindNetConnect, "registry.npmjs.org:443", "104.16.24.35")))

	if f := corr(a); f != nil {
		t.Errorf("a correlated destination produced %+v", *f)
	}
	// And the rest of the model is untouched: the event still scores as the
	// departure it is.
	if a.Score == 0 {
		t.Error("a departure scored zero")
	}
}

// A hostname-only destination — no address attribute at all — is still
// correlated: the target names the host, which is the whole question.
func TestAHostnameOnlyDestinationProducesNoFactor(t *testing.T) {
	e := observedEvent(capability.KindNetConnect, "registry.npmjs.org:443")
	e.Result = event.Result{Succeeded: true}
	e.Observation.Attributes = map[string]string{capability.AttrProtocol: "tcp"}

	if f := corr(score(t, netDeparture(e))); f != nil {
		t.Errorf("a hostname-only destination produced %+v", *f)
	}
}

// The case the feature exists for: an address, and enrichment recording that no
// name was correlated to it.
func TestAnUncorrelatedDestinationFires(t *testing.T) {
	a := score(t, netDeparture(uncorrelatedEvent(capability.KindNetConnect, "203.0.113.10:8443")))

	f := corr(a)
	if f == nil {
		t.Fatalf("no %s factor; factors were %v", FactorUncorrelatedDestination, names(a))
	}
	if f.Weight != UncorrelatedDestinationPoints {
		t.Errorf("Weight = %v, want %v", f.Weight, UncorrelatedDestinationPoints)
	}
	if f.Description == "" {
		t.Error("the factor carries no description")
	}

	want := map[string]string{
		EvidenceCapability:  string(capability.KindNetConnect),
		EvidenceTarget:      "203.0.113.10:8443",
		EvidenceHost:        "203.0.113.10",
		EvidenceHostKind:    HostKindLabelAddress,
		EvidenceDestIP:      "203.0.113.10",
		EvidenceCorrelation: CorrelationLabelMissing,
	}
	for k, v := range want {
		if got := f.Evidence[k]; got != v {
			t.Errorf("evidence[%q] = %q, want %q", k, got, v)
		}
	}
	if _, ok := f.Evidence[EvidenceNotCharged]; ok {
		t.Error("a departing event reported not_charged")
	}
}

// Missing evidence is reported as missing, never converted into a finding. An
// observation that carries an address target and no correlation attribute is
// not one this build's resolver produces, so what it says about correlation is
// nothing at all.
func TestMissingCorrelationEvidenceIsIndeterminate(t *testing.T) {
	for _, c := range []struct {
		name  string
		event *event.Event
	}{
		{
			// An address target with no attribute. observeNetwork always writes
			// the flag beside an address, so this observation came from
			// somewhere else.
			name:  "an address with no correlation attribute",
			event: bareObservationEvent(capability.KindNetConnect, "203.0.113.10:8443"),
		},
		{
			// Contradictory: the flag says correlation failed and the target
			// carries a name.
			name: "a name carrying a correlation-failed flag",
			event: func() *event.Event {
				e := observedEvent(capability.KindNetConnect, "registry.npmjs.org:443")
				e.Observation.Attributes = map[string]string{capability.AttrHostnameCorrelated: "false"}
				return e
			}(),
		},
		{
			// A vocabulary this build does not write. "true" is not a value the
			// resolver produces, and guessing what it meant would be inventing
			// evidence.
			name: "an unrecognized attribute value",
			event: func() *event.Event {
				e := observedEvent(capability.KindNetConnect, "203.0.113.10:8443")
				e.Observation.Attributes = map[string]string{capability.AttrHostnameCorrelated: "true"}
				return e
			}(),
		},
		{
			// No destination to speak about at all — the shape the validator
			// reports as indeterminate.
			name:  "no resolved destination",
			event: bareObservationEvent(capability.KindNetConnect, ""),
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := corr(score(t, netDeparture(c.event)))
			if f == nil {
				t.Fatal("no factor; missing evidence must be reported, not omitted")
			}
			if got := f.Evidence[EvidenceCorrelation]; got != CorrelationLabelIndeterminate {
				t.Errorf("correlation = %q, want %q", got, CorrelationLabelIndeterminate)
			}
			if f.Weight != 0 {
				t.Errorf("Weight = %v; missing evidence must never be charged", f.Weight)
			}
		})
	}
}

// classifyCorrelation is total and its table is the specification, so it is
// asserted directly as well as through the scorer.
func TestClassifyCorrelationIsTotal(t *testing.T) {
	obs := func(kv ...string) capability.Observation {
		o := capability.Observation{}
		if len(kv) > 0 {
			o.Attributes = map[string]string{}
			for i := 0; i+1 < len(kv); i += 2 {
				o.Attributes[kv[i]] = kv[i+1]
			}
		}
		return o
	}

	for _, c := range []struct {
		name     string
		obs      capability.Observation
		hostKind string
		want     correlationState
	}{
		{"a name and no flag", obs(), HostKindLabelName, correlationPresent},
		{"an address and a false flag", obs(capability.AttrHostnameCorrelated, "false"), HostKindLabelAddress, correlationMissing},
		{"an address and no flag", obs(), HostKindLabelAddress, correlationIndeterminate},
		{"a name and a false flag", obs(capability.AttrHostnameCorrelated, "false"), HostKindLabelName, correlationIndeterminate},
		{"an unknown value", obs(capability.AttrHostnameCorrelated, "yes"), HostKindLabelAddress, correlationIndeterminate},
		{"an unclassifiable host", obs(), HostKindLabelUnknown, correlationIndeterminate},
		{"an unclassifiable host with a flag", obs(capability.AttrHostnameCorrelated, "false"), HostKindLabelUnknown, correlationIndeterminate},
	} {
		if got := classifyCorrelation(c.obs, c.hostKind); got != c.want {
			t.Errorf("%s: state = %v, want %v", c.name, got, c.want)
		}
	}
}

// --- 2. scope --------------------------------------------------------------------------

// Only capabilities whose observation names a remote destination the agent
// selected are evaluated. Every exclusion is a claim, so every one is asserted.
func TestOnlyDestinationNamingCapabilitiesAreEvaluated(t *testing.T) {
	for _, c := range []struct {
		kind capability.Kind
		want bool
		why  string
	}{
		{capability.KindNetConnect, true, "the agent chose this destination"},
		{capability.KindNetSend, true, "the agent chose this destination"},

		{capability.KindNetDNS, false, "the payload address is the resolver, not a destination"},
		{capability.KindNetReceive, false, "the return path of a connection already reported"},
		{capability.KindNetAccept, false, "an inbound peer the agent did not choose"},
		{capability.KindNetBind, false, "a local address"},
		{capability.KindNetListen, false, "a local address"},
		{capability.KindNetRawSock, false, "socket creation, not a destination"},

		{capability.KindFileRead, false, "not a network capability"},
		{capability.KindProcessExec, false, "not a network capability"},
		{capability.KindIPCUnixSock, false, "does not leave the host"},
	} {
		if got := namesRemoteDestination(c.kind); got != c.want {
			t.Errorf("namesRemoteDestination(%s) = %v, want %v (%s)", c.kind, got, c.want, c.why)
		}

		// And through the engine, on an observation that would otherwise fire.
		got := corr(score(t, netDeparture(uncorrelatedEvent(c.kind, "203.0.113.10:8443")))) != nil
		if got != c.want {
			t.Errorf("%s: factor produced = %v, want %v (%s)", c.kind, got, c.want, c.why)
		}
	}
}

// A DNS query is never an uncorrelated destination, whatever its payload
// carries. The address in a DNS observation is the resolver's, and scoring it
// would fire on ordinary name resolution.
func TestADNSQueryIsNeverAnUncorrelatedDestination(t *testing.T) {
	// The ordinary shape: the query names a host.
	named := observedEvent(capability.KindNetDNS, "registry.npmjs.org")
	if f := corr(score(t, netDeparture(named))); f != nil {
		t.Errorf("a named DNS query produced %+v", *f)
	}

	// And the shape that would fire if the exclusion were by observation rather
	// than by capability: a DNS event whose target is the resolver's address,
	// flagged uncorrelated.
	byAddr := uncorrelatedEvent(capability.KindNetDNS, "127.0.0.53")
	if f := corr(score(t, netDeparture(byAddr))); f != nil {
		t.Errorf("a DNS query to a resolver address produced %+v; the address is the resolver's", *f)
	}
}

// The qualifying set currently equals the egress set, and that is a coincidence
// of two different questions rather than one shared definition. Pinned so a
// change to either is deliberate.
func TestTheQualifyingSetMatchesEgressToday(t *testing.T) {
	for _, k := range capability.AllKinds() {
		if namesRemoteDestination(k) != IsEgress(k) {
			t.Errorf("%s: namesRemoteDestination = %v but IsEgress = %v — if that divergence is "+
				"intended, update this test and say why in both predicates",
				k, namesRemoteDestination(k), IsEgress(k))
		}
	}
}

// --- 3. the invariants -------------------------------------------------------------------

// An event the envelope covered scores exactly zero, and the finding is still
// reported. A grant naming a destination by address is meant to be reached by
// address, and an auditor should see that the grant matched with no name behind
// it.
func TestACoveredUncorrelatedDestinationKeepsItsZero(t *testing.T) {
	req := netDeparture(uncorrelatedEvent(capability.KindNetConnect, "203.0.113.10:8443"))
	req.Validation = result(decision.VerdictWithinEnvelope)

	a := score(t, req)
	if a.Score != 0 || a.Level != decision.LevelNone {
		t.Errorf("a covered event scored %v (%q); the zero invariant is load-bearing", a.Score, a.Level)
	}

	f := corr(a)
	if f == nil {
		t.Fatal("the finding went unreported on a covered event")
	}
	if f.Weight != 0 {
		t.Errorf("Weight = %v on a covered event", f.Weight)
	}
	if f.Evidence[EvidenceNotCharged] == "" {
		t.Error("points were withheld without the record saying why")
	}
	if f.Evidence[EvidenceCorrelation] != CorrelationLabelMissing {
		t.Error("the withheld finding lost its correlation state")
	}
}

// The factor reads no history and no configuration, so it answers the same way
// whatever the session has done and whatever list is loaded.
func TestCorrelationReadsNeitherHistoryNorConfiguration(t *testing.T) {
	e := uncorrelatedEvent(capability.KindNetConnect, "203.0.113.10:8443")

	fresh := netDeparture(e)
	seen := netDeparture(e)
	seen.History = history().
		withSeen(capability.KindNetConnect, "203.0.113.10:8443").
		withViolations(40)
	none := netDeparture(e)
	none.History = nil

	weight := func(req ScoreRequest) float64 {
		f := corr(score(t, req))
		if f == nil {
			t.Fatal("no factor")
		}
		return f.Weight
	}

	if a, b, c := weight(fresh), weight(seen), weight(none); a != b || b != c {
		t.Errorf("the factor moved with history: fresh %v, seen %v, absent %v", a, b, c)
	}

	// Nor with an oracle behind the engine, which is the configuration the two
	// sensitivity factors read and this one does not.
	rated := corr(scoreWith(t, engineWith(t, defaultOracle(t)), netDeparture(e)))
	if rated == nil || rated.Weight != UncorrelatedDestinationPoints {
		t.Errorf("the factor changed when an oracle was supplied: %+v", rated)
	}
}

// --- 4. independence from the neighbouring factors ----------------------------------------

// Novelty and correlation are different questions and must both survive on one
// event. Neither may suppress or replace the other.
func TestNoveltyAndCorrelationAreIndependent(t *testing.T) {
	e := uncorrelatedEvent(capability.KindNetConnect, "203.0.113.10:8443")

	novelAndUncorrelated := netDeparture(e) // history() has seen nothing
	seenAndUncorrelated := netDeparture(e)
	seenAndUncorrelated.History = history().withSeen(capability.KindNetConnect, "203.0.113.10:8443")

	both := score(t, novelAndUncorrelated)
	if factor(both, FactorNovelTarget) == nil {
		t.Error("novel_target was suppressed by the correlation factor")
	}
	if corr(both) == nil {
		t.Error("the correlation factor was suppressed by novel_target")
	}

	onlyCorrelation := score(t, seenAndUncorrelated)
	if factor(onlyCorrelation, FactorNovelTarget) != nil {
		t.Error("novel_target fired for a target already seen")
	}
	if corr(onlyCorrelation) == nil {
		t.Error("the correlation factor disappeared when the target became familiar")
	}

	// The two contribute separately and additively, which is what "independent"
	// has to mean numerically.
	if got := both.Score - onlyCorrelation.Score; got != NovelTargetPoints {
		t.Errorf("novelty contributed %v alongside the correlation factor, want %v", got, NovelTargetPoints)
	}

	// And a *correlated* novel destination still gets novelty and no
	// correlation factor, which is the other diagonal of the same claim.
	named := score(t, netDeparture(correlatedEvent(capability.KindNetConnect, "registry.npmjs.org:443", "104.16.24.35")))
	if factor(named, FactorNovelTarget) == nil {
		t.Error("a novel correlated destination lost its novelty factor")
	}
	if corr(named) != nil {
		t.Error("a correlated destination produced a correlation factor")
	}
}

// Sensitivity and correlation are also different questions: one reads a list,
// the other reads telemetry. Both must be independently represented.
func TestSensitivityAndCorrelationAreIndependent(t *testing.T) {
	e := engineWith(t, defaultOracle(t))

	// 169.254.169.254 is rated critical by the shipped list *and* is reached by
	// address with no name, so both factors have something to say.
	both := scoreWith(t, e, netDeparture(uncorrelatedEvent(capability.KindNetConnect, "169.254.169.254:80")))

	hf := factor(both, FactorSensitiveHost)
	cf := corr(both)
	if hf == nil {
		t.Fatal("sensitive_host was suppressed")
	}
	if cf == nil {
		t.Fatal("uncorrelated_destination was suppressed")
	}
	if hf.Evidence[EvidenceSensitivity] != string(capability.SeverityCritical) {
		t.Errorf("sensitive_host reported %q, want critical", hf.Evidence[EvidenceSensitivity])
	}
	if cf.Weight != UncorrelatedDestinationPoints {
		t.Errorf("uncorrelated_destination contributed %v", cf.Weight)
	}

	// An unlisted address gets the correlation factor and an explicit unknown
	// from the list — the two answering separately about one destination.
	unlisted := scoreWith(t, e, netDeparture(uncorrelatedEvent(capability.KindNetConnect, "203.0.113.10:8443")))
	if got := factor(unlisted, FactorSensitiveHost).Evidence[EvidenceSensitivity]; got != SensitivityUnknownLabel {
		t.Errorf("sensitive_host reported %q for an unlisted address, want unknown", got)
	}
	if corr(unlisted) == nil {
		t.Error("the correlation factor disappeared for an unlisted destination")
	}

	// The difference between the two events is exactly the sensitivity grade,
	// so the correlation factor charged the same amount either way.
	if got := both.Score - unlisted.Score; got != sensitivityPoints[capability.SeverityCritical] {
		t.Errorf("the two destinations differ by %v, want the grade's %v",
			got, sensitivityPoints[capability.SeverityCritical])
	}
}

// The sequence detector and the correlation factor both speak on an egress
// event, and each charges its own amount once.
func TestSequenceAndCorrelationDoNotDoubleCount(t *testing.T) {
	e := engineWith(t, defaultOracle(t))

	withAccess := netDeparture(uncorrelatedEvent(capability.KindNetConnect, "203.0.113.10:8443"))
	withAccess.History = history().withRecent(readAt("a-1", credentialPath, true))

	withoutAccess := netDeparture(uncorrelatedEvent(capability.KindNetConnect, "203.0.113.10:8443"))

	a, b := scoreWith(t, e, withAccess), scoreWith(t, e, withoutAccess)

	if seq(a) == nil {
		t.Fatal("the sequence factor did not fire")
	}
	if corr(a) == nil || corr(b) == nil {
		t.Fatal("the correlation factor did not fire")
	}
	if corr(a).Weight != corr(b).Weight {
		t.Errorf("the correlation factor charged %v with a sequence and %v without",
			corr(a).Weight, corr(b).Weight)
	}
	if got := a.Score - b.Score; got != SequencePoints {
		t.Errorf("the sequence contributed %v alongside the correlation factor, want %v", got, SequencePoints)
	}

	// Each factor appears exactly once, which is what "no double counting"
	// means structurally rather than arithmetically.
	counts := map[string]int{}
	for _, f := range a.Factors {
		counts[f.Name]++
	}
	for name, n := range counts {
		if n != 1 {
			t.Errorf("factor %q appears %d times", name, n)
		}
	}
}

// Path sensitivity is untouched by this feature: a filesystem event produces no
// correlation factor and the path factor is unchanged.
func TestPathSensitivityIsUnchanged(t *testing.T) {
	a := scoreWith(t, engineWith(t, defaultOracle(t)), departure(capability.KindFileRead, "/home/dev/.ssh/id_rsa"))

	if corr(a) != nil {
		t.Error("a filesystem event produced a correlation factor")
	}
	f := factor(a, FactorSensitivePath)
	if f == nil {
		t.Fatal("sensitive_path disappeared")
	}
	if f.Weight != sensitivityPoints[capability.SeverityCritical] {
		t.Errorf("sensitive_path contributed %v, want %v", f.Weight, sensitivityPoints[capability.SeverityCritical])
	}
}

// --- 5. determinism and admission -----------------------------------------------------------

func TestCorrelationScoringIsDeterministic(t *testing.T) {
	e := engineWith(t, defaultOracle(t))
	req := netDeparture(uncorrelatedEvent(capability.KindNetConnect, "169.254.169.254:80"))

	first := scoreWith(t, e, req)
	for i := 0; i < 50; i++ {
		if got := scoreWith(t, e, req); !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d diverged\n got %+v\nwant %+v", i, got, first)
		}
	}
}

func TestCorrelationScorerMetadata(t *testing.T) {
	s := UncorrelatedDestinationScorer{}
	if s.Name() != FactorUncorrelatedDestination {
		t.Errorf("Name = %q", s.Name())
	}
	if s.Weight() != UncorrelatedDestinationPoints {
		t.Errorf("Weight = %v", s.Weight())
	}
	// The point value is the model's existing floor rather than a new number,
	// which is the whole justification for it. If NovelTargetPoints moves, this
	// should be reconsidered rather than silently follow.
	if UncorrelatedDestinationPoints != NovelTargetPoints {
		t.Errorf("the point value drifted from the model's smallest existing contribution")
	}

	if _, err := s.Evaluate(context.Background(), ScoreRequest{
		Event: uncorrelatedEvent(capability.KindNetConnect, "203.0.113.10:8443"),
	}); !errors.Is(err, ErrNoValidation) {
		t.Errorf("Evaluate returned %v on an unvalidated request, want ErrNoValidation", err)
	}
}

// The scorer needs no oracle, so it is in every engine — including the one a
// caller gets by default.
func TestEveryEngineCarriesTheCorrelationScorer(t *testing.T) {
	has := func(e *BaselineEngine) bool {
		for _, s := range e.Scorers() {
			if s.Name() == FactorUncorrelatedDestination {
				return true
			}
		}
		return false
	}
	if !has(NewEngine()) {
		t.Error("the unrated engine does not carry the correlation scorer; its evidence is telemetry, not configuration")
	}
	if !has(engineWith(t, defaultOracle(t))) {
		t.Error("the oracle-backed engine does not carry the correlation scorer")
	}
}

// --- 6. benchmarks -----------------------------------------------------------------------------

// The common case: a filesystem event, which the scorer exits on after one
// capability comparison and never allocates for.
func BenchmarkScoreCorrelationNonNetwork(b *testing.B) {
	benchmarkCorrelation(b, ScoreRequest{
		Event:      fileEvent(capability.KindFileWrite, ws+"/a.go"),
		Validation: result(decision.VerdictWithinEnvelope),
		Envelope:   envelope(),
		History:    history(),
	})
}

// A correlated destination: the scorer classifies the host and exits without
// building a factor.
func BenchmarkScoreCorrelationCorrelated(b *testing.B) {
	benchmarkCorrelation(b, netDeparture(
		correlatedEvent(capability.KindNetConnect, "registry.npmjs.org:443", "104.16.24.35")))
}

// The firing case, which is the only one that allocates an evidence map.
func BenchmarkScoreCorrelationUncorrelated(b *testing.B) {
	benchmarkCorrelation(b, netDeparture(uncorrelatedEvent(capability.KindNetConnect, "203.0.113.10:8443")))
}

func benchmarkCorrelation(b *testing.B, req ScoreRequest) {
	b.Helper()

	e := NewEngine()
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := e.Score(ctx, req); err != nil {
			b.Fatal(err)
		}
	}
}
