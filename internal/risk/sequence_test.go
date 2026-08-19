package risk

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"testing"

	"github.com/stringNameMahin/ALLSEER/internal/validator"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// These tests are about a *relationship*, so most of them are shaped the same
// way: build a history, score one egress event against it, and assert on the
// factor rather than only on the number. A sequence detector that produced the
// right score from the wrong pair would pass every score assertion and be
// useless, which is why the evidence is asserted at least as hard as the total.
//
// The shipped sensitivity list is used throughout rather than a fixture list.
// What counts as credential access is defined in terms of that file's grades,
// so a test against a private list would be a test of the test.

// --- fixtures ---------------------------------------------------------------------

// credentialPath is graded critical by the shipped list, and awsReason is why.
const (
	credentialPath = "/home/dev/.aws/credentials"
	npmrcPath      = "/home/dev/.npmrc"      // high
	passwdPath     = "/etc/passwd"           // medium: identity, not credential
	hostsPath      = "/etc/hosts"            // low
	headerPath     = "/usr/include/stdio.h"  // info: rated, and unremarkable
	unlistedPath   = "/home/dev/app/main.go" // unknown: on no list at all
)

const egressTarget = "198.51.100.77:8443"

// readAt builds a recorded filesystem read, which is the only shape that can be
// the first half of the sequence.
func readAt(id, path string, succeeded bool) event.Event {
	e := fileEvent(capability.KindFileRead, path)
	e.ID = id
	e.Result = event.Result{ReturnCode: 3, Succeeded: succeeded}
	if !succeeded {
		e.Result = event.Result{ReturnCode: -2, Errno: "ENOENT", Succeeded: false}
	}
	return *e
}

// writeAt is the same resource touched by a capability that discloses nothing.
func writeAt(id, path string) event.Event {
	e := fileEvent(capability.KindFileWrite, path)
	e.ID = id
	e.Result = event.Result{Succeeded: true}
	return *e
}

// netAt builds a network event with a resolved observation, so a capability
// with no filesystem payload can be scored without inventing one.
func netAt(id string, kind capability.Kind, target string) *event.Event {
	e := observedEvent(kind, target)
	e.ID = id
	e.Result = event.Result{Succeeded: true}
	return e
}

func netRecord(id string, kind capability.Kind, target string) event.Event {
	return *netAt(id, kind, target)
}

// seqEngine is the engine a caller gets with the shipped list behind it, which
// is the composition that carries the sequence detector.
func seqEngine(t *testing.T) *BaselineEngine {
	t.Helper()
	return engineWith(t, defaultOracle(t))
}

func seqScorer(t *testing.T, window int) CredentialEgressScorer {
	t.Helper()
	s, err := NewCredentialEgressScorerWith(defaultOracle(t), window)
	if err != nil {
		t.Fatalf("NewCredentialEgressScorerWith(%d): %v", window, err)
	}
	return s
}

// egressReq is a departing egress event: the shape that gets the sequence
// charged rather than merely reported.
func egressReq(id string, kind capability.Kind, target string, h History) ScoreRequest {
	return ScoreRequest{
		Event: netAt(id, kind, target),
		Validation: result(decision.VerdictOutsideEnvelope,
			viol(validator.ViolationUngrantedCapability, capability.SeverityHigh)),
		Envelope: envelope(),
		History:  h,
	}
}

// seq returns the sequence factor, or nil when none was reported.
func seq(a *decision.RiskAssessment) *decision.Factor {
	return factor(a, FactorCredentialEgress)
}

// --- 1. the sequence the detector exists for ----------------------------------------

// A successful read of credential material followed by an outbound connection.
// The factor has to name both ends, the window it searched, and the distance
// between them — a score with no decomposition cannot be defended, and a
// sequence with no attribution cannot be checked.
func TestSensitiveAccessThenEgressIsASequence(t *testing.T) {
	h := history().withRecent(
		readAt("a-1", unlistedPath, true),
		readAt("a-2", credentialPath, true),
		readAt("a-3", unlistedPath, true),
	)

	a := scoreWith(t, seqEngine(t), egressReq("e-egress", capability.KindNetConnect, egressTarget, h))

	f := seq(a)
	if f == nil {
		t.Fatalf("no %s factor; factors were %v", FactorCredentialEgress, names(a))
	}
	if f.Weight != SequencePoints {
		t.Errorf("Weight = %v, want %v", f.Weight, SequencePoints)
	}
	if f.Description == "" {
		t.Error("the factor carries no description")
	}

	want := map[string]string{
		EvidenceAccessEventID:     "a-2",
		EvidenceAccessTarget:      credentialPath,
		EvidenceAccessCapability:  string(capability.KindFileRead),
		EvidenceAccessSensitivity: string(capability.SeverityCritical),
		EvidenceAccessSucceeded:   "true",
		EvidenceEgressCapability:  string(capability.KindNetConnect),
		EvidenceEgressTarget:      egressTarget,
		EvidenceWindowEvents:      strconv.Itoa(DefaultSequenceWindow),
		EvidenceDistanceEvents:    "2",
	}
	for k, v := range want {
		if got := f.Evidence[k]; got != v {
			t.Errorf("evidence[%q] = %q, want %q", k, got, v)
		}
	}

	// The list author's sentence travels into the record, so "why did this
	// score go up" is answered by a human's words rather than by a glob.
	if f.Evidence[EvidenceAccessReason] == "" {
		t.Error("the sensitivity list's reason did not reach the record")
	}
	// Only three events were retained and the window is 256, so nothing was cut
	// off and the record must not imply it was.
	if _, ok := f.Evidence[EvidenceWindowTruncated]; ok {
		t.Errorf("evidence claims the window was truncated over %d retained events", 3)
	}
	if _, ok := f.Evidence[EvidenceNotCharged]; ok {
		t.Error("a departing egress reported not_charged")
	}
}

// The other half of the same claim: the score moves by exactly the sequence's
// contribution and nothing else moves with it. A factor that quietly perturbed
// its neighbours would be indistinguishable from one that was simply worth more.
func TestSequenceStacksWithoutDisturbingTheOtherFactors(t *testing.T) {
	e := seqEngine(t)

	without := scoreWith(t, e, egressReq("e-1", capability.KindNetConnect, egressTarget,
		history().withRecent(readAt("a-1", unlistedPath, true))))
	with := scoreWith(t, e, egressReq("e-1", capability.KindNetConnect, egressTarget,
		history().withRecent(readAt("a-1", credentialPath, true))))

	if seq(without) != nil {
		t.Fatal("the control run reported a sequence")
	}
	if with.Score-without.Score != SequencePoints {
		t.Errorf("score moved by %v, want exactly %v", with.Score-without.Score, SequencePoints)
	}

	for _, name := range names(without) {
		a, b := factor(without, name), factor(with, name)
		if b == nil {
			t.Errorf("factor %q disappeared when the sequence fired", name)
			continue
		}
		if a.Weight != b.Weight {
			t.Errorf("factor %q moved from %v to %v; the sequence factor must only add its own",
				name, a.Weight, b.Weight)
		}
	}

	// Confidence is a count of available inputs, and the detector consumed no
	// input the basis did not already name.
	if with.Confidence != without.Confidence {
		t.Errorf("confidence moved from %v to %v", without.Confidence, with.Confidence)
	}
}

// --- 2. the negatives, one per rule ---------------------------------------------------

// Credential access with nothing after it is not a sequence. The detector runs
// on the egress event, so an access on its own has nothing to attach to — and,
// just as importantly, an access followed by an ordinary file operation must
// not manufacture one.
func TestSensitiveAccessWithNoEgressIsNotASequence(t *testing.T) {
	e := seqEngine(t)
	h := history().withRecent(readAt("a-1", credentialPath, true))

	for _, kind := range []capability.Kind{
		capability.KindFileRead, capability.KindFileWrite, capability.KindProcessExec,
	} {
		req := ScoreRequest{
			Event:      fileEvent(capability.KindFileRead, unlistedPath),
			Validation: result(decision.VerdictOutsideEnvelope, viol(validator.ViolationUngrantedCapability, capability.SeverityMedium)),
			Envelope:   envelope(),
			History:    h,
		}
		if kind != capability.KindFileRead {
			req.Event = observedEvent(kind, unlistedPath)
		}
		if f := seq(scoreWith(t, e, req)); f != nil {
			t.Errorf("%s produced a sequence factor: %+v", kind, *f)
		}
	}
}

// Egress with nothing behind it is not a sequence, whether history is empty,
// absent, or full of ordinary work.
func TestEgressWithNoPriorAccessIsNotASequence(t *testing.T) {
	e := seqEngine(t)

	for _, c := range []struct {
		name string
		h    History
	}{
		{"no history at all", nil},
		{"an empty history", history()},
		{"ordinary work only", history().withRecent(
			readAt("a-1", unlistedPath, true),
			writeAt("a-2", unlistedPath),
			netRecord("a-3", capability.KindNetDNS, "registry.npmjs.org"),
		)},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := scoreWith(t, e, egressReq("e-1", capability.KindNetConnect, egressTarget, c.h))
			if f := seq(a); f != nil {
				t.Errorf("reported a sequence with no qualifying access: %+v", *f)
			}
		})
	}
}

// Two events that merely happened are not a sequence. This is the failure mode
// the whole design is arranged against: a detector that added points because a
// file was read and a socket was opened would fire on every build.
func TestTwoUnrelatedEventsAreNotASequence(t *testing.T) {
	a := scoreWith(t, seqEngine(t), egressReq("e-1", capability.KindNetConnect, "registry.npmjs.org:443",
		history().withRecent(readAt("a-1", headerPath, true))))

	if f := seq(a); f != nil {
		t.Errorf("a system header read and a registry connection were paired: %+v", *f)
	}
}

// A read that failed disclosed nothing, so there is nothing that could
// subsequently leave. The corpus already carries this exact case — gt-009, an
// ENOENT on ~/.ssh/id_rsa — and counting it would build a sequence on an event
// that transferred no bytes.
func TestAFailedAccessDoesNotQualify(t *testing.T) {
	a := scoreWith(t, seqEngine(t), egressReq("e-1", capability.KindNetConnect, egressTarget,
		history().withRecent(readAt("a-1", credentialPath, false))))

	if f := seq(a); f != nil {
		t.Errorf("a failed read qualified as credential access: %+v", *f)
	}
}

// Only reading discloses. Writing to a credential path is tampering or
// persistence — a real concern and a different one, belonging to a scorer that
// does not exist.
func TestOnlyAReadQualifiesAsAccess(t *testing.T) {
	e := seqEngine(t)
	for _, kind := range []capability.Kind{
		capability.KindFileWrite, capability.KindFileCreate, capability.KindFileDelete,
		capability.KindFileChmod, capability.KindFileLink, capability.KindFileRename,
	} {
		prev := fileEvent(kind, credentialPath)
		prev.ID = "a-1"
		prev.Result = event.Result{Succeeded: true}

		a := scoreWith(t, e, egressReq("e-1", capability.KindNetConnect, egressTarget,
			history().withRecent(*prev)))
		if f := seq(a); f != nil {
			t.Errorf("%s on a credential path qualified as access: %+v", kind, *f)
		}
	}
}

// Only egress can be the second half, and "egress" is the set the shipped rule
// set already names. A DNS lookup, an inbound capability, or a local socket
// must not start the search.
func TestOnlyEgressCapabilitiesAreEvaluated(t *testing.T) {
	e := seqEngine(t)
	h := history().withRecent(readAt("a-1", credentialPath, true))

	for _, c := range []struct {
		kind capability.Kind
		want bool
	}{
		{capability.KindNetConnect, true},
		{capability.KindNetSend, true},
		{capability.KindNetDNS, false},
		{capability.KindNetReceive, false},
		{capability.KindNetBind, false},
		{capability.KindNetListen, false},
		{capability.KindNetAccept, false},
		{capability.KindNetRawSock, false},
		{capability.KindIPCUnixSock, false},
	} {
		if got := IsEgress(c.kind); got != c.want {
			t.Errorf("IsEgress(%s) = %v, want %v", c.kind, got, c.want)
		}
		got := seq(scoreWith(t, e, egressReq("e-1", c.kind, egressTarget, h))) != nil
		if got != c.want {
			t.Errorf("%s: sequence reported = %v, want %v", c.kind, got, c.want)
		}
	}
}

// --- 3. the grade boundary ------------------------------------------------------------

// A path on no list is unknown, and unknown is not credential access. This is
// the load-bearing case: if it were, every unlisted read would be the first
// half of a sequence and the detector would fire on almost every session.
func TestUnknownSensitivityIsNotCredentialAccess(t *testing.T) {
	if AccessSensitivityQualifies(SensitivityUnknown) {
		t.Error("SensitivityUnknown qualifies as credential access")
	}

	a := scoreWith(t, seqEngine(t), egressReq("e-1", capability.KindNetConnect, egressTarget,
		history().withRecent(readAt("a-1", unlistedPath, true))))
	if f := seq(a); f != nil {
		t.Errorf("an unrated path qualified as credential access: %+v", *f)
	}

	// And the same read through an engine whose oracle rates nothing.
	silent := engineWith(t, oracleFrom(t, "  - patterns: [/nothing/here]\n    sensitivity: critical\n    reason: t\n"))
	if f := seq(scoreWith(t, silent, egressReq("e-1", capability.KindNetConnect, egressTarget,
		history().withRecent(readAt("a-1", credentialPath, true))))); f != nil {
		t.Errorf("a list that does not cover the path still produced a sequence: %+v", *f)
	}
}

// An `info` rating means "we looked, and this is ordinary". It must not become
// credential access by accident, and neither must `low` or `medium` — the
// shipped list describes medium as identity and history routinely read by
// ordinary tooling, which is exactly the traffic a detector must not fire on.
func TestGradesBelowHighAreNotCredentialAccess(t *testing.T) {
	e := seqEngine(t)

	for _, c := range []struct {
		path  string
		grade capability.Severity
		want  bool
	}{
		{headerPath, capability.SeverityInfo, false},
		{hostsPath, capability.SeverityLow, false},
		{passwdPath, capability.SeverityMedium, false},
		{npmrcPath, capability.SeverityHigh, true},
		{credentialPath, capability.SeverityCritical, true},
	} {
		// The grade the test asserts against is the grade the shipped list
		// actually assigns, checked here rather than assumed, so a list edit
		// fails this test instead of silently changing what it means.
		if got := defaultOracle(t).PathSensitivity(c.path); got != c.grade {
			t.Fatalf("%s is graded %q by the shipped list, the test assumes %q", c.path, got, c.grade)
		}
		if got := AccessSensitivityQualifies(c.grade); got != c.want {
			t.Errorf("AccessSensitivityQualifies(%s) = %v, want %v", c.grade, got, c.want)
		}

		got := seq(scoreWith(t, e, egressReq("e-1", capability.KindNetConnect, egressTarget,
			history().withRecent(readAt("a-1", c.path, true))))) != nil
		if got != c.want {
			t.Errorf("%s (%s): sequence reported = %v, want %v", c.path, c.grade, got, c.want)
		}
	}
}

// --- 4. the window --------------------------------------------------------------------

// The window is a count of recorded events, and it bounds the claim. An access
// further back than the window is not reported, because the detector's finding
// is about proximity and a window that covered the whole session would make it
// a finding about co-occurrence.
func TestAccessOutsideTheWindowIsNotASequence(t *testing.T) {
	s := seqScorer(t, 3)

	// The access sits five events back, the window reaches three.
	h := history().withRecent(
		readAt("a-1", credentialPath, true),
		readAt("a-2", unlistedPath, true),
		readAt("a-3", unlistedPath, true),
		readAt("a-4", unlistedPath, true),
		readAt("a-5", unlistedPath, true),
	)

	f, err := s.Evaluate(context.Background(), egressReq("e-1", capability.KindNetConnect, egressTarget, h))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if f != nil {
		t.Errorf("an access %d events back was reported through a %d-event window: %+v", 5, s.Window(), *f)
	}
}

// The same history with the access inside the window, so the boundary is
// pinned from both sides rather than only from the safe one.
func TestAccessInsideTheWindowIsASequence(t *testing.T) {
	s := seqScorer(t, 3)

	h := history().withRecent(
		readAt("a-1", unlistedPath, true),
		readAt("a-2", unlistedPath, true),
		readAt("a-3", credentialPath, true), // three back, the last position the window reaches
		readAt("a-4", unlistedPath, true),
		readAt("a-5", unlistedPath, true),
	)

	f, err := s.Evaluate(context.Background(), egressReq("e-1", capability.KindNetConnect, egressTarget, h))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if f == nil {
		t.Fatalf("an access %d events back was missed by a %d-event window", 3, s.Window())
	}
	if got := f.Evidence[EvidenceAccessEventID]; got != "a-3" {
		t.Errorf("attributed to %q, want a-3", got)
	}
	if got := f.Evidence[EvidenceDistanceEvents]; got != "3" {
		t.Errorf("distance_events = %q, want 3", got)
	}
	if got := f.Evidence[EvidenceWindowEvents]; got != "3" {
		t.Errorf("window_events = %q, want the configured 3", got)
	}
	// History returned a full window, so an older access may exist that was
	// never searched. The finding stands; the record says what it did not see.
	if f.Evidence[EvidenceWindowTruncated] != "true" {
		t.Error("a full window was not reported as truncated")
	}
}

// Retention is not the window, and the detector must not silently inherit it.
// A history that retains less than the window under-reports, which is the safe
// direction, and the record must not claim the search reached further than it did.
func TestHistorySaturationUnderReportsAndSaysSo(t *testing.T) {
	s := seqScorer(t, 64)

	// A session whose ring holds only the last two events: the access has
	// already been evicted, exactly as a saturated MemoryState would present it.
	evicted := history().withRecent(
		readAt("a-4", unlistedPath, true),
		readAt("a-5", unlistedPath, true),
	)
	f, err := s.Evaluate(context.Background(), egressReq("e-1", capability.KindNetSend, egressTarget, evicted))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if f != nil {
		t.Errorf("an evicted access was reported from a history that no longer holds it: %+v", *f)
	}

	// And a retained one is found, with the truncation flag absent because the
	// window was not filled.
	kept := history().withRecent(
		readAt("a-4", credentialPath, true),
		readAt("a-5", unlistedPath, true),
	)
	f, err = s.Evaluate(context.Background(), egressReq("e-1", capability.KindNetSend, egressTarget, kept))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if f == nil {
		t.Fatal("a retained access was missed")
	}
	if _, ok := f.Evidence[EvidenceWindowTruncated]; ok {
		t.Error("a partially filled window was reported as truncated")
	}
}

// --- 5. attribution -------------------------------------------------------------------

// Several qualifying accesses, one egress. The nearest is attributed: it is the
// pairing whose temporal relationship is strongest, it is what an operator
// asking "which read" expects, and it is what lets the backwards scan stop
// early. Asserted as an exact evidence map so a change of policy here is
// deliberate.
func TestNearestQualifyingAccessIsAttributed(t *testing.T) {
	h := history().withRecent(
		readAt("a-1", credentialPath, true),  // qualifying, but further back
		readAt("a-2", passwdPath, true),      // medium: does not qualify
		readAt("a-3", npmrcPath, true),       // qualifying, and nearest
		readAt("a-4", credentialPath, false), // critical but failed
		readAt("a-5", unlistedPath, true),
	)

	f := seq(scoreWith(t, seqEngine(t), egressReq("e-1", capability.KindNetConnect, egressTarget, h)))
	if f == nil {
		t.Fatal("no sequence reported")
	}
	if got := f.Evidence[EvidenceAccessEventID]; got != "a-3" {
		t.Errorf("attributed to %q, want a-3, the nearest qualifying access", got)
	}
	if got := f.Evidence[EvidenceAccessSensitivity]; got != string(capability.SeverityHigh) {
		t.Errorf("access_sensitivity = %q, want %q", got, capability.SeverityHigh)
	}
	if got := f.Evidence[EvidenceDistanceEvents]; got != "3" {
		t.Errorf("distance_events = %q, want 3", got)
	}
}

// Several egress events, one access. Each is evaluated on its own and each
// reports the same antecedent with a growing distance, because the antecedent
// is a fact about the session rather than a token that gets consumed.
func TestEveryEgressEventIsEvaluatedIndependently(t *testing.T) {
	e := seqEngine(t)
	base := []event.Event{readAt("a-1", credentialPath, true)}

	for i, c := range []struct {
		kind         capability.Kind
		trailing     []event.Event
		wantDistance string
	}{
		{capability.KindNetConnect, nil, "1"},
		{capability.KindNetSend, []event.Event{netRecord("n-1", capability.KindNetConnect, egressTarget)}, "2"},
		{capability.KindNetSend, []event.Event{
			netRecord("n-1", capability.KindNetConnect, egressTarget),
			netRecord("n-2", capability.KindNetSend, egressTarget),
		}, "3"},
	} {
		h := history().withRecent(append(append([]event.Event{}, base...), c.trailing...)...)
		f := seq(scoreWith(t, e, egressReq("e-x", c.kind, egressTarget, h)))
		if f == nil {
			t.Fatalf("case %d (%s): no sequence reported", i, c.kind)
		}
		if got := f.Evidence[EvidenceAccessEventID]; got != "a-1" {
			t.Errorf("case %d: attributed to %q, want a-1", i, got)
		}
		if got := f.Evidence[EvidenceDistanceEvents]; got != c.wantDistance {
			t.Errorf("case %d: distance_events = %q, want %q", i, got, c.wantDistance)
		}
		if got := f.Evidence[EvidenceEgressCapability]; got != string(c.kind) {
			t.Errorf("case %d: egress_capability = %q, want %q", i, got, c.kind)
		}
	}
}

// --- 6. the ordering the whole pipeline is built around --------------------------------

// An event cannot be its own antecedent.
//
// The pipeline guarantees this structurally — commit runs after the whole stage
// list, so the event under judgment is not in history — and internal/pipeline
// asserts that end to end. Asserted here too, against a request assembled by
// hand with the current event planted in its own history, because the scorer
// must not depend on a caller getting the ordering right to avoid fabricating a
// sequence out of one event.
func TestTheCurrentEventCannotSatisfyItsOwnSequence(t *testing.T) {
	current := netAt("e-self", capability.KindNetSend, egressTarget)

	// A history that wrongly contains an event with the current event's own ID,
	// and which would otherwise qualify.
	poisoned := readAt("e-self", credentialPath, true)

	req := ScoreRequest{
		Event: current,
		Validation: result(decision.VerdictOutsideEnvelope,
			viol(validator.ViolationUngrantedCapability, capability.SeverityHigh)),
		Envelope: envelope(),
		History:  history().withRecent(poisoned),
	}

	if f := seq(scoreWith(t, seqEngine(t), req)); f != nil {
		t.Errorf("the event matched itself: %+v", *f)
	}

	// A different event carrying the same access does qualify, which proves the
	// rejection above was the identity guard rather than something else about
	// the fixture.
	ok := readAt("a-1", credentialPath, true)
	req.History = history().withRecent(ok)
	if f := seq(scoreWith(t, seqEngine(t), req)); f == nil {
		t.Fatal("the same access under a different event ID was also rejected")
	}
}

// --- 7. the invariant a covered event keeps ---------------------------------------------

// An event the envelope covered scores exactly zero, sequence or not — LevelNone
// has to keep meaning "nothing departed". The finding is still reported, with
// not_charged saying why, because a granted connection after a credential read
// is the envelope author's decision and an auditor should see it happened.
func TestAGrantedEgressKeepsItsZeroButNotItsSilence(t *testing.T) {
	req := ScoreRequest{
		Event:      netAt("e-1", capability.KindNetConnect, "registry.npmjs.org:443"),
		Validation: result(decision.VerdictWithinEnvelope),
		Envelope:   envelope(),
		History:    history().withRecent(readAt("a-1", credentialPath, true)),
	}

	a := scoreWith(t, seqEngine(t), req)
	if a.Score != 0 || a.Level != decision.LevelNone {
		t.Errorf("a covered event scored %v (%q); the zero invariant is load-bearing", a.Score, a.Level)
	}

	f := seq(a)
	if f == nil {
		t.Fatal("the sequence went unreported on a covered event; the grade of silence is the wrong one")
	}
	if f.Weight != 0 {
		t.Errorf("Weight = %v on a covered event, want 0", f.Weight)
	}
	if f.Evidence[EvidenceNotCharged] == "" {
		t.Error("points were withheld without the record saying why")
	}
	if f.Evidence[EvidenceAccessEventID] != "a-1" {
		t.Error("the withheld finding lost its attribution")
	}
}

// --- 8. determinism ---------------------------------------------------------------------

// The same request scored repeatedly has to produce the same assessment, field
// for field. The detector walks a slice and builds a map, both of which are
// places an ordering bug hides.
func TestSequenceScoringIsDeterministic(t *testing.T) {
	e := seqEngine(t)
	h := history().withRecent(
		readAt("a-1", credentialPath, true),
		readAt("a-2", npmrcPath, true),
		readAt("a-3", passwdPath, true),
	)

	first := scoreWith(t, e, egressReq("e-1", capability.KindNetConnect, egressTarget, h))
	for i := 0; i < 50; i++ {
		if got := scoreWith(t, e, egressReq("e-1", capability.KindNetConnect, egressTarget, h)); !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d diverged\n got %+v\nwant %+v", i, got, first)
		}
	}
}

// --- 9. admission and metadata ------------------------------------------------------------

// The constructor refuses the two configurations that would produce a detector
// that looks enabled and finds nothing.
func TestSequenceScorerAdmission(t *testing.T) {
	if _, err := NewCredentialEgressScorer(nil); err == nil {
		t.Error("a nil oracle was accepted; the detector would recognize no read as sensitive")
	}
	for _, w := range []int{0, -1, -256} {
		if _, err := NewCredentialEgressScorerWith(defaultOracle(t), w); err == nil {
			t.Errorf("a window of %d was accepted", w)
		}
	}
	s, err := NewCredentialEgressScorer(defaultOracle(t))
	if err != nil {
		t.Fatalf("NewCredentialEgressScorer: %v", err)
	}
	if s.Window() != DefaultSequenceWindow {
		t.Errorf("Window() = %d, want the default %d", s.Window(), DefaultSequenceWindow)
	}

	// A hand-built scorer with no oracle is a wiring fault, and it is reported
	// as one rather than as "no sequence found".
	var bare CredentialEgressScorer
	if _, err := bare.Evaluate(context.Background(), egressReq("e-1", capability.KindNetConnect, egressTarget, history())); err == nil {
		t.Error("a scorer with no oracle reported no sequence instead of refusing")
	}
}

// The same metadata check the standard scorer set gets: a factor has to be
// named after its scorer, stay under its declared ceiling, and explain itself.
func TestSequenceScorerAgreesWithItsMetadata(t *testing.T) {
	s := seqScorer(t, DefaultSequenceWindow)
	if s.Name() != FactorCredentialEgress {
		t.Errorf("Name = %q", s.Name())
	}
	if s.Weight() != SequencePoints {
		t.Errorf("Weight = %v, want %v", s.Weight(), SequencePoints)
	}

	f, err := s.Evaluate(context.Background(), egressReq("e-1", capability.KindNetConnect, egressTarget,
		history().withRecent(readAt("a-1", credentialPath, true))))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if f == nil {
		t.Fatal("no factor")
	}
	if f.Name != s.Name() || f.Weight > s.Weight() || f.Description == "" {
		t.Errorf("factor %+v disagrees with its scorer", *f)
	}

	if _, err := s.Evaluate(context.Background(), ScoreRequest{
		Event: netAt("e-1", capability.KindNetConnect, egressTarget),
	}); !errors.Is(err, ErrNoValidation) {
		t.Errorf("Evaluate returned %v on an unvalidated request, want ErrNoValidation", err)
	}
}

// The engine with an oracle carries the detector; the engine without one does
// not, and the difference is visible in the scorer list rather than hidden in a
// factor that never fires.
func TestOnlyAnOracleBackedEngineCarriesTheDetector(t *testing.T) {
	has := func(e *BaselineEngine) bool {
		for _, s := range e.Scorers() {
			if s.Name() == FactorCredentialEgress {
				return true
			}
		}
		return false
	}

	if has(NewEngine()) {
		t.Error("an engine with no oracle carries the sequence detector; it could recognize no access")
	}
	if !has(seqEngine(t)) {
		t.Error("an oracle-backed engine does not carry the sequence detector")
	}

	// And the unrated engine finds nothing on the sequence it cannot see, which
	// is the observable consequence of the same fact.
	a := score(t, egressReq("e-1", capability.KindNetConnect, egressTarget,
		history().withRecent(readAt("a-1", credentialPath, true))))
	if seq(a) != nil {
		t.Error("the unrated engine produced a sequence factor")
	}
}

// --- 10. benchmarks -------------------------------------------------------------------------

// The number that matters most: an event that is not egress. That is almost
// every event a session produces, and the detector must cost it one comparison
// and no history read at all.
func BenchmarkScoreSequenceNonEgress(b *testing.B) {
	o, err := LoadPathOracle(defaultListPath())
	if err != nil {
		b.Fatal(err)
	}
	e, err := NewEngineWithOracle(o)
	if err != nil {
		b.Fatal(err)
	}

	h := history()
	for i := 0; i < DefaultSequenceWindow; i++ {
		h.recent = append(h.recent, readAt("a-"+strconv.Itoa(i), unlistedPath, true))
	}
	req := ScoreRequest{
		Event:      fileEvent(capability.KindFileWrite, "/ws/a.go"),
		Validation: result(decision.VerdictWithinEnvelope),
		Envelope:   envelope(),
		History:    h,
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

// The absolute worst case, and it is deliberately pathological: a full window
// in which *every* retained event is a successful read of a distinct path the
// list has never heard of, so every candidate reaches the oracle and the scan
// still finds nothing. Distinct paths rather than one repeated path, because a
// repeated path would let any future memo make this number look good without
// making a real session faster.
//
// This is the number that bounds the feature's cost, and the cost is one oracle
// lookup per retained read. See the note on the scan in sequence.go.
func BenchmarkScoreSequenceEgressFullScan(b *testing.B) {
	h := history()
	for i := 0; i < DefaultSequenceWindow; i++ {
		h.recent = append(h.recent,
			readAt("a-"+strconv.Itoa(i), "/home/dev/app/pkg"+strconv.Itoa(i)+"/main.go", true))
	}
	benchmarkSequenceEgress(b, h)
}

// The realistic shape of a build's window: reads, writes, execs and network
// traffic mixed, so only some candidates reach the oracle at all. The two cheap
// pre-checks — the syscall's result and the observation's Kind — are what stand
// between this number and the one above.
func BenchmarkScoreSequenceEgressMixedWindow(b *testing.B) {
	h := history()
	for i := 0; i < DefaultSequenceWindow; i++ {
		n := strconv.Itoa(i)
		switch i % 4 {
		case 0:
			h.recent = append(h.recent, readAt("a-"+n, "/home/dev/app/pkg"+n+"/main.go", true))
		case 1:
			h.recent = append(h.recent, writeAt("a-"+n, "/home/dev/app/out/"+n+".o"))
		case 2:
			h.recent = append(h.recent, *observedEvent(capability.KindProcessExec, "/usr/bin/cc"))
		default:
			h.recent = append(h.recent, netRecord("a-"+n, capability.KindNetReceive, egressTarget))
		}
	}
	benchmarkSequenceEgress(b, h)
}

// The common alarming case: an egress event whose antecedent is the event just
// before it, so the backwards scan stops immediately. This is what the detector
// costs when it actually finds something.
func BenchmarkScoreSequenceEgressHit(b *testing.B) {
	h := history()
	for i := 0; i < DefaultSequenceWindow; i++ {
		h.recent = append(h.recent,
			readAt("a-"+strconv.Itoa(i), "/home/dev/app/pkg"+strconv.Itoa(i)+"/main.go", true))
	}
	h.recent[len(h.recent)-1] = readAt("a-hit", credentialPath, true)
	benchmarkSequenceEgress(b, h)
}

func benchmarkSequenceEgress(b *testing.B, h *fakeHistory) {
	b.Helper()

	o, err := LoadPathOracle(defaultListPath())
	if err != nil {
		b.Fatal(err)
	}
	e, err := NewEngineWithOracle(o)
	if err != nil {
		b.Fatal(err)
	}

	req := egressReq("e-1", capability.KindNetConnect, egressTarget, h)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := e.Score(ctx, req); err != nil {
			b.Fatal(err)
		}
	}
}
