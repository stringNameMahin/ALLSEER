package risk

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/stringNameMahin/ALLSEER/internal/validator"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
)

// This file is the first factor that reads more than the event under judgment.
// Every other scorer in this package answers a question about one observation;
// this one answers a question about a *relationship* between two, and that
// difference is what the whole file is arranged around.
//
// # What it claims, and what it does not
//
// It reports one shape: a successful read of a resource the sensitivity list
// grades high or critical, followed within a bounded window by a capability
// that moves data off the host. That shape is worth reporting because it is the
// order an exfiltration happens in and the order almost nothing else happens
// in.
//
// It is emphatically **not** a claim that credentials were exfiltrated, and the
// factor name says the most it can honestly say. Three gaps are permanent
// rather than temporary, and none of them is closed by more scoring:
//
//   - **Sensitive resource access is not confirmed credential access.** The
//     oracle grades a *location*, not a file's contents. A test fixture named
//     key.pem is graded critical and holds nothing.
//   - **Nothing connects the bytes read to the bytes sent.** There is no taint
//     tracking here and there will not be: payload inspection is out of scope
//     (devRead section 10.2), so the relationship the detector establishes is temporal
//     ordering and nothing stronger.
//   - **A sequence is not an intent.** `npm install` reads `.npmrc` -- graded
//     high, and correctly so -- and then connects to a registry. That is the
//     detector firing on exactly the behavior it was built to see, on a session
//     that is entirely honest. The factor raises a score by an amount that
//     cannot on its own reach the top band; deciding what to do about it is
//     policy's business.
//
// # The three decisions, and why they went the way they did
//
// ## What counts as the first half
//
// A prior event qualifies when all four hold:
//
//	1. it resolves to an observation with a non-empty target
//	2. that observation's Kind is fs.read
//	3. the syscall succeeded
//	4. the SensitivityOracle grades the target high or critical
//
// Each is a rule that can be checked by hand against the recorded event, which
// is the property that matters most: an operator reading the evidence map can
// re-derive the finding from the stream.
//
// **fs.read alone**, not the filesystem domain. Reading is what discloses
// content. A write to a credential path is tampering or persistence -- a real
// concern, and a different one, belonging to a scorer that does not exist yet.
//
// **The read must have succeeded.** A read that returned ENOENT disclosed
// nothing, so there is nothing that could subsequently leave. The corpus
// already contains this case (`gt-009`, a failed read of `~/.ssh/id_rsa`) and
// counting it would let the detector build a sequence on an event that
// transferred no bytes. Note the deliberate asymmetry with the egress half
// below: the halves are not symmetric because the failures mean different
// things.
//
// **high or critical**, read out of the shipped list's own grade vocabulary
// rather than invented here. `configs/sensitivity.default.yaml` documents
// `critical` as credential material reaching other systems and `high` as
// service-scoped credentials and account shape -- both are credentials. It
// documents `medium` as "identity and history ... **routinely read by ordinary
// tooling**", which is `/etc/passwd` and shell history: real signal in a
// departure, and read by getpwnam on every build. A detector whose first half
// fired on `/etc/passwd` would report a sequence on most sessions that touch
// the network, and a detector that reports constantly reports nothing.
// `low` and `info` contribute zero points precisely because they are
// unremarkable, and a grade worth zero points cannot be worth thirty here.
//
// **Verdict is deliberately not a condition**, and it could not be one:
// risk.History carries events, not decisions, so the validator's answer about a
// *prior* event is not available to a scorer through the interface it is given.
// That is a limitation worth stating rather than working around, and the
// working-around would be worse than the limitation -- but it is also the right
// answer on the merits. An envelope granting a credential read does not license
// shipping the result off the machine, so requiring the access to have been a
// departure would make "grant the read" the way to hide the sequence.
//
// ## The window
//
// An **event count**, not a duration, and not both.
//
// Count is what risk.History natively supports: RecentEvents(n) is the only
// lookup it offers and it is count-bounded. A duration would have to be derived
// from the events themselves -- from WallClock, which pkg/event states is
// subject to adjustment and explicitly not the ordering key, or from
// KernelTimestamp, which is sound within a boot but would need a number of
// seconds nobody has measured. Adding a second bound would mean two parameters
// where one suffices and one more thing to get wrong under replay.
//
// The count is **the detector's own constant**, defaulting to
// DefaultSequenceWindow, rather than "whatever the ring happens to hold". The
// two coincide at 256 today and that is not a coincidence:
// session.DefaultHistorySize was chosen *for this consumer*, with the reasoning
// written down -- the read and the connection must fall inside one window even
// when a build's file traffic separates them, a few hundred events covers a
// compile-and-link burst and a few dozen does not. This consumer now exists and
// confirms that reasoning; no measurement exists to move it. Owning the number
// here rather than inheriting it buys two things: a deployment that raises
// retention does not silently widen the behavioral claim, and a labeled corpus
// can tune the window without touching memory policy.
//
// The window is a ceiling on the lookback, never a floor. When history retains
// less than the window the detector sees less, which under-reports rather than
// over-reports; `window_truncated` states when that could have happened so the
// record does not overstate what was searched.
//
// ## One factor, not two halves plus a combination
//
// One scorer, one factor. The halves are already represented where they were
// observed: `sensitive_path` grades the resource on the access event, and the
// egress event's own verdict and violation_severity factors weigh the egress.
// Splitting the sequence into per-half scorers would charge points on events
// that are not part of any sequence, and would make the sequence itself the sum
// of two independent findings -- which is exactly the "two unrelated events
// happened" arithmetic a sequence detector exists to avoid. This factor is
// charged only when the relationship is proven, and its evidence names both
// ends so the proof is checkable.

// FactorCredentialEgress is the sequence factor's name, and it is a wire
// contract like every other factor name.
//
// Named for the two observations rather than for a conclusion: "credential
// access to egress" is what was seen. Calling it "exfiltration" would put a
// verdict in the record that the evidence does not support.
const FactorCredentialEgress = "credential_access_egress"

// DefaultSequenceWindow is how many recorded events back the detector looks.
//
// See the window discussion in the file comment. Chosen rather than inherited,
// and equal to session.DefaultHistorySize today because that value was picked
// for this detector and this detector confirms the reasoning. It is a
// documented estimate awaiting a labeled corpus, exactly as the point values
// are.
const DefaultSequenceWindow = 256

// SequencePoints is what a proven sequence contributes.
//
// Calibrated the way every other value in this model is: against the bands the
// shipped rule set already states, since no labeled corpus exists.
//
//   - It equals the verdict factor's weight for outside_envelope (30). A
//     sequence is evidence as strong as the envelope's author not having
//     anticipated the operation, and no stronger. It is deliberately below an
//     explicit denial's 55: a human writing a denial is a stronger statement
//     than a relationship this package inferred.
//   - It carries an indeterminate egress across the boundary the rule set
//     itself declares. An egress whose destination could not be attributed
//     scores 20 for the verdict plus 15 for the unresolvable violation's
//     severity; `indeterminate-low-risk` claims everything below 50 and
//     `indeterminate-high-risk` everything from 50 up, and the sequence is what
//     moves such an event from the first to the second. "Unresolved is not
//     safe" is that rule's own wording, and a credential read behind it is
//     precisely when it should hold.
//   - It cannot reach LevelCritical on its own or in combination with a bare
//     departure. 85 stays reserved for an explicit denial carrying critical
//     consequence, which is an observation rather than an inference.
const SequencePoints = 30.0

// MinAccessSensitivity is the lowest grade that qualifies as the first half.
//
// See the file comment: read out of the shipped list's grade vocabulary, where
// high and critical are described as credentials and medium is described as
// identity and history routinely read by ordinary tooling.
const MinAccessSensitivity = capability.SeverityHigh

// Evidence keys on the credential_access_egress factor.
//
// Between them they answer the five questions the factor has to answer: which
// prior event was the first half, which current event was the egress, why the
// pair is a sequence, what window was searched, and what it contributed. The
// last is the factor's Weight; the rest are here.
const (
	// EvidenceAccessEventID names the prior event, so a reader can find it in
	// the stream rather than take the finding on trust.
	EvidenceAccessEventID = "access_event_id"

	// EvidenceAccessTarget is the resolved path that was read.
	EvidenceAccessTarget = "access_target"

	// EvidenceAccessCapability is the prior event's capability. Always fs.read
	// today, and recorded rather than implied so that widening the qualifying
	// set later cannot silently change what an archived record meant.
	EvidenceAccessCapability = "access_capability"

	// EvidenceAccessSensitivity is the grade the oracle assigned the path.
	EvidenceAccessSensitivity = "access_sensitivity"

	// EvidenceAccessReason is the sentence the sensitivity list's author wrote
	// about that location, carried for the reason sensitive_path carries it:
	// "why did this score go up" should be answered by a human's sentence
	// rather than by a glob the reader has to interpret.
	EvidenceAccessReason = "access_reason"

	// EvidenceAccessSucceeded records that the read returned successfully. It
	// is always "true" -- a failed read does not qualify -- and it is stated
	// anyway, because the rule is one an auditor should be able to see applied
	// rather than have to know.
	EvidenceAccessSucceeded = "access_succeeded"

	// EvidenceEgressCapability is the current event's capability.
	EvidenceEgressCapability = "egress_capability"

	// EvidenceEgressTarget is the destination, omitted when the current event
	// has no resolved target. An absent key reads as "not recorded", which is
	// the truth; an empty string in a record reads as a missing field.
	EvidenceEgressTarget = "egress_target"

	// EvidenceWindowEvents is the lookback the detector was configured with.
	EvidenceWindowEvents = "window_events"

	// EvidenceDistanceEvents is how far back the access was found, counted in
	// recorded events, where 1 means immediately before this one. It is the
	// number a labeled corpus would tune the window against.
	EvidenceDistanceEvents = "distance_events"

	// EvidenceWindowTruncated is "true" when history returned a full window, so
	// an older qualifying access may exist that was never searched. It
	// qualifies the finding rather than changing it: the sequence found is
	// still the nearest one.
	EvidenceWindowTruncated = "window_truncated"
)

// IsEgress reports whether a capability moves data off the host.
//
// Exactly the set configs/rules.default.yaml's `unexpected-network-egress` rule
// names, read from that file rather than decided again here. The capability
// table's own network section already states the reasoning: egress outranks
// ingress throughout, because an outbound connection is how data leaves and
// that cannot be undone after the fact.
//
// Everything else in the network domain is deliberately excluded, and each
// exclusion is a claim the detector does not make:
//
//   - net.dns resolves a name. DNS tunnelling is real and this does not catch
//     it; the table rates net.dns low and describes it as correlation support,
//     and treating every lookup as egress would fire on every session.
//   - net.bind, net.listen, net.accept, net.receive are inbound or local.
//   - ipc.unixsocket does not leave the host. A governed process reaching an
//     ungoverned one through it is a real channel and a different detector.
func IsEgress(k capability.Kind) bool {
	return k == capability.KindNetConnect || k == capability.KindNetSend
}

// AccessSensitivityQualifies reports whether a grade is high enough for the
// first half of the sequence.
//
// SensitivityUnknown never qualifies, and that is the load-bearing case: an
// unrated path is one the list has never heard of, and treating it as
// credential material would make every unlisted read the first half of a
// sequence. It is also why an `info` rating cannot qualify -- an explicit "we
// looked, and this is ordinary" must not become credential access by accident.
func AccessSensitivityQualifies(g capability.Severity) bool {
	if !KnownSensitivity(g) {
		return false
	}
	return severityRank(g) >= severityRank(MinAccessSensitivity)
}

// CredentialEgressScorer reports a sensitive-read-then-egress sequence.
//
// Holds an oracle and a window and nothing else; it is immutable after
// construction, performs no I/O, and is safe for concurrent use like every
// other scorer here.
type CredentialEgressScorer struct {
	oracle SensitivityOracle
	window int
}

var (
	_ Scorer      = CredentialEgressScorer{}
	_ localScorer = CredentialEgressScorer{}
)

// NewCredentialEgressScorer builds the detector over an oracle, with the
// default window.
//
// A nil oracle is refused rather than defaulted away, for the reason
// NewEngineWithOracle refuses one: a detector that rated nothing would find no
// sequences while looking configured, which is worse than not being there.
func NewCredentialEgressScorer(o SensitivityOracle) (CredentialEgressScorer, error) {
	return NewCredentialEgressScorerWith(o, DefaultSequenceWindow)
}

// NewCredentialEgressScorerWith builds the detector with an explicit window.
//
// Exposed because the window is the one number in this file a labeled corpus is
// expected to move, and a value nothing can vary is a value nothing can measure.
func NewCredentialEgressScorerWith(o SensitivityOracle, window int) (CredentialEgressScorer, error) {
	if o == nil {
		return CredentialEgressScorer{}, errors.New("risk: credential_access_egress needs a sensitivity oracle; " +
			"without one no read can be recognized as sensitive and the detector would silently find nothing")
	}
	if window <= 0 {
		return CredentialEgressScorer{}, fmt.Errorf("risk: sequence window is %d; a window of no events "+
			"can never contain a prior access, so a detector configured with one would be a disabled "+
			"detector that reads as an enabled one", window)
	}
	return CredentialEgressScorer{oracle: o, window: window}, nil
}

// Name identifies the factor this scorer produces.
func (CredentialEgressScorer) Name() string { return FactorCredentialEgress }

// Weight is the most this scorer can contribute.
func (CredentialEgressScorer) Weight() float64 { return SequencePoints }

// Window reports the configured lookback in events.
func (s CredentialEgressScorer) Window() int { return s.window }

// Evaluate returns the sequence factor, or nil when no sequence was proven.
func (s CredentialEgressScorer) Evaluate(_ context.Context, req ScoreRequest) (*decision.Factor, error) {
	if req.Validation == nil {
		return nil, ErrNoValidation
	}
	f, applied, err := s.evaluate(newScoreCtx(req))
	if err != nil || !applied {
		return nil, err
	}
	return &f, nil
}

// evaluate proves the relationship or says nothing.
//
// Silence here means "no qualifying access was found in the window", which is a
// complete answer rather than an absent one -- unlike sensitive_path, whose
// silence would be indistinguishable from having no oracle at all. This scorer
// is present in the set exactly when an oracle is, so a reader can tell from
// Scorers() that the search happened, and emitting a negative finding on every
// egress event would put a line in every network decision to say nothing.
//
// # Cost, measured
//
// The first check is the capability of the *current* event, so an event that is
// not egress -- which is almost every event a session produces -- costs one
// comparison and reads no history at all. That is the claim the feature lives
// or dies on, and it holds exactly: BenchmarkProcessWithSequenceDetector is
// identical to BenchmarkProcessRated at 2374 B and 43 allocs per event, so a
// file operation pays nothing measurable for the detector's presence.
//
// Only an egress event pays for the scan, and the scan walks backwards and
// stops at the first qualifying access, so the case that finds something is
// cheap: 1.4 us and 14 allocs at the engine level, against 0.9 us for the same
// engine with no sequence to find.
//
// The number that bounds the feature is an egress event over a full window
// containing *no* qualifying access, since that is the one that runs to the end:
//
//	BenchmarkScoreSequenceEgressHit          1.4 us      14 allocs
//	BenchmarkScoreSequenceEgressMixedWindow   85 us      70 allocs
//	BenchmarkScoreSequenceEgressFullScan     340 us     262 allocs
//	BenchmarkProcessEgressOverAFullWindow    120 us      99 allocs, 98 KB
//
// Two components, both linear in the window and neither surprising once
// measured. The 98 KB is History.RecentEvents copying the ring, which it does
// by contract so a caller cannot reach back into it. The microseconds are one
// oracle lookup per retained *successful read*, at roughly 1.3 us each against
// the shipped forty-pattern list -- the mixed-window figure is lower purely
// because only a quarter of that window is reads.
//
// This is charged to connect and send and to nothing else, on syscalls that
// already cost milliseconds of network latency, so it is proportionate as it
// stands. It is not free, and shrinking the window is deliberately *not* the
// answer: that would trade the detection the feature exists for against latency
// on the one syscall class able to absorb it. The two fixes are named in the
// TODOs at the foot of this file, each with the measurement that justifies it.
//
// # Ordering
//
// The scan is over History.RecentEvents, which the pipeline guarantees holds
// the session as it stood *before* this event: commit runs after the whole
// stage list (see pipeline.EventPipeline). The current event therefore cannot
// appear among the candidates. The identity guard below is belt and braces
// against a caller that assembles a request by hand, and it is tested.
func (s CredentialEgressScorer) evaluate(sc *scoreCtx) (decision.Factor, bool, error) {
	if s.oracle == nil {
		// Only reachable through a hand-built scorer set. Refused rather than
		// reported as "no sequence": one is a statement about the session, the
		// other is a statement about the wiring.
		return decision.Factor{}, false, errors.New("risk: credential_access_egress scorer has no oracle")
	}

	// The hot-path exit. Nothing but an egress capability can be the second
	// half, so nothing else reads history.
	if !IsEgress(sc.kind) {
		return decision.Factor{}, false, nil
	}
	if sc.req.History == nil {
		// No history is an absent input, not an empty one: nothing is known
		// about what came before, so nothing is said. It is never "no
		// credential was read". The evidence basis already records that history
		// was unavailable, which is where a reader sees it.
		return decision.Factor{}, false, nil
	}

	recent := sc.req.History.RecentEvents(s.window)
	if len(recent) == 0 {
		return decision.Factor{}, false, nil
	}

	// Backwards, so the first hit is the *nearest* preceding qualifying access.
	// Two properties come from that and both are wanted: attribution is
	// deterministic under any number of candidates, and the scan stops early.
	// Nearest rather than earliest because it is the pairing whose temporal
	// relationship is strongest, and because an operator asked "which read"
	// expects the one just before the connection.
	for i := len(recent) - 1; i >= 0; i-- {
		prev := &recent[i]

		// An event cannot be its own antecedent. Unreachable through the
		// pipeline, which commits last, and cheap enough to keep as a guard
		// against a request assembled by hand.
		if prev.ID != "" && prev.ID == sc.req.Event.ID {
			continue
		}

		// Cheapest discriminator first: a bool already on the event.
		if !prev.Result.Succeeded {
			continue
		}

		obs, err := validator.ObservationOf(prev)
		if err != nil {
			// An event this build cannot interpret is a blind spot, and a blind
			// spot is not a qualifying access. It is also not a reason to stop:
			// an older event in the window may still qualify.
			continue
		}
		if obs.Kind != capability.KindFileRead || obs.Target == "" {
			continue
		}

		grade := s.oracle.PathSensitivity(obs.Target)
		if !AccessSensitivityQualifies(grade) {
			continue
		}

		return s.factor(sc, prev.ID, obs, grade, len(recent)-i, len(recent) >= s.window), true, nil
	}

	return decision.Factor{}, false, nil
}

// factor renders the finding.
//
// Points are withheld -- the finding is not -- when the envelope covered this
// egress, which is the same arrangement sensitive_path makes and is there for
// the same invariant: an event a grant covered scores exactly zero, so that
// LevelNone keeps meaning "nothing departed" rather than "nothing was looked
// at". A granted connection after a credential read is the envelope author's
// decision, and an auditor should be able to see it happened.
func (s CredentialEgressScorer) factor(
	sc *scoreCtx,
	accessID string,
	access capability.Observation,
	grade capability.Severity,
	distance int,
	truncated bool,
) decision.Factor {
	ev := map[string]string{
		EvidenceAccessEventID:     accessID,
		EvidenceAccessTarget:      access.Target,
		EvidenceAccessCapability:  string(access.Kind),
		EvidenceAccessSensitivity: string(grade),
		EvidenceAccessSucceeded:   "true",
		EvidenceEgressCapability:  string(sc.kind),
		EvidenceWindowEvents:      strconv.Itoa(s.window),
		EvidenceDistanceEvents:    strconv.Itoa(distance),
	}
	if sc.target != "" {
		ev[EvidenceEgressTarget] = sc.target
	}
	if truncated {
		ev[EvidenceWindowTruncated] = "true"
	}
	if o, ok := s.oracle.(interface {
		PathSensitivityReason(string) (capability.Severity, string)
	}); ok {
		if _, reason := o.PathSensitivityReason(access.Target); reason != "" {
			ev[EvidenceAccessReason] = reason
		}
	}

	points := SequencePoints
	if !sc.departed {
		points = 0
		ev[EvidenceNotCharged] = "the envelope covered this egress"
	}

	return decision.Factor{
		Name:   FactorCredentialEgress,
		Weight: points,
		Description: "a successful read of a resource graded " + string(MinAccessSensitivity) +
			" or above was followed, within the detector's window, by a capability that moves data off the host",
		Evidence: ev,
	}
}

// TODO(risk): measure the window against a labeled corpus. distance_events is
// recorded on every finding precisely so the distribution can be read off real
// sessions rather than argued about; until it can be, 256 is a documented
// estimate that this detector inherited the reasoning for rather than the number.
// TODO(risk): the scan allocates 98 KB per egress event, because
// History.RecentEvents copies the ring so a caller cannot reach back into it.
// The scan wants none of that: it walks backwards and usually stops early. The
// fix is a reverse iterator alongside RecentEvents -- probed for the way
// SeenTargetsSaturated already is, so a History without one keeps working --
// which would take the copy to zero. Deliberately not built here: it widens an
// interface two packages implement, and the milestone is the detector.
// TODO(risk): the scan's microseconds are one PathSensitivity call per retained
// successful read, ~1.3 us each against a forty-pattern list. sensitivity.go
// already specifies the fix and already declined to build it, on the grounds
// that scoring one unrated path was proportionate at 982 ns; this consumer
// makes that call happen up to 256 times per egress event instead of once per
// event, which is the evidence that TODO was waiting for.
// TODO(risk): the egress half asks nothing of the destination, because
// HostSensitivity rates nothing in this build. When it does, an egress to an
// unfamiliar host after a credential read is a materially different finding
// from one to a host the session has already used, and this is the scorer that
// should say so.
// TODO(risk): a session-level counterpart. ScoreSession still cannot see
// sequences, because it is handed violations rather than events; giving it the
// same view this scorer has would let "the session read credentials and then
// connected out" be reported once at the end rather than only on the event that
// happened to be the egress.
