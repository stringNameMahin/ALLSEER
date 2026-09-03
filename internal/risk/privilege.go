package risk

import (
	"context"
	"strconv"
	"strings"

	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// This file scores the one thing a privilege-domain event establishes on its
// own: the process attempted to change what it is allowed to do.
//
// # Why the factor exists when a rule already blocks
//
// The obvious objection is that configs/rules.default.yaml already blocks
// privilege operations terminally, so a risk factor moves a number and changes
// no action. That objection was checked against the shipped rule set rather
// than assumed, and it is false for two of the five privilege capabilities.
//
// The privilege-escalation rule matches `capabilities: [priv.escalate,
// priv.setuid, priv.capset]`. priv.namespace and priv.seccomp are not in it,
// and nothing else in the file names them. An ungranted priv.namespace
// therefore falls through eleven rules to medium-risk-departure and is
// warned, not blocked -- the capability the catalog describes as "how a process
// escapes the attribution the collector depends on". Before this factor it
// scored 60: verdict 30 plus critical severity 30, and nothing else, because a
// privilege observation has no target and so cannot be novel. With it, the same
// event scores 85 and reaches high-risk-departure, which asks a human.
//
// The rule also matches only three of the six verdicts. A privilege change the
// envelope granted is within_envelope, is not matched by the block rule, and is
// allowed -- correctly, since the envelope's author said so, but silently,
// because nothing in the record said what was granted away. This factor is
// emitted on those events too, with its points withheld, for the same reason
// sensitive_path reports a granted read of a credential path.
//
// So the answer to "what does the factor add when the domain is blocked" is
// four concrete things, in descending order of how much they are worth:
//
//  1. It changes the action on priv.namespace, from warn to request_approval.
//     This is not an auditability argument; it is a coverage gap in the shipped
//     rule set that the risk model can close without loosening anything.
//  2. It distinguishes privilege changes from each other. Every privilege
//     event in the tree scores exactly 60 today, because validator.severityFor
//     takes the maximum of the violation-type floor and the catalog baseline,
//     and for a critical capability that maximum saturates. A seccomp filter
//     and a setuid to root are the same number. The catalog already grades them
//     apart; this is the first factor that reads that grade undiluted.
//  3. It is the first and only consumer of event.PrivPayload. Before this file,
//     nothing outside tests read the field: privilege events crossed the whole
//     pipeline with their payload unopened. A payload nothing reads is a
//     payload nothing can notice has drifted -- and it has. See below.
//  4. It makes the domain legible in monitor mode, where no action is applied
//     at all and the record is the entire product.
//
// # What a privilege change is here, and what it is not
//
// The factor is charged from the capability kind, which the catalog defines and
// grades, and never from the payload. The payload is read for evidence and
// contributes no points. That split is the whole design, and it follows from
// what the two inputs can actually support:
//
//   - The kind is a closed vocabulary fixed at compile time in
//     pkg/capability/table.go, with a reviewed BaselineSeverity per entry. It
//     is produced by the catalog, not by a probe, so it means the same thing on
//     every event of that kind.
//   - Every field of PrivPayload is either free text with no vocabulary defined
//     anywhere in the repository (Operation, NamespaceType), one-sided
//     (CapabilitiesAdded), or ambiguous on its most important value (OldUID,
//     NewUID -- see the UID note below). And no probe writes any of them: there
//     is no privilege decoder, and no replay fixture in test/testdata carries a
//     privilege event at all.
//
// Charging points off a field whose vocabulary has not been decided would be
// scoring a guess, which is the objection correlation.go raises against scoring
// net.bind and net.accept before their probes exist. The same objection applies
// here and gets the same answer: report the field, charge the thing that is
// already defined.
//
// # Capability-set deltas are not representable, and this does not pretend
//
// docs/milestones.md specifies this scorer "over PrivPayload, including
// capability set deltas". A delta needs a before and an after. The repository
// has neither, and its two halves disagree about what it has instead:
//
//	                     pkg/event.PrivPayload        bpf/include/allseer_event.h
//	capability evidence  CapabilitiesAdded []string   caps_effective, caps_permitted (__u64)
//	shape                names, added only            absolute bitmasks, post-change
//	namespace            NamespaceType string         no field at all
//	operation            string                       __u32 enum
//
// Neither side carries a removal, and the two do not carry the same thing. The
// Go side names capabilities gained; the kernel side snapshots two whole sets
// after the fact, from which "added" cannot be recovered without the prior
// snapshot nothing keeps. pkg/event already carries the TODO for this --
// "generate the Go decoder from the shared C struct layout so kernel and user
// space cannot drift" -- and this is that drift, found by writing the first
// consumer.
//
// So the factor states what it has and labels it. EvidenceCapabilityDelta
// carries CapabilityDeltaAddedOnly whenever capabilities were reported, so a
// reader of the audit record is told that a set of dropped capabilities would
// look identical to none. An empty CapabilitiesAdded is not evidence that
// nothing changed, and is never scored as though it were.
//
// # The UID fields cannot answer the question they look like they answer
//
// OldUID and NewUID are int32 tagged omitempty. Zero is uid 0 -- root, the
// single most consequential value either field can hold -- and it is also what
// an absent field decodes to, and what an encoder omits. A transition to root
// and a record that never carried a UID are therefore the same two integers.
//
// This factor will not resolve that by guessing. It classifies the pair into
// four states (see uidTransition), reports the literal values beside the
// classification so a reader is never dependent on it, and charges nothing
// either way. Fixing it belongs to pkg/event -- dropping omitempty on both
// fields makes zero mean zero -- and is a wire-format change that should not
// ride along inside a risk milestone.
//
// # A malformed payload is charged, not refused
//
// Every other unreadable input in this package is refused: an unknown verdict
// returns an error, and the pipeline turns it into an explicit indeterminate
// decision. Here that would be a security hole. pipeline.IndeterminateHandler
// assigns ActionForFailure -- request_approval -- and bypasses the policy engine
// entirely, so a privilege event whose payload failed to decode would be
// downgraded from a terminal block to a prompt. Making a malformed payload the
// cheapest route past the privilege rule is exactly backwards.
//
// So an absent or malformed payload is charged in full from the kind, which
// never came from the payload, and the gap is named in EvidencePrivEvidence.

// FactorPrivilegeChange is the factor's name, and it is a wire contract like
// every other factor name.
//
// The name docs/roadmap.md and configs/allseerd.example.yaml already use, kept
// verbatim: the example config's `privilege_change: 1.5` weight entry has been
// inert since it was written, and a rename would have left it inert for a
// second reason.
const FactorPrivilegeChange = "privilege_change"

// Evidence keys on the privilege_change factor.
//
// EvidenceCapability and EvidenceNotCharged are shared with the factors that
// already use them, because they answer the same questions in the same words.
const (
	// EvidenceBaselineSeverity is the catalog grade the points were read from.
	// Recorded so the arithmetic is checkable from the record alone: the grade
	// names the row of sensitivityPoints, and the row gives the weight.
	EvidenceBaselineSeverity = "baseline_severity"

	// EvidencePrivEvidence states what the event carried in the way of
	// privilege detail, in the three-state vocabulary below. It is the key that
	// keeps "the payload said nothing" apart from "the payload was not there".
	EvidencePrivEvidence = "privilege_evidence"

	// EvidenceOperation is PrivPayload.Operation verbatim. Free text with no
	// vocabulary defined anywhere in the repository, so it is carried and never
	// interpreted.
	EvidenceOperation = "operation"

	// EvidenceNamespaceType is PrivPayload.NamespaceType verbatim, on the same
	// terms as EvidenceOperation.
	EvidenceNamespaceType = "namespace_type"

	// EvidenceCapabilitiesAdded lists the Linux capabilities the payload says
	// were gained, joined by a single space.
	//
	// The join is lossless here in a way capability.AttrArgv's identical join
	// is not: a CAP_ name contains no space, so the string can be split back
	// into the list it came from.
	EvidenceCapabilitiesAdded = "capabilities_added"

	// EvidenceCapabilityDelta states what kind of capability evidence this is,
	// so nobody reads a one-sided list as a delta. See CapabilityDeltaAddedOnly.
	EvidenceCapabilityDelta = "capability_delta"

	// EvidenceUIDTransition classifies the OldUID/NewUID pair. See uidTransition.
	EvidenceUIDTransition = "uid_transition"

	// EvidenceOldUID and EvidenceNewUID carry the literal integers beside the
	// classification, so a reader can check it or disagree with it.
	EvidenceOldUID = "old_uid"
	EvidenceNewUID = "new_uid"
)

// What the event carried in the way of privilege detail.
//
// Three states rather than two, for the reason the sensitivity list keeps
// rated, unrated, and unasked apart: a payload that was never attached and a
// payload that arrived without the field its own schema requires are different
// failures with different owners, and collapsing them would hide whichever one
// is happening.
const (
	// PrivEvidenceRecorded: a payload was attached and carried an operation.
	PrivEvidenceRecorded = "recorded"

	// PrivEvidenceAbsent: no payload was attached to a privilege event. The
	// decoder did not produce one, or the record predates it.
	PrivEvidenceAbsent = "absent"

	// PrivEvidenceMalformed: a payload was attached without an Operation, which
	// api/schema/event.v1alpha1.schema.json marks required. The event is still
	// charged in full; see the header note on why refusing it would be a hole.
	PrivEvidenceMalformed = "malformed"
)

// CapabilityDeltaAddedOnly is what EvidenceCapabilityDelta always carries in
// this build.
//
// A constant with one value on purpose. The key exists so the record states the
// limitation rather than leaving a reader to infer it from a field name, and it
// is a constant rather than a literal so the day a real delta becomes
// representable, the compiler shows every place that has to change.
const CapabilityDeltaAddedOnly = "added_only"

// How the OldUID/NewUID pair reads.
//
// The classification is about the record, not about the process. Every state
// below except UIDTransitionChanged is a statement that the record cannot
// settle what happened, and none of them carries points.
const (
	// UIDTransitionChanged: both values are non-zero and differ. The one
	// unambiguous shape, because neither value can be the zero an absent field
	// decodes to.
	UIDTransitionChanged = "changed"

	// UIDTransitionUnchanged: both values are non-zero and equal. A setuid to
	// the identity the process already had is a real no-op and worth recording
	// as one -- but see the header: an unchanged UID is not evidence that the
	// event changed nothing, because a capset moves no UID at all.
	UIDTransitionUnchanged = "unchanged"

	// UIDTransitionAmbiguous: exactly one value is zero. Root is uid 0 and an
	// absent field decodes to 0, so "dropped from root", "escalated to root",
	// and "this half was never recorded" are the same integer.
	UIDTransitionAmbiguous = "ambiguous"

	// UIDTransitionUnrecorded: both values are zero. Almost certainly a payload
	// that carried no UID data, and indistinguishable from root to root.
	UIDTransitionUnrecorded = "unrecorded"
)

// PrivilegeChangeScorer weighs a change to what the process is allowed to do.
//
// Stateless, so the zero value works and it is safe for concurrent use. It
// reads the catalog and one payload struct, consults no list, no history, and
// no envelope, and allocates an evidence map only on privilege events.
//
// It needs no SensitivityOracle, which is why it is in every engine rather than
// only the oracle-backed ones. STATUS.md carried the open question of whether
// SensitivityOracle.ExecutableSensitivity was its prerequisite; it is not, and
// the reason is that they rate different things. ExecutableSensitivity rates a
// binary path -- a resource -- and a privilege observation names no resource at
// all: telemetry.resolve leaves Target empty for the whole domain, because
// "exercising the capability is the whole observation". Rating
// Process.Executable instead would be rating the actor rather than the act,
// which nothing in the model does yet and which would be a different factor
// with a different name.
type PrivilegeChangeScorer struct{}

var (
	_ Scorer      = PrivilegeChangeScorer{}
	_ localScorer = PrivilegeChangeScorer{}
)

// Name identifies the factor this scorer produces.
func (PrivilegeChangeScorer) Name() string { return FactorPrivilegeChange }

// Weight is the most this scorer can contribute: the critical row of
// sensitivityPoints, which four of the five privilege kinds are graded at.
func (PrivilegeChangeScorer) Weight() float64 { return sensitivityPoints[capability.SeverityCritical] }

// Evaluate returns the privilege factor, or nil when the event changed no
// privilege.
func (s PrivilegeChangeScorer) Evaluate(_ context.Context, req ScoreRequest) (*decision.Factor, error) {
	if req.Validation == nil {
		return nil, ErrNoValidation
	}
	f, applied, err := s.evaluate(newScoreCtx(req))
	if err != nil || !applied {
		return nil, err
	}
	return &f, nil
}

// evaluate speaks only about events in the privilege domain.
//
// Silence means the catalog does not place this capability in the privilege
// domain, and it never means "we did not look": the scorer is in every engine
// and has nothing to be configured with, so there is no build in which it could
// be absent while privilege events flow.
//
// The domain comes from the catalog and never from Event.Domain, for the reason
// internal/policy and dimensionFor both derive it that way: Domain is a
// denormalized convenience written by the decoder, and a mis-decoded record must
// not be able to talk its way out of the privilege domain by disagreeing with
// the catalog about which domain its own capability is in.
//
// An unresolvable event is silent too. sc.kind is empty when the observation
// could not be produced, the validator already reports that as indeterminate,
// and deriving a privilege finding from a record the system could not interpret
// would be the fabricated evidence this package exists to avoid.
func (PrivilegeChangeScorer) evaluate(sc *scoreCtx) (decision.Factor, bool, error) {
	desc, known := capability.Describe(sc.kind)
	if !known || desc.Domain != capability.DomainPrivilege {
		return decision.Factor{}, false, nil
	}

	var payload *event.PrivPayload
	if sc.req.Event != nil {
		payload = sc.req.Event.Privil
	}

	ev := map[string]string{
		EvidenceCapability:       string(sc.kind),
		EvidenceBaselineSeverity: string(desc.BaselineSeverity),
		EvidencePrivEvidence:     privEvidenceState(payload),
	}
	describePayload(payload, ev)

	// Points come from the kind's catalog grade through the same table
	// sensitive_path and sensitive_host read. It is the right table because it
	// answers the same question they do -- how consequential is the thing that
	// happened -- and reusing it means a change to how the project weighs
	// consequence moves all three together rather than two of them.
	//
	// It is also the first place the risk model sees the catalog's baseline
	// undiluted. validator.severityFor already folds that baseline into
	// Violation.Severity by taking the maximum with the violation type's floor,
	// and for a critical capability the maximum saturates: an ungranted
	// priv.seccomp and an ungranted priv.escalate both arrive at
	// violation_severity as one number. Reading the grade here separates them
	// without re-deriving it, because the grade is the catalog's own and this
	// factor asks a different question of it.
	points := sensitivityPointsFor(desc.BaselineSeverity)

	// Points are withheld -- not the finding -- for an event the envelope
	// covered, exactly as on the sensitivity and correlation sides, so the
	// invariant that an expected event scores exactly zero holds. The case is
	// reachable and is the one worth recording most: an envelope that grants
	// priv.setuid is not matched by the shipped block rule, so a granted
	// privilege change is allowed today with nothing in the record naming what
	// was given away.
	if !sc.departed {
		points = 0
		ev[EvidenceNotCharged] = "the envelope covered this operation"
	}

	return decision.Factor{
		Name:   FactorPrivilegeChange,
		Weight: points,
		Description: "the process changed what it is permitted to do; the weight is the " +
			"capability catalog's own grade for this kind of change",
		Evidence: ev,
	}, true, nil
}

// privEvidenceState reports what the event carried, and nothing about whether
// it was alarming.
func privEvidenceState(p *event.PrivPayload) string {
	switch {
	case p == nil:
		return PrivEvidenceAbsent
	case strings.TrimSpace(p.Operation) == "":
		return PrivEvidenceMalformed
	default:
		return PrivEvidenceRecorded
	}
}

// describePayload copies the payload into evidence verbatim.
//
// Every value here is carried, not interpreted. None of them contributes a
// point, none of them is compared against a list, and none of them is parsed
// into a conclusion -- the header says why. A reader of the audit record gets
// exactly what the event said, in the event's own words, plus the labels this
// package attaches to say how far the words can be trusted.
func describePayload(p *event.PrivPayload, ev map[string]string) {
	if p == nil {
		return
	}
	if op := strings.TrimSpace(p.Operation); op != "" {
		ev[EvidenceOperation] = op
	}
	if ns := strings.TrimSpace(p.NamespaceType); ns != "" {
		ev[EvidenceNamespaceType] = ns
	}
	if len(p.CapabilitiesAdded) > 0 {
		ev[EvidenceCapabilitiesAdded] = strings.Join(p.CapabilitiesAdded, " ")
		// Stated on every finding that reports capabilities, never inferred
		// from the key's name. A dropped capability produces the same empty
		// list as no change at all, and a reader who assumed otherwise would
		// read "capabilities_added: CAP_SYS_ADMIN" as the whole change.
		ev[EvidenceCapabilityDelta] = CapabilityDeltaAddedOnly
	}

	// The literals travel beside the classification, always, including in the
	// unrecorded case where they are two zeroes. Recording them is what lets a
	// reader see that the classification is a reading of the same two integers
	// they are looking at rather than a separate claim.
	ev[EvidenceUIDTransition] = uidTransition(p.OldUID, p.NewUID)
	ev[EvidenceOldUID] = strconv.FormatInt(int64(p.OldUID), 10)
	ev[EvidenceNewUID] = strconv.FormatInt(int64(p.NewUID), 10)
}

// uidTransition classifies the pair without resolving its ambiguity.
//
// The zero value is load-bearing in two incompatible ways at once -- uid 0 is
// root, and 0 is what an absent omitempty field decodes to -- so three of the
// four states below are statements that the record cannot settle what happened.
// Guessing between them would put a claim about privilege escalation into an
// audit log on the strength of a missing JSON key.
func uidTransition(oldUID, newUID int32) string {
	switch {
	case oldUID == 0 && newUID == 0:
		return UIDTransitionUnrecorded
	case oldUID == 0 || newUID == 0:
		return UIDTransitionAmbiguous
	case oldUID == newUID:
		return UIDTransitionUnchanged
	default:
		return UIDTransitionChanged
	}
}

// TODO(risk): the payload fields are reported and never charged, because no
// probe writes them and no vocabulary defines them. When the privilege decoder
// lands, three of them become scoreable and each is a separate decision:
// whether a transition to uid 0 outweighs the kind's own grade, whether a
// CAP_SYS_ADMIN gain outweighs a CAP_NET_BIND_SERVICE one, and whether entering
// a user namespace differs from entering a mount namespace. None can be settled
// against a vocabulary that does not exist yet.
// TODO(risk): the drift between pkg/event.PrivPayload and
// bpf/include/allseer_event.h -- names against bitmasks, a string operation
// against a __u32 enum, a NamespaceType with no kernel field behind it -- is the
// concrete instance of pkg/event's standing TODO about generating the decoder
// from the shared C layout. Writing the first consumer of the payload is what
// surfaced it; resolving it belongs to pkg/event and bpf, not here.
// TODO(event): OldUID and NewUID are tagged omitempty on a field whose zero
// value is root. Dropping the tag is a one-line change to pkg/event and a
// change to the recorded wire format, which is why it is not made here -- but
// until it is, UIDTransitionAmbiguous is the honest answer to the most
// important privilege transition there is.
