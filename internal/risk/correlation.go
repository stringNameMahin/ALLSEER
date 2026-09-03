package risk

import (
	"context"

	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
)

// This file scores one fact the telemetry already carries and nothing else:
// the destination was observed as a literal address, and no hostname was
// correlated to it.
//
// # What it is, and the four things it is not
//
// docs/network-matching.md section 1 states the rule the whole network side is built
// on -- a name and an address are never assumed to be the same thing -- and names
// the consequence: when an envelope grants a hostname and the observation
// carries only an address, matching answers no, and "that false is not an
// accusation ... so upstream can escalate an uncorrelated connection to the risk
// engine, which weighs it in context". This scorer is that escalation. It is
// the only place the project weighs the correlation gap rather than merely
// reporting it.
//
// The gap matters because of what causes it. DNS-over-HTTPS, a hardcoded
// address, an expired cache entry, and a host reached by an unrelated name all
// defeat correlation -- and so does an agent that resolves names out of band on
// purpose. section 1 again: any other answer "makes skipping DNS the easiest way to
// evade a network grant, and nothing in the log would look wrong". An address
// with no name behind it is the shape that evasion takes, and it is also the
// shape a great deal of honest tooling takes, which is why it is worth five
// points and not fifty.
//
// It is emphatically not four adjacent things, each of which already has an
// owner:
//
//   - **Not novelty.** novel_target answers "has this session touched this
//     before" from History.TargetSeen. This scorer reads no history at all and
//     would give the same answer on the session's first event and its ten
//     thousandth.
//   - **Not sensitivity.** sensitive_host answers "is this destination
//     consequential" from the configured list. This scorer consults no list and
//     has no configuration.
//   - **Not a verdict.** Whether the envelope covered the connection is the
//     validator's answer, already charged by the verdict factor.
//   - **Not an accusation.** An uncorrelated destination is a gap in what we
//     know, not a finding about where the agent went. The factor name says
//     "uncorrelated", which is what was observed, rather than "unknown host" or
//     "suspicious destination", which are conclusions the evidence does not
//     support.
//
// # Why novel_network_destination is not this scorer, and is not coming
//
// The planned scorer list in docs/roadmap.md names novel_network_destination,
// and docs/milestones.md specifies it as "using risk.History.TargetSeen". That
// specification predates NovelTargetScorer, which implements exactly that
// mechanism, is domain-agnostic, and already fires on network events --
// registry.npmjs.org alone produces three separate novelty findings in the npm
// recording, one per capability that touched it. Implementing the planned
// scorer would have been a second factor computing an existing predicate over
// the same map for a subset of events. It is closed as a duplicate; this file
// is the distinct network signal that analysis actually turned up.

// FactorUncorrelatedDestination is the factor's name, and it is a wire contract
// like every other factor name.
//
// Named for the observation rather than for a conclusion. "unknown_host" would
// collide with the sensitivity list's own unknown state, which is a different
// question with a different owner, and "suspicious_destination" would put a
// verdict in the record that a missing DNS answer does not support.
const FactorUncorrelatedDestination = "uncorrelated_destination"

// UncorrelatedDestinationPoints is what an uncorrelated destination contributes.
//
// **No point value for this signal is specified anywhere in the repository**,
// and this one is therefore chosen rather than derived. The only number the
// tree carries under a related name is `novel_network_destination: 1.0` in
// configs/allseerd.example.yaml, which is a scorer *weight* multiplier for a
// scorer that was never built, in a config type nothing loads yet -- not a point
// value, and not for this scorer.
//
// So it is set to the smallest non-zero contribution the model already uses,
// which is NovelTargetPoints, and it is set there because that constant's own
// reasoning transfers exactly: "First contact with a target is weak evidence ...
// it earns its place by sharpening events that are already departures rather
// than by carrying a verdict on its own." An uncorrelated destination is weak
// evidence in precisely the same way. DNS-over-HTTPS is ordinary, hardcoded
// addresses appear in honest tooling, and a probe that missed the DNS exchange
// produces the same observation as an agent that skipped it deliberately.
//
// Five points cannot move an event between risk levels on its own from any
// starting point in the shipped model, and that is the intended property: this
// is a qualifier on a departure, not a departure.
const UncorrelatedDestinationPoints = NovelTargetPoints

// Evidence keys on the uncorrelated_destination factor.
//
// The destination, host, and not-charged keys are shared with sensitive_host,
// because they answer the same questions about the same resource and a reader
// should not have to learn two spellings of "which host".
const (
	// EvidenceCapability names the capability that reached the destination. The
	// same key novel_target writes, so one vocabulary describes both.
	EvidenceCapability = "capability"

	// EvidenceCorrelation is what the observation says about correlation, in
	// the three-state vocabulary below. It is the field that distinguishes a
	// recorded failure from an observation that never spoke.
	EvidenceCorrelation = "correlation"

	// EvidenceDestIP mirrors capability.AttrDestIP: the literal address the
	// kernel connected to, which is the one thing about the destination that is
	// never best-effort. Carried so an operator can act on the finding -- an
	// address is what you look up, block, or search the audit log for.
	EvidenceDestIP = "dest_ip"
)

// Correlation states carried on the factor.
//
// The three-state distinction is the same one the sensitivity list keeps
// between rated, unrated, and unasked, and it is kept for the same reason:
// collapsing "we know correlation failed" into "we cannot tell" would let a
// gap in enrichment read as a finding about the agent, and collapsing it the
// other way would let a real evasion read as a shrug.
const (
	// CorrelationLabelMissing: enrichment recorded that correlation failed and
	// the observation carries an address. This is the case the factor charges.
	CorrelationLabelMissing = "missing"

	// CorrelationLabelIndeterminate: the observation does not establish
	// correlation either way. Reported, and charged nothing -- missing evidence
	// is never silently converted into a finding.
	CorrelationLabelIndeterminate = "indeterminate"
)

// correlationState is what the observation establishes about correlation.
type correlationState int

const (
	// correlationPresent: the destination is named, so correlation succeeded.
	// The name in the target is the evidence; nothing needs to be said.
	correlationPresent correlationState = iota

	// correlationMissing: the address is there and the flag says the name is not.
	correlationMissing

	// correlationIndeterminate: the observation contradicts itself, or does not
	// carry the flag on an address destination, or names no destination at all.
	correlationIndeterminate
)

// classifyCorrelation reads what the observation establishes, and refuses to
// read more than that.
//
// Two canonical shapes come out of telemetry.resolve, and everything else is
// indeterminate on purpose:
//
//	target host   AttrHostnameCorrelated   state            why
//	-----------   ----------------------   --------------   ----------------------
//	a name        absent                   present          correlation succeeded, and
//	                                                        the name proves it
//	an address    "false"                  missing          enrichment said so, and the
//	                                                        target agrees
//	an address    absent                   indeterminate    resolve.observeNetwork always
//	                                                        writes the flag beside an
//	                                                        address target, so an
//	                                                        observation that did not is one
//	                                                        this build did not produce
//	a name        "false"                  indeterminate    contradictory: the flag says
//	                                                        correlation failed and the
//	                                                        target carries a name
//	anything      any other value          indeterminate    the attribute's vocabulary is
//	                                                        "false" or absent; a third
//	                                                        value is not this build's
//	unclassifiable  any                    indeterminate    no destination to speak about
//
// The absent-flag-with-a-name row is the one worth pausing on. pkg/capability
// documents the attribute as "Absent when correlation succeeded", so absence is
// a positive claim in the wire contract -- but this package's first rule is that
// absence of evidence is never evidence of safety, and the two would collide if
// absence alone were read as success. They do not collide here, because absence
// is only ever read as success *alongside a named target*, which is independent
// evidence that a name was recovered. Absence beside an address gets the honest
// answer instead.
func classifyCorrelation(obs capability.Observation, hostKind string) correlationState {
	flag, flagged := obs.Attributes[capability.AttrHostnameCorrelated]

	switch {
	case flagged && flag != "false":
		// A vocabulary this build does not write. Refused rather than guessed,
		// the same answer sensitivityPointsFor gives an unrecognized grade.
		return correlationIndeterminate

	case hostKind == HostKindLabelName:
		if flagged {
			return correlationIndeterminate
		}
		return correlationPresent

	case hostKind == HostKindLabelAddress:
		if flagged {
			return correlationMissing
		}
		return correlationIndeterminate

	default:
		return correlationIndeterminate
	}
}

// namesRemoteDestination reports whether a capability's observation names a
// remote destination the agent selected.
//
// Deliberately its own predicate rather than a call to IsEgress, even though
// the two currently name the same pair. They are different questions -- "does
// this move data off the host" and "does this observation name a destination
// the agent chose" -- and the day one of them changes, the other should have to
// change on purpose. TestTheQualifyingSetMatchesEgressToday pins the present
// coincidence so a divergence is deliberate rather than accidental.
//
// Every other network capability is excluded, and each exclusion is a claim:
//
//   - net.dns is excluded even though its payload carries an address, because
//     that address is the *resolver* rather than a destination the agent chose.
//     resolve.observeNetwork already special-cases the same distinction --
//     "A DNS query acts on a name, not on an endpoint" -- and scoring the
//     resolver here would make every lookup on a host with no reverse-mapped
//     stub resolver an uncorrelated destination.
//   - net.bind and net.listen act on a *local* address. There is no remote
//     destination to have failed to correlate.
//   - net.accept is an inbound connection the agent did not choose, so an
//     unresolved peer is a fact about whoever dialled in.
//   - net.receive is the return path of a connection net.connect already
//     reported. Charging it again would count one destination twice.
//   - net.rawsocket is socket creation, not a destination.
//
// The last four are also excluded on a second ground worth stating plainly: no
// probe exists yet, so what a bind, listen, accept, or raw-socket event will
// actually carry in NetworkPayload.DestAddr is unspecified. Scoring a field
// whose meaning has not been decided would be scoring a guess.
func namesRemoteDestination(k capability.Kind) bool {
	switch k {
	case capability.KindNetConnect, capability.KindNetSend:
		return true
	}
	return false
}

// UncorrelatedDestinationScorer weighs a destination known only by address.
//
// The cheapest scorer in the set: it reads two fields of an observation the
// resolver already produced, consults no list, no history, and no envelope, and
// allocates one evidence map only on the events it speaks about. Stateless, so
// the zero value works and it is trivially safe for concurrent use.
//
// It needs no SensitivityOracle, which is why it is in every engine rather than
// only the oracle-backed ones. The evidence it reads is telemetry, and telemetry
// is present whether or not a deployment has written a list.
type UncorrelatedDestinationScorer struct{}

var (
	_ Scorer      = UncorrelatedDestinationScorer{}
	_ localScorer = UncorrelatedDestinationScorer{}
)

// Name identifies the factor this scorer produces.
func (UncorrelatedDestinationScorer) Name() string { return FactorUncorrelatedDestination }

// Weight is the most this scorer can contribute.
func (UncorrelatedDestinationScorer) Weight() float64 { return UncorrelatedDestinationPoints }

// Evaluate returns the correlation factor, or nil when it does not apply.
func (s UncorrelatedDestinationScorer) Evaluate(_ context.Context, req ScoreRequest) (*decision.Factor, error) {
	if req.Validation == nil {
		return nil, ErrNoValidation
	}
	f, applied, err := s.evaluate(newScoreCtx(req))
	if err != nil || !applied {
		return nil, err
	}
	return &f, nil
}

// evaluate speaks only about events that name a remote destination.
//
// Silence means one of two things and never a third: the capability does not
// name a destination the agent chose, or the destination is named and
// correlation therefore succeeded. It never means "we did not look" -- this
// scorer is in every engine and has nothing to be configured with, so there is
// no build in which it could be absent while network events flow.
//
// Points are withheld -- not the finding -- for an event the envelope covered,
// exactly as on the sensitivity side, so the invariant that an expected event
// scores exactly zero holds. That case is reachable and worth recording: an
// envelope that grants a destination by address is *supposed* to be reached by
// address, and an auditor should be able to see that the grant matched with no
// name behind it.
func (UncorrelatedDestinationScorer) evaluate(sc *scoreCtx) (decision.Factor, bool, error) {
	if !namesRemoteDestination(sc.kind) {
		return decision.Factor{}, false, nil
	}

	var obs capability.Observation
	if sc.req.Event != nil {
		obs = sc.req.Event.Observation
	}

	host := bareHost(sc.target)
	hostKind := hostKindLabel(host)

	state := classifyCorrelation(obs, hostKind)
	if state == correlationPresent {
		return decision.Factor{}, false, nil
	}

	ev := map[string]string{
		EvidenceCapability: string(sc.kind),
		EvidenceTarget:     sc.target,
		EvidenceHostKind:   hostKind,
	}
	if host != "" {
		ev[EvidenceHost] = host
	}
	// The literal address the kernel is certain of, read from the observation
	// rather than re-derived from the target: for an uncorrelated destination
	// the two are the same string, and for an indeterminate one they may not be,
	// in which case recording both is what makes the disagreement visible.
	if ip := obs.Attributes[capability.AttrDestIP]; ip != "" {
		ev[EvidenceDestIP] = ip
	}

	if state == correlationIndeterminate {
		ev[EvidenceCorrelation] = CorrelationLabelIndeterminate
		return decision.Factor{
			Name:   FactorUncorrelatedDestination,
			Weight: 0,
			Description: "whether a hostname was correlated to this destination could not be " +
				"established from the observation",
			Evidence: ev,
		}, true, nil
	}

	ev[EvidenceCorrelation] = CorrelationLabelMissing
	points := UncorrelatedDestinationPoints
	if !sc.departed {
		points = 0
		ev[EvidenceNotCharged] = "the envelope covered this operation"
	}

	return decision.Factor{
		Name:   FactorUncorrelatedDestination,
		Weight: points,
		Description: "the destination was reached by address with no correlated hostname, so a " +
			"grant naming hosts could not be compared against it",
		Evidence: ev,
	}, true, nil
}

// TODO(risk): the four excluded network capabilities should be revisited when
// probes exist for them. Whether a net.accept peer or a net.bind local address
// belongs in this signal is a question about what those events will carry, and
// that has not been decided -- see pkg/event's TODO on generating the decoder
// from the shared C struct layout.
// TODO(risk): an uncorrelated destination and a *correlated* one are worth
// different amounts, and this scorer only charges the first. Whether a
// correlated destination should ever reduce a score is a live question and the
// answer here is no, for the reason the sensitivity list may only raise: a
// factor that could subtract would make "resolve the name first" a way to
// launder a connection.
