package risk

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"

	"github.com/stringNameMahin/ALLSEER/internal/validator"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
)

// Host sensitivity is the second body of security knowledge in the risk engine,
// and it is arranged as a deliberate parallel to the first: the same list file,
// the same grade vocabulary, the same admission discipline, the same three
// states. What is *not* parallel is the matching, and that difference is the
// whole reason this lives in its own file.
//
// # The vocabulary is the validator's, not a second one
//
// Every pattern here goes through validator.ValidateHostPattern at admission
// and validator.MatchHost at lookup. Not a reimplementation, not a
// glob-flavoured approximation of one — the same functions an envelope's
// network grants are compared with. An entry in this list therefore means
// exactly what an identically written grant means, which is the property
// sensitivity.go established for paths and the property that stops the two
// halves of the system disagreeing about what a host is.
//
// That decision settles the vocabulary questions before they can be answered
// twice, and every answer below is read out of docs/network-matching.md rather
// than chosen here:
//
//	entry                what it covers
//	-------------------  ------------------------------------------------------
//	api.github.com       that name exactly, case-insensitively, trailing dot
//	                     ignored. Whole names only: it does not cover
//	                     evil-github.com, notgithub.com, or api.github.com.evil
//	*.github.com         exactly one additional label — api.github.com, but
//	                     not a.b.github.com and not the apex github.com
//	169.254.169.254      that address, compared as a parsed address, so every
//	                     spelling of it is it; IPv4-mapped IPv6 is unmapped
//	169.254.0.0/16       containment, host bits masked away
//
// **There is deliberately no filesystem-style globbing.** `*.github.com` is a
// wildcard *domain* covering one label, not a `**` covering an arbitrary
// suffix, and `api-*.github.com` is refused rather than quietly treated as a
// prefix match. Path patterns and host patterns look superficially similar and
// mean different things; borrowing the path vocabulary here would produce a
// list that reads like it protects more than it does.
//
// **The apex is not a subdomain and a subdomain is not the apex.** An entry
// intending both writes both, exactly as an envelope granting both writes both.
// Covering the apex from a wildcard would silently widen every entry, and a
// sensitivity list may only ever raise — so a silent widening is a false
// positive on every sibling name rather than a hole, but it is still a claim
// nobody wrote.
//
// # The name/address boundary is respected, not bridged
//
// docs/network-matching.md §1: a name and an address are never assumed to be
// the same thing. MatchHost enforces it, so a name entry can only ever rate an
// observed name and an address entry can only ever rate an observed address.
// Nothing here reverse-resolves, and nothing here treats an address as standing
// in for a name nobody observed.
//
// The consequence is worth stating plainly, because it shapes how the shipped
// list is written: **a destination is rated by the identity the observation
// carries.** When DNS correlation succeeded the observation names the host, and
// only name and wildcard entries can rate it; when correlation failed the
// observation carries the address, and only address and block entries can. An
// entry meant to cover a destination reachable both ways therefore lists both
// spellings — which is why the shipped list carries
// `metadata.google.internal` *and* `169.254.169.254`.
//
// The alternative, rating the correlated name and the literal address together,
// was considered and rejected. It would have closed the gap where a private
// block cannot rate a destination that resolved to a name, at the cost of a
// second rule about which of an observation's fields count as "the
// destination" — and net.dns is the case that breaks it, since its payload
// address is the *resolver* rather than the destination the query is about.
// Two identities scored under one factor would also make "why did this score
// go up" have two possible answers with no way to tell them apart. Listing
// both spellings costs an operator one extra line and keeps the record
// unambiguous.
//
// # What this factor does not do
//
// It does not charge anything for a destination being *uncorrelated*. That an
// address was never resolved to a name is real signal, and it is
// novel_network_destination's signal — the TODO in risk.go has named it since
// before this file existed, and capability.AttrHostnameCorrelated already
// records the fact. Charging it here would put two unrelated findings under one
// factor name. What this factor does is *report* correlation state alongside
// its answer, so an operator reading an `unknown` on an address can see that
// the list might well cover the name and never got the chance to try.

// FactorSensitiveHost is the host-sensitivity factor's name, and it is a wire
// contract like every other factor name.
//
// Separate from sensitive_path rather than folded into it. They read different
// configuration through different matchers with different vocabularies, and an
// operator asking "why is this host rated" should not have to discover that the
// answer lives under a factor named after filesystem paths.
const FactorSensitiveHost = "sensitive_host"

// Evidence keys specific to the sensitive_host factor. The grade, reason,
// target, and not-charged keys are shared with sensitive_path, because they
// answer the same questions about a different resource and a reader should not
// have to learn two spellings of "sensitivity".
const (
	// EvidenceHost is the bare host that was actually rated, extracted from the
	// observation's target. Recorded separately from EvidenceTarget because the
	// target carries a port and the rating never does — MatchHost takes a bare
	// host, and a reader checking this factor by hand needs the value that was
	// passed to it rather than the one it was derived from.
	EvidenceHost = "host"

	// EvidenceHostKind is what the destination was, in the validator's own
	// vocabulary: "name" when DNS correlation gave the observation a hostname,
	// "address" when it did not. It is the field that explains why a name entry
	// did or did not get a chance to match.
	EvidenceHostKind = "host_kind"

	// EvidenceHostnameCorrelated mirrors capability.AttrHostnameCorrelated.
	// Present as "false" only when enrichment recorded that correlation failed,
	// so an unknown on an address is attributable to the gap rather than to the
	// list.
	EvidenceHostnameCorrelated = "hostname_correlated"
)

// Host kind labels carried on the factor. Derived from validator.ClassifyHost
// rather than restated, so the record cannot come to disagree with the matcher
// about what it was looking at.
const (
	HostKindLabelName    = "name"
	HostKindLabelAddress = "address"

	// HostKindLabelUnknown covers a destination the classifier could not read
	// at all — an empty target, or a value that is neither a name nor an
	// address. It is not "no host": it is a destination we cannot interpret,
	// and the same refusal PathSensitivity makes about an unresolved path.
	HostKindLabelUnknown = "unknown"
)

// --- the list -------------------------------------------------------------------

// HostSensitivityEntry grades a set of host patterns, with the reason written
// down.
//
// The same shape as SensitivityEntry, deliberately, so the two halves of the
// file read alike and an operator learns one format. It is a distinct type
// rather than the same one because the two are validated against different
// vocabularies, and a shared type would make it possible to move an entry from
// one section to the other and have it silently mean something else.
type HostSensitivityEntry struct {
	// Patterns are host patterns in validator.ValidateHostPattern's vocabulary:
	// an exact name, a "*." wildcard domain, a literal address, or a CIDR
	// block. Never a filesystem glob.
	Patterns []string `yaml:"patterns" json:"patterns"`

	// Sensitivity is the grade, from the same five-value vocabulary the path
	// entries use. SensitivityUnknown is not writable, for the reason it is not
	// writable there: an entry that grades nothing says nothing.
	Sensitivity capability.Severity `yaml:"sensitivity" json:"sensitivity"`

	// Reason is why reaching this destination is consequential, and it is
	// required. Carried into the audit record, so "why did this score go up" is
	// answered by the sentence its author wrote.
	Reason string `yaml:"reason" json:"reason"`
}

// validateHostEntries is the admission check for the hosts section, and it
// fails closed for the same reasons the path section does.
//
// The one rule that is specific to hosts: an entry may not name a destination
// this build's matcher cannot compare. ValidateHostPattern is called rather
// than approximated, so a pattern refused in an envelope grant is refused here
// too — including the ones that look plausible and are not, such as
// "github.com:443" (a port belongs to the observation, not the host) and
// "api-*.github.com" (a wildcard is only ever a whole leftmost label).
func validateHostEntries(entries []HostSensitivityEntry, source string) error {
	for i, e := range entries {
		where := fmt.Sprintf("host entry #%d in %s", i, source)

		if len(e.Patterns) == 0 {
			return fmt.Errorf("risk: %s has no patterns", where)
		}
		if e.Sensitivity == SensitivityUnknown {
			return fmt.Errorf("risk: %s does not set sensitivity; write it out, since an entry "+
				"that grades nothing is an entry that says nothing", where)
		}
		if !KnownSensitivity(e.Sensitivity) {
			return fmt.Errorf("risk: %s has unknown sensitivity %q; want one of info, low, medium, high, critical",
				where, e.Sensitivity)
		}
		if e.Reason == "" {
			return fmt.Errorf("risk: %s has no reason; every entry in a sensitivity list is a security "+
				"claim, and a claim nobody can review is a claim nobody will remove", where)
		}

		for _, p := range e.Patterns {
			// Called, not reimplemented, so an entry here means exactly what an
			// identically written network grant means.
			if err := validator.ValidateHostPattern(p); err != nil {
				return fmt.Errorf("risk: %s: %w; an unusable pattern matches nothing, "+
					"so the list is refused rather than silently protecting less than it reads", where, err)
			}
		}
	}
	return nil
}

// hostRule is one compiled host pattern with the grade and reason behind it.
//
// A flat slice rather than a compiled set, unlike the path side. The scan calls
// validator.MatchHost per pattern, which is the whole point: MatchHost owns the
// name/address boundary, IPv4-mapped unmapping, wildcard label counting, and
// case folding, and a compiled shortcut here would be a second implementation
// of all four with permission to drift. The slice is ordered highest-grade
// first at construction so the first match is the highest-grade match, exactly
// as the path set is.
type hostRule struct {
	pattern string
	grade   capability.Severity
	reason  string

	// kind is the pattern's classification, computed once. It is used only to
	// skip rules that cannot possibly match the observation's kind — see
	// canCompare — and never to decide a match, which stays MatchHost's job.
	kind validator.HostKind
}

// compileHostRules flattens the entries into the scan order.
//
// Highest grade first, ties broken by declaration order, stable — so a list
// loaded twice produces one oracle. The reason a matched entry names travels
// into the audit record, and a record whose explanation depends on an unstable
// sort is not reproducible.
func compileHostRules(entries []HostSensitivityEntry) []hostRule {
	ordered := make([]int, len(entries))
	for i := range ordered {
		ordered[i] = i
	}
	sort.SliceStable(ordered, func(a, b int) bool {
		return severityRank(entries[ordered[a]].Sensitivity) > severityRank(entries[ordered[b]].Sensitivity)
	})

	var out []hostRule
	for _, idx := range ordered {
		e := entries[idx]
		for _, p := range e.Patterns {
			out = append(out, hostRule{
				pattern: p,
				grade:   e.Sensitivity,
				reason:  e.Reason,
				kind:    validator.ClassifyHost(p),
			})
		}
	}
	return out
}

// canCompare reports whether a pattern of this kind could match an observation
// of that kind.
//
// It is the name/address boundary of docs/network-matching.md §1, and it is
// used purely to skip work: MatchHost enforces the same boundary and would
// return false for every pair this rejects, so declining to ask is provably
// equivalent to asking and being told no.
//
// The skip is worth having because it is not free to ask. MatchHost classifies
// the observation on every call, and classifying a name means attempting to
// parse it as an address first — which fails, and allocates. Scanning a
// twenty-entry list for a named destination measured at 6 µs and 107
// allocations before this; every one of those parses was answering a question
// the boundary had already settled.
func canCompare(pattern, observed validator.HostKind) bool {
	switch observed {
	case validator.HostKindName:
		return pattern == validator.HostKindName || pattern == validator.HostKindWildcard
	case validator.HostKindIP:
		return pattern == validator.HostKindIP || pattern == validator.HostKindCIDR
	}
	return false
}

// --- the scorer -------------------------------------------------------------------

// SensitiveHostScorer weighs how consequential the destination reached is.
//
// The network counterpart of SensitivePathScorer, and arranged the same way: it
// reads the SensitivityOracle and nothing else, it does not consult the
// envelope, and it carries no list of its own.
//
// It uses the same point table as sensitive_path, and that is a decision rather
// than an omission. The grades mean one thing — how consequential this resource
// is — and pricing the same word differently depending on whether it describes
// a file or a host would be two models of one question, which is the drift
// score.go already refuses when it declines to re-derive violation severity. The
// argument for pricing hosts higher is that egress is the higher-consequence
// operation, and that argument is already paid: violation_severity folds in the
// capability catalog's baseline, where net.connect and net.send are `high` and
// fs.read is `low`. Charging it a second time here would count one fact twice.
type SensitiveHostScorer struct{ oracle SensitivityOracle }

var (
	_ Scorer      = SensitiveHostScorer{}
	_ localScorer = SensitiveHostScorer{}
)

// NewSensitiveHostScorer wraps an oracle as a standalone scorer.
//
// A nil oracle is refused rather than defaulted away, for the reason
// NewEngineWithOracle refuses one: a scorer that rated nothing while looking
// configured is the failure the whole sensitivity file is arranged to prevent.
func NewSensitiveHostScorer(o SensitivityOracle) (SensitiveHostScorer, error) {
	if o == nil {
		return SensitiveHostScorer{}, errors.New("risk: sensitive_host scorer needs a sensitivity oracle")
	}
	return SensitiveHostScorer{oracle: o}, nil
}

// Name identifies the factor this scorer produces.
func (SensitiveHostScorer) Name() string { return FactorSensitiveHost }

// Weight is the most this scorer can contribute.
func (SensitiveHostScorer) Weight() float64 { return sensitivityPoints[capability.SeverityCritical] }

// Evaluate returns the host sensitivity factor, or nil when the event did not
// reach a network destination.
func (s SensitiveHostScorer) Evaluate(_ context.Context, req ScoreRequest) (*decision.Factor, error) {
	if req.Validation == nil {
		return nil, ErrNoValidation
	}
	f, applied, err := s.evaluate(newScoreCtx(req))
	if err != nil || !applied {
		return nil, err
	}
	return &f, nil
}

// evaluate produces a factor for every network event and for no other event.
//
// The domain gate is the whole of its applicability: a filesystem read has no
// destination, so reporting "host: unknown" on one would be an answer to a
// question nobody asked. Within the network domain it never goes silent, for
// the reason SensitivePathScorer never goes silent within the filesystem
// domain — silence would be indistinguishable from an engine built with no host
// ratings, and those are different claims. Three states, kept apart:
//
//	no sensitive_host factor at all   nothing rates hosts in this build
//	factor reading "unknown"          asked, and this destination is on no list
//	factor carrying a grade           asked, rated, and the author's reason with it
//
// Points are withheld — not the finding — for an event the envelope covered,
// exactly as on the path side. A grant naming a consequential destination is
// the envelope author's decision, and the place to challenge it is envelope
// linting rather than a risk score; charging it here would break the invariant
// that an expected event scores exactly zero.
func (s SensitiveHostScorer) evaluate(sc *scoreCtx) (decision.Factor, bool, error) {
	if s.oracle == nil {
		// Only reachable through a hand-built scorer set. Refused rather than
		// reported as unknown: an unknown is a statement about a destination,
		// and this is a statement about the wiring.
		return decision.Factor{}, false, errors.New("risk: sensitive_host scorer has no oracle")
	}
	if dimensionFor(sc.kind) != DimensionHost {
		return decision.Factor{}, false, nil
	}

	// The observation's target is "host:port" for an endpoint and a bare name
	// for a DNS query. MatchHost takes a bare host and the caller splits, which
	// docs/network-matching.md §2 states and this is the caller.
	host := bareHost(sc.target)
	kind := hostKindLabel(host)

	ev := map[string]string{
		EvidenceDimension: DimensionHost,
		EvidenceTarget:    sc.target,
		EvidenceHost:      host,
		EvidenceHostKind:  kind,
	}
	// Correlation state is reported rather than inferred from the target's
	// shape, because enrichment already wrote it down and reading the fact is
	// less error-prone than re-deriving it. It qualifies the answer and never
	// changes it: an uncorrelated destination is novel_network_destination's
	// business, not this factor's.
	if sc.req.Event != nil {
		if v, ok := sc.req.Event.Observation.Attributes[capability.AttrHostnameCorrelated]; ok {
			ev[EvidenceHostnameCorrelated] = v
		}
	}

	grade := s.oracle.HostSensitivity(host)
	if grade == SensitivityUnknown {
		ev[EvidenceSensitivity] = SensitivityUnknownLabel
		return decision.Factor{
			Name:        FactorSensitiveHost,
			Weight:      0,
			Description: "how consequential the destination reached is; this one is unrated",
			Evidence:    ev,
		}, true, nil
	}

	ev[EvidenceSensitivity] = string(grade)
	if o, ok := s.oracle.(interface {
		HostSensitivityReason(string) (capability.Severity, string)
	}); ok {
		if _, reason := o.HostSensitivityReason(host); reason != "" {
			ev[EvidenceReason] = reason
		}
	}

	points := sensitivityPointsFor(grade)
	if !sc.departed {
		points = 0
		ev[EvidenceNotCharged] = "the envelope covered this operation"
	}

	return decision.Factor{
		Name:        FactorSensitiveHost,
		Weight:      points,
		Description: "how consequential the destination reached is",
		Evidence:    ev,
	}, true, nil
}

// bareHost strips the port from an observation target.
//
// The target is "host:port" for an endpoint, "[v6]:port" for an IPv6 endpoint,
// and a bare name for a DNS query, which resolve.observeNetwork builds with
// net.JoinHostPort precisely so it can be split back apart. A value that does
// not split is used as it stands: a bare IPv6 literal has colons and no port,
// and SplitHostPort refuses it, which must not turn a legitimate destination
// into an empty one.
func bareHost(target string) string {
	if target == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(target); err == nil {
		return h
	}
	return target
}

// hostKindLabel reports what the destination is, in the matcher's own terms.
//
// A block or a wildcard in the observed position means something upstream
// passed a pattern where a fact belongs, so both fall to unknown alongside the
// genuinely uninterpretable — the same judgement MatchHost makes about an
// observation.
func hostKindLabel(host string) string {
	switch validator.ClassifyHost(host) {
	case validator.HostKindName:
		return HostKindLabelName
	case validator.HostKindIP:
		return HostKindLabelAddress
	default:
		return HostKindLabelUnknown
	}
}

// ratesHosts reports whether an oracle has any host knowledge to offer.
//
// The probe is what keeps the first of the three states honest. An oracle built
// from a list with no hosts section answers "unknown" to every destination, and
// so does an oracle that was never taught this particular host — but those are
// different claims, and emitting a factor for the first would say "we asked and
// do not know" about a build where nobody was ever taught any host at all.
//
// An oracle that does not implement the probe is assumed to rate hosts. That is
// the safe direction: it means the factor is emitted and reports whatever the
// oracle actually said, which is true of any oracle we genuinely queried. Only
// a type that can state its own emptiness gets to suppress the factor.
func ratesHosts(o SensitivityOracle) bool {
	if o == nil {
		return false
	}
	if r, ok := o.(interface{ RatesHosts() bool }); ok {
		return r.RatesHosts()
	}
	return true
}

// TODO(risk): the scan is linear in the number of host entries and still calls
// validator.MatchHost per comparable pattern, which re-classifies both sides
// every time. Measured against the shipped list:
//
//	destination            ns/op    allocs
//	---------------------  -------  ------
//	rated by address        850      8      first match, addresses scanned first
//	unrated address        ~3000     8      every address rule, no match
//	rated by name          ~3900    67      every name rule, matched last
//
// The address cases are already cheap, because canCompare skips the name rules
// outright. The name case is not: fourteen name and wildcard rules each cost a
// MatchHost call that re-parses both sides, and an `info`-rated registry is
// matched last precisely because the highest grade is scanned first.
//
// The residual is left standing deliberately. Removing it means classifying the
// patterns *and* the observation once and comparing the compiled forms, which
// is validator.PatternSet's shape and belongs in internal/validator beside the
// semantics it would be caching — a second matcher in this package would be
// free to drift from MatchHost, which is the one thing this file is arranged
// not to do. Affordable meanwhile: network events are a minority of a session,
// and the whole pipeline is ~5 µs.
// TODO(risk): the credential-access-to-egress detector still asks nothing of
// the destination. It now could: an egress to a critical-rated host after a
// credential read is a materially different finding from one to a host rated
// info, and sequence.go's TODO has been waiting for exactly this. Deliberately
// not wired in the same change that introduces the ratings, so that any
// movement in the sequence detector's own numbers is attributable.
