package validator

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/stringNameMahin/ALLSEER/pkg/capability"
)

// Precedence decides which envelope entry governs an observation when several
// cover it.
//
// It matters more than "any grant covers it, so allow it" suggests, because the
// winner is reported and charged:
//
//   - Result.MatchedGrant is what a human reads when asking why an operation was
//     permitted, and what the audit log preserves. Naming a broad catch-all
//     grant where a narrow purpose-built one also applied makes the envelope
//     look sloppier than it is, and hides which stated purpose the operation
//     actually served.
//   - Selector.MaxCount is per grant, so which counter is charged determines
//     when a budget runs out.
//   - A non-optional grant never exercised is worth reporting at session end.
//     That signal is only as good as the attribution.
//
// Two rules, in order:
//
//  1. Denials always override grants, regardless of specificity.
//  2. Within a class, the most specific entry wins; ties break toward the
//     earlier position in the envelope.
//
// See docs/grant-precedence.md for the full specification.

// Match is one envelope entry that covered an observation, with its position in
// the envelope's Grants or Denials slice.
//
// Index is carried because it is the final, always-available tiebreak, and
// because SessionState.GrantUseCount is keyed by it.
type Match struct {
	Index int
	Grant *capability.Grant
}

// Resolution is the outcome of applying precedence.
type Resolution struct {
	// Winner is the entry that governs, or nil when nothing matched.
	Winner *Match

	// Denied reports that Winner came from the envelope's denials.
	Denied bool

	// Reason explains how the winner was chosen, for the reasoning chain that
	// reaches the audit log. A decision nobody can follow is not defensible
	// months later.
	Reason string
}

// ResolvePrecedence picks the entry that governs an observation.
//
// Both arguments hold only entries that already matched. Matching is the
// Matcher's job; this function decides between the results, which keeps the
// ordering rules testable without a matcher and keeps them from being
// reimplemented differently at each call site.
func ResolvePrecedence(grants, denials []Match) Resolution {
	// A denial that matched wins outright. Specificity does not enter into it:
	// denials exist as carve-outs from grants broad enough to swallow them, so
	// letting a narrower grant outrank a denial would invert exactly the intent
	// the author wrote the denial to express.
	if len(denials) > 0 {
		winner, why := mostSpecific(denials)
		return Resolution{
			Winner: winner,
			Denied: true,
			Reason: "explicit denial overrides any matching grant: " + why,
		}
	}

	if len(grants) > 0 {
		winner, why := mostSpecific(grants)
		return Resolution{Winner: winner, Reason: why}
	}

	return Resolution{Reason: "no grant or denial matched"}
}

// mostSpecific returns the narrowest entry and an explanation of what decided
// it. Callers guarantee a non-empty slice.
func mostSpecific(matches []Match) (*Match, string) {
	best := pickNarrowest(matches, -1)
	if len(matches) == 1 {
		return &matches[best], fmt.Sprintf("entry %d, the only match", matches[best].Index)
	}

	// Explain against the runner-up rather than against whichever entry the
	// winner last displaced: the reason a human wants is what separated the
	// top two.
	runnerUp := pickNarrowest(matches, best)
	cmp, dim := compareSpecificity(
		SpecificityOf(*matches[best].Grant),
		SpecificityOf(*matches[runnerUp].Grant),
	)
	if cmp == 0 {
		return &matches[best], fmt.Sprintf("entry %d, the earliest of %d equally specific matches",
			matches[best].Index, len(matches))
	}
	return &matches[best], fmt.Sprintf("entry %d, the most specific of %d matches (decided by %s)",
		matches[best].Index, len(matches), dimensionNames[dim])
}

// pickNarrowest returns the position of the narrowest entry, skipping skip.
//
// Equally specific entries resolve to the lower envelope Index, not to whichever
// arrived first in the slice. The winner therefore does not depend on the order
// the matcher happened to collect matches in, nor on a sort's stability.
func pickNarrowest(matches []Match, skip int) int {
	best := -1
	var bestSpec Specificity

	for i := range matches {
		if i == skip {
			continue
		}
		spec := SpecificityOf(*matches[i].Grant)
		if best < 0 {
			best, bestSpec = i, spec
			continue
		}
		cmp, _ := compareSpecificity(spec, bestSpec)
		if cmp > 0 || (cmp == 0 && matches[i].Index < matches[best].Index) {
			best, bestSpec = i, spec
		}
	}
	return best
}

// Specificity measures how narrow a grant's selector is.
//
// A grant is exactly as broad as its broadest selector: a grant listing both
// /ws/src/** and /** permits everything, and calling it specific because one of
// its patterns is narrow would let a catch-all outrank a purpose-built grant by
// carrying a decorative narrow pattern alongside.
//
// The dimensions are compared in a fixed order, documented in
// docs/grant-precedence.md. The order is part of the specification: a change to
// it changes which grant an audit log names.
type Specificity struct {
	dims [numDimensions]int
}

// Dimension indices, in comparison order. Higher values are always narrower.
const (
	dimPathDepth int = iota
	dimPathTerminal
	dimPathSegments

	dimExecDepth
	dimExecTerminal
	dimExecSegments

	dimHostRank
	dimHostPrecision

	dimPortConstrained
	dimPortPrecision

	dimProtocolConstrained
	dimProtocolPrecision

	dimArgsConstrained

	dimCountBounded
	dimCountPrecision

	numDimensions
)

var dimensionNames = [numDimensions]string{
	dimPathDepth:           "path anchor depth",
	dimPathTerminal:        "path recursion",
	dimPathSegments:        "path length",
	dimExecDepth:           "executable anchor depth",
	dimExecTerminal:        "executable recursion",
	dimExecSegments:        "executable path length",
	dimHostRank:            "host exactness",
	dimHostPrecision:       "host precision",
	dimPortConstrained:     "port constraint",
	dimPortPrecision:       "port count",
	dimProtocolConstrained: "protocol constraint",
	dimProtocolPrecision:   "protocol count",
	dimArgsConstrained:     "argument constraint",
	dimCountBounded:        "use limit",
	dimCountPrecision:      "use limit size",
}

// SpecificityOf measures a grant's selector.
//
// Only entries that already matched reach precedence, so a selector dimension
// left empty is genuinely unconstrained rather than merely unmatched, and
// scores zero — the broadest possible value.
func SpecificityOf(g capability.Grant) Specificity {
	var s Specificity
	sel := g.Selector

	if p, ok := broadestPathPattern(sel.PathPatterns); ok {
		s.dims[dimPathDepth] = p.depth
		s.dims[dimPathTerminal] = p.terminal
		s.dims[dimPathSegments] = p.segments
	}
	if p, ok := broadestPathPattern(sel.Executables); ok {
		s.dims[dimExecDepth] = p.depth
		s.dims[dimExecTerminal] = p.terminal
		s.dims[dimExecSegments] = p.segments
	}
	if rank, precision, ok := broadestHostPattern(sel.Hosts); ok {
		s.dims[dimHostRank] = rank
		s.dims[dimHostPrecision] = precision
	}

	if len(sel.Ports) > 0 {
		s.dims[dimPortConstrained] = 1
		// Negated: a longer list permits more.
		s.dims[dimPortPrecision] = -len(sel.Ports)
	}
	if len(sel.Protocols) > 0 {
		s.dims[dimProtocolConstrained] = 1
		s.dims[dimProtocolPrecision] = -len(sel.Protocols)
	}
	if len(sel.ArgPatterns) > 0 {
		// Constrained or not, and nothing finer. Argument matching is a
		// readability convenience and never a security boundary, so letting it
		// outrank a real narrowing would misreport which control applied.
		s.dims[dimArgsConstrained] = 1
	}
	if sel.MaxCount > 0 {
		s.dims[dimCountBounded] = 1
		s.dims[dimCountPrecision] = -sel.MaxCount
	}

	return s
}

// CompareSpecificity orders two measurements: positive when a is narrower than
// b, negative when b is narrower, zero when they are equally specific.
func CompareSpecificity(a, b Specificity) int {
	cmp, _ := compareSpecificity(a, b)
	return cmp
}

// compareSpecificity also reports which dimension decided, for the reasoning
// chain. The deciding dimension is meaningless when the result is zero.
func compareSpecificity(a, b Specificity) (int, int) {
	for i := range numDimensions {
		switch {
		case a.dims[i] > b.dims[i]:
			return 1, i
		case a.dims[i] < b.dims[i]:
			return -1, i
		}
	}
	return 0, 0
}

// String renders the non-zero dimensions, so a surprising precedence outcome
// can be traced without a debugger.
func (s Specificity) String() string {
	var parts []string
	for i := range numDimensions {
		if s.dims[i] != 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", dimensionNames[i], s.dims[i]))
		}
	}
	if len(parts) == 0 {
		return "unconstrained"
	}
	return strings.Join(parts, " ")
}

// pathScore measures one path pattern.
type pathScore struct {
	// depth is how many leading segments are literal, which is how far the
	// pattern is anchored before any wildcard widens it.
	depth int

	// terminal is 1 when the pattern cannot span arbitrary depth, i.e. it holds
	// no **.
	terminal int

	// segments is the pattern's total length, which separates patterns that
	// are otherwise equally anchored.
	segments int
}

func comparePathScore(a, b pathScore) int {
	switch {
	case a.depth != b.depth:
		return a.depth - b.depth
	case a.terminal != b.terminal:
		return a.terminal - b.terminal
	default:
		return a.segments - b.segments
	}
}

// broadestPathPattern scores the widest usable pattern in the list.
//
// Invalid patterns are skipped rather than counted as maximally broad: a
// pattern that cannot be parsed matches nothing, so it widens nothing. A grant
// whose patterns are all invalid never matches and so never reaches precedence.
func broadestPathPattern(patterns []string) (pathScore, bool) {
	var broadest pathScore
	found := false

	for _, p := range patterns {
		score, ok := scorePathPattern(p)
		if !ok {
			continue
		}
		if !found || comparePathScore(score, broadest) < 0 {
			broadest, found = score, true
		}
	}
	return broadest, found
}

func scorePathPattern(pattern string) (pathScore, bool) {
	if ValidatePattern(pattern) != nil {
		return pathScore{}, false
	}

	segs := segments(normalize(pattern))
	score := pathScore{terminal: 1, segments: len(segs)}
	for _, seg := range segs {
		if seg == "**" {
			score.terminal = 0
		}
	}
	for _, seg := range segs {
		if strings.ContainsAny(seg, "*?[") {
			break
		}
		score.depth++
	}
	return score, true
}

// Host exactness ranks, ordered by how many destinations a pattern can cover.
const (
	hostRankBlock    = 1 // a CIDR block: many addresses
	hostRankWildcard = 2 // a wildcard domain: many names
	hostRankExact    = 3 // one name or one address
)

// broadestHostPattern scores the widest usable host pattern, as (rank,
// precision). Invalid patterns are skipped, for the same reason as paths.
func broadestHostPattern(patterns []string) (rank, precision int, ok bool) {
	for _, p := range patterns {
		r, prec, valid := scoreHostPattern(p)
		if !valid {
			continue
		}
		if !ok || r < rank || (r == rank && prec < precision) {
			rank, precision, ok = r, prec, true
		}
	}
	return rank, precision, ok
}

func scoreHostPattern(pattern string) (rank, precision int, ok bool) {
	switch ClassifyHost(pattern) {
	case HostKindIP:
		// One address. Label counting would be meaningless here, and an exact
		// name is no narrower than an exact address, so both score the same.
		return hostRankExact, 0, true

	case HostKindName:
		return hostRankExact, 0, true

	case HostKindCIDR:
		prefix, err := netip.ParsePrefix(pattern)
		if err != nil {
			return 0, 0, false
		}
		if prefix.Bits() == prefix.Addr().BitLen() {
			// A full-length prefix is a single address however it is written.
			return hostRankExact, 0, true
		}
		// More prefix bits, fewer addresses.
		return hostRankBlock, prefix.Bits(), true

	case HostKindWildcard:
		// A longer suffix covers fewer names: *.a.github.com is narrower than
		// *.github.com.
		suffix := strings.TrimSuffix(pattern[len("*."):], ".")
		return hostRankWildcard, strings.Count(suffix, ".") + 1, true
	}

	return 0, 0, false
}
