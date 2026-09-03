package validator

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/stringNameMahin/ALLSEER/pkg/capability"
)

// The composing matcher answers "is this observation covered by this grant" by
// dispatching to the path and network matchers and combining their answers.
//
// Two rules govern the combination, and they are opposites on purpose:
//
//   - Across dimensions, AND. Every constrained dimension must be satisfied. A
//     grant of api.github.com on port 443 does not cover port 22.
//   - Within one dimension's list, OR. Any pattern in PathPatterns covering the
//     target is enough. A list is a set of alternatives.
//
// An unconstrained dimension covers everything, including an observation that
// could not be resolved: uncertainty about the target cannot change coverage
// when the grant does not narrow that dimension at all. That holds for denials
// as well as grants, which is what makes it safe in both directions.
//
// See docs/selector-matching.md.

// MatchResult is the outcome of matching one observation against one grant.
//
// Unevaluable is the field that earns this type. The Matcher interface returns
// only a bool and a string, and a caller that had to distinguish "this grant
// does not cover the operation" from "we could not tell" by reading the string
// would break the moment the wording changed. The distinction is the difference
// between reporting a violation and reporting a blind spot.
type MatchResult struct {
	// Matched reports coverage. False with Unevaluable set is not a mismatch.
	Matched bool

	// Unevaluable reports that a constrained dimension could not be compared:
	// an unresolved path, a destination known only by address against a grant
	// written in names, a missing protocol or port. Upstream must raise
	// ViolationUnresolvable and VerdictIndeterminate rather than
	// ViolationSelectorMismatch.
	Unevaluable bool

	// Reason explains the outcome for the reasoning chain that reaches the
	// audit log.
	Reason string
}

// SelectorMatcher implements Matcher over the path and network matchers.
//
// Safe for concurrent use when its constituents are, which the defaults are.
type SelectorMatcher struct {
	paths   PathMatcher
	network NetworkMatcher
}

var _ Matcher = (*SelectorMatcher)(nil)

// NewMatcher returns a matcher over the default path and network matchers.
func NewMatcher() *SelectorMatcher {
	return &SelectorMatcher{paths: NewPathMatcher(), network: NewNetworkMatcher()}
}

// NewMatcherWith returns a matcher over the given constituents, for a daemon
// that resolves symlinked workspace roots or for tests.
func NewMatcherWith(paths PathMatcher, network NetworkMatcher) *SelectorMatcher {
	return &SelectorMatcher{paths: paths, network: network}
}

// Matches implements Matcher. Callers needing the mismatch/unevaluable
// distinction should use Match instead.
func (m *SelectorMatcher) Matches(g capability.Grant, obs capability.Observation) (bool, string) {
	r := m.Match(g, obs)
	return r.Matched, r.Reason
}

// Match reports whether the observation falls within the grant.
func (m *SelectorMatcher) Match(g capability.Grant, obs capability.Observation) MatchResult {
	if g.Kind != obs.Kind {
		return mismatch("grant is for %s, observation is %s", g.Kind, obs.Kind)
	}

	// The Kind's domain from the catalog, not Grant.Domain: the two can
	// disagree in a hand-edited or generated envelope, and the Kind is the
	// field everything else keys on.
	domain, known := capability.DomainOf(g.Kind)
	if !known {
		// An unknown Kind should have been rejected when the envelope was
		// admitted. Reaching here means it was not, and guessing how to
		// interpret its Target would be inventing a selector.
		return unevaluable("capability %q is not in this build's catalog", g.Kind)
	}

	switch domain {
	case capability.DomainFilesystem:
		return m.matchPaths(g.Selector.PathPatterns, obs.Target, "path")

	case capability.DomainNetwork:
		return m.matchNetwork(g.Selector, obs)

	case capability.DomainProcess:
		if r := m.matchPaths(g.Selector.Executables, obs.Target, "executable"); !r.Matched {
			return r
		}
		return matchArgs(g.Selector.ArgPatterns, obs.Attributes[capability.AttrArgv])

	default:
		// Privilege, IPC, and kernel capabilities have no selector dimension of
		// their own, so the Kind alone decides -- except that an IPC socket or a
		// loaded module is named by a path, and a grant narrowing PathPatterns
		// plainly means it.
		if len(g.Selector.PathPatterns) > 0 {
			return m.matchPaths(g.Selector.PathPatterns, obs.Target, "path")
		}
		return matched("capability %s, which takes no selector", g.Kind)
	}
}

// matchPaths applies a path-shaped dimension: PathPatterns or Executables.
func (m *SelectorMatcher) matchPaths(patterns []string, target, label string) MatchResult {
	if len(patterns) == 0 {
		return matched("no %s constraint", label)
	}
	if !IsResolved(target) {
		// Enrichment failed, or the probe truncated the path at
		// ALLSEER_PATH_MAX. Either way the operation's target is unknown, and
		// an unknown target is not a target outside the grant.
		return unevaluable("%s %q is not a resolved absolute path", label, target)
	}

	for _, p := range patterns {
		if m.paths.Match(p, target) {
			return matched("%s %q matches %q", label, target, p)
		}
	}
	return mismatch("no %s pattern covers %q", label, target)
}

// matchNetwork applies the host, port, and protocol dimensions.
func (m *SelectorMatcher) matchNetwork(sel capability.Selector, obs capability.Observation) MatchResult {
	if len(sel.Hosts) == 0 && len(sel.Ports) == 0 && len(sel.Protocols) == 0 {
		return matched("no network constraint")
	}

	host, port, hasPort, ok := splitTarget(obs.Target)
	if !ok {
		return unevaluable("destination %q is not a host or host:port", obs.Target)
	}

	if len(sel.Hosts) > 0 {
		if r := m.matchHosts(sel.Hosts, host, obs.Attributes[capability.AttrDestIP]); !r.Matched {
			return r
		}
	}

	if len(sel.Ports) > 0 {
		if !hasPort {
			return unevaluable("destination %q carries no port, and the grant constrains ports", obs.Target)
		}
		if !m.network.MatchPort(sel.Ports, port) {
			return mismatch("port %d is not in %v", port, sel.Ports)
		}
	}

	if len(sel.Protocols) > 0 {
		protocol := obs.Attributes[capability.AttrProtocol]
		if protocol == "" {
			return unevaluable("protocol is unknown, and the grant constrains protocols")
		}
		if !containsFold(sel.Protocols, protocol) {
			return mismatch("protocol %q is not in %v", protocol, sel.Protocols)
		}
	}

	return matched("destination %q is within the grant", obs.Target)
}

// matchHosts compares the granted host patterns against what is known of the
// destination: its correlated name, its literal address, or both.
//
// Both are tried because both are facts. Matching the address against a CIDR
// grant is not the hopeful equivalence docs/network-matching.md forbids -- the
// address is what the kernel connected to. What is forbidden is treating an
// address as standing in for a name nobody observed, and that case ends here as
// unevaluable rather than as a mismatch.
func (m *SelectorMatcher) matchHosts(patterns []string, host, address string) MatchResult {
	candidates := make([]string, 0, 2)
	if host != "" {
		candidates = append(candidates, host)
	}
	if address != "" && address != host {
		candidates = append(candidates, address)
	}
	if len(candidates) == 0 {
		return unevaluable("destination has neither a name nor an address")
	}

	uncomparable := ""
	for _, p := range patterns {
		comparable := false
		for _, c := range candidates {
			if m.network.MatchHost(p, c) {
				return matched("destination %q matches %q", c, p)
			}
			if !CorrelationMissing(p, c) {
				comparable = true
			}
		}
		if !comparable && uncomparable == "" {
			uncomparable = p
		}
	}

	if uncomparable != "" {
		// At least one granted host could not be compared against anything we
		// observed, so this connection may well have been to it. Answering
		// "mismatch" would report a violation the evidence does not support.
		return unevaluable("cannot tell whether %v is %q: no correlated hostname",
			candidates, uncomparable)
	}
	return mismatch("no granted host covers %v", candidates)
}

// matchArgs applies Selector.ArgPatterns.
//
// A pattern matches if it covers any single argument or the whole command
// line, whichever the author meant -- "clone" and "git clone *" both work. The
// forgiving reading is deliberate: this dimension is a readability convenience
// and never a security boundary, so being strict here would buy nothing and
// surprise every envelope author.
//
// Patterns use the same wildcards as paths, without path semantics: there are
// no segments here, so * spans any bytes including "/".
func matchArgs(patterns []string, argv string) MatchResult {
	if len(patterns) == 0 {
		return matched("no argument constraint")
	}
	if argv == "" {
		return unevaluable("argument vector is unavailable, and the grant constrains arguments")
	}

	args := strings.Fields(argv)
	for _, p := range patterns {
		if matchSegment(p, argv) {
			return matched("command line matches %q", p)
		}
		for _, a := range args {
			if matchSegment(p, a) {
				return matched("argument %q matches %q", a, p)
			}
		}
	}
	return mismatch("no argument pattern covers %q", argv)
}

// splitTarget separates a network target into host and port.
//
// The target may be "host:port", "[v6]:port", or a bare host. A bare IPv6
// literal is the trap: it is full of colons and looks like host:port to any
// naive split, so a failed parse falls back to testing whether the whole string
// is itself a host.
func splitTarget(target string) (host string, port int, hasPort, ok bool) {
	if target == "" {
		return "", 0, false, false
	}

	h, p, err := net.SplitHostPort(target)
	if err != nil {
		if ClassifyHost(target) == HostKindInvalid {
			return "", 0, false, false
		}
		return target, 0, false, true
	}

	if p == "" {
		return h, 0, false, h != ""
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		return "", 0, false, false
	}
	return h, n, true, true
}

func containsFold(haystack []string, needle string) bool {
	for _, s := range haystack {
		if strings.EqualFold(s, needle) {
			return true
		}
	}
	return false
}

func matched(format string, args ...any) MatchResult {
	return MatchResult{Matched: true, Reason: fmt.Sprintf(format, args...)}
}

func mismatch(format string, args ...any) MatchResult {
	return MatchResult{Reason: fmt.Sprintf(format, args...)}
}

func unevaluable(format string, args ...any) MatchResult {
	return MatchResult{Unevaluable: true, Reason: fmt.Sprintf(format, args...)}
}
