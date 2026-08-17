package validator

import (
	"fmt"
	"net/netip"
	"strings"
)

// Network matching has one rule that matters more than all the others: a name
// and an address are never assumed to be the same thing.
//
// Envelopes are written in hostnames, because that is how a human describes a
// task ("may reach proxy.golang.org"). The kernel observes addresses. The
// bridge between them is DNS correlation, which is best-effort by nature — DNS
// over HTTPS, hardcoded addresses, a cache that expired, and a connection to a
// host reached by an unrelated name all defeat it.
//
// So when an envelope grants a hostname and the observation carries only an
// address, the answer here is no match. Not a guess, not a reverse lookup, not
// "it is probably that host". The connection escalates to the risk engine,
// which can weigh it in context. Any other answer makes skipping DNS the
// easiest way to evade a network grant, and nothing in the log would look
// wrong.
//
// See docs/network-matching.md for the full specification.

// HostKind classifies a host pattern or an observed destination.
//
// Exported because the difference between "the envelope did not cover this
// destination" and "the envelope could not be compared against this
// destination" is a governance distinction, not an implementation detail. See
// CorrelationMissing.
type HostKind string

const (
	// HostKindInvalid: unparseable, or malformed for every other kind.
	HostKindInvalid HostKind = "invalid"

	// HostKindIP: a literal IPv4 or IPv6 address.
	HostKindIP HostKind = "ip"

	// HostKindCIDR: an address block. Patterns only; an observation is never a
	// block.
	HostKindCIDR HostKind = "cidr"

	// HostKindName: a DNS hostname.
	HostKindName HostKind = "name"

	// HostKindWildcard: a leading "*." followed by a hostname. Patterns only.
	HostKindWildcard HostKind = "wildcard"
)

// NetworkPatternMatcher implements NetworkMatcher.
//
// Stateless, so the zero value works and it is trivially safe for concurrent
// use. It performs no DNS resolution of any kind: resolution here would be a
// second, later answer to a question the kernel already answered, and it would
// put a network round trip on the validation hot path.
type NetworkPatternMatcher struct{}

var _ NetworkMatcher = NetworkPatternMatcher{}

// NewNetworkMatcher returns a network matcher.
func NewNetworkMatcher() NetworkPatternMatcher { return NetworkPatternMatcher{} }

// MatchHost reports whether hostOrIP satisfies pattern.
//
// hostOrIP is the destination as enrichment resolved it: the correlated
// hostname when DNS correlation succeeded, otherwise the literal address. It is
// a bare host, never "host:port"; the caller splits.
func (NetworkPatternMatcher) MatchHost(pattern, hostOrIP string) bool {
	return MatchHost(pattern, hostOrIP)
}

// MatchPort reports whether port is in allowed. An empty list means any port.
func (NetworkPatternMatcher) MatchPort(allowed []int, port int) bool {
	return MatchPort(allowed, port)
}

// MatchHost is the free-function form, so the semantics can be exercised and
// fuzzed without constructing a matcher.
func MatchHost(pattern, hostOrIP string) bool {
	patternKind := ClassifyHost(pattern)
	if patternKind == HostKindInvalid {
		return false
	}

	// An observation is only ever a name or an address. A block or a wildcard
	// in the observed position means something upstream passed a pattern where
	// a fact belongs.
	observedKind := ClassifyHost(hostOrIP)
	switch observedKind {
	case HostKindIP, HostKindName:
	default:
		return false
	}

	switch patternKind {
	case HostKindIP:
		if observedKind != HostKindIP {
			return false
		}
		want, ok1 := parseAddr(pattern)
		got, ok2 := parseAddr(hostOrIP)
		return ok1 && ok2 && want == got

	case HostKindCIDR:
		if observedKind != HostKindIP {
			return false
		}
		prefix, err := netip.ParsePrefix(pattern)
		if err != nil {
			return false
		}
		got, ok := parseAddr(hostOrIP)
		if !ok {
			return false
		}
		return prefix.Masked().Contains(got)

	case HostKindName:
		if observedKind != HostKindName {
			return false
		}
		return normalizeHost(pattern) == normalizeHost(hostOrIP)

	case HostKindWildcard:
		if observedKind != HostKindName {
			return false
		}
		// "*.example.com" covers exactly one additional label, matching the
		// TLS certificate convention. It does not cover the apex, and it does
		// not cover a deeper subdomain.
		suffix := normalizeHost(pattern[len("*."):])
		host := normalizeHost(hostOrIP)
		rest, found := strings.CutSuffix(host, "."+suffix)
		return found && rest != "" && !strings.Contains(rest, ".")
	}

	return false
}

// MatchPort reports whether port is in allowed.
//
// An empty list means any port, which is what an envelope means when it grants
// a host without qualifying it. That is deliberately unconditional: a probe
// reporting no meaningful port — ICMP, a raw socket — must not turn "any port"
// into a mismatch. Callers that care whether a port is well-formed have
// IsValidPort.
func MatchPort(allowed []int, port int) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, p := range allowed {
		if p == port {
			return true
		}
	}
	return false
}

// IsValidPort reports whether port is a usable TCP or UDP port.
//
// Zero is excluded: as an observed destination it means the probe had nothing
// to report, not that the agent connected to port zero.
func IsValidPort(port int) bool {
	return port >= 1 && port <= 65535
}

// CorrelationMissing reports whether a false from MatchHost is explained by a
// name-versus-address mismatch rather than by a genuine mismatch.
//
// This is the network analogue of IsResolved. "The envelope did not grant this
// destination" and "the envelope names hosts, and we never learned this
// address's name" are different findings, and reporting the second as the first
// would let every uncorrelated connection read as a deliberate violation — or,
// worse, invite someone to make hostnames match addresses hopefully so the
// noise goes away.
//
// Upstream should treat a true here as grounds for scrutiny by the risk engine
// rather than as a clean selector mismatch.
func CorrelationMissing(pattern, hostOrIP string) bool {
	patternKind := ClassifyHost(pattern)
	observedKind := ClassifyHost(hostOrIP)

	switch patternKind {
	case HostKindName, HostKindWildcard:
		return observedKind == HostKindIP
	case HostKindIP, HostKindCIDR:
		return observedKind == HostKindName
	}
	return false
}

// ClassifyHost reports what a host pattern or observed destination is.
//
// HostKindInvalid covers everything that cannot be interpreted, including
// non-ASCII names: see ValidateHostPattern.
func ClassifyHost(s string) HostKind {
	if s == "" {
		return HostKindInvalid
	}

	if strings.HasPrefix(s, "*.") {
		if isValidName(s[len("*."):]) {
			return HostKindWildcard
		}
		return HostKindInvalid
	}

	if strings.Contains(s, "/") {
		prefix, err := netip.ParsePrefix(s)
		if err != nil || prefix.Addr().Zone() != "" {
			return HostKindInvalid
		}
		return HostKindCIDR
	}

	// A zone ("fe80::1%eth0") names a local interface, which is a property of
	// this host rather than of the destination. It still classifies as an
	// address; ValidateHostPattern rejects it in a pattern, and parseAddr
	// strips it from an observation.
	if _, err := netip.ParseAddr(s); err == nil {
		return HostKindIP
	}

	if isValidName(s) {
		return HostKindName
	}
	return HostKindInvalid
}

// ValidateHostPattern reports why a host selector cannot be evaluated, or nil.
//
// Envelope validation should call this when a grant is admitted. A host
// pattern nobody can interpret matches nothing, which silently guts a denial,
// and the only good time to catch that is while a human is looking at it.
func ValidateHostPattern(pattern string) error {
	if pattern == "" {
		return fmt.Errorf("host pattern is empty")
	}
	if strings.ContainsAny(pattern, " \t\r\n") {
		return fmt.Errorf("host pattern %q contains whitespace", pattern)
	}
	if strings.Contains(pattern, ":") && !strings.Contains(pattern, "/") {
		// A bare IPv6 literal is legal and contains colons; "host:port" is not
		// a host. Distinguishing them by parse result is the only reliable way.
		if _, err := netip.ParseAddr(pattern); err != nil {
			return fmt.Errorf("host pattern %q looks like host:port; ports belong in Selector.Ports", pattern)
		}
	}

	switch ClassifyHost(pattern) {
	case HostKindIP:
		if addr, err := netip.ParseAddr(pattern); err == nil && addr.Zone() != "" {
			return fmt.Errorf("host pattern %q carries an interface zone, which names a local interface rather than a destination", pattern)
		}
		return nil
	case HostKindCIDR, HostKindName, HostKindWildcard:
		return nil
	}

	if strings.Contains(pattern, "*") {
		return fmt.Errorf("host pattern %q: a wildcard is only valid as a leading \"*.\" label", pattern)
	}
	return fmt.Errorf("host pattern %q is not a hostname, address, CIDR block, or wildcard domain", pattern)
}

// parseAddr parses an address for comparison, unmapping IPv4-in-IPv6 and
// dropping any interface zone.
//
// Unmapping is what makes ::ffff:93.184.216.34 and 93.184.216.34 the same host,
// which they are: a dual-stack socket reports the mapped form for a connection
// an envelope would name in dotted quad.
func parseAddr(s string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap().WithZone(""), true
}

// normalizeHost lowercases a name and drops the root's trailing dot. DNS is
// case-insensitive, and "example.com." and "example.com" are the same name.
func normalizeHost(h string) string {
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

// isValidName reports whether s is a syntactically valid DNS hostname.
//
// ASCII only. A name with non-ASCII bytes is rejected rather than normalized,
// because the resolver and the kernel see the punycode A-label and an envelope
// that disagreed with them would grant a host that can never be observed.
// Rejecting also removes the homoglyph problem outright: an envelope cannot
// contain a Cyrillic "github.com" that a reviewer would read as the real one.
func isValidName(s string) bool {
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return false
	}

	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z',
				c >= 'A' && c <= 'Z',
				c >= '0' && c <= '9',
				c == '-', c == '_':
			default:
				return false
			}
		}
	}
	return true
}
