package validator

import (
	"strings"
	"testing"

	"github.com/stringNameMahin/ALLSEER/pkg/capability"
)

// pathGrant is a fs.write grant over the given patterns.
func pathGrant(patterns ...string) capability.Grant {
	return capability.Grant{
		Kind:     capability.KindFileWrite,
		Domain:   capability.DomainFilesystem,
		Selector: capability.Selector{PathPatterns: patterns},
	}
}

// hostGrant is a net.connect grant over the given host patterns.
func hostGrant(hosts ...string) capability.Grant {
	return capability.Grant{
		Kind:     capability.KindNetConnect,
		Domain:   capability.DomainNetwork,
		Selector: capability.Selector{Hosts: hosts},
	}
}

func matches(grants ...capability.Grant) []Match {
	out := make([]Match, len(grants))
	for i := range grants {
		out[i] = Match{Index: i, Grant: &grants[i]}
	}
	return out
}

func TestSpecificityOrdering(t *testing.T) {
	// Each case states that narrower is strictly more specific than broader.
	tests := []struct {
		name     string
		narrower capability.Grant
		broader  capability.Grant
	}{
		{
			"deeper anchor beats shallower",
			pathGrant("/ws/src/**"),
			pathGrant("/ws/**"),
		},
		{
			"any anchor beats none",
			pathGrant("/ws/**"),
			pathGrant("/**"),
		},
		{
			"bounded depth beats recursive at equal anchor",
			pathGrant("/ws/*"),
			pathGrant("/ws/**"),
		},
		{
			"longer pattern beats shorter at equal anchor and recursion",
			pathGrant("/ws/*/*.go"),
			pathGrant("/ws/*"),
		},
		{
			"a constrained path beats an unconstrained selector",
			pathGrant("/**"),
			capability.Grant{Kind: capability.KindFileWrite, Domain: capability.DomainFilesystem},
		},
		{
			// The rule that stops a catch-all from posing as narrow by
			// carrying a decorative specific pattern alongside.
			"a grant is as broad as its broadest pattern",
			pathGrant("/ws/src/**"),
			pathGrant("/ws/src/**", "/**"),
		},

		{
			"exact host beats wildcard domain",
			hostGrant("api.github.com"),
			hostGrant("*.github.com"),
		},
		{
			"wildcard domain beats CIDR block",
			hostGrant("*.github.com"),
			hostGrant("10.0.0.0/8"),
		},
		{
			"longer wildcard suffix beats shorter",
			hostGrant("*.api.github.com"),
			hostGrant("*.github.com"),
		},
		{
			"smaller block beats larger",
			hostGrant("10.1.2.0/24"),
			hostGrant("10.0.0.0/8"),
		},
		{
			"a full-length prefix ranks as an exact address",
			hostGrant("10.1.2.3/32"),
			hostGrant("10.1.2.0/24"),
		},
		{
			"a broad host list is as broad as its broadest entry",
			hostGrant("api.github.com"),
			hostGrant("api.github.com", "0.0.0.0/0"),
		},

		{
			"a port constraint beats none",
			capability.Grant{Selector: capability.Selector{Ports: []int{443}}},
			capability.Grant{},
		},
		{
			"fewer ports beat more",
			capability.Grant{Selector: capability.Selector{Ports: []int{443}}},
			capability.Grant{Selector: capability.Selector{Ports: []int{80, 443, 8443}}},
		},
		{
			"a protocol constraint beats none",
			capability.Grant{Selector: capability.Selector{Protocols: []string{"tcp"}}},
			capability.Grant{},
		},
		{
			"a use limit beats none",
			capability.Grant{Selector: capability.Selector{MaxCount: 5}},
			capability.Grant{},
		},
		{
			"a smaller use limit beats a larger one",
			capability.Grant{Selector: capability.Selector{MaxCount: 1}},
			capability.Grant{Selector: capability.Selector{MaxCount: 100}},
		},
		{
			"an executable constraint beats none",
			capability.Grant{Selector: capability.Selector{Executables: []string{"/usr/bin/git"}}},
			capability.Grant{},
		},

		{
			// Paths outrank everything else, so a grant narrowed to a file
			// outranks one merely narrowed to a port.
			"path specificity outranks port specificity",
			pathGrant("/ws/go.mod"),
			capability.Grant{Selector: capability.Selector{Ports: []int{443}}},
		},
		{
			"host specificity outranks port specificity",
			hostGrant("api.github.com"),
			capability.Grant{Selector: capability.Selector{Ports: []int{443}}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			narrow := SpecificityOf(tt.narrower)
			broad := SpecificityOf(tt.broader)

			if got := CompareSpecificity(narrow, broad); got <= 0 {
				t.Errorf("CompareSpecificity(narrower, broader) = %d, want > 0\n narrower: %s\n broader:  %s",
					got, narrow, broad)
			}
			// Antisymmetry: the comparison must not depend on argument order.
			if got := CompareSpecificity(broad, narrow); got >= 0 {
				t.Errorf("CompareSpecificity(broader, narrower) = %d, want < 0", got)
			}
		})
	}
}

func TestSpecificityIsReflexive(t *testing.T) {
	grants := []capability.Grant{
		{},
		pathGrant("/ws/**"),
		pathGrant("/ws/src/*.go", "/ws/testdata/**"),
		hostGrant("*.github.com"),
		{Selector: capability.Selector{Ports: []int{443}, MaxCount: 3}},
	}
	for _, g := range grants {
		s := SpecificityOf(g)
		if got := CompareSpecificity(s, s); got != 0 {
			t.Errorf("CompareSpecificity(s, s) = %d for %s, want 0", got, s)
		}
	}
}

// TestSpecificityIgnoresInvalidPatterns pins the rule that an unparseable
// pattern widens nothing: it matches nothing, so it cannot be what makes a
// grant broad.
func TestSpecificityIgnoresInvalidPatterns(t *testing.T) {
	clean := SpecificityOf(pathGrant("/ws/src/**"))
	withJunk := SpecificityOf(pathGrant("/ws/src/**", "/ws/[unterminated", "relative/path"))
	if CompareSpecificity(clean, withJunk) != 0 {
		t.Errorf("an invalid pattern changed specificity:\n clean: %s\n junk:  %s", clean, withJunk)
	}

	cleanHost := SpecificityOf(hostGrant("api.github.com"))
	junkHost := SpecificityOf(hostGrant("api.github.com", "api-*.github.com", "host:443"))
	if CompareSpecificity(cleanHost, junkHost) != 0 {
		t.Errorf("an invalid host pattern changed specificity:\n clean: %s\n junk:  %s", cleanHost, junkHost)
	}
}

func TestResolveDenialsAlwaysOverride(t *testing.T) {
	// The grant is as narrow as a grant gets; the denial is as broad as one
	// gets. The denial still wins, because a denial is a carve-out from a
	// broader grant and specificity would invert the author's intent.
	grants := matches(pathGrant("/ws/src/main.go"))
	denials := matches(pathGrant("/**"))

	got := ResolvePrecedence(grants, denials)
	if !got.Denied {
		t.Fatal("Denied = false; a matching denial must override every grant")
	}
	if got.Winner == nil || got.Winner.Grant != denials[0].Grant {
		t.Error("the winner is not the denial")
	}
	if !strings.Contains(got.Reason, "denial") {
		t.Errorf("Reason = %q, want it to name the denial", got.Reason)
	}
}

func TestResolvePicksMostSpecificGrant(t *testing.T) {
	all := matches(
		pathGrant("/**"),          // 0: catch-all
		pathGrant("/ws/**"),       // 1: workspace
		pathGrant("/ws/src/*.go"), // 2: the narrowest
		pathGrant("/ws/src/**"),   // 3
	)

	got := ResolvePrecedence(all, nil)
	if got.Denied {
		t.Fatal("Denied = true with no denials")
	}
	if got.Winner == nil || got.Winner.Index != 2 {
		t.Fatalf("winner = %v, want entry 2", got.Winner)
	}
	if !strings.Contains(got.Reason, "most specific") {
		t.Errorf("Reason = %q, want it to explain specificity", got.Reason)
	}
}

func TestResolvePicksMostSpecificDenial(t *testing.T) {
	denials := matches(
		pathGrant("/ws/**"),
		pathGrant("/ws/.git/**"),
	)

	got := ResolvePrecedence(nil, denials)
	if got.Winner == nil || got.Winner.Index != 1 {
		t.Fatalf("winner = %v, want entry 1, the narrower denial", got.Winner)
	}
}

func TestResolveTieBreaksOnEnvelopeOrder(t *testing.T) {
	// Two grants of identical shape. The earlier one must win, and must win
	// regardless of the order the matcher collected them in.
	a := pathGrant("/ws/src/**")
	b := pathGrant("/ws/lib/**")

	forward := ResolvePrecedence([]Match{{Index: 3, Grant: &a}, {Index: 7, Grant: &b}}, nil)
	if forward.Winner.Index != 3 {
		t.Errorf("winner = %d, want 3", forward.Winner.Index)
	}

	reversed := ResolvePrecedence([]Match{{Index: 7, Grant: &b}, {Index: 3, Grant: &a}}, nil)
	if reversed.Winner.Index != 3 {
		t.Errorf("winner = %d with reversed input, want 3; precedence depends on collection order",
			reversed.Winner.Index)
	}
	if !strings.Contains(forward.Reason, "equally specific") {
		t.Errorf("Reason = %q, want it to say the match was a tie", forward.Reason)
	}
}

func TestResolveNoMatch(t *testing.T) {
	got := ResolvePrecedence(nil, nil)
	if got.Winner != nil {
		t.Error("a winner was produced with nothing matching")
	}
	if got.Denied {
		t.Error("Denied = true with nothing matching")
	}
	if got.Reason == "" {
		t.Error("Reason is empty; an outcome with no explanation reaches the audit log unexplained")
	}
}

func TestResolveSingleMatchExplainsItself(t *testing.T) {
	only := matches(pathGrant("/ws/**"))

	got := ResolvePrecedence(only, nil)
	if got.Winner == nil || got.Winner.Index != 0 {
		t.Fatalf("winner = %v, want entry 0", got.Winner)
	}
	if !strings.Contains(got.Reason, "only match") {
		t.Errorf("Reason = %q, want it to say this was the only match", got.Reason)
	}
}

// TestResolveIsDeterministic guards the property the audit log depends on:
// the same inputs always name the same entry.
func TestResolveIsDeterministic(t *testing.T) {
	all := matches(
		pathGrant("/ws/**"),
		pathGrant("/ws/src/**"),
		pathGrant("/ws/src/*.go"),
		pathGrant("/**"),
	)

	first := ResolvePrecedence(all, nil)
	for range 100 {
		got := ResolvePrecedence(all, nil)
		if got.Winner.Index != first.Winner.Index || got.Reason != first.Reason {
			t.Fatalf("resolution varied between runs: %v %q vs %v %q",
				got.Winner.Index, got.Reason, first.Winner.Index, first.Reason)
		}
	}
}

func TestSpecificityString(t *testing.T) {
	if got := SpecificityOf(capability.Grant{}).String(); got != "unconstrained" {
		t.Errorf("String() = %q for an empty selector, want %q", got, "unconstrained")
	}

	got := SpecificityOf(pathGrant("/ws/src/**")).String()
	for _, want := range []string{"path anchor depth=2", "path length=3"} {
		if !strings.Contains(got, want) {
			t.Errorf("String() = %q, want it to contain %q", got, want)
		}
	}
}

func BenchmarkResolvePrecedence(b *testing.B) {
	grants := matches(
		pathGrant("/ws/**"),
		pathGrant("/ws/src/**"),
		pathGrant("/ws/src/*.go"),
		hostGrant("*.github.com"),
		pathGrant("/**"),
	)

	b.ReportAllocs()
	for range b.N {
		ResolvePrecedence(grants, nil)
	}
}
