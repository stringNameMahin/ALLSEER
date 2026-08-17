package validator

import (
	"strings"
	"sync"
	"testing"
)

func TestMatchPort(t *testing.T) {
	tests := []struct {
		name    string
		allowed []int
		port    int
		want    bool
	}{
		// The rule with a footgun in it: an empty list is "any port", not
		// "no ports". Reading it as deny-all would silently turn every host
		// grant written without a port into a grant that covers nothing.
		{"empty list means any", nil, 443, true},
		{"empty slice means any", []int{}, 443, true},
		{"empty list means any, unusual port", nil, 31337, true},
		{"empty list means any, even a meaningless one", nil, 0, true},

		{"single allowed port", []int{443}, 443, true},
		{"single disallowed port", []int{443}, 80, false},
		{"one of several", []int{80, 443, 8443}, 8443, true},
		{"none of several", []int{80, 443, 8443}, 22, false},

		// Off-by-one around a listed port: adjacency is not membership.
		{"one below", []int{443}, 442, false},
		{"one above", []int{443}, 444, false},

		{"unspecified port against a list", []int{443}, 0, false},
		{"negative port against a list", []int{443}, -1, false},
	}

	m := NewNetworkMatcher()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.MatchPort(tt.allowed, tt.port); got != tt.want {
				t.Errorf("MatchPort(%v, %d) = %v, want %v", tt.allowed, tt.port, got, tt.want)
			}
		})
	}
}

func TestIsValidPort(t *testing.T) {
	valid := []int{1, 22, 443, 8080, 65535}
	for _, p := range valid {
		if !IsValidPort(p) {
			t.Errorf("IsValidPort(%d) = false, want true", p)
		}
	}
	invalid := []int{0, -1, 65536, 1 << 20}
	for _, p := range invalid {
		if IsValidPort(p) {
			t.Errorf("IsValidPort(%d) = true, want false", p)
		}
	}

	// IsValidPort is a lint for callers, not a gate inside MatchPort: an
	// unspecified port must not turn "any port" into a mismatch.
	if !MatchPort(nil, 0) {
		t.Error("MatchPort(nil, 0) = false; an empty allow list is unconditional")
	}
}

func TestClassifyHost(t *testing.T) {
	tests := []struct {
		in   string
		want HostKind
	}{
		{"93.184.216.34", HostKindIP},
		{"::1", HostKindIP},
		{"fe80::1%eth0", HostKindIP},
		{"10.0.0.0/8", HostKindCIDR},
		{"2001:db8::/32", HostKindCIDR},
		{"api.github.com", HostKindName},
		{"localhost", HostKindName},
		{"api.github.com.", HostKindName},
		{"build_server.internal", HostKindName},
		{"*.github.com", HostKindWildcard},
		{"*.internal", HostKindWildcard},

		{"", HostKindInvalid},
		{"*", HostKindInvalid},
		{"*.", HostKindInvalid},
		{"api-*.github.com", HostKindInvalid},
		{"api.github.com:443", HostKindInvalid},
		{"https://api.github.com", HostKindInvalid},
		{"10.0.0.0/33", HostKindInvalid},
		{"-leading.com", HostKindInvalid},
		{"trailing-.com", HostKindInvalid},
		{"double..dot.com", HostKindInvalid},
		{"café.example.com", HostKindInvalid},
	}

	for _, tt := range tests {
		if got := ClassifyHost(tt.in); got != tt.want {
			t.Errorf("ClassifyHost(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestClassifyHostLabelLimits(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	if got := ClassifyHost(label63 + ".com"); got != HostKindName {
		t.Errorf("a 63-byte label classified as %q, want a name", got)
	}
	if got := ClassifyHost(strings.Repeat("a", 64) + ".com"); got != HostKindInvalid {
		t.Errorf("a 64-byte label classified as %q, want invalid", got)
	}

	// 4 * 63 + 3 separators = 255 bytes, past the 253-byte limit.
	long := strings.Join([]string{label63, label63, label63, label63}, ".")
	if got := ClassifyHost(long); got != HostKindInvalid {
		t.Errorf("a %d-byte name classified as %q, want invalid", len(long), got)
	}
}

// TestHostnamesAndAddressesNeverCorrelate is the property the module exists
// for. It is stated once more here, outside the corpus, because a corpus line
// can be deleted and a named test cannot be deleted quietly.
func TestHostnamesAndAddressesNeverCorrelate(t *testing.T) {
	pairs := []struct{ pattern, observed string }{
		{"api.github.com", "140.82.121.5"},
		{"*.github.com", "140.82.121.5"},
		{"proxy.golang.org", "142.250.72.17"},
		{"140.82.121.5", "api.github.com"},
		{"10.0.0.0/8", "build.internal"},
		{"localhost", "127.0.0.1"},
		{"localhost", "::1"},
	}

	m := NewNetworkMatcher()
	for _, p := range pairs {
		if m.MatchHost(p.pattern, p.observed) {
			t.Errorf("MatchHost(%q, %q) = true; a name was assumed equivalent to an address", p.pattern, p.observed)
		}
		if !CorrelationMissing(p.pattern, p.observed) {
			t.Errorf("CorrelationMissing(%q, %q) = false; the risk engine would never learn correlation failed",
				p.pattern, p.observed)
		}
	}
}

func TestCorrelationMissingIsNotAnExcuse(t *testing.T) {
	// A genuine mismatch between two comparable values must not be reported as
	// a correlation failure, or every real violation could be explained away
	// as telemetry trouble.
	comparable := []struct{ pattern, observed string }{
		{"api.github.com", "evil.example.com"},
		{"*.github.com", "a.b.github.com"},
		{"10.0.0.0/8", "11.0.0.1"},
		{"93.184.216.34", "93.184.216.35"},
		{"api.github.com", "api.github.com"},
	}
	for _, c := range comparable {
		if CorrelationMissing(c.pattern, c.observed) {
			t.Errorf("CorrelationMissing(%q, %q) = true, want false", c.pattern, c.observed)
		}
	}

	// An uninterpretable pattern is a validation failure, not a correlation
	// failure.
	if CorrelationMissing("api-*.github.com", "140.82.121.5") {
		t.Error("an invalid pattern was reported as a correlation failure")
	}
}

func TestValidateHostPattern(t *testing.T) {
	valid := []string{
		"api.github.com",
		"api.github.com.",
		"*.github.com",
		"*.internal",
		"localhost",
		"93.184.216.34",
		"::1",
		"2606:2800:220:1:248:1893:25c8:1946",
		"::ffff:93.184.216.34",
		"10.0.0.0/8",
		"2001:db8::/32",
		"10.1.2.3/8", // host bits set; masked at match time
	}
	for _, p := range valid {
		if err := ValidateHostPattern(p); err != nil {
			t.Errorf("ValidateHostPattern(%q) = %v, want nil", p, err)
		}
	}

	invalid := []string{
		"",
		" api.github.com",
		"api.github.com:443",
		"93.184.216.34:443",
		"https://api.github.com",
		"api.github.com/v3",
		"*",
		"*.",
		"api-*.github.com",
		"*.*.github.com",
		"10.0.0.0/33",
		"giтhub.com",   // Cyrillic т
		"fe80::1%eth0", // an interface zone names a local interface
	}
	for _, p := range invalid {
		if err := ValidateHostPattern(p); err == nil {
			t.Errorf("ValidateHostPattern(%q) = nil, want an error", p)
		}
		if MatchHost(p, "api.github.com") || MatchHost(p, "93.184.216.34") {
			t.Errorf("MatchHost(%q, ...) matched despite the pattern being invalid", p)
		}
	}
}

func TestNetworkMatcherIsConcurrencySafe(t *testing.T) {
	m := NewNetworkMatcher()

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 200 {
				m.MatchHost("*.github.com", "api.github.com")
				m.MatchHost("10.0.0.0/8", "10.1.2.3")
				m.MatchPort([]int{443}, 443)
			}
		}()
	}
	wg.Wait()
}

// FuzzMatchHost asserts the invariants that must hold for every input: no
// panic, no match on an invalid pattern, and — the one that matters — no match
// across the name/address boundary.
func FuzzMatchHost(f *testing.F) {
	seeds := [][2]string{
		{"api.github.com", "api.github.com"},
		{"*.github.com", "a.github.com"},
		{"10.0.0.0/8", "10.1.2.3"},
		{"93.184.216.34", "::ffff:93.184.216.34"},
		{"api.github.com", "140.82.121.5"},
		{"fe80::1", "fe80::1%eth0"},
		{"", ""},
		{"*", "*"},
		{"api.github.com:443", "api.github.com"},
	}
	for _, s := range seeds {
		f.Add(s[0], s[1])
	}

	f.Fuzz(func(t *testing.T, pattern, host string) {
		if !MatchHost(pattern, host) {
			return
		}
		if err := ValidateHostPattern(pattern); err != nil {
			t.Fatalf("matched with an invalid pattern %q: %v", pattern, err)
		}

		patternKind := ClassifyHost(pattern)
		observedKind := ClassifyHost(host)
		if observedKind != HostKindIP && observedKind != HostKindName {
			t.Fatalf("matched a destination that is neither a name nor an address: %q (%s)", host, observedKind)
		}

		nameSide := patternKind == HostKindName || patternKind == HostKindWildcard
		if nameSide != (observedKind == HostKindName) {
			t.Fatalf("matched across the name/address boundary: pattern=%q (%s) host=%q (%s)",
				pattern, patternKind, host, observedKind)
		}
		if CorrelationMissing(pattern, host) {
			t.Fatalf("matched a pair reported as uncorrelated: pattern=%q host=%q", pattern, host)
		}
	})
}

func BenchmarkMatchHost(b *testing.B) {
	benchmarks := []struct{ name, pattern, host string }{
		{"name_hit", "api.github.com", "api.github.com"},
		{"name_miss", "api.github.com", "proxy.golang.org"},
		{"wildcard_hit", "*.github.com", "api.github.com"},
		{"ip_hit", "93.184.216.34", "93.184.216.34"},
		{"cidr_hit", "10.0.0.0/8", "10.1.2.3"},
		{"uncorrelated", "api.github.com", "140.82.121.5"},
	}
	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				MatchHost(bm.pattern, bm.host)
			}
		})
	}
}
