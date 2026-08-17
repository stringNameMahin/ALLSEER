package validator

import (
	"fmt"
	"strings"
	"testing"
)

var networkExpectations = []string{"match", "nomatch", "invalid", "uncorrelated"}

func TestNetworkCorpus(t *testing.T) {
	m := NewNetworkMatcher()

	for _, c := range loadCorpus(t, networkCorpusPath, networkExpectations...) {
		host := c.path // the corpus's third field is a host here

		t.Run(fmt.Sprintf("line%d_%s", c.line, c.expect), func(t *testing.T) {
			got := m.MatchHost(c.pattern, host)

			switch c.expect {
			case "match":
				if !got {
					t.Errorf("line %d: MatchHost(%q, %q) = false, want true", c.line, c.pattern, host)
				}
			case "nomatch", "uncorrelated":
				if got {
					t.Errorf("line %d: MatchHost(%q, %q) = true, want false", c.line, c.pattern, host)
				}
				// A pattern that fails to parse would also produce false. The
				// corpus must not let a broken selector pose as a working one.
				if err := ValidateHostPattern(c.pattern); err != nil {
					t.Errorf("line %d: pattern %q is invalid (%v); mark it 'invalid'", c.line, c.pattern, err)
				}
			case "invalid":
				if err := ValidateHostPattern(c.pattern); err == nil {
					t.Errorf("line %d: ValidateHostPattern(%q) = nil, want an error", c.line, c.pattern)
				}
				if got {
					t.Errorf("line %d: MatchHost(%q, %q) = true, want false for an invalid pattern", c.line, c.pattern, host)
				}
			}

			// The distinction the module exists for: a false caused by missing
			// name/address correlation is a different finding from a false
			// caused by a genuine mismatch, and the corpus states which is
			// which.
			if c.expect == "invalid" {
				return
			}
			wantMissing := c.expect == "uncorrelated"
			if gotMissing := CorrelationMissing(c.pattern, host); gotMissing != wantMissing {
				t.Errorf("line %d: CorrelationMissing(%q, %q) = %v, want %v",
					c.line, c.pattern, host, gotMissing, wantMissing)
			}
		})
	}
}

// TestNetworkCorpusCoverage guards against the corpus losing a case family.
func TestNetworkCorpusCoverage(t *testing.T) {
	cases := loadCorpus(t, networkCorpusPath, networkExpectations...)

	counts := map[string]int{}
	for _, c := range cases {
		counts[c.expect]++
	}
	for _, expect := range networkExpectations {
		if counts[expect] < 4 {
			t.Errorf("corpus has %d %q cases, want at least 4", counts[expect], expect)
		}
	}

	var cidr, wildcard, v6 int
	for _, c := range cases {
		if strings.Contains(c.pattern, "/") {
			cidr++
		}
		if strings.HasPrefix(c.pattern, "*.") {
			wildcard++
		}
		if strings.Contains(c.pattern, ":") || strings.Contains(c.path, ":") {
			v6++
		}
	}
	if cidr == 0 || wildcard == 0 || v6 == 0 {
		t.Errorf("corpus lost a case family: cidr=%d wildcard=%d ipv6=%d", cidr, wildcard, v6)
	}
}
