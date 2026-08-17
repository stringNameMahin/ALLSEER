package validator

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// corpusPath is the shared adversarial table. It lives under test/testdata so
// it is reviewable as data rather than buried in a Go literal, and so a future
// matcher implementation can be held to the same expectations.
const corpusPath = "../../test/testdata/paths/corpus.tsv"

type corpusCase struct {
	line    int
	expect  string
	pattern string
	path    string
}

func loadCorpus(t *testing.T) []corpusCase {
	t.Helper()

	f, err := os.Open(filepath.FromSlash(corpusPath))
	if err != nil {
		t.Fatalf("open corpus: %v", err)
	}
	defer f.Close()

	var cases []corpusCase
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		raw := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(raw) == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		fields := strings.Split(raw, "\t")
		if len(fields) != 3 {
			t.Fatalf("corpus line %d: want 3 tab-separated fields, got %d: %q", line, len(fields), raw)
		}
		c := corpusCase{line: line, expect: fields[0], pattern: fields[1], path: fields[2]}
		switch c.expect {
		case "match", "nomatch", "invalid", "unresolved":
		default:
			t.Fatalf("corpus line %d: unknown expectation %q", line, c.expect)
		}
		cases = append(cases, c)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("corpus is empty; the matcher would be untested")
	}
	return cases
}

func TestCorpus(t *testing.T) {
	m := NewPathMatcher()

	for _, c := range loadCorpus(t) {
		t.Run(fmt.Sprintf("line%d_%s", c.line, c.expect), func(t *testing.T) {
			got := m.Match(c.pattern, c.path)

			switch c.expect {
			case "match":
				if !got {
					t.Errorf("line %d: Match(%q, %q) = false, want true", c.line, c.pattern, c.path)
				}
			case "nomatch":
				if got {
					t.Errorf("line %d: Match(%q, %q) = true, want false", c.line, c.pattern, c.path)
				}
				// A nomatch case must be a genuine mismatch, not a malformed
				// input that happens to return false. Conflating the two would
				// let a broken pattern masquerade as a working denial.
				if err := ValidatePattern(c.pattern); err != nil {
					t.Errorf("line %d: pattern %q is invalid (%v); mark it 'invalid', not 'nomatch'", c.line, c.pattern, err)
				}
				if !IsResolved(c.path) {
					t.Errorf("line %d: path %q is unresolved; mark it 'unresolved', not 'nomatch'", c.line, c.path)
				}
			case "invalid":
				if err := ValidatePattern(c.pattern); err == nil {
					t.Errorf("line %d: ValidatePattern(%q) = nil, want an error", c.line, c.pattern)
				}
				if got {
					t.Errorf("line %d: Match(%q, %q) = true, want false for an invalid pattern", c.line, c.pattern, c.path)
				}
			case "unresolved":
				if IsResolved(c.path) {
					t.Errorf("line %d: IsResolved(%q) = true, want false", c.line, c.path)
				}
				if got {
					t.Errorf("line %d: Match(%q, %q) = true, want false for an unresolved path", c.line, c.pattern, c.path)
				}
			}
		})
	}
}

// TestCorpusCoverage guards against the corpus quietly losing the case
// families it exists for. Counts are lower bounds, not exact.
func TestCorpusCoverage(t *testing.T) {
	cases := loadCorpus(t)

	counts := map[string]int{}
	for _, c := range cases {
		counts[c.expect]++
	}
	for _, expect := range []string{"match", "nomatch", "invalid", "unresolved"} {
		if counts[expect] < 4 {
			t.Errorf("corpus has %d %q cases, want at least 4", counts[expect], expect)
		}
	}

	var traversal, doublestar, dotfile int
	for _, c := range cases {
		if strings.Contains(c.path, "..") {
			traversal++
		}
		if strings.Contains(c.pattern, "**") {
			doublestar++
		}
		if strings.Contains(c.path, "/.") {
			dotfile++
		}
	}
	if traversal == 0 || doublestar == 0 || dotfile == 0 {
		t.Errorf("corpus lost a case family: traversal=%d doublestar=%d dotfile=%d", traversal, doublestar, dotfile)
	}
}
