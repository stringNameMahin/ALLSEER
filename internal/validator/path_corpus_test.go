package validator

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The adversarial tables live under test/testdata so they are reviewable as
// data rather than buried in Go literals, and so a future matcher
// implementation can be held to the same expectations.
const (
	pathCorpusPath    = "../../test/testdata/paths/corpus.tsv"
	networkCorpusPath = "../../test/testdata/network/corpus.tsv"
)

// corpusCase is one line of a corpus file. The third field is a path for the
// path corpus and a host for the network one.
type corpusCase struct {
	line    int
	expect  string
	pattern string
	path    string
}

// loadCorpus parses a corpus file, enforcing the shared format. Both matchers
// use it, so a malformed table fails as a format error rather than as a
// mysterious matcher failure.
func loadCorpus(t *testing.T, corpusPath string, expectations ...string) []corpusCase {
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
			t.Fatalf("%s line %d: want 3 tab-separated fields, got %d: %q", corpusPath, line, len(fields), raw)
		}
		c := corpusCase{line: line, expect: fields[0], pattern: fields[1], path: fields[2]}
		if !slices.Contains(expectations, c.expect) {
			t.Fatalf("%s line %d: unknown expectation %q, want one of %v", corpusPath, line, c.expect, expectations)
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

func TestPathCorpus(t *testing.T) {
	m := NewPathMatcher()

	for _, c := range loadCorpus(t, pathCorpusPath, "match", "nomatch", "invalid", "unresolved") {
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

// TestPathCorpusCoverage guards against the corpus quietly losing the case
// families it exists for. Counts are lower bounds, not exact.
func TestPathCorpusCoverage(t *testing.T) {
	cases := loadCorpus(t, pathCorpusPath, "match", "nomatch", "invalid", "unresolved")

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
