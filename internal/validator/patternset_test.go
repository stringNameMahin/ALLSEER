package validator

import (
	"strings"
	"testing"
)

// PatternSet exists to make a many-pattern scan cheap, so the property that
// matters most is that it stays *identical* to the single-pattern path it
// replaces. A faster matcher that answers differently is not an optimization.

func TestPatternSetAgreesWithMatchPath(t *testing.T) {
	patterns := []string{
		"/ws/**",
		"/ws/src/*.go",
		"/**/.ssh/id_*",
		"/**/.ssh/**",
		"/etc/shadow",
		"/etc/sudoers.d/**",
		"/proc/*/environ",
		"/usr/include/**",
		"/**/*.pem",
		"/ws/a?c.txt",
		"/ws/[abc]/x",
	}
	paths := []string{
		"/ws/main.go",
		"/ws/src/main.go",
		"/ws/src/deep/main.go",
		"/home/dev/.ssh/id_rsa",
		"/home/dev/.ssh/config",
		"/root/.ssh",
		"/etc/shadow",
		"/etc/shadows",
		"/etc/sudoers.d/90-x",
		"/proc/1234/environ",
		"/proc/environ",
		"/usr/include/stdio.h",
		"/srv/certs/a.pem",
		"/ws/abc.txt",
		"/ws/b/x",
		"/ws/d/x",
		"/",
		"/nowhere/at/all",
		// Forms the matcher must refuse rather than answer about.
		"relative/path",
		"/etc/../etc/shadow",
		"",
		"/double//slash",
	}

	set, err := CompilePatterns(patterns)
	if err != nil {
		t.Fatalf("CompilePatterns: %v", err)
	}
	if set.Len() != len(patterns) {
		t.Fatalf("Len = %d, want %d", set.Len(), len(patterns))
	}

	for _, path := range paths {
		// The reference answer: the first pattern MatchPath accepts.
		want := -1
		for i, p := range patterns {
			if MatchPath(p, path) {
				want = i
				break
			}
		}
		if got := set.MatchIndex(path); got != want {
			t.Errorf("MatchIndex(%q) = %d (%q), want %d (%q)",
				path, got, set.Pattern(got), want, patternAt(patterns, want))
		}
		if got, wantBool := set.Match(path), want >= 0; got != wantBool {
			t.Errorf("Match(%q) = %v, want %v", path, got, wantBool)
		}
	}
}

func patternAt(patterns []string, i int) string {
	if i < 0 || i >= len(patterns) {
		return "<none>"
	}
	return patterns[i]
}

// The index is declaration order, which is what lets a caller encode a
// precedence — internal/risk orders by grade so the first match is the highest
// grade, and never compares.
func TestPatternSetReturnsTheFirstMatch(t *testing.T) {
	set, err := CompilePatterns([]string{"/ws/secrets/**", "/ws/**"})
	if err != nil {
		t.Fatalf("CompilePatterns: %v", err)
	}
	if got := set.MatchIndex("/ws/secrets/key"); got != 0 {
		t.Errorf("MatchIndex = %d, want the first of two matching patterns", got)
	}
	if got := set.MatchIndex("/ws/main.go"); got != 1 {
		t.Errorf("MatchIndex = %d, want 1", got)
	}
}

// An invalid pattern refuses the set rather than becoming an entry that never
// matches. MatchPath can afford "no match" for a bad pattern because its caller
// supplied one; a set is built from configuration a human wrote and should be
// refused while that human is looking.
func TestCompilePatternsRejectsWhatValidatePatternRejects(t *testing.T) {
	for _, bad := range []string{
		"", "relative/**", "/a**b/c", "/a/../b", "/a//b", "/a/./b",
	} {
		if _, err := CompilePatterns([]string{"/ws/**", bad}); err == nil {
			t.Errorf("CompilePatterns accepted %q", bad)
		} else if ValidatePattern(bad) == nil {
			t.Errorf("%q was rejected by the set but accepted by ValidatePattern", bad)
		}
	}

	// And the error names the pattern, so a config file with forty entries
	// points at the one that is wrong.
	_, err := CompilePatterns([]string{"/ok/**", "/a**b/c"})
	if err == nil || !strings.Contains(err.Error(), "a**b") {
		t.Errorf("error = %v, want it to name the offending pattern", err)
	}
}

// The nil and empty cases are usable and report nothing, which is what keeps a
// caller from having to guard every lookup.
func TestPatternSetZeroValues(t *testing.T) {
	var nilSet *PatternSet
	if nilSet.Len() != 0 || nilSet.Match("/etc/shadow") || nilSet.MatchIndex("/etc/shadow") != -1 {
		t.Error("a nil PatternSet did not report as empty")
	}
	if nilSet.Pattern(0) != "" {
		t.Error("a nil PatternSet returned a pattern")
	}

	empty, err := CompilePatterns(nil)
	if err != nil {
		t.Fatalf("CompilePatterns(nil): %v", err)
	}
	if empty.Match("/etc/shadow") {
		t.Error("an empty set matched")
	}
	if empty.Pattern(-1) != "" || empty.Pattern(5) != "" {
		t.Error("an out-of-range index returned a pattern")
	}
}

// One allocation per lookup: the path is segmented once for the whole set
// rather than once per pattern. This is the entire reason the type exists, so
// it is asserted rather than assumed.
func TestPatternSetSegmentsThePathOnce(t *testing.T) {
	patterns := make([]string, 0, 64)
	for i := 0; i < 64; i++ {
		patterns = append(patterns, "/never/matches/"+string(rune('a'+i%26))+"/**")
	}
	set, err := CompilePatterns(patterns)
	if err != nil {
		t.Fatalf("CompilePatterns: %v", err)
	}

	got := testing.AllocsPerRun(100, func() { set.MatchIndex("/home/dev/project/main.go") })
	if got > 1 {
		t.Errorf("MatchIndex allocated %v times over 64 patterns, want at most 1", got)
	}
}

func BenchmarkPatternSetMiss(b *testing.B) {
	set := benchSet(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		set.MatchIndex("/home/dev/project/internal/parser/parse.go")
	}
}

func BenchmarkPatternSetHit(b *testing.B) {
	set := benchSet(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		set.MatchIndex("/home/dev/.ssh/id_rsa")
	}
}

// BenchmarkMatchPathScan is the same scan through the single-pattern entry
// point, which is what PatternSet replaces. The gap between the two is the
// measurement that justified adding the type.
func BenchmarkMatchPathScan(b *testing.B) {
	patterns := benchPatterns()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, p := range patterns {
			if MatchPath(p, "/home/dev/project/internal/parser/parse.go") {
				break
			}
		}
	}
}

func benchPatterns() []string {
	return []string{
		"/**/.ssh/id_*", "/**/.ssh/*_key", "/**/.ssh/*_ed25519", "/**/.ssh/*_rsa",
		"/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/sudoers.d/**",
		"/**/.aws/credentials", "/**/.aws/config", "/**/.kube/config",
		"/**/.docker/config.json", "/**/.netrc", "/**/.pgpass", "/**/.git-credentials",
		"/**/.gnupg/**", "/**/*.pem", "/**/*.p12", "/**/*.pfx", "/**/.ssh/**",
		"/**/.env", "/**/.env.*", "/**/.npmrc", "/**/.pypirc", "/**/.gem/credentials",
		"/**/.config/gh/**", "/**/.config/gcloud/**", "/**/.azure/**",
		"/proc/*/environ", "/proc/*/mem", "/proc/*/maps", "/etc/passwd", "/etc/group",
		"/**/.bash_history", "/**/.zsh_history", "/**/.psql_history",
		"/etc/hosts", "/etc/resolv.conf", "/etc/nsswitch.conf",
		"/usr/include/**", "/usr/share/**", "/usr/lib/**", "/usr/local/include/**",
		"/etc/ssl/certs/**", "/etc/pki/tls/certs/**",
	}
}

func benchSet(b *testing.B) *PatternSet {
	b.Helper()
	set, err := CompilePatterns(benchPatterns())
	if err != nil {
		b.Fatal(err)
	}
	return set
}
