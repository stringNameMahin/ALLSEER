package validator

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func TestMatchSegmentBoundaries(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		path    string
		want    bool
	}{
		{"star does not cross separator", "/ws/*", "/ws/a/b", false},
		{"star matches empty", "/ws/a*", "/ws/a", true},
		{"star alone matches any single segment", "/ws/*", "/ws/anything", true},
		{"star does not match zero segments", "/ws/*", "/ws", false},
		{"multiple stars in one segment", "/ws/*-*.go", "/ws/a-b.go", true},
		{"multiple stars backtrack", "/ws/*b*c", "/ws/abxc", true},
		{"question does not cross separator", "/ws/?", "/ws/a/b", false},
		{"class does not cross separator", "/ws/[a-z]", "/ws/a/b", false},

		{"doublestar matches zero segments", "/ws/**", "/ws", true},
		{"doublestar matches one segment", "/ws/**", "/ws/a", true},
		{"doublestar matches many segments", "/ws/**", "/ws/a/b/c", true},
		{"doublestar then literal", "/ws/**/go.mod", "/ws/a/b/go.mod", true},
		{"doublestar then literal at depth zero", "/ws/**/go.mod", "/ws/go.mod", true},
		{"two doublestars", "/ws/**/x/**", "/ws/a/x/b/c", true},
		{"root doublestar matches everything", "/**", "/etc/passwd", true},
		{"root doublestar matches root", "/**", "/", true},
		{"root matches only root", "/", "/etc", false},
		{"root matches root", "/", "/", true},
	}

	m := NewPathMatcher()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Match(tt.pattern, tt.path); got != tt.want {
				t.Errorf("Match(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
			}
		})
	}
}

// TestMatchUnicode pins the byte-exact rule with the code points spelled out,
// which a testdata file cannot do: NFC and NFD café are indistinguishable on
// screen, and a homoglyph is indistinguishable by design.
func TestMatchUnicode(t *testing.T) {
	const (
		nfc       = "/ws/caf\u00e9.txt"     // é as U+00E9
		nfd       = "/ws/cafe\u0301.txt"    // e + U+0301 combining acute
		homoglyph = "/ws/p\u0430ckage.json" // Cyrillic а U+0430
		latin     = "/ws/package.json"      //
		twoByte   = "/ws/\u00e9"            // one character, two bytes
	)

	m := NewPathMatcher()

	if !m.Match(nfc, nfc) {
		t.Error("a path does not match its own literal spelling")
	}
	if m.Match(nfc, nfd) {
		t.Error("NFC pattern matched an NFD path; the matcher is normalizing, and the kernel does not")
	}
	if m.Match(nfd, nfc) {
		t.Error("NFD pattern matched an NFC path")
	}
	if m.Match(homoglyph, latin) {
		t.Error("Cyrillic homoglyph matched its Latin lookalike")
	}

	// ? counts bytes, not characters. Documented, and the reason a pattern
	// should not use ? on paths that may hold non-ASCII names.
	if m.Match("/ws/?", twoByte) {
		t.Error("? matched a two-byte character; it must match exactly one byte")
	}
	if !m.Match("/ws/??", twoByte) {
		t.Error("?? did not match a two-byte character")
	}

	// Invalid UTF-8 must stay distinguishable. Decoding to U+FFFD would make
	// these two different filenames compare equal.
	if m.Match("/ws/\xff", "/ws/\xfe") {
		t.Error("distinct invalid-UTF-8 bytes compared equal")
	}
	if !m.Match("/ws/\xff", "/ws/\xff") {
		t.Error("an invalid-UTF-8 byte did not match itself")
	}
}

func TestIsResolved(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/ws/main.go", true},
		{"/ws", true},
		{"/", true},
		{"/ws/", true},             // a single trailing slash is a spelling, not a defect
		{"/ws/.env", true},         // a dotfile is an ordinary file
		{"/ws/...", true},          // three dots is a filename
		{"/ws/a..b", true},         // dots inside a segment are a filename
		{"", false},                // enrichment produced nothing
		{"ws/main.go", false},      // relative
		{"./ws", false},            //
		{"/ws/../etc", false},      // traversal
		{"/ws/./x", false},         // unnormalized
		{"/ws//x", false},          // empty segment
		{"//", false},              //
		{"/ws/\x00etc", false},     // NUL truncation trick
		{"C:\\ws\\main.go", false}, // a Windows path is not a kernel path
	}

	for _, tt := range tests {
		if got := IsResolved(tt.path); got != tt.want {
			t.Errorf("IsResolved(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestValidatePattern(t *testing.T) {
	valid := []string{
		"/ws/**",
		"/ws/*.go",
		"/ws/**/*.go",
		"/**",
		"/",
		"/ws/[a-z]*.go",
		"/ws/[!a-z]",
		"/ws/[]]",
		"/ws/src/", // trailing slash normalizes away
		"/ws/.*",
	}
	for _, p := range valid {
		if err := ValidatePattern(p); err != nil {
			t.Errorf("ValidatePattern(%q) = %v, want nil", p, err)
		}
	}

	invalid := []string{
		"",
		"ws/**",
		"*.go",
		"/ws/**.go",
		"/ws/a**",
		"/ws/**b/c",
		"/ws/[abc",
		"/ws/../etc",
		"/ws/./x",
		"/ws//x",
		"/ws/\x00",
	}
	for _, p := range invalid {
		if err := ValidatePattern(p); err == nil {
			t.Errorf("ValidatePattern(%q) = nil, want an error", p)
		}
		if MatchPath(p, "/ws/x") {
			t.Errorf("MatchPath(%q, ...) matched despite the pattern being invalid", p)
		}
	}
}

func TestMatchRejectsUnevaluableInputs(t *testing.T) {
	m := NewPathMatcher()

	// The security property: nothing that cannot be evaluated ever matches.
	// Every one of these must be false, whatever the pattern says.
	cases := []struct{ pattern, path string }{
		{"/**", ""},
		{"/**", "relative/path"},
		{"/**", "/ws/../etc/passwd"},
		{"/**", "/ws//etc"},
		{"/**", "/ws/\x00"},
		{"", "/ws/x"},
		{"**", "/ws/x"},
	}
	for _, c := range cases {
		if m.Match(c.pattern, c.path) {
			t.Errorf("Match(%q, %q) = true; unevaluable input must never match", c.pattern, c.path)
		}
	}
}

func TestWithinRoot(t *testing.T) {
	tests := []struct {
		name string
		root string
		path string
		want bool
	}{
		{"file in root", "/ws", "/ws/main.go", true},
		{"nested file", "/ws", "/ws/a/b/c.go", true},
		{"root itself is within root", "/ws", "/ws", true},
		{"trailing slash on root", "/ws/", "/ws/main.go", true},
		{"trailing slash on path", "/ws", "/ws/src/", true},
		{"filesystem root contains all", "/", "/etc/passwd", true},

		// The prefix trap: string containment is not path containment.
		{"sibling sharing a name prefix", "/ws", "/ws-evil/secret", false},
		{"sibling sharing a longer prefix", "/home/u/work", "/home/u/work2/x", false},
		{"parent is not within child", "/ws/src", "/ws", false},
		{"unrelated tree", "/ws", "/etc/passwd", false},

		// Unresolved inputs are refused rather than cleaned.
		{"traversal in path", "/ws", "/ws/../etc/passwd", false},
		{"relative root", "ws", "/ws/main.go", false},
		{"empty root", "", "/ws/main.go", false},
		{"empty path", "/ws", "", false},
	}

	m := NewPathMatcher()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.WithinRoot(tt.root, tt.path); got != tt.want {
				t.Errorf("WithinRoot(%q, %q) = %v, want %v", tt.root, tt.path, got, tt.want)
			}
		})
	}
}

// TestWithinRootSymlinkedRoot covers the case a lexical matcher gets wrong on
// every event: the workspace root is a symlink, so enrichment reports resolved
// paths under the link's target while the envelope names the link.
func TestWithinRootSymlinkedRoot(t *testing.T) {
	target := filepath.Join(t.TempDir(), "real")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink creation unavailable: %v", err)
		}
		t.Fatalf("symlink: %v", err)
	}

	// Resolve through the temp dir itself: on macOS /tmp is a symlink to
	// /private/tmp, so an unresolved target would fail for the wrong reason.
	realTarget, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatalf("resolve target: %v", err)
	}

	root := filepath.ToSlash(link)
	inside := filepath.ToSlash(filepath.Join(realTarget, "main.go"))
	if !IsResolved(root) || !IsResolved(inside) {
		t.Skipf("host paths are not POSIX-shaped (root=%q path=%q)", root, inside)
	}

	if NewPathMatcher().WithinRoot(root, inside) {
		t.Error("the lexical matcher claimed containment through a symlink; it cannot know that")
	}

	m := NewPathMatcherWithResolver(EvalSymlinks)
	if !m.WithinRoot(root, inside) {
		t.Errorf("WithinRoot(%q, %q) = false; a symlinked root must not produce a spurious escape", root, inside)
	}

	// Resolution must not turn containment into a blanket yes.
	outside := filepath.ToSlash(filepath.Join(filepath.Dir(realTarget), "elsewhere", "x"))
	if m.WithinRoot(root, outside) {
		t.Errorf("WithinRoot(%q, %q) = true, want false", root, outside)
	}
}

func TestWithinRootResolverFailureIsNotPermissive(t *testing.T) {
	failing := func(string) (string, error) { return "", errors.New("boom") }
	m := NewPathMatcherWithResolver(failing)

	if m.WithinRoot("/ws", "/elsewhere/x") {
		t.Error("a failing resolver produced a containment claim")
	}
	if !m.WithinRoot("/ws", "/ws/x") {
		t.Error("a failing resolver broke the lexical answer, which does not need it")
	}

	// A resolver returning something unusable must not be trusted either.
	junk := func(string) (string, error) { return "not-absolute", nil }
	if NewPathMatcherWithResolver(junk).WithinRoot("/ws", "/elsewhere/x") {
		t.Error("an unusable resolver result was accepted as a root")
	}
}

func TestResolverCalledOncePerRoot(t *testing.T) {
	var mu sync.Mutex
	calls := map[string]int{}
	counting := func(p string) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		calls[p]++
		return "/real" + p, nil
	}

	m := NewPathMatcherWithResolver(counting)
	for range 5 {
		if !m.WithinRoot("/ws", "/real/ws/main.go") {
			t.Fatal("WithinRoot = false, want true through the resolver")
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if calls["/ws"] != 1 {
		t.Errorf("resolver called %d times for one root, want 1", calls["/ws"])
	}
}

func TestMatcherIsConcurrencySafe(t *testing.T) {
	m := NewPathMatcherWithResolver(func(p string) (string, error) { return "/real" + p, nil })

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for range 100 {
				m.Match("/ws/**/*.go", "/ws/a/b/main.go")
				m.WithinRoot("/ws", "/real/ws/main.go")
			}
		}(i)
	}
	wg.Wait()
}

// FuzzMatchPath asserts the two properties that must hold for every input: it
// never panics, and it never claims a match outside the pattern's literal
// prefix — the part before the first wildcard, which no wildcard can widen.
func FuzzMatchPath(f *testing.F) {
	seeds := [][2]string{
		{"/ws/**", "/ws/a/b.go"},
		{"/ws/*.go", "/ws/main.go"},
		{"/ws/[a-z]*", "/ws/x"},
		{"/ws/**/.git/**", "/ws/a/.git/config"},
		{"/", "/"},
		{"/**", "/etc/passwd"},
		{"/ws/a**", "/ws/ab"},
		{"/ws/[", "/ws/x"},
		{"", ""},
	}
	for _, s := range seeds {
		f.Add(s[0], s[1])
	}

	f.Fuzz(func(t *testing.T, pattern, path string) {
		if !MatchPath(pattern, path) {
			return
		}
		if !IsResolved(path) {
			t.Fatalf("matched an unresolved path: pattern=%q path=%q", pattern, path)
		}
		if err := ValidatePattern(pattern); err != nil {
			t.Fatalf("matched with an invalid pattern %q: %v", pattern, err)
		}
		if prefix := literalPrefix(pattern); !strings.HasPrefix(normalize(path), prefix) {
			t.Fatalf("match escaped the pattern's literal prefix %q: pattern=%q path=%q", prefix, pattern, path)
		}
	})
}

// literalPrefix returns the leading portion of a pattern that contains no
// wildcard, truncated at a segment boundary. Any path the pattern matches must
// start with it.
func literalPrefix(pattern string) string {
	segs := segments(normalize(pattern))
	var out strings.Builder
	for _, seg := range segs {
		if strings.ContainsAny(seg, "*?[") {
			break
		}
		out.WriteString("/")
		out.WriteString(seg)
	}
	if out.Len() == 0 {
		return "/"
	}
	return out.String()
}

func BenchmarkMatchPath(b *testing.B) {
	benchmarks := []struct{ name, pattern, path string }{
		{"literal", "/ws/src/main.go", "/ws/src/main.go"},
		{"star", "/ws/src/*.go", "/ws/src/main.go"},
		{"doublestar", "/ws/**/*.go", "/ws/a/b/c/d/e/main.go"},
		{"doublestar_miss", "/ws/**/*.json", "/ws/a/b/c/d/e/main.go"},
		{"deep_backtrack", "/ws/**/x/**/*.go", "/ws/a/x/b/x/c/main.go"},
	}
	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				MatchPath(bm.pattern, bm.path)
			}
		})
	}
}
