package validator

import (
	"strings"
	"testing"
)

// The corpus in test/testdata/paths/corpus.windows.tsv carries the cases a
// reviewer should be able to read as data. What lives here is what a text table
// cannot show: exact bytes, the shape of the parse rather than its verdict, and
// the invariants a fuzzer checks.

func TestWindowsCanonicalFormAccepts(t *testing.T) {
	// Paths taken from a real ETW capture, after the device-to-drive
	// translation enrichment performs. If the canonical form rejected these,
	// nothing on this platform would ever be matchable.
	resolved := []string{
		`C:\`,
		`D:\ALLSEER\dev\spike-results\fileprobe\alpha-created.txt`,
		`C:\Windows\System32\cmd.exe`,
		`C:\Users\desktop.ini:Zone.Identifier`,
		`C:\Program Files\EdgeWebView\manifest.json::$ATTRIBUTE_LIST`,
		`C:\ws\Package~31bf3856ad364e35~amd64~.cat`,
		// A leading space is legal; only a trailing one is stripped by Win32.
		`C:\ws\ leading.txt`,
		// Dots inside a name are ordinary, and a dotfile is not special.
		`C:\ws\.gitignore`,
		`C:\ws\a.b.c.txt`,
	}
	for _, p := range resolved {
		if err := ExplainWindowsPath(p); err != nil {
			t.Errorf("ExplainWindowsPath(%q) = %v, want nil", p, err)
		}
	}
}

func TestWindowsStreamParse(t *testing.T) {
	tests := []struct {
		path    string
		file    string
		present bool
		name    string
		typed   bool
		typ     string
	}{
		{path: `C:\ws\notes.txt`, file: "notes.txt"},
		{path: `C:\ws\notes.txt:hidden`, file: "notes.txt", present: true, name: "hidden"},
		// The form the design did not anticipate: an empty stream name with an
		// explicit type. It must not collapse into a stream named
		// ":$ATTRIBUTE_LIST", which is what splitting on the first colon and
		// keeping the remainder would produce.
		{path: `C:\ws\m.json::$ATTRIBUTE_LIST`, file: "m.json", present: true, name: "", typed: true, typ: "$ATTRIBUTE_LIST"},
		{path: `C:\ws\m.json:s:$DATA`, file: "m.json", present: true, name: "s", typed: true, typ: "$DATA"},
		// A stream name may contain dots; Zone.Identifier is the common case.
		{path: `C:\ws\a.txt:Zone.Identifier`, file: "a.txt", present: true, name: "Zone.Identifier"},
	}
	for _, tt := range tests {
		wp, err := parseWindowsPath(tt.path, false)
		if err != nil {
			t.Errorf("parseWindowsPath(%q) = %v, want nil", tt.path, err)
			continue
		}
		if got := wp.segs[len(wp.segs)-1]; got != tt.file {
			t.Errorf("%q: file part = %q, want %q", tt.path, got, tt.file)
		}
		got := wp.stream
		if got.present != tt.present || got.name != tt.name || got.typed != tt.typed || got.typ != tt.typ {
			t.Errorf("%q: stream = %+v, want {present:%v name:%q typed:%v typ:%q}",
				tt.path, got, tt.present, tt.name, tt.typed, tt.typ)
		}
	}
}

// TestWindowsStreamAbsentIsNotEmpty pins the distinction the winStream.present
// flag exists for. "no stream" and "a stream whose name is empty" are different
// files, and a representation that collapsed them would make a grant for the
// plain file cover an attribute-list write.
func TestWindowsStreamAbsentIsNotEmpty(t *testing.T) {
	plain := `C:\ws\m.json`
	typed := `C:\ws\m.json::$ATTRIBUTE_LIST`

	if MatchWindowsPath(plain, typed) {
		t.Errorf("a pattern naming no stream matched %q", typed)
	}
	if MatchWindowsPath(typed, plain) {
		t.Errorf("a pattern naming a typed stream matched the plain path %q", plain)
	}
	if !MatchWindowsPath(typed, typed) {
		t.Errorf("%q did not match itself", typed)
	}
}

// TestWindowsWildcardDoesNotCrossStreamSeparator pins the rule
// docs/path-matching.md 9.4 left open. It is the single most consequential
// choice in this grammar: the other reading would make every "*.txt" grant a
// grant over every stream on every .txt file.
func TestWindowsWildcardDoesNotCrossStreamSeparator(t *testing.T) {
	stream := `C:\ws\notes.txt:hidden`

	for _, pattern := range []string{
		`C:\ws\*`,
		`C:\ws\*.txt`,
		`C:\ws\notes*`,
		`C:\ws\**`,
		`C:\ws\notes.tx?`,
	} {
		if MatchWindowsPath(pattern, stream) {
			t.Errorf("pattern %q crossed the stream separator to match %q", pattern, stream)
		}
	}

	// Reaching a stream requires saying so, and then a wildcard works normally
	// within the stream name.
	for _, pattern := range []string{
		`C:\ws\*.txt:*`,
		`C:\ws\notes.txt:h*n`,
		`C:\ws\**:hidden`,
	} {
		if !MatchWindowsPath(pattern, stream) {
			t.Errorf("pattern %q did not match %q", pattern, stream)
		}
	}
}

func TestWindowsCaseFolding(t *testing.T) {
	tests := []struct {
		pattern, path string
		want          bool
	}{
		{`C:\ws\Makefile`, `C:\ws\Makefile`, true},
		{`C:\ws\makefile`, `C:\ws\Makefile`, true},
		{`C:\WS\MAKEFILE`, `C:\ws\Makefile`, true},
		{`c:\ws\*`, `C:\ws\Makefile`, true},
		// Folding is ASCII only. These are the bytes a text corpus cannot show
		// a reviewer: U+00E9 in both spellings, differing only in case.
		{"C:\\ws\\caf\u00c9.txt", "C:\\ws\\caf\u00e9.txt", false},
		{"C:\\ws\\caf\u00e9.txt", "C:\\ws\\caf\u00e9.txt", true},
		// Nor does folding reach a decomposed spelling: "e" + U+0301 is a
		// different byte sequence from U+00E9 and stays a different file, as it
		// does on Linux.
		{"C:\\ws\\cafe\u0301.txt", "C:\\ws\\caf\u00e9.txt", false},
	}
	for _, tt := range tests {
		if got := MatchWindowsPath(tt.pattern, tt.path); got != tt.want {
			t.Errorf("MatchWindowsPath(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
		}
	}
}

// TestWindowsFoldDoesNotRewriteClassRanges guards the reason matchClass tries
// both cases of the input byte instead of lowering the class body. Lowering
// "[A-_]" would move a range covering six punctuation bytes to somewhere its
// author never wrote.
func TestWindowsFoldDoesNotRewriteClassRanges(t *testing.T) {
	// "^" (0x5E) lies between "Z" and "a", inside [A-_] and outside [a-_].
	if !MatchWindowsPath(`C:\ws\[A-_]`, `C:\ws\^`) {
		t.Error(`[A-_] should still cover "^" under folding`)
	}
	// A letter matches through either case, from either side of the range.
	if !MatchWindowsPath(`C:\ws\[a-m]ain.go`, `C:\ws\Main.go`) {
		t.Error(`[a-m] should cover "M" under folding`)
	}
	if !MatchWindowsPath(`C:\ws\[A-M]ain.go`, `C:\ws\main.go`) {
		t.Error(`[A-M] should cover "m" under folding`)
	}
	// Negation still applies after folding, rather than to each case separately.
	if MatchWindowsPath(`C:\ws\[!a-m]ain.go`, `C:\ws\Main.go`) {
		t.Error(`[!a-m] should exclude "M" under folding`)
	}
}

func TestWithinWindowsRoot(t *testing.T) {
	tests := []struct {
		name, root, path string
		want             bool
	}{
		{"root itself", `C:\ws`, `C:\ws`, true},
		{"child", `C:\ws`, `C:\ws\src\main.go`, true},
		{"case folded", `C:\WS`, `C:\ws\src\main.go`, true},
		{"case folded root", `C:\ws`, `C:\WS\src\main.go`, true},
		// The escape a string-prefix check would miss.
		{"sibling with shared prefix", `C:\ws`, `C:\ws-evil\x`, false},
		{"parent", `C:\ws\src`, `C:\ws`, false},
		{"other drive", `C:\ws`, `D:\ws\main.go`, false},
		{"drive root contains all", `C:\`, `C:\ws\main.go`, true},
		// A stream on a file inside the root is inside the root.
		{"stream under root", `C:\ws`, `C:\ws\a.txt:Zone.Identifier`, true},
		// A root is a directory. A stream is not one.
		{"stream as root", `C:\ws\a.txt:s`, `C:\ws\a.txt:s`, false},
		// Unresolved on either side is unanswerable, never "contained".
		{"unresolved path", `C:\ws`, `C:\ws\..\etc`, false},
		{"unresolved root", `C:\ws\.`, `C:\ws\main.go`, false},
		{"posix root", `/ws`, `C:\ws\main.go`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := WithinWindowsRoot(tt.root, tt.path); got != tt.want {
				t.Errorf("WithinWindowsRoot(%q, %q) = %v, want %v", tt.root, tt.path, got, tt.want)
			}
		})
	}
}

func TestIsWindowsShortName(t *testing.T) {
	tests := []struct {
		seg  string
		want bool
	}{
		{"LONGDI~1", true},
		{"PROGRA~1", true},
		{"PROGRA~2", true},
		{"MICROS~1.TXT", true},
		{"ABCDEFG~123456", false}, // base longer than 8
		{"~1", false},             // nothing before the tilde
		{"ABC~", false},           // nothing after it
		{"ABC~X", false},          // not digits
		{"main.go", false},
		{"Makefile", false},
		// The measured false-positive class: ordinary long names containing a
		// tilde. All six "~" hits in a cold-build capture looked like this.
		{"Package~31bf3856ad364e35~amd64~.cat", false},
		// Lowercase means an ordinary name, since the generator emits uppercase.
		{"longdi~1", false},
	}
	for _, tt := range tests {
		if got := isWindowsShortName(tt.seg); got != tt.want {
			t.Errorf("isWindowsShortName(%q) = %v, want %v", tt.seg, got, tt.want)
		}
	}
}

func TestIsWindowsReservedName(t *testing.T) {
	reserved := []string{"CON", "con", "NUL", "NUL.txt", "COM1", "lpt9", "AUX", "PRN"}
	for _, seg := range reserved {
		if !isWindowsReservedName(seg) {
			t.Errorf("isWindowsReservedName(%q) = false, want true", seg)
		}
	}
	ordinary := []string{"CONFIG", "NULL", "COM", "COM10", "LPT", "console.log", "auxiliary"}
	for _, seg := range ordinary {
		if isWindowsReservedName(seg) {
			t.Errorf("isWindowsReservedName(%q) = true, want false", seg)
		}
	}
}

// TestWindowsRulesDoNotLeakIntoPOSIX is the regression guard for the one shared
// change this grammar required: matchSegment and matchClass grew a fold flag.
// Every Linux caller passes false, and these are the cases that would show it
// if one stopped.
func TestWindowsRulesDoNotLeakIntoPOSIX(t *testing.T) {
	if MatchPath("/ws/Makefile", "/ws/makefile") {
		t.Error("POSIX matching folded case")
	}
	if MatchPath("/ws/[a-m]ain.go", "/ws/Main.go") {
		t.Error("POSIX character class folded case")
	}
	if !MatchPath(`/ws/a:b`, `/ws/a:b`) {
		t.Error("POSIX matching treated a colon as a stream separator")
	}
	if !IsResolved(`/ws/CON`) || !IsResolved(`/ws/secret.txt.`) || !IsResolved(`/ws/LONGDI~1`) {
		t.Error("a Windows-only rejection reached the POSIX grammar")
	}
	// And the reverse: a Linux path is not a Windows path.
	if IsResolvedWindows("/ws/main.go") {
		t.Error("IsResolvedWindows accepted a POSIX path")
	}
}

func FuzzMatchWindowsPath(f *testing.F) {
	seeds := [][2]string{
		{`C:\ws\**`, `C:\ws\a\b.go`},
		{`C:\ws\*.go`, `C:\ws\main.go`},
		{`C:\ws\[a-z]*`, `C:\ws\x`},
		{`C:\ws\*.txt:*`, `C:\ws\a.txt:Zone.Identifier`},
		{`C:\ws\m.json::$*`, `C:\ws\m.json::$ATTRIBUTE_LIST`},
		{`C:\`, `C:\`},
		{`C:\**`, `C:\Windows\System32\cmd.exe`},
		{`C:\ws\a**`, `C:\ws\ab`},
		{`C:\ws\[`, `C:\ws\x`},
		{"", ""},
	}
	for _, s := range seeds {
		f.Add(s[0], s[1])
	}

	f.Fuzz(func(t *testing.T, pattern, path string) {
		if !MatchWindowsPath(pattern, path) {
			return
		}
		if !IsResolvedWindows(path) {
			t.Fatalf("matched an unresolved path: pattern=%q path=%q", pattern, path)
		}
		if err := ValidateWindowsPattern(pattern); err != nil {
			t.Fatalf("matched with an invalid pattern %q: %v", pattern, err)
		}
		// A match may never escape the pattern's literal prefix, which no
		// wildcard can widen. Compared case-folded, since that is the
		// comparison the matcher itself performs.
		prefix := windowsLiteralPrefix(pattern)
		if len(path) < len(prefix) || !equalFoldASCII(path[:len(prefix)], prefix) {
			t.Fatalf("match escaped the pattern's literal prefix %q: pattern=%q path=%q", prefix, pattern, path)
		}
	})
}

// windowsLiteralPrefix returns the leading portion of a pattern that contains
// no wildcard, truncated at a segment boundary. Any path the pattern matches
// must start with it, up to ASCII case.
func windowsLiteralPrefix(pattern string) string {
	wp, err := parseWindowsPath(pattern, true)
	if err != nil {
		return ""
	}
	var out strings.Builder
	out.WriteByte(wp.drive)
	out.WriteString(`:\`)
	for i, seg := range wp.segs {
		if strings.ContainsAny(seg, "*?[") {
			break
		}
		if i > 0 {
			out.WriteString(`\`)
		}
		out.WriteString(seg)
	}
	return out.String()
}

func BenchmarkMatchWindowsPath(b *testing.B) {
	benchmarks := []struct{ name, pattern, path string }{
		{"literal", `C:\ws\src\main.go`, `C:\ws\src\main.go`},
		{"star", `C:\ws\src\*.go`, `C:\ws\src\main.go`},
		{"doublestar", `C:\ws\**\*.go`, `C:\ws\a\b\c\d\e\main.go`},
		{"stream", `C:\ws\**\*.txt:*`, `C:\ws\a\b\notes.txt:Zone.Identifier`},
	}
	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if !MatchWindowsPath(bm.pattern, bm.path) {
					b.Fatal("benchmark case does not match")
				}
			}
		})
	}
}
