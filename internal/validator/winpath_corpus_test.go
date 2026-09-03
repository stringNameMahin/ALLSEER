package validator

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// The Windows corpus is a separate file rather than a platform column in
// corpus.tsv. The two grammars share no row -- a Linux path is never a valid
// Windows path and the reverse -- so a column would repeat the same word on
// every one of the existing lines to separate two sets that never mix. It is
// loaded by the same loadCorpus as the Linux table, so a malformed Windows
// table fails as a format error rather than as a mysterious matcher failure.
const windowsPathCorpusPath = "../../test/testdata/paths/corpus.windows.tsv"

// decodeCorpusEscapes expands the \xNN escapes the Windows corpus allows.
//
// Only the Windows table uses them, and the decoding is deliberately not in
// loadCorpus: putting it there would silently reinterpret any Linux row that
// happened to contain the sequence, and a corpus that quietly means something
// other than what it says is worse than no corpus at all.
//
// The escape includes its own leading backslash, which is what lets a trailing
// space be written where the byte goes rather than as an invisible character at
// the end of a field.
func decodeCorpusEscapes(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+3 >= len(s) || s[i+1] != 'x' {
			b.WriteByte(s[i])
			continue
		}
		v, err := strconv.ParseUint(s[i+2:i+4], 16, 8)
		if err != nil {
			b.WriteByte(s[i])
			continue
		}
		b.WriteByte(byte(v))
		i += 3
	}
	return b.String()
}

func TestDecodeCorpusEscapes(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{`C:\ws\secret.txt`, `C:\ws\secret.txt`},
		{`C:\ws\secret.txt\x20`, "C:\\ws\\secret.txt "},
		{`C:\ws\sub\x20\secret.txt`, "C:\\ws\\sub \\secret.txt"},
		{`C:\ws\secret\x00.txt`, "C:\\ws\\secret\x00.txt"},
		// Not an escape: "\xz" is a directory named "xz", and a bare trailing
		// "\x" is a directory named "x".
		{`C:\ws\xz`, `C:\ws\xz`},
		{`C:\ws\x`, `C:\ws\x`},
	}
	for _, tt := range tests {
		if got := decodeCorpusEscapes(tt.in); got != tt.want {
			t.Errorf("decodeCorpusEscapes(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestWindowsPathCorpus(t *testing.T) {
	m := NewWindowsPathMatcher()

	for _, c := range loadCorpus(t, windowsPathCorpusPath, "match", "nomatch", "invalid", "unresolved") {
		pattern := decodeCorpusEscapes(c.pattern)
		path := decodeCorpusEscapes(c.path)

		t.Run(fmt.Sprintf("line%d_%s", c.line, c.expect), func(t *testing.T) {
			got := m.Match(pattern, path)

			switch c.expect {
			case "match":
				if !got {
					t.Errorf("line %d: Match(%q, %q) = false, want true", c.line, pattern, path)
				}
			case "nomatch":
				if got {
					t.Errorf("line %d: Match(%q, %q) = true, want false", c.line, pattern, path)
				}
				// A nomatch case must be a genuine mismatch, not a malformed
				// input that happens to return false. Conflating the two would
				// let a broken pattern masquerade as a working denial.
				if err := ValidateWindowsPattern(pattern); err != nil {
					t.Errorf("line %d: pattern %q is invalid (%v); mark it 'invalid', not 'nomatch'", c.line, pattern, err)
				}
				if err := ExplainWindowsPath(path); err != nil {
					t.Errorf("line %d: path %q is unresolved (%v); mark it 'unresolved', not 'nomatch'", c.line, path, err)
				}
			case "invalid":
				if err := ValidateWindowsPattern(pattern); err == nil {
					t.Errorf("line %d: ValidateWindowsPattern(%q) = nil, want an error", c.line, pattern)
				}
				if got {
					t.Errorf("line %d: Match(%q, %q) = true, want false for an invalid pattern", c.line, pattern, path)
				}
			case "unresolved":
				if IsResolvedWindows(path) {
					t.Errorf("line %d: IsResolvedWindows(%q) = true, want false", c.line, path)
				}
				if got {
					t.Errorf("line %d: Match(%q, %q) = true, want false for an unresolved path", c.line, pattern, path)
				}
			}
		})
	}
}

// TestWindowsPathCorpusCoverage guards against the corpus quietly losing the
// equivalence axes it exists for. Counts are lower bounds, not exact.
//
// The device-namespace axis is absent by construction: an NT device path never
// reaches the matcher, because translating it is enrichment's step zero. It is
// covered in internal/telemetry/winpath instead.
func TestWindowsPathCorpusCoverage(t *testing.T) {
	cases := loadCorpus(t, windowsPathCorpusPath, "match", "nomatch", "invalid", "unresolved")

	counts := map[string]int{}
	for _, c := range cases {
		counts[c.expect]++
	}
	for _, expect := range []string{"match", "nomatch", "invalid", "unresolved"} {
		if counts[expect] < 4 {
			t.Errorf("windows corpus has %d %q cases, want at least 4", counts[expect], expect)
		}
	}

	axes := map[string]int{
		"stream":    0,
		"shortname": 0,
		"traversal": 0,
		"trailing":  0,
		"reserved":  0,
		"unc":       0,
		"case":      0,
	}
	for _, c := range cases {
		last := c.path[strings.LastIndex(c.path, `\`)+1:]
		if strings.Contains(last, ":") {
			axes["stream"]++
		}
		if strings.Contains(c.path, "~1") {
			axes["shortname"]++
		}
		if strings.Contains(c.path, `\..\`) || strings.Contains(c.path, `\.\`) {
			axes["traversal"]++
		}
		if strings.Contains(c.path, `\x20`) || strings.HasSuffix(c.path, ".") {
			axes["trailing"]++
		}
		if isWindowsReservedName(last) {
			axes["reserved"]++
		}
		if strings.HasPrefix(c.path, `\\`) {
			axes["unc"]++
		}
		if strings.EqualFold(c.pattern, c.path) && c.pattern != c.path {
			axes["case"]++
		}
	}
	for axis, n := range axes {
		if n == 0 {
			t.Errorf("windows corpus lost the %q axis", axis)
		}
	}
}
