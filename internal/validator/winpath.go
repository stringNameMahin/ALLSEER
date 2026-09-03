package validator

import (
	"fmt"
	"strings"
)

// Windows path matching. The POSIX rules in path.go are unchanged and remain
// the only rules applied to a Linux path; everything here is a second grammar,
// selected by the platform an event came from rather than by the platform the
// binary was built for.
//
// Two grammars rather than one behind a build tag, deliberately. A build tag
// would make the Windows rules untestable on a Linux CI host and the Linux
// rules untestable on a Windows developer's machine, which is the wrong
// property for the most security-sensitive code in the system. Both compile
// everywhere and both are exercised everywhere.
//
// The normative statement of these rules is docs/path-matching.md section 9,
// which also records what was measured to justify each one. In brief, the Linux
// justification for byte-exact matching -- "a path is an opaque byte sequence,
// the only special bytes are / and NUL" -- is simply false on Windows, where
// the kernel maps many spellings onto one file. So the canonical form is
// narrower and comparison folds case:
//
//   - A resolved path is drive-letter absolute with an uppercase drive,
//     backslash-separated, with no trailing separator except at a drive root.
//   - No ".", "..", empty, 8.3-short, reserved-device, or trailing-dot /
//     trailing-space segments. All are rejected, never repaired.
//   - Comparison folds ASCII case. This is required for correctness, not only
//     against evasion: ETW reports the same file with two different casings
//     inside a single trace, so a byte-exact matcher could not correlate two
//     events about one file from one provider.
//   - An alternate data stream is part of the path and is matched as its own
//     component. A wildcard never crosses the ":" that introduces one.
//
// Every one of those fails closed in the same direction path.go does: where a
// rule could go either way, it goes the way that matches less.

// WindowsPathMatcher implements PathMatcher over the semantics above.
//
// The zero value is usable. Unlike GlobPathMatcher it takes no Resolver: the
// Windows analogue of a symlinked root is a reparse point, and resolving one
// needs a Windows handle rather than a portable filesystem call. Root
// canonicalization is therefore enrichment's job on this platform -- see
// internal/telemetry/winpath -- and the matcher stays a pure function of its
// inputs.
//
// Safe for concurrent use.
type WindowsPathMatcher struct{}

var _ PathMatcher = WindowsPathMatcher{}

// NewWindowsPathMatcher returns a matcher over the Windows canonical form.
//
// Nothing selects between this and NewPathMatcher yet. Platform selection
// belongs with the collector that knows which platform an event came from, and
// no such seam exists while there is one collector; inventing one here would be
// guessing at an interface rather than deriving it.
func NewWindowsPathMatcher() WindowsPathMatcher { return WindowsPathMatcher{} }

// Match reports whether path satisfies pattern under the Windows rules.
func (WindowsPathMatcher) Match(pattern, path string) bool {
	return MatchWindowsPath(pattern, path)
}

// WithinRoot reports whether path is contained by root, comparing case-folded.
func (WindowsPathMatcher) WithinRoot(root, path string) bool {
	return WithinWindowsRoot(root, path)
}

// MatchWindowsPath is Match as a free function, so the semantics can be
// exercised -- and fuzzed -- without constructing a matcher.
//
// An unusable pattern or an unresolved path matches nothing, exactly as in
// MatchPath and for the same reason: a selector nobody can interpret grants
// nothing. Callers needing to tell "did not match" from "could not be
// evaluated" check IsResolvedWindows themselves and raise
// ViolationUnresolvable.
func MatchWindowsPath(pattern, path string) bool {
	pat, err := parseWindowsPath(pattern, true)
	if err != nil {
		return false
	}
	tgt, err := parseWindowsPath(path, false)
	if err != nil {
		return false
	}
	if !equalByte(pat.drive, tgt.drive, true) {
		return false
	}
	if !matchSegments(pat.segs, tgt.segs, true) {
		return false
	}
	return matchWindowsStream(pat.stream, tgt.stream)
}

// WithinWindowsRoot reports whether path is root or lies beneath it.
//
// The root itself counts as within, as on Linux. Containment is checked segment
// by segment rather than by string prefix, so C:\workspace-evil is not inside
// C:\workspace even though one folds to a prefix of the other.
//
// A root naming a stream is refused: a workspace root is a directory, and a
// stream is not one.
func WithinWindowsRoot(root, path string) bool {
	rt, err := parseWindowsPath(root, false)
	if err != nil || rt.stream.present {
		return false
	}
	tgt, err := parseWindowsPath(path, false)
	if err != nil {
		return false
	}
	if !equalByte(rt.drive, tgt.drive, true) {
		return false
	}
	if len(rt.segs) > len(tgt.segs) {
		return false
	}
	for i, seg := range rt.segs {
		if !equalFoldASCII(seg, tgt.segs[i]) {
			return false
		}
	}
	return true
}

// IsResolvedWindows reports whether p is in the canonical Windows form the
// matcher requires.
//
// Like IsResolved it is a check and not a fixer, and for a sharper version of
// the same reason. Stripping a trailing dot from "secret.txt." would silently
// rewrite what the caller asked for; accepting both spellings is precisely what
// creates the hole, since the kernel opens one file for both. Enrichment
// canonicalizes and this verifies.
//
// A false answer is what should become ViolationUnresolvable upstream.
func IsResolvedWindows(p string) bool {
	_, err := parseWindowsPath(p, false)
	return err == nil
}

// ExplainWindowsPath reports why a path is not in canonical form, or nil.
//
// IsResolvedWindows answers the hot-path question; this one exists for the
// diagnostics an operator reads, where "not resolved" without a reason is a
// bug report nobody can act on.
func ExplainWindowsPath(p string) error {
	_, err := parseWindowsPath(p, false)
	return err
}

// ValidateWindowsPattern reports why a Windows selector pattern cannot be
// evaluated, or nil. The counterpart of ValidatePattern, used at the same
// point: envelope admission, while a human is still looking.
func ValidateWindowsPattern(pattern string) error {
	if _, err := parseWindowsPath(pattern, true); err != nil {
		return fmt.Errorf("windows pattern: %w", err)
	}
	return nil
}

// --- The canonical form -----------------------------------------------------

// winPath is a parsed Windows path or pattern.
//
// Parsing into a structure rather than matching over the raw string is what
// makes the stream rule enforceable: "does this pattern name a stream" is a
// question about the parse, and a matcher working on the string would have to
// answer it by scanning for a ":" that may belong to the drive designator.
type winPath struct {
	drive  byte
	segs   []string
	stream winStream
}

// winStream is the alternate-data-stream suffix of a path's final segment.
//
// NTFS's full grammar is filename:streamname:$streamtype, and the two forms
// observed on a real host are both projections of it -- "f.txt:Zone.Identifier"
// and "f.txt::$ATTRIBUTE_LIST", the second an empty stream name with an
// explicit type. Three positions are therefore parsed, not two, and an empty
// name with a type must not collapse into a stream named ":$ATTRIBUTE_LIST".
//
// present distinguishes "no stream" from "a stream whose name is empty". Those
// are different files, and a flag per position is the only way to keep them so.
type winStream struct {
	present bool
	name    string
	typed   bool
	typ     string
}

// winReservedNames are the DOS device names, which name a device in every
// directory at once rather than naming a file.
var winReservedNames = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true,
	"COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true,
	"LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

// parseWindowsPath parses and validates a path or a pattern.
//
// One function for both, so the two can never drift: a pattern accepted at
// admission time that the matcher then refuses would match nothing, silently,
// which is the failure ValidatePattern exists to prevent on the Linux side. The
// pattern flag relaxes exactly three things and nothing else -- glob
// metacharacters are legal, the drive letter may be written in either case, and
// a stream type need not begin with "$" so that both "$*" and "*" can be
// written.
func parseWindowsPath(p string, pattern bool) (winPath, error) {
	var wp winPath

	if p == "" {
		return wp, fmt.Errorf("path is empty")
	}
	if strings.ContainsRune(p, 0) {
		return wp, fmt.Errorf("%q contains a NUL byte", p)
	}
	if len(p) < 3 || p[1] != ':' || p[2] != '\\' {
		// One check catches every non-canonical anchoring: the relative forms
		// "ws\main.go" and "\ws\main.go", the extended-length prefix
		// "\\?\C:\...", the UNC admin-share alias "\\localhost\C$\...", and
		// drive-relative "C:main.go", which names a different file per process
		// depending on that process's per-drive working directory.
		return wp, fmt.Errorf("%q is not a drive-letter absolute path", p)
	}

	switch d := p[0]; {
	case d >= 'A' && d <= 'Z':
		wp.drive = d
	case d >= 'a' && d <= 'z':
		if !pattern {
			return wp, fmt.Errorf("%q has a lowercase drive letter; the canonical form is uppercase", p)
		}
		wp.drive = d
	default:
		return wp, fmt.Errorf("%q does not begin with a drive letter", p)
	}

	rest := p[3:]
	if strings.ContainsRune(rest, '/') {
		return wp, fmt.Errorf("%q uses a forward slash; the canonical separator is a backslash", p)
	}
	if rest == "" {
		// A drive root. No segments, which is what lets "C:\**" cover the whole
		// drive through the zero-segment case, exactly as "/**" does on Linux.
		return wp, nil
	}

	segs := strings.Split(rest, "\\")
	for i, seg := range segs {
		if seg == "" {
			// One check for a doubled separator and for a trailing one. Both
			// occur on real events -- ETW reports directory operations as
			// "...\fileprobe\" -- and both are enrichment's to strip, not the
			// matcher's to tolerate.
			return wp, fmt.Errorf("%q has an empty path segment", p)
		}
		if i == len(segs)-1 {
			file, st, err := splitWindowsStream(seg, pattern)
			if err != nil {
				return wp, fmt.Errorf("%q: %w", p, err)
			}
			seg, wp.stream = file, st
		} else if strings.ContainsRune(seg, ':') {
			// A stream suffix can only appear on the final segment, so a colon
			// anywhere else is a literal character in a directory name -- which
			// Win32 cannot express, and which a parser splitting on the first
			// colon would read as a stream. This is not hypothetical: one cold
			// build emitted 48 events under a directory literally named
			// "$env:PATH", from an unexpanded PATH entry. Refusing is the
			// fail-closed reading and it keeps the canonical form
			// re-expressible as a Win32 path.
			return wp, fmt.Errorf("%q has a colon outside its final segment; ':' is reserved for the drive and for a stream suffix", p)
		}
		if err := validateWindowsSegment(seg, pattern); err != nil {
			return wp, fmt.Errorf("%q: %w", p, err)
		}
		segs[i] = seg
	}

	if !pattern && wp.stream.present {
		if err := validateWindowsNameBytes(wp.stream.name); err != nil {
			return wp, fmt.Errorf("%q stream name: %w", p, err)
		}
		if err := validateWindowsNameBytes(wp.stream.typ); err != nil {
			return wp, fmt.Errorf("%q stream type: %w", p, err)
		}
	}

	wp.segs = segs
	return wp, nil
}

// splitWindowsStream separates a final segment into its file part and its
// stream suffix.
func splitWindowsStream(seg string, pattern bool) (string, winStream, error) {
	parts := strings.Split(seg, ":")
	switch len(parts) {
	case 1:
		return seg, winStream{}, nil
	case 2:
		if parts[1] == "" {
			return "", winStream{}, fmt.Errorf("segment %q ends in a bare stream separator", seg)
		}
		return parts[0], winStream{present: true, name: parts[1]}, nil
	case 3:
		if parts[2] == "" {
			return "", winStream{}, fmt.Errorf("segment %q names an empty stream type", seg)
		}
		if !pattern && parts[2][0] != '$' {
			return "", winStream{}, fmt.Errorf("segment %q has stream type %q, which does not begin with '$'", seg, parts[2])
		}
		return parts[0], winStream{present: true, name: parts[1], typed: true, typ: parts[2]}, nil
	default:
		return "", winStream{}, fmt.Errorf("segment %q has %d stream separators; NTFS allows at most two", seg, len(parts)-1)
	}
}

// matchWindowsStream compares the stream components of a pattern and a path.
//
// The rule docs/path-matching.md 9.4 left open is decided here and stated once:
// a wildcard never crosses the ":" introducing a stream. Each of the three
// positions -- file, stream name, stream type -- is matched on its own, and a
// pattern naming no stream matches only a path naming no stream.
//
// So a grant for "C:\ws\*.txt" does not authorize writing to
// "C:\ws\notes.txt:hidden". That is the fail-closed direction and it makes
// stream access something an envelope has to ask for. The measured rate is tens
// of stream-bearing paths per cold build, "Zone.Identifier" -- mark of the web
// -- among them, so this is a rule that fires on ordinary workloads rather than
// only under attack.
func matchWindowsStream(pat, tgt winStream) bool {
	if pat.present != tgt.present {
		return false
	}
	if !pat.present {
		return true
	}
	if !matchSegment(pat.name, tgt.name, true) {
		return false
	}
	if pat.typed != tgt.typed {
		return false
	}
	if !pat.typed {
		return true
	}
	return matchSegment(pat.typ, tgt.typ, true)
}

// validateWindowsSegment applies the per-segment rules of the canonical form.
func validateWindowsSegment(seg string, pattern bool) error {
	switch seg {
	case "":
		return fmt.Errorf("empty path segment")
	case ".", "..":
		// Rejected, never cleaned. Lexical cleaning is wrong across a reparse
		// point for the same reason it is wrong across a symlink: the kernel
		// resolves ".." against the target, so the cleaned path names a file
		// that was never touched.
		return fmt.Errorf("relative segment %q", seg)
	}

	if pattern {
		// Glob well-formedness is one rule for both platforms; a second copy
		// here would be a second answer to the question the fuzzer covers.
		if err := validateSegment(seg); err != nil {
			return err
		}
	} else if err := validateWindowsNameBytes(seg); err != nil {
		return err
	}

	if strings.HasSuffix(seg, ".") || strings.HasSuffix(seg, " ") {
		// The cheapest evasion measured on this platform: one character, no
		// reparse point, no race. Win32 strips both before the kernel sees the
		// name, so "secret.txt." opens "secret.txt" and a denial written for
		// the latter would miss the former.
		return fmt.Errorf("segment %q ends in a dot or a space, so it names the same file as the segment without it", seg)
	}
	if isWindowsReservedName(seg) {
		return fmt.Errorf("segment %q is a reserved device name, which names a device rather than a file", seg)
	}
	if isWindowsShortName(seg) {
		return fmt.Errorf("segment %q is an 8.3 short name; expand it with GetLongPathName before matching", seg)
	}
	return nil
}

// validateWindowsNameBytes rejects bytes that cannot occur in a real name.
//
// Applied to paths only. These are the characters Win32 refuses in a filename,
// so a path carrying one either did not come from the filesystem or was
// corrupted on the way here, and both readings say the same thing: it is not
// something to match a grant against. Note that "*" and "?" are in the set,
// which is what stops a pattern from being accepted as a path.
func validateWindowsNameBytes(seg string) error {
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		if c < 0x20 {
			return fmt.Errorf("segment %q contains a control byte", seg)
		}
		if strings.IndexByte("<>\"|?*", c) >= 0 {
			return fmt.Errorf("segment %q contains %q, which is not legal in a Windows filename", seg, string(rune(c)))
		}
	}
	return nil
}

// isWindowsReservedName reports whether a segment names a DOS device.
//
// The name is reserved with or without an extension: "NUL.txt" is the null
// device, not a text file.
func isWindowsReservedName(seg string) bool {
	base := seg
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	return winReservedNames[strings.ToUpper(base)]
}

// isWindowsShortName reports whether a segment looks like a generated 8.3 alias.
//
// Shape rather than a filesystem query, because the matcher performs no I/O and
// because the alias for a given long name is not stable across volumes anyway.
// The test is the shape the generator actually produces: an all-uppercase name
// of at most 8 characters plus at most a 3-character extension, whose base ends
// in "~" followed by digits.
//
// The uppercase requirement is what keeps this from firing on ordinary names,
// and it was measured: a search for "~" across a cold-build capture returned
// six hits, all six long names of the form
// "...Required-Package~31bf3856ad364e35~amd64~...", none of them short names.
//
// A genuine all-caps long name of the same shape -- "BACKUP~1" -- is refused
// too. That is a false positive in the fail-closed direction: the path becomes
// unevaluable and is reported as such, rather than being matched against a
// grant under a spelling the kernel treats as an alias for another file.
func isWindowsShortName(seg string) bool {
	base, ext := seg, ""
	if i := strings.LastIndexByte(seg, '.'); i >= 0 {
		base, ext = seg[:i], seg[i+1:]
	}
	if base == "" || len(base) > 8 || len(ext) > 3 {
		return false
	}
	tilde := strings.LastIndexByte(base, '~')
	if tilde <= 0 || tilde == len(base)-1 || len(base)-tilde-1 > 6 {
		return false
	}
	for i := tilde + 1; i < len(base); i++ {
		if base[i] < '0' || base[i] > '9' {
			return false
		}
	}
	for i := 0; i < len(seg); i++ {
		if seg[i] >= 'a' && seg[i] <= 'z' {
			return false
		}
	}
	return true
}

// equalFoldASCII compares two strings byte for byte, folding ASCII case.
//
// Not strings.EqualFold, which folds Unicode. The difference is the whole
// argument of docs/path-matching.md 9.3: Unicode folding is locale- and
// normalization-dependent, and importing it would trade the documented gap on
// non-ASCII names for an undocumented one everywhere.
func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if !equalByte(a[i], b[i], true) {
			return false
		}
	}
	return true
}
