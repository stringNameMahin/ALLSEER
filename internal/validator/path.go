package validator

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
)

// Path matching is the sharpest security surface in the system, so its rules
// are stated once, here and in docs/path-matching.md, and implemented literally.
//
// The whole semantics in brief:
//
//   - Matching is lexical and byte-exact. Both pattern and path must be
//     absolute and already resolved; the matcher never resolves anything and
//     never cleans "." or ".." out of a path.
//   - "*", "?" and "[...]" match within one path segment and never cross "/".
//   - "**" is a segment of its own and matches zero or more whole segments.
//   - Dotfiles are ordinary. Nothing is hidden from a pattern.
//   - Anything unresolved, relative, or malformed matches nothing.
//
// Every one of those choices fails closed: the failure mode of a wrong answer
// here is a grant that covers more than its author intended, so where a rule
// could go either way it goes the way that matches less.

// Resolver canonicalizes a path, resolving symlinks. It exists so WithinRoot
// can cope with a workspace root that is itself a symlink without the matcher
// taking a hard dependency on the filesystem.
type Resolver func(path string) (string, error)

// EvalSymlinks is the production Resolver, backed by the filesystem.
var EvalSymlinks Resolver = filepath.EvalSymlinks

// GlobPathMatcher implements PathMatcher over the semantics documented above.
//
// The zero value is usable and purely lexical. A matcher built by
// NewPathMatcherWithResolver additionally canonicalizes workspace roots, which
// is the one place a lexical answer is not good enough: a root recorded as
// /home/u/work when /home/u/work is a symlink to /mnt/w would report every
// event under /mnt/w as a workspace escape.
//
// Safe for concurrent use.
type GlobPathMatcher struct {
	// resolver canonicalizes roots only. Event paths arrive already resolved
	// from enrichment; re-resolving them here would be both slow on the hot
	// path and wrong, since the file may have been replaced since the syscall.
	resolver Resolver

	// roots memoizes resolver results. Resolution is a syscall per component
	// and a session's root never changes during that session.
	roots sync.Map // string -> resolvedRoot
}

type resolvedRoot struct {
	path string
	err  error
}

var _ PathMatcher = (*GlobPathMatcher)(nil)

// NewPathMatcher returns a purely lexical matcher. This is what validation
// should use once workspace roots are canonicalized at envelope generation,
// because a matcher that touches no filesystem is a pure function of its
// inputs, and a pure validator is a reproducible one.
func NewPathMatcher() *GlobPathMatcher {
	return &GlobPathMatcher{}
}

// NewPathMatcherWithResolver returns a matcher that falls back to r when a
// lexical WithinRoot check fails. Pass EvalSymlinks for the filesystem-backed
// behavior.
//
// The fallback only ever turns a "no" into a "yes", so a resolver failure
// degrades to the lexical answer rather than to a permissive one.
func NewPathMatcherWithResolver(r Resolver) *GlobPathMatcher {
	return &GlobPathMatcher{resolver: r}
}

// Match reports whether path satisfies pattern.
//
// Both must be absolute and resolved. An invalid pattern, an unresolved path,
// or a relative anything returns false: a selector nobody can interpret grants
// nothing. Callers that need to distinguish "did not match" from "could not be
// evaluated" must check IsResolved themselves and raise
// ViolationUnresolvable — the two are not the same finding and must not be
// reported as if they were.
func (m *GlobPathMatcher) Match(pattern, path string) bool {
	return MatchPath(pattern, path)
}

// WithinRoot reports whether path is contained by root, after resolution.
//
// The root itself counts as within: a grant scoped to a workspace covers the
// workspace directory, not only its contents. Containment is checked at a
// segment boundary, so /workspace-evil is not inside /workspace.
func (m *GlobPathMatcher) WithinRoot(root, path string) bool {
	if !IsResolved(root) || !IsResolved(path) {
		return false
	}
	root = normalize(root)
	path = normalize(path)

	if containedBy(root, path) {
		return true
	}
	if m.resolver == nil {
		return false
	}

	// The lexical answer was "escape". Before believing it, canonicalize the
	// root: a symlinked root is the one case where a correct system reports a
	// false escape on every single event.
	canonical, err := m.resolveRoot(root)
	if err != nil {
		return false
	}
	if canonical == root {
		return false
	}
	return containedBy(canonical, path)
}

func (m *GlobPathMatcher) resolveRoot(root string) (string, error) {
	if v, ok := m.roots.Load(root); ok {
		rr := v.(resolvedRoot)
		return rr.path, rr.err
	}
	resolved, err := m.resolver(root)
	if err == nil {
		resolved = normalize(filepath.ToSlash(resolved))
		if !IsResolved(resolved) {
			err = fmt.Errorf("resolver returned unusable root %q", resolved)
		}
	}
	rr := resolvedRoot{path: resolved, err: err}
	m.roots.Store(root, rr)
	return rr.path, rr.err
}

// containedBy reports whether path is root or lies beneath it. Both arguments
// must already be normalized and resolved.
func containedBy(root, path string) bool {
	if root == "/" {
		return true
	}
	if path == root {
		return true
	}
	return strings.HasPrefix(path, root+"/")
}

// MatchPath is Match as a free function, so the semantics can be exercised —
// and fuzzed — without constructing a matcher.
func MatchPath(pattern, path string) bool {
	if ValidatePattern(pattern) != nil {
		return false
	}
	if !IsResolved(path) {
		return false
	}
	return matchSegments(segments(normalize(pattern)), segments(normalize(path)))
}

// PatternSet is a set of path patterns with their segmentation precomputed.
//
// MatchPath is the right shape for one pattern against one path and the wrong
// shape for many: it revalidates the pattern and re-splits both sides on every
// call, so scanning n patterns costs n validations of the same pattern list and
// n splits of the same path. A PatternSet pays the pattern cost once at
// construction and the path cost once per lookup, which turns a linear scan
// from allocation-heavy into one allocation.
//
// Written for internal/risk's sensitivity list, which scans every configured
// pattern for every event on the hot path. It applies equally to a grant scan,
// which has the same shape and the same problem — see the benchmarking TODO in
// validator.go.
//
// Immutable after construction and safe for concurrent use.
type PatternSet struct {
	raw  []string
	segs [][]string
}

// CompilePatterns validates and segments a pattern list.
//
// Validation is ValidatePattern, called rather than repeated, so a set accepts
// exactly the patterns the single-pattern path accepts. An invalid pattern is
// an error rather than an entry that silently never matches: MatchPath can
// afford to answer "no match" for a bad pattern because its caller supplied one
// pattern and one answer, while a set is built once from configuration a human
// wrote and should refuse it while that human is still looking.
func CompilePatterns(patterns []string) (*PatternSet, error) {
	set := &PatternSet{
		raw:  make([]string, 0, len(patterns)),
		segs: make([][]string, 0, len(patterns)),
	}
	for _, p := range patterns {
		if err := ValidatePattern(p); err != nil {
			return nil, err
		}
		set.raw = append(set.raw, p)
		set.segs = append(set.segs, segments(normalize(p)))
	}
	return set, nil
}

// Len reports how many patterns the set holds.
func (s *PatternSet) Len() int {
	if s == nil {
		return 0
	}
	return len(s.raw)
}

// Pattern returns the i'th pattern as written.
func (s *PatternSet) Pattern(i int) string {
	if s == nil || i < 0 || i >= len(s.raw) {
		return ""
	}
	return s.raw[i]
}

// MatchIndex returns the index of the first pattern covering path, or -1.
//
// "First" is the order the set was built in, so a caller that needs a
// precedence other than declaration order orders its patterns accordingly
// rather than scanning for all matches.
//
// An unresolved path matches nothing, the same refusal MatchPath makes and for
// the same reason: a truncated or relative path is one the matcher cannot
// reason about, and a confident answer about it would be a confident answer
// about a path that never existed.
func (s *PatternSet) MatchIndex(path string) int {
	if s == nil || len(s.segs) == 0 {
		return -1
	}
	// Split once for the whole set, and get the resolution check out of the
	// same split. This is the line the type exists for: calling IsResolved and
	// then segmenting would split the path twice before the scan even starts.
	pathSegs, ok := resolvedSegments(path)
	if !ok {
		return -1
	}
	for i, pat := range s.segs {
		if matchSegments(pat, pathSegs) {
			return i
		}
	}
	return -1
}

// Match reports whether any pattern in the set covers path.
func (s *PatternSet) Match(path string) bool { return s.MatchIndex(path) >= 0 }

// IsResolved reports whether p is in the form the matcher requires: absolute,
// free of "." and ".." segments, free of empty segments, and free of NUL.
//
// It is deliberately a check and not a fixer. Lexically cleaning ".." out of a
// path is wrong whenever a symlink is involved — /ws/link/../x resolves to a
// sibling of the link's target, not of the link — and a validator that cleaned
// paths itself would produce confident answers about paths that never existed.
// Enrichment resolves; the validator verifies and refuses.
//
// A false answer is what should become ViolationUnresolvable upstream. The
// most common cause in production will be a path truncated at
// ALLSEER_PATH_MAX by the probe, which is exactly the case that must never be
// mistaken for a complete path.
func IsResolved(p string) bool {
	_, ok := resolvedSegments(p)
	return ok
}

// resolvedSegments is IsResolved with the segmentation kept.
//
// One definition of "resolved", used by both the predicate and the scan. A
// second implementation here to save an allocation would be two answers to the
// question the fuzzer covers, and the cheaper one would be the one nobody
// fuzzed.
//
// A resolved "/" yields no segments and true, which is what makes "/**" match
// the root through the zero-segment case.
func resolvedSegments(p string) ([]string, bool) {
	if p == "" || p[0] != '/' {
		return nil, false
	}
	if strings.ContainsRune(p, 0) || strings.Contains(p, "//") {
		return nil, false
	}
	p = normalize(p)
	if p == "/" {
		return nil, true
	}
	segs := segments(p)
	for _, seg := range segs {
		if seg == "" || seg == "." || seg == ".." {
			return nil, false
		}
	}
	return segs, true
}

// ValidatePattern reports why a selector pattern cannot be evaluated, or nil.
//
// Envelope validation should call this when a grant is admitted, so a
// mistyped selector is rejected at approval time by a human who can fix it,
// rather than silently matching nothing for the whole session.
func ValidatePattern(pattern string) error {
	if pattern == "" {
		return fmt.Errorf("pattern is empty")
	}
	if pattern[0] != '/' {
		return fmt.Errorf("pattern %q is not absolute", pattern)
	}
	if strings.ContainsRune(pattern, 0) {
		return fmt.Errorf("pattern contains a NUL byte")
	}
	if strings.Contains(pattern, "//") {
		return fmt.Errorf("pattern %q has an empty path segment", pattern)
	}
	for _, seg := range segments(normalize(pattern)) {
		if err := validateSegment(seg); err != nil {
			return fmt.Errorf("pattern %q: %w", pattern, err)
		}
	}
	return nil
}

func validateSegment(seg string) error {
	switch seg {
	case "":
		return fmt.Errorf("empty path segment")
	case ".", "..":
		return fmt.Errorf("relative segment %q", seg)
	case "**":
		return nil
	}
	if strings.Contains(seg, "**") {
		// "**/x" is a grant over a subtree; "a**b" reads like one but cannot be,
		// since ** only means anything as a whole segment. Rejecting is the
		// only safe reading: silently demoting it to "*" would hand the author
		// a narrower grant than they think they wrote, and promoting it to a
		// subtree would hand them a wider one.
		return fmt.Errorf("segment %q mixes ** with other characters; ** must be a whole segment", seg)
	}
	for i := 0; i < len(seg); i++ {
		if seg[i] == '[' {
			end := classEnd(seg, i)
			if end < 0 {
				return fmt.Errorf("segment %q has an unterminated character class", seg)
			}
			i = end - 1
		}
	}
	return nil
}

// normalize strips trailing slashes, leaving root intact. A directory written
// with a trailing slash and the same directory written without one are the same
// directory, and an envelope that behaved differently for the two would be a
// trap for whoever writes it.
func normalize(p string) string {
	for len(p) > 1 && strings.HasSuffix(p, "/") {
		p = p[:len(p)-1]
	}
	return p
}

// segments splits a normalized absolute path. "/" yields no segments, which is
// what makes "/**" match "/" through the zero-segment case.
func segments(p string) []string {
	if p == "/" {
		return nil
	}
	return strings.Split(p[1:], "/")
}

// matchSegments walks pattern and path segment by segment. "**" is the only
// construct that consumes more than one, and it backtracks.
func matchSegments(pattern, path []string) bool {
	for len(pattern) > 0 {
		if pattern[0] == "**" {
			rest := pattern[1:]
			if len(rest) == 0 {
				// A trailing ** absorbs whatever is left, including nothing.
				return true
			}
			for i := 0; i <= len(path); i++ {
				if matchSegments(rest, path[i:]) {
					return true
				}
			}
			return false
		}
		if len(path) == 0 {
			return false
		}
		if !matchSegment(pattern[0], path[0]) {
			return false
		}
		pattern, path = pattern[1:], path[1:]
	}
	return len(path) == 0
}

// matchSegment matches one segment, byte by byte.
//
// Bytes, not runes: Linux paths are opaque byte strings, and decoding them as
// UTF-8 would map every invalid byte to U+FFFD, making two different filenames
// compare equal. Two visually identical names in different Unicode
// normalizations are different paths here, exactly as they are to the kernel.
func matchSegment(pattern, s string) bool {
	var (
		px, sx         int
		starPx, starSx = -1, -1
	)
	for px < len(pattern) || sx < len(s) {
		if px < len(pattern) {
			switch c := pattern[px]; c {
			case '*':
				// Remember where to resume if the rest fails to match.
				starPx, starSx = px, sx+1
				px++
				continue
			case '?':
				if sx < len(s) {
					px++
					sx++
					continue
				}
			case '[':
				if sx < len(s) {
					if end := classEnd(pattern, px); end >= 0 {
						if matchClass(pattern[px:end], s[sx]) {
							px = end
							sx++
							continue
						}
					}
				}
			default:
				if sx < len(s) && c == s[sx] {
					px++
					sx++
					continue
				}
			}
		}
		if starSx >= 0 && starSx <= len(s) {
			px, sx = starPx, starSx
			continue
		}
		return false
	}
	return true
}

// classEnd returns the index just past the ']' closing the class opened at
// start, or -1 if the class is unterminated. A ']' immediately after the
// opening bracket (or its negation marker) is a literal, per POSIX.
func classEnd(pattern string, start int) int {
	i := start + 1
	if i < len(pattern) && (pattern[i] == '!' || pattern[i] == '^') {
		i++
	}
	if i < len(pattern) && pattern[i] == ']' {
		i++
	}
	for ; i < len(pattern); i++ {
		if pattern[i] == ']' {
			return i + 1
		}
	}
	return -1
}

// matchClass evaluates a well-formed class, given as "[...]" including both
// brackets, against one byte.
func matchClass(class string, c byte) bool {
	body := class[1 : len(class)-1]
	negated := false
	if len(body) > 0 && (body[0] == '!' || body[0] == '^') {
		negated = true
		body = body[1:]
	}

	matched := false
	for i := 0; i < len(body); i++ {
		lo := body[i]
		hi := lo
		if i+2 < len(body) && body[i+1] == '-' {
			hi = body[i+2]
			i += 2
		}
		if lo <= c && c <= hi {
			matched = true
		}
	}
	return matched != negated
}
