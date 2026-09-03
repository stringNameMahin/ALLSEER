package abigen

import (
	"fmt"
	"strconv"
	"strings"
)

// Header is what the parser recovers from allseer_event.h.
//
// Ordered slices rather than maps throughout, because the generated file is
// compared byte for byte against the committed one by the staleness test and
// Go's map iteration order is randomized. A generator whose output depends on
// map order would report drift on every second run.
type Header struct {
	Defines []Define
	Enums   []Enum
	Structs []Struct
}

// Define is an integer #define. Valueless defines -- the include guard -- are
// skipped rather than recorded, since they name nothing the ABI needs.
type Define struct {
	Name  string
	Value int

	// UsedAsBound reports whether some array in the header is declared with
	// this define as its bound.
	//
	// Recorded because the two kinds of define mean different things and the
	// generated file should not describe them as one. A bound is a cap on what
	// a probe can report -- exceed it and the value is truncated. A define no
	// array uses is a value the kernel and user sides compare, and calling it a
	// limit in the emitted comment would be a plain misstatement about the
	// contract, in the one file nobody is supposed to edit by hand.
	//
	// Derived from use rather than from the name. A rule that read a suffix
	// like _MAX would be a second, weaker copy of the header's meaning, and it
	// would be wrong the first time somebody named a bound differently.
	UsedAsBound bool
}

// Enum is a C enum with every member explicitly valued.
type Enum struct {
	Name    string
	Members []EnumMember
}

// EnumMember carries its literal value. Implicit values are refused at parse
// time: the header calls these "a wire contract: append only, never renumber",
// and a value nobody wrote down is a value nobody reviewed.
type EnumMember struct {
	Name  string
	Value int
}

// Struct is a C struct declaration.
type Struct struct {
	Name   string
	Fields []Field
}

// Field is one member of a struct, or one member of a union inside a struct.
type Field struct {
	// Name is the C member name.
	Name string

	// Type is the C type: a scalar ("__u64", "char"), or a struct reference
	// ("struct allseer_proc"). Empty when Union is set.
	Type string

	// Dims holds array dimensions, outermost first, already resolved to
	// integers from #defines. Nil for a scalar.
	Dims []int

	// Union holds the members of an anonymous union declared inline. Set only
	// for struct allseer_event's payload, and supported because that one union
	// is what the ring buffer record is built around; anything more elaborate
	// is refused.
	Union []Field

	// Line is the 1-based line in the header, for error messages. A generator
	// that says "unsupported construct" without saying where is a generator
	// that costs more time than it saves.
	Line int
}

// IsUnion reports whether the field is an inline union.
func (f Field) IsUnion() bool { return len(f.Union) > 0 }

// Parse recovers the ABI declarations from C header source.
//
// Comments are stripped first, then preprocessor lines, then the remainder is
// scanned for enum and struct declarations. That order works because
// allseer_event.h has no preprocessor directives inside a struct body, and the
// parser refuses anything it does not recognize rather than assuming it can.
func Parse(src string) (*Header, error) {
	src = stripComments(src)

	h := &Header{}
	body, err := takePreprocessor(src, h)
	if err != nil {
		return nil, err
	}

	if err := parseDeclarations(body, h); err != nil {
		return nil, err
	}

	if len(h.Structs) == 0 {
		return nil, fmt.Errorf("no struct declarations found; the header is not what this generator expects")
	}
	return h, nil
}

// stripComments removes block and line comments, preserving newlines so that
// reported line numbers stay accurate.
func stripComments(src string) string {
	var b strings.Builder
	b.Grow(len(src))

	for i := 0; i < len(src); {
		switch {
		case strings.HasPrefix(src[i:], "/*"):
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				// Unterminated: consume the rest. The declaration parser will
				// report the resulting absence rather than this position.
				for _, r := range src[i:] {
					if r == '\n' {
						b.WriteByte('\n')
					}
				}
				return b.String()
			}
			for _, r := range src[i : i+2+end+2] {
				if r == '\n' {
					b.WriteByte('\n')
				}
			}
			i += 2 + end + 2
		case strings.HasPrefix(src[i:], "//"):
			for i < len(src) && src[i] != '\n' {
				i++
			}
		default:
			b.WriteByte(src[i])
			i++
		}
	}
	return b.String()
}

// takePreprocessor records integer #defines and returns the source with every
// preprocessor line blanked out, newlines preserved.
func takePreprocessor(src string, h *Header) (string, error) {
	lines := strings.Split(src, "\n")
	for i, ln := range lines {
		t := strings.TrimSpace(ln)
		if !strings.HasPrefix(t, "#") {
			continue
		}
		lines[i] = "" // blanked, not removed, so line numbers survive

		fields := strings.Fields(t)
		if len(fields) == 0 || fields[0] != "#define" {
			continue // #ifndef, #endif and friends carry nothing the ABI needs
		}
		if len(fields) == 2 {
			continue // the include guard: a name with no value
		}
		if len(fields) != 3 {
			return "", fmt.Errorf("line %d: unsupported #define %q; this generator handles only "+
				"integer defines of the form `#define NAME <int>`", i+1, t)
		}
		v, err := strconv.Atoi(fields[2])
		if err != nil {
			return "", fmt.Errorf("line %d: #define %s has non-integer value %q; the ABI uses "+
				"defines only for array bounds, which must be integers", i+1, fields[1], fields[2])
		}
		h.Defines = append(h.Defines, Define{Name: fields[1], Value: v})
	}
	return strings.Join(lines, "\n"), nil
}

// parseDeclarations scans for top-level `enum NAME { ... };` and
// `struct NAME { ... };` and refuses anything else that is not whitespace.
func parseDeclarations(src string, h *Header) error {
	i := 0
	for {
		// Skip whitespace and stray semicolons between declarations.
		for i < len(src) && (isSpace(src[i]) || src[i] == ';') {
			i++
		}
		if i >= len(src) {
			return nil
		}

		start := i
		kw, name, rest, err := takeDeclHead(src, &i)
		if err != nil {
			return fmt.Errorf("line %d: %w", lineOf(src, start), err)
		}

		bodyStart := i
		body, err := takeBracedBody(src, &i)
		if err != nil {
			return fmt.Errorf("line %d: %w", lineOf(src, bodyStart), err)
		}
		_ = rest

		// A declaration ends at the semicolon after the closing brace. Anything
		// between them -- a variable name, an attribute -- is unsupported.
		for i < len(src) && isSpace(src[i]) {
			i++
		}
		if i >= len(src) || src[i] != ';' {
			return fmt.Errorf("line %d: expected `;` after the body of %s %s", lineOf(src, i), kw, name)
		}
		i++

		switch kw {
		case "enum":
			e, err := parseEnumBody(name, body, lineOf(src, bodyStart))
			if err != nil {
				return err
			}
			h.Enums = append(h.Enums, e)
		case "struct":
			s, err := parseStructBody(name, body, lineOf(src, bodyStart), h)
			if err != nil {
				return err
			}
			h.Structs = append(h.Structs, s)
		}
	}
}

// takeDeclHead consumes `enum NAME` or `struct NAME` and leaves i at the `{`.
func takeDeclHead(src string, i *int) (kw, name, rest string, err error) {
	kw = takeIdent(src, i)
	if kw != "enum" && kw != "struct" {
		return "", "", "", fmt.Errorf("unsupported top-level construct starting with %q; "+
			"this generator handles only `enum` and `struct` declarations", kw)
	}
	skipSpace(src, i)
	name = takeIdent(src, i)
	if name == "" {
		return "", "", "", fmt.Errorf("anonymous top-level %s; every ABI declaration must be named", kw)
	}
	skipSpace(src, i)
	if *i >= len(src) || src[*i] != '{' {
		return "", "", "", fmt.Errorf("expected `{` after %s %s; forward declarations and typedefs are not supported", kw, name)
	}
	return kw, name, "", nil
}

// takeBracedBody consumes a balanced { ... } and returns its interior.
func takeBracedBody(src string, i *int) (string, error) {
	if *i >= len(src) || src[*i] != '{' {
		return "", fmt.Errorf("expected `{`")
	}
	depth := 0
	start := *i + 1
	for ; *i < len(src); *i++ {
		switch src[*i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				body := src[start:*i]
				*i++
				return body, nil
			}
		}
	}
	return "", fmt.Errorf("unterminated `{`")
}

func parseEnumBody(name, body string, line int) (Enum, error) {
	e := Enum{Name: name}
	for _, raw := range strings.Split(body, ",") {
		t := strings.TrimSpace(raw)
		if t == "" {
			continue
		}
		eq := strings.Index(t, "=")
		if eq < 0 {
			return e, fmt.Errorf("line %d: enum %s member %q has no explicit value; "+
				"the header calls these values a wire contract, and an implicit one is a value nobody reviewed",
				line, name, t)
		}
		mn := strings.TrimSpace(t[:eq])
		mv, err := strconv.Atoi(strings.TrimSpace(t[eq+1:]))
		if err != nil {
			return e, fmt.Errorf("line %d: enum %s member %s has non-integer value %q",
				line, name, mn, strings.TrimSpace(t[eq+1:]))
		}
		e.Members = append(e.Members, EnumMember{Name: mn, Value: mv})
	}
	if len(e.Members) == 0 {
		return e, fmt.Errorf("line %d: enum %s is empty", line, name)
	}
	return e, nil
}

func parseStructBody(name, body string, line int, h *Header) (Struct, error) {
	s := Struct{Name: name}
	for _, decl := range splitTopLevel(body, ';') {
		t := strings.TrimSpace(decl)
		if t == "" {
			continue
		}
		f, err := parseField(t, line, h)
		if err != nil {
			return s, fmt.Errorf("struct %s: %w", name, err)
		}
		s.Fields = append(s.Fields, f)
	}
	if len(s.Fields) == 0 {
		return s, fmt.Errorf("line %d: struct %s has no fields", line, name)
	}
	return s, nil
}

// parseField handles one declaration: a scalar, an array, a nested struct
// reference, or an inline union.
func parseField(decl string, line int, h *Header) (Field, error) {
	f := Field{Line: line}

	if strings.Contains(decl, "*") {
		return f, fmt.Errorf("declaration %q contains a pointer; the header's own layout rules forbid "+
			"pointers, because nothing that means anything only inside kernel address space may cross the ABI", decl)
	}
	if strings.Contains(decl, ":") {
		return f, fmt.Errorf("declaration %q looks like a bitfield; bitfield layout is "+
			"implementation-defined and must not appear in a wire contract", decl)
	}

	if strings.HasPrefix(decl, "union") {
		return parseUnionField(decl, line, h)
	}

	if strings.Contains(decl, ",") {
		return f, fmt.Errorf("declaration %q declares more than one name; "+
			"one declaration per field keeps the generated offsets reviewable", decl)
	}

	// The name is the last identifier before any array brackets.
	head, dims, err := splitArray(decl, h)
	if err != nil {
		return f, err
	}
	parts := strings.Fields(head)
	if len(parts) < 2 {
		return f, fmt.Errorf("declaration %q has no name, or no type", decl)
	}
	name := parts[len(parts)-1]

	f.Name = name
	f.Type = strings.Join(parts[:len(parts)-1], " ")
	f.Dims = dims
	return f, nil
}

func parseUnionField(decl string, line int, h *Header) (Field, error) {
	f := Field{Line: line}

	open := strings.Index(decl, "{")
	closeIdx := strings.LastIndex(decl, "}")
	if open < 0 || closeIdx < 0 || closeIdx < open {
		return f, fmt.Errorf("declaration %q looks like a union but has no balanced body; "+
			"only an inline anonymous union with a member name is supported", decl)
	}
	if strings.TrimSpace(decl[len("union"):open]) != "" {
		return f, fmt.Errorf("declaration %q names the union type; only an anonymous inline union is supported", decl)
	}

	name := strings.TrimSpace(decl[closeIdx+1:])
	if name == "" {
		return f, fmt.Errorf("declaration %q is an anonymous union with no member name; "+
			"the payload has to be addressable", decl)
	}

	for _, m := range splitTopLevel(decl[open+1:closeIdx], ';') {
		t := strings.TrimSpace(m)
		if t == "" {
			continue
		}
		mf, err := parseField(t, line, h)
		if err != nil {
			return f, fmt.Errorf("inside union %s: %w", name, err)
		}
		if mf.IsUnion() {
			return f, fmt.Errorf("union %s contains a nested union; one level is all the record needs "+
				"and all this generator supports", name)
		}
		f.Union = append(f.Union, mf)
	}
	if len(f.Union) == 0 {
		return f, fmt.Errorf("union %s is empty", name)
	}

	f.Name = name
	return f, nil
}

// splitArray separates `char argv[A][B]` into head `char argv` and dims {A, B},
// resolving each bound through the #defines.
func splitArray(decl string, h *Header) (head string, dims []int, err error) {
	open := strings.Index(decl, "[")
	if open < 0 {
		return decl, nil, nil
	}
	head = decl[:open]

	rest := decl[open:]
	for len(rest) > 0 {
		if rest[0] != '[' {
			return "", nil, fmt.Errorf("declaration %q has text between array dimensions", decl)
		}
		end := strings.Index(rest, "]")
		if end < 0 {
			return "", nil, fmt.Errorf("declaration %q has an unterminated array dimension", decl)
		}
		bound := strings.TrimSpace(rest[1:end])
		n, err := resolveBound(bound, h)
		if err != nil {
			return "", nil, fmt.Errorf("declaration %q: %w", decl, err)
		}
		dims = append(dims, n)
		rest = strings.TrimSpace(rest[end+1:])
	}
	return head, dims, nil
}

// resolveBound turns an array bound into an integer, accepting a literal or a
// previously seen #define. An unknown name is an error rather than a guess.
func resolveBound(b string, h *Header) (int, error) {
	if n, err := strconv.Atoi(b); err == nil {
		if n <= 0 {
			return 0, fmt.Errorf("array bound %q is not positive", b)
		}
		return n, nil
	}
	for i := range h.Defines {
		d := &h.Defines[i]
		if d.Name == b {
			if d.Value <= 0 {
				return 0, fmt.Errorf("array bound %s resolves to %d, which is not positive", b, d.Value)
			}
			d.UsedAsBound = true
			return d.Value, nil
		}
	}
	return 0, fmt.Errorf("array bound %q is neither an integer literal nor a known #define", b)
}

// splitTopLevel splits on sep, ignoring separators nested inside braces. That
// is what keeps a union's internal semicolons from ending the enclosing field.
func splitTopLevel(s string, sep byte) []string {
	var out []string
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
		case sep:
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, s[start:])
	return out
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

func skipSpace(s string, i *int) {
	for *i < len(s) && isSpace(s[*i]) {
		*i++
	}
}

func takeIdent(s string, i *int) string {
	skipSpace(s, i)
	start := *i
	for *i < len(s) {
		c := s[*i]
		if c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			*i++
			continue
		}
		break
	}
	return s[start:*i]
}

func lineOf(s string, pos int) int {
	if pos > len(s) {
		pos = len(s)
	}
	return strings.Count(s[:pos], "\n") + 1
}
