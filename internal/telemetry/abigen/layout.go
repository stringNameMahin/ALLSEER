package abigen

import (
	"fmt"
	"sort"
)

// Model is the laid-out ABI: every size and every offset computed, ready to
// emit.
type Model struct {
	Defines []Define
	Enums   []Enum
	Structs []LaidStruct

	// Root is the struct the ring buffer carries: the one nothing else embeds.
	// Named so the emitter can give it the decode entry point.
	Root string

	// HeaderSHA256 is the digest of the normalized header the model came from.
	//
	// Embedded in the generated file so "stale" means "not produced from the
	// committed header" -- a claim checkable without trusting the parser. It is
	// computed over the header with CRLF normalized to LF, because this
	// repository's .gitattributes leaves source line endings to core.autocrlf
	// and a digest that differed between a Windows and a Linux checkout would
	// make the staleness check fail on one of them for no reason.
	HeaderSHA256 string
}

// LaidStruct is a struct with its layout resolved.
type LaidStruct struct {
	Name   string
	Size   int
	Align  int
	Fields []LaidField

	// InternalPad is bytes of implicit padding between fields, excluding
	// trailing padding at the end of the struct.
	//
	// Reported rather than merely tolerated. The header's own layout rules say
	// "fields ordered largest-first to avoid implicit padding", and implicit
	// padding is a place where the C compiler and any hand-written mirror can
	// disagree without either being obviously wrong. Surfacing the number in
	// the generated file means a reviewer sees it appear.
	InternalPad int
}

// LaidField is a field with its offset and size resolved.
type LaidField struct {
	Name   string
	Type   string
	Dims   []int
	Offset int
	Size   int
	Align  int

	// Elem is the size of one array element; equal to Size when Dims is nil.
	Elem int

	// Union members, each with an offset of zero relative to the union.
	Union []LaidField

	// StructRef names the struct this field embeds, empty for scalars.
	StructRef string
}

// IsUnion reports whether the field is an inline union.
func (f LaidField) IsUnion() bool { return len(f.Union) > 0 }

// IsArray reports whether the field is an array.
func (f LaidField) IsArray() bool { return len(f.Dims) > 0 }

// scalar describes a fixed-width C type.
type scalar struct {
	size   int
	align  int
	signed bool
	// goType is the Go type the emitter uses for a single element.
	goType string
}

// scalars is the complete set of types this ABI is allowed to use.
//
// Closed on purpose. The header's layout rules demand "explicit fixed-width
// types only (__u32, not unsigned int)", and the way to enforce that is to have
// no entry for the types it forbids: `int` is not here, so a header that grows
// one fails to generate rather than generating something whose width depends on
// the compiler.
var scalars = map[string]scalar{
	"__u8":  {1, 1, false, "uint8"},
	"__s8":  {1, 1, true, "int8"},
	"__u16": {2, 2, false, "uint16"},
	"__s16": {2, 2, true, "int16"},
	"__u32": {4, 4, false, "uint32"},
	"__s32": {4, 4, true, "int32"},
	"__u64": {8, 8, false, "uint64"},
	"__s64": {8, 8, true, "int64"},
	"char":  {1, 1, false, "byte"},
}

// Layout resolves sizes, alignments, and offsets for every declared struct.
//
// The model is LP64 with natural alignment -- a struct's alignment is its widest
// member's, its size is rounded up to that alignment, and each field starts at
// the next offset satisfying its own alignment. That is what both supported
// targets do: BPF_CFLAGS in the Makefile maps uname -m onto x86 and arm64, and
// both are LP64 little-endian.
func Layout(h *Header) (*Model, error) {
	m := &Model{Defines: h.Defines, Enums: h.Enums}

	// Structs are laid out in declaration order, so a struct may only reference
	// one already declared. C requires that too, for a member by value.
	seen := make(map[string]LaidStruct, len(h.Structs))

	for _, s := range h.Structs {
		ls := LaidStruct{Name: s.Name}
		off, maxAlign, pad := 0, 1, 0

		for _, f := range s.Fields {
			lf, err := layoutField(f, seen)
			if err != nil {
				return nil, fmt.Errorf("struct %s: %w", s.Name, err)
			}

			aligned := align(off, lf.Align)
			pad += aligned - off
			lf.Offset = aligned
			off = aligned + lf.Size

			if lf.Align > maxAlign {
				maxAlign = lf.Align
			}
			ls.Fields = append(ls.Fields, lf)
		}

		ls.Align = maxAlign
		ls.Size = align(off, maxAlign)
		ls.InternalPad = pad
		seen[s.Name] = ls
		m.Structs = append(m.Structs, ls)
	}

	if len(m.Structs) == 0 {
		return nil, fmt.Errorf("no structs to lay out")
	}

	// The root record is the struct nothing else embeds. Derived rather than
	// hardcoded to a name, so renaming the record in the header does not
	// silently produce a generator that decodes the wrong thing.
	root, err := findRoot(m.Structs)
	if err != nil {
		return nil, err
	}
	m.Root = root

	return m, nil
}

func layoutField(f Field, seen map[string]LaidStruct) (LaidField, error) {
	lf := LaidField{Name: f.Name, Type: f.Type, Dims: f.Dims}

	if f.IsUnion() {
		size, alignment := 0, 1
		for _, u := range f.Union {
			lu, err := layoutField(u, seen)
			if err != nil {
				return lf, err
			}
			if lu.IsUnion() {
				return lf, fmt.Errorf("nested union in %q", f.Name)
			}
			if lu.Size > size {
				size = lu.Size
			}
			if lu.Align > alignment {
				alignment = lu.Align
			}
			lu.Offset = 0
			lf.Union = append(lf.Union, lu)
		}
		lf.Align = alignment
		lf.Size = align(size, alignment)
		lf.Elem = lf.Size
		return lf, nil
	}

	elem, alignment, ref, err := baseType(f.Type, seen)
	if err != nil {
		return lf, fmt.Errorf("field %q: %w", f.Name, err)
	}
	lf.Elem = elem
	lf.Align = alignment
	lf.StructRef = ref

	total := elem
	for _, d := range f.Dims {
		total *= d
	}
	lf.Size = total
	return lf, nil
}

func baseType(t string, seen map[string]LaidStruct) (size, alignment int, structRef string, err error) {
	if s, ok := scalars[t]; ok {
		return s.size, s.align, "", nil
	}
	const p = "struct "
	if len(t) > len(p) && t[:len(p)] == p {
		name := t[len(p):]
		ls, ok := seen[name]
		if !ok {
			return 0, 0, "", fmt.Errorf("references struct %s, which is not declared before it", name)
		}
		return ls.Size, ls.Align, name, nil
	}
	return 0, 0, "", fmt.Errorf("type %q is not a supported fixed-width type; the header's layout rules "+
		"require explicit fixed-width types, so this generator has no entry for anything else", t)
}

// findRoot returns the one struct no other struct embeds.
func findRoot(structs []LaidStruct) (string, error) {
	embedded := make(map[string]bool)
	for _, s := range structs {
		for _, f := range s.Fields {
			if f.StructRef != "" {
				embedded[f.StructRef] = true
			}
			for _, u := range f.Union {
				if u.StructRef != "" {
					embedded[u.StructRef] = true
				}
			}
		}
	}

	var roots []string
	for _, s := range structs {
		if !embedded[s.Name] {
			roots = append(roots, s.Name)
		}
	}
	sort.Strings(roots)

	switch len(roots) {
	case 1:
		return roots[0], nil
	case 0:
		return "", fmt.Errorf("every struct is embedded in another; there is no ring buffer record")
	default:
		return "", fmt.Errorf("more than one struct is embedded by nothing (%v); the generator cannot tell "+
			"which one the ring buffer carries", roots)
	}
}

func align(off, a int) int {
	if a <= 1 {
		return off
	}
	return (off + a - 1) / a * a
}
