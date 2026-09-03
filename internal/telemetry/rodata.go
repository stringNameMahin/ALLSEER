package telemetry

// Reading a read-only global out of a compiled object, before it is loaded.
//
// One question, like btf.go next door: "what ABI version was this object
// compiled against". The answer is a value rather than a type, so it is not
// something BTF alone can give, and this file is deliberately the smallest
// thing that can produce it.
//
// # Why the ELF symbol table and not BTF
//
// BTF does describe the variable -- a BTF_KIND_VAR named by the string section,
// listed in the BTF_KIND_DATASEC for .rodata with an offset and a size -- and
// the offset is exactly what a reader would want. In a compiled, unlinked
// object it is zero. DATASEC offsets are filled in from the .rel.BTF
// relocations, which resolve against the ELF symbol table, and libbpf performs
// that fixup itself at load time. A reader that trusted the raw DATASEC offset
// would find every variable in .rodata at offset 0 and would read the first
// four bytes of the section whatever it asked for -- which for a single-variable
// section is the right answer by accident, and stops being right the moment a
// second read-only global is added.
//
// So the symbol table is consulted for the offset, and it carries the section,
// the size and the binding as well, which are the other three things worth
// checking. That is the same source libbpf's own fixup resolves to, arrived at
// without reimplementing relocation processing.

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
)

// roDataSection is the section a `const` global at file scope is placed in by
// clang for the BPF target, and the section libbpf turns into a frozen array
// map at load. Requiring it is how "read-only" is checked rather than assumed:
// a global that lost its const would be emitted into .data, and .data is a map
// user space can write after load.
const roDataSection = ".rodata"

// readOnlyU32FromObject returns the value of a named 4-byte read-only global in
// a compiled object.
//
// Every failure is a refusal. There is no value this can return that means "the
// object did not say", because the whole point of the read is that a caller is
// about to decide whether to trust the object, and a zero standing in for an
// absent symbol is the version-check equivalent of no check at all.
func readOnlyU32FromObject(objectPath, symbol string) (uint32, error) {
	f, err := elf.Open(objectPath)
	if err != nil {
		return 0, fmt.Errorf("telemetry: opening %s: %w", objectPath, err)
	}
	defer f.Close()

	v, err := readOnlyU32FromELF(f, symbol)
	if err != nil {
		return 0, fmt.Errorf("%w (in %s)", err, objectPath)
	}
	return v, nil
}

// readOnlyU32FromELF is the read itself, split from the file handling so it can
// be tested against an ELF assembled in memory rather than only against one a
// compiler has to produce first. btf.go splits recordSizeFromBTF for the same
// reason.
func readOnlyU32FromELF(f *elf.File, symbol string) (uint32, error) {
	const width = 4

	syms, err := f.Symbols()
	if err != nil {
		// A stripped object, or one with no symbol table at all. Distinct from
		// a symbol table that does not list the symbol only in the message;
		// both mean the value cannot be read, and both refuse.
		return 0, fmt.Errorf("%w: %q: no symbol table (%v)", ErrNoObjectGlobal, symbol, err)
	}

	var sym *elf.Symbol
	for i := range syms {
		if syms[i].Name == symbol {
			sym = &syms[i]
			break
		}
	}
	if sym == nil {
		return 0, fmt.Errorf("%w: no symbol named %q", ErrNoObjectGlobal, symbol)
	}

	if int(sym.Section) >= len(f.Sections) || sym.Section == elf.SHN_UNDEF {
		return 0, fmt.Errorf("%w: symbol %q names no section in this object", ErrNoObjectGlobal, symbol)
	}
	sec := f.Sections[sym.Section]
	if sec.Name != roDataSection {
		return 0, fmt.Errorf("%w: symbol %q lives in %s, not %s, so it is not a read-only global",
			ErrNoObjectGlobal, symbol, sec.Name, roDataSection)
	}
	if sym.Size != width {
		return 0, fmt.Errorf("%w: symbol %q is %d bytes, not %d", ErrNoObjectGlobal, symbol, sym.Size, width)
	}

	data, err := sec.Data()
	if err != nil {
		return 0, fmt.Errorf("%w: reading %s: %v", ErrNoObjectGlobal, sec.Name, err)
	}
	if sym.Value > uint64(len(data)) || uint64(len(data))-sym.Value < width {
		return 0, fmt.Errorf("%w: symbol %q lies at offset %d of a %d-byte %s",
			ErrNoObjectGlobal, symbol, sym.Value, len(data), sec.Name)
	}

	// The object is compiled on the host that loads it, so the ELF header's
	// byte order and the host's own agree in every expected case. It is read
	// rather than assumed for the reason btf.go gives about BTF's magic:
	// detecting the other case costs nothing and misreading it costs a wrong
	// answer to a safety check.
	var bo binary.ByteOrder = f.ByteOrder
	return bo.Uint32(data[sym.Value : sym.Value+width]), nil
}
