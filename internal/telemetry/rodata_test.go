package telemetry

// Tests for the read-only-global read and for the ABI version check built on
// it.
//
// They are here rather than in startup_test.go beside the other startup checks
// because most of the file is the ELF assembler below, and burying that in the
// middle of the cgroup and ring-buffer tests would make both harder to read.
// The check under test, checkABIVersion, lives in startup.go with its siblings.

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stringNameMahin/ALLSEER/internal/telemetry/abi"
)

// --- A minimal ELF assembler -------------------------------------------------
//
// Enough of an ELF64 relocatable object for debug/elf to parse and for the read
// under test to succeed or fail on, and nothing else. It exists so the failure
// cases have coverage on a host with no clang: an object whose global is
// missing, writable, the wrong width, or pointing off the end of its section is
// not something `make bpf` can be asked to produce, and a checked-in binary
// fixture would be four opaque kilobytes nobody could review.
//
// buildBTF in startup_test.go is the same idea applied to the BTF parser.

// elfSym is one symbol to place in the assembled object's symbol table.
type elfSym struct {
	name    string
	section string // section name; must be one this object carries
	value   uint64 // offset within that section
	size    uint64 // st_size, which the read compares against 4
}

// buildObject assembles an ELF64 little-endian relocatable object carrying a
// read-only .rodata section, a writable .data section, and the given symbols.
//
// withSymtab: false omits the symbol table entirely, which is what a stripped
// object looks like to the read.
func buildObject(t *testing.T, rodata, data []byte, syms []elfSym, withSymtab bool) []byte {
	t.Helper()

	const (
		ehSize = 64 // Elf64_Ehdr
		shSize = 64 // Elf64_Shdr
		symLen = 24 // Elf64_Sym
	)

	// Section names, in the order the section header table will list them.
	// Index 0 is the mandatory null section.
	names := []string{"", ".rodata", ".data", ".symtab", ".strtab", ".shstrtab"}
	if !withSymtab {
		names = []string{"", ".rodata", ".data", ".shstrtab"}
	}
	idxOf := func(name string) int {
		for i, n := range names {
			if n == name {
				return i
			}
		}
		t.Fatalf("buildObject: no section named %q in this fixture", name)
		return 0
	}

	// .strtab holds the symbol names; the leading NUL is required, since offset
	// zero must mean "no name".
	strtab := []byte{0}
	strOff := make(map[string]uint32, len(syms))
	for _, s := range syms {
		strOff[s.name] = uint32(len(strtab))
		strtab = append(strtab, append([]byte(s.name), 0)...)
	}

	// .symtab. Entry zero is reserved and must be all zeroes; debug/elf skips
	// it and returns the rest.
	symtab := make([]byte, symLen)
	for _, s := range syms {
		e := make([]byte, symLen)
		binary.LittleEndian.PutUint32(e[0:], strOff[s.name])
		e[4] = byte(elf.ST_INFO(elf.STB_GLOBAL, elf.STT_OBJECT))
		binary.LittleEndian.PutUint16(e[6:], uint16(idxOf(s.section)))
		binary.LittleEndian.PutUint64(e[8:], s.value)
		binary.LittleEndian.PutUint64(e[16:], s.size)
		symtab = append(symtab, e...)
	}

	// .shstrtab holds the section names.
	shstrtab := []byte{0}
	shName := make(map[string]uint32, len(names))
	for _, n := range names[1:] {
		shName[n] = uint32(len(shstrtab))
		shstrtab = append(shstrtab, append([]byte(n), 0)...)
	}

	contentOf := map[string][]byte{
		".rodata":   rodata,
		".data":     data,
		".symtab":   symtab,
		".strtab":   strtab,
		".shstrtab": shstrtab,
	}

	// Lay the section contents out end to end after the header, recording where
	// each landed, then append the section header table.
	body := make([]byte, 0, 1024)
	offset := make(map[string]uint64, len(names))
	for _, n := range names[1:] {
		offset[n] = uint64(ehSize + len(body))
		body = append(body, contentOf[n]...)
	}
	shoff := uint64(ehSize + len(body))

	hdr := make([]byte, ehSize)
	copy(hdr, []byte{0x7f, 'E', 'L', 'F'})
	hdr[4] = byte(elf.ELFCLASS64)
	hdr[5] = byte(elf.ELFDATA2LSB)
	hdr[6] = byte(elf.EV_CURRENT)
	binary.LittleEndian.PutUint16(hdr[16:], uint16(elf.ET_REL))
	binary.LittleEndian.PutUint16(hdr[18:], uint16(elf.EM_BPF))
	binary.LittleEndian.PutUint32(hdr[20:], uint32(elf.EV_CURRENT))
	binary.LittleEndian.PutUint64(hdr[40:], shoff)
	binary.LittleEndian.PutUint16(hdr[52:], ehSize)
	binary.LittleEndian.PutUint16(hdr[58:], shSize)
	binary.LittleEndian.PutUint16(hdr[60:], uint16(len(names)))
	binary.LittleEndian.PutUint16(hdr[62:], uint16(idxOf(".shstrtab")))

	shdrs := make([]byte, 0, len(names)*shSize)
	for _, n := range names {
		sh := make([]byte, shSize)
		if n != "" {
			var typ elf.SectionType
			var flags elf.SectionFlag
			var link, info uint32
			var entsize uint64
			switch n {
			case ".rodata":
				typ, flags = elf.SHT_PROGBITS, elf.SHF_ALLOC
			case ".data":
				typ, flags = elf.SHT_PROGBITS, elf.SHF_ALLOC|elf.SHF_WRITE
			case ".symtab":
				typ, entsize = elf.SHT_SYMTAB, symLen
				link, info = uint32(idxOf(".strtab")), 1
			default:
				typ = elf.SHT_STRTAB
			}
			binary.LittleEndian.PutUint32(sh[0:], shName[n])
			binary.LittleEndian.PutUint32(sh[4:], uint32(typ))
			binary.LittleEndian.PutUint64(sh[8:], uint64(flags))
			binary.LittleEndian.PutUint64(sh[24:], offset[n])
			binary.LittleEndian.PutUint64(sh[32:], uint64(len(contentOf[n])))
			binary.LittleEndian.PutUint32(sh[40:], link)
			binary.LittleEndian.PutUint32(sh[44:], info)
			binary.LittleEndian.PutUint64(sh[48:], 1) // sh_addralign
			binary.LittleEndian.PutUint64(sh[56:], entsize)
		}
		shdrs = append(shdrs, sh...)
	}

	return append(hdr, append(body, shdrs...)...)
}

// u32le is the four bytes of a version as .rodata would carry them.
func u32le(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }

// writeObject puts an assembled object on disk so the path-taking checks can be
// pointed at it.
func writeObject(t *testing.T, blob []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fixture.bpf.o")
	if err := os.WriteFile(p, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func openObject(t *testing.T, blob []byte) *elf.File {
	t.Helper()
	f, err := elf.NewFile(bytes.NewReader(blob))
	if err != nil {
		t.Fatalf("assembled fixture does not parse as ELF: %v", err)
	}
	return f
}

// --- The read ----------------------------------------------------------------

func TestReadOnlyU32FromELF(t *testing.T) {
	const sym = objectABIVersionGlobal

	t.Run("reads a read-only global", func(t *testing.T) {
		blob := buildObject(t, u32le(7), nil,
			[]elfSym{{name: sym, section: ".rodata", value: 0, size: 4}}, true)
		got, err := readOnlyU32FromELF(openObject(t, blob), sym)
		if err != nil {
			t.Fatal(err)
		}
		if got != 7 {
			t.Errorf("got %d, want 7", got)
		}
	})

	t.Run("reads one at a non-zero offset", func(t *testing.T) {
		// The case a BTF DATASEC offset could not answer: with two globals in
		// .rodata the raw offsets are both zero until .rel.BTF is applied, so
		// this is what proves the symbol table is what is being consulted.
		blob := buildObject(t, append(u32le(99), u32le(7)...), nil, []elfSym{
			{name: "something_else", section: ".rodata", value: 0, size: 4},
			{name: sym, section: ".rodata", value: 4, size: 4},
		}, true)
		got, err := readOnlyU32FromELF(openObject(t, blob), sym)
		if err != nil {
			t.Fatal(err)
		}
		if got != 7 {
			t.Errorf("got %d, want 7 -- the read took the wrong global's bytes", got)
		}
	})

	for _, tc := range []struct {
		name string
		blob func(t *testing.T) []byte
		why  string
	}{
		{
			name: "no symbol of that name",
			blob: func(t *testing.T) []byte {
				return buildObject(t, u32le(1), nil,
					[]elfSym{{name: "unrelated", section: ".rodata", value: 0, size: 4}}, true)
			},
			why: "an object that never declared the global",
		},
		{
			name: "no symbol table at all",
			blob: func(t *testing.T) []byte {
				return buildObject(t, u32le(1), nil, nil, false)
			},
			why: "a stripped object",
		},
		{
			name: "the global is writable",
			blob: func(t *testing.T) []byte {
				return buildObject(t, nil, u32le(1),
					[]elfSym{{name: sym, section: ".data", value: 0, size: 4}}, true)
			},
			why: "a global that lost its const lands in .data, which is a map user space can write after load",
		},
		{
			name: "the global is the wrong width",
			blob: func(t *testing.T) []byte {
				return buildObject(t, make([]byte, 8), nil,
					[]elfSym{{name: sym, section: ".rodata", value: 0, size: 8}}, true)
			},
			why: "a __u64 version would be read as its low half",
		},
		{
			name: "the global lies past the end of its section",
			blob: func(t *testing.T) []byte {
				return buildObject(t, u32le(1), nil,
					[]elfSym{{name: sym, section: ".rodata", value: 4, size: 4}}, true)
			},
			why: "a truncated section must not be read past",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := readOnlyU32FromELF(openObject(t, tc.blob(t)), sym)
			if !errors.Is(err, ErrNoObjectGlobal) {
				t.Fatalf("want ErrNoObjectGlobal (%s), got %v", tc.why, err)
			}
		})
	}
}

func TestReadOnlyU32FromObjectRejectsNonObjects(t *testing.T) {
	p := writeObject(t, []byte("this is not an ELF file"))
	if _, err := readOnlyU32FromObject(p, objectABIVersionGlobal); err == nil {
		t.Fatal("want an error for a file that is not an ELF object")
	}
}

// --- The check ---------------------------------------------------------------

// The check accepts an object carrying this binary's version, and the two other
// outcomes are refusals rather than a zero that happens to compare unequal.
func TestCheckABIVersion(t *testing.T) {
	sym := objectABIVersionGlobal

	t.Run("accepts a matching version", func(t *testing.T) {
		p := writeObject(t, buildObject(t, u32le(abi.ABIVersion), nil,
			[]elfSym{{name: sym, section: ".rodata", value: 0, size: 4}}, true))
		if err := checkABIVersion(p, abi.ABIVersion); err != nil {
			t.Fatalf("checkABIVersion on a matching object: %v", err)
		}
	})

	t.Run("refuses a mismatched version", func(t *testing.T) {
		p := writeObject(t, buildObject(t, u32le(abi.ABIVersion+1), nil,
			[]elfSym{{name: sym, section: ".rodata", value: 0, size: 4}}, true))
		err := checkABIVersion(p, abi.ABIVersion)
		if !errors.Is(err, ErrABIVersionDrift) {
			t.Fatalf("want ErrABIVersionDrift, got %v", err)
		}
		// Both numbers, because a failure that says only "mismatch" leaves the
		// operator to work out which side is stale.
		for _, want := range []string{fmt.Sprint(abi.ABIVersion + 1), fmt.Sprint(abi.ABIVersion)} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q names neither the observed nor the expected version %s", err, want)
			}
		}
	})

	t.Run("refuses a missing version rather than reading it as zero", func(t *testing.T) {
		p := writeObject(t, buildObject(t, u32le(abi.ABIVersion), nil,
			[]elfSym{{name: "unrelated", section: ".rodata", value: 0, size: 4}}, true))
		err := checkABIVersion(p, abi.ABIVersion)
		if !errors.Is(err, ErrNoObjectGlobal) {
			t.Fatalf("want ErrNoObjectGlobal, got %v", err)
		}
		if errors.Is(err, ErrABIVersionDrift) {
			t.Error("a missing global was reported as a version disagreement")
		}
		if !strings.Contains(err.Error(), sym) {
			t.Errorf("error %q does not name the global it looked for", err)
		}
	})
}

// --- Against the object this repository builds --------------------------------

// The check that matters, and the counterpart to
// TestCompiledObjectMatchesDecoderLayout: the object this repository compiles
// carries the version this binary decodes. If these disagree, every record the
// object emits carries a version the decoder will refuse, one at a time, after
// the probes are already running.
func TestCompiledObjectExposesTheABIVersion(t *testing.T) {
	obj := objectOrSkip(t)

	got, err := readOnlyU32FromObject(obj, objectABIVersionGlobal)
	if err != nil {
		t.Fatalf("reading %s from %s: %v", objectABIVersionGlobal, obj, err)
	}
	if got != abi.ABIVersion {
		t.Errorf("object exposes ALLSEER_ABI_VERSION %d, this binary decodes %d", got, abi.ABIVersion)
	}
	if err := checkABIVersion(obj, abi.ABIVersion); err != nil {
		t.Errorf("checkABIVersion: %v", err)
	}
}

// A version the object does not carry must be refused, and refused with the
// sentinel the loader turns into a startup failure. Without this, a passing
// checkABIVersion would prove only that the function returns nil.
func TestCompiledObjectABIVersionDriftIsRefused(t *testing.T) {
	obj := objectOrSkip(t)

	err := checkABIVersion(obj, abi.ABIVersion+1)
	if !errors.Is(err, ErrABIVersionDrift) {
		t.Fatalf("want ErrABIVersionDrift for a version this binary does not decode, got %v", err)
	}
}

// objectWithABIVersion copies the compiled object with the four bytes of its
// `allseer_abi_version` global overwritten, and returns the path to the copy.
//
// The smallest possible mismatched fixture: the real object, its real BTF, its
// real programs and maps, differing from the one the repository builds in
// exactly the four bytes under test. The alternatives were a second C file
// compiled with a different -D, which makes `make bpf` produce an object nobody
// should ever load, and a checked-in binary, which nobody could review and
// which would go stale against the header on its own schedule.
//
// It patches the file rather than the parsed section because debug/elf is a
// reader: the section's file offset plus the symbol's offset within it is where
// the bytes are, and that arithmetic is the whole of the edit.
func objectWithABIVersion(t *testing.T, version uint32) string {
	t.Helper()

	src := objectOrSkip(t)
	blob, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("reading %s: %v", src, err)
	}

	f := openObject(t, blob)
	syms, err := f.Symbols()
	if err != nil {
		t.Fatalf("%s has no symbol table: %v", src, err)
	}
	for _, s := range syms {
		if s.Name != objectABIVersionGlobal {
			continue
		}
		sec := f.Sections[s.Section]
		at := sec.Offset + s.Value
		if sec.Type == elf.SHT_NOBITS || at+4 > uint64(len(blob)) {
			t.Fatalf("%s lies outside the file's %s contents", s.Name, sec.Name)
		}
		binary.LittleEndian.PutUint32(blob[at:], version)
		return writeObject(t, blob)
	}
	t.Fatalf("%s declares no %s; the fixture cannot be built", src, objectABIVersionGlobal)
	return ""
}

// objectWithoutABIVersion copies the compiled object with the name of its
// `allseer_abi_version` symbol mangled in .strtab, and returns the path to the
// copy.
//
// The companion fixture to objectWithABIVersion and built the same way, because
// an object with no version at all is not something a compiler can be asked for
// either. Renaming the symbol rather than deleting it keeps every offset in the
// file where it was -- the symbol table, the BTF and the programs are all
// untouched -- so the object differs from the real one in exactly the respect
// under test: the loader cannot find the global.
//
// The edit is confined to the .strtab section's own bytes. The same name also
// appears in .BTF's string section and in the DWARF strings, and patching those
// would be changing what the object says about itself rather than what its
// symbol table is called.
func objectWithoutABIVersion(t *testing.T) string {
	t.Helper()

	src := objectOrSkip(t)
	blob, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("reading %s: %v", src, err)
	}

	f := openObject(t, blob)
	sec := f.Section(".strtab")
	if sec == nil {
		t.Fatalf("%s has no .strtab", src)
	}
	strs, err := sec.Data()
	if err != nil {
		t.Fatalf("reading .strtab from %s: %v", src, err)
	}

	// A whole entry, not a suffix of a longer name: string table entries are
	// NUL-separated, so the byte before the match must be the previous entry's
	// terminator.
	want := append([]byte(objectABIVersionGlobal), 0)
	at := -1
	for from := 0; ; {
		i := bytes.Index(strs[from:], want)
		if i < 0 {
			break
		}
		if from+i > 0 && strs[from+i-1] == 0 {
			at = from + i
			break
		}
		from += i + 1
	}
	if at < 0 {
		t.Fatalf("%s declares no %s; the fixture cannot be built", src, objectABIVersionGlobal)
	}

	blob[sec.Offset+uint64(at)] = 'X'
	return writeObject(t, blob)
}

// The two fixtures are what the loader tests point Load at, so the edits
// themselves are checked here: each must change the one thing it is for and
// nothing else about how the object reads.
func TestPatchedObjectCarriesTheWrongVersionAndNothingElse(t *testing.T) {
	patched := objectWithABIVersion(t, abi.ABIVersion+1)

	got, err := readOnlyU32FromObject(patched, objectABIVersionGlobal)
	if err != nil {
		t.Fatalf("reading the patched object: %v", err)
	}
	if got != abi.ABIVersion+1 {
		t.Fatalf("patched object exposes version %d, want %d", got, abi.ABIVersion+1)
	}
	if err := checkABIVersion(patched, abi.ABIVersion); !errors.Is(err, ErrABIVersionDrift) {
		t.Fatalf("checkABIVersion on the patched object = %v, want ErrABIVersionDrift", err)
	}
	// The size check must still pass on it, so a loader test using this fixture
	// is failing on the version and not incidentally on the layout.
	if err := checkRecordLayout(patched, NewDecoder().EventSize()); err != nil {
		t.Fatalf("the patch disturbed the record layout: %v", err)
	}
}

func TestObjectWithoutABIVersionHidesOnlyTheGlobal(t *testing.T) {
	stripped := objectWithoutABIVersion(t)

	if _, err := readOnlyU32FromObject(stripped, objectABIVersionGlobal); !errors.Is(err, ErrNoObjectGlobal) {
		t.Fatalf("reading the mangled object = %v, want ErrNoObjectGlobal", err)
	}
	if err := checkABIVersion(stripped, abi.ABIVersion); !errors.Is(err, ErrNoObjectGlobal) {
		t.Fatalf("checkABIVersion on the mangled object = %v, want ErrNoObjectGlobal", err)
	}
	// BTF is untouched, so a loader test using this fixture is failing on the
	// absent global and not on a record type the rename took with it.
	if err := checkRecordLayout(stripped, NewDecoder().EventSize()); err != nil {
		t.Fatalf("the rename disturbed the record layout: %v", err)
	}
}
