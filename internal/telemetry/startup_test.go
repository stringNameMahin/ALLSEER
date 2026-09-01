package telemetry

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stringNameMahin/ALLSEER/internal/telemetry/abi"
)

// The object the repository builds. Present only after `make bpf`, and
// gitignored, so every test that wants it skips rather than fails when it is
// absent: `go test ./...` must pass on a host with no clang.
const builtObject = "../../bpf/allseer.bpf.o"

func objectOrSkip(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs(builtObject)
	if err != nil {
		t.Fatalf("resolving %s: %v", builtObject, err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Skipf("no compiled object at %s; run `make bpf` (needs clang) to exercise this test", p)
	}
	return p
}

// The check that matters: the object this repository compiles agrees with the
// decoder this binary was generated from. If these ever disagree, every other
// test in the tree is testing a decoder against bytes nothing produces.
func TestCompiledObjectMatchesDecoderLayout(t *testing.T) {
	obj := objectOrSkip(t)

	size, err := recordSizeFromObject(obj)
	if err != nil {
		t.Fatalf("reading record size from %s: %v", obj, err)
	}
	if want := NewDecoder().EventSize(); size != want {
		t.Errorf("object declares sizeof(struct allseer_event) = %d, decoder expects %d", size, want)
	}
	if size != abi.RecordSize {
		t.Errorf("object declares sizeof(struct allseer_event) = %d, abi.RecordSize is %d", size, abi.RecordSize)
	}
	if err := checkRecordLayout(obj, NewDecoder().EventSize()); err != nil {
		t.Errorf("checkRecordLayout: %v", err)
	}
}

// A size the object does not declare must be refused, and refused with the
// sentinel the loader turns into a startup failure. Without this, a passing
// checkRecordLayout would prove only that the function returns nil.
func TestRecordLayoutDriftIsRefused(t *testing.T) {
	obj := objectOrSkip(t)

	err := checkRecordLayout(obj, abi.RecordSize+8)
	if !errors.Is(err, ErrLayoutDrift) {
		t.Fatalf("want ErrLayoutDrift for a mismatched size, got %v", err)
	}
}

func TestRecordSizeFromObjectRejectsNonObjects(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "not-an-elf")
	if err := os.WriteFile(p, []byte("this is not an ELF file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := recordSizeFromObject(p); err == nil {
		t.Fatal("want an error for a file that is not an ELF object")
	}
}

// buildBTF assembles a minimal, well-formed BTF blob declaring one struct, so
// the parser can be exercised without a compiler. The layout is the kernel's:
// a 24-byte header, then types, then strings.
func buildBTF(t *testing.T, name string, size uint32, vlen uint32) []byte {
	t.Helper()

	strs := append([]byte{0}, append([]byte(name), 0)...)
	nameOff := uint32(1)

	var types []byte
	put := func(v uint32) { types = binary.LittleEndian.AppendUint32(types, v) }
	put(nameOff)
	put(uint32(btfKindStruct)<<24 | vlen) // info: kind in bits 24..28, vlen in 0..15
	put(size)
	types = append(types, make([]byte, int(vlen)*12)...) // member trailer

	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint16(hdr[0:], btfMagic)
	hdr[2] = 1 // version
	binary.LittleEndian.PutUint32(hdr[4:], 24)
	binary.LittleEndian.PutUint32(hdr[8:], 0)                   // type_off
	binary.LittleEndian.PutUint32(hdr[12:], uint32(len(types))) // type_len
	binary.LittleEndian.PutUint32(hdr[16:], uint32(len(types))) // str_off
	binary.LittleEndian.PutUint32(hdr[20:], uint32(len(strs)))  // str_len

	return append(hdr, append(types, strs...)...)
}

func TestRecordSizeFromBTF(t *testing.T) {
	t.Run("finds the record struct", func(t *testing.T) {
		got, err := recordSizeFromBTF(buildBTF(t, btfRecordStruct, 856, 3))
		if err != nil {
			t.Fatal(err)
		}
		if got != 856 {
			t.Errorf("got size %d, want 856", got)
		}
	})

	t.Run("reports a BTF that declares no record", func(t *testing.T) {
		_, err := recordSizeFromBTF(buildBTF(t, "something_else", 16, 0))
		if !errors.Is(err, ErrNoRecordType) {
			t.Fatalf("want ErrNoRecordType, got %v", err)
		}
	})

	t.Run("refuses bytes that are not BTF", func(t *testing.T) {
		_, err := recordSizeFromBTF(make([]byte, 64))
		if !errors.Is(err, ErrMalformedBTF) {
			t.Fatalf("want ErrMalformedBTF, got %v", err)
		}
	})

	t.Run("refuses a truncated blob", func(t *testing.T) {
		_, err := recordSizeFromBTF([]byte{0x9f, 0xeb, 1, 0})
		if !errors.Is(err, ErrMalformedBTF) {
			t.Fatalf("want ErrMalformedBTF, got %v", err)
		}
	})

	t.Run("refuses a section declared past the end", func(t *testing.T) {
		b := buildBTF(t, btfRecordStruct, 856, 0)
		binary.LittleEndian.PutUint32(b[12:], 1<<20) // type_len beyond the blob
		_, err := recordSizeFromBTF(b)
		if !errors.Is(err, ErrMalformedBTF) {
			t.Fatalf("want ErrMalformedBTF, got %v", err)
		}
	})

	t.Run("refuses a type whose trailer runs off the end", func(t *testing.T) {
		// vlen claims members the blob does not carry.
		b := buildBTF(t, btfRecordStruct, 856, 0)
		binary.LittleEndian.PutUint32(b[24+4:], uint32(btfKindStruct)<<24|4)
		_, err := recordSizeFromBTF(b)
		if !errors.Is(err, ErrMalformedBTF) {
			t.Fatalf("want ErrMalformedBTF, got %v", err)
		}
	})
}

func TestBTFTrailerRefusesUnknownKinds(t *testing.T) {
	if _, err := btfTrailer(btfKindMax+1, 0); !errors.Is(err, ErrMalformedBTF) {
		t.Fatalf("want ErrMalformedBTF for an unknown kind, got %v", err)
	}
	if _, err := btfTrailer(0, 0); !errors.Is(err, ErrMalformedBTF) {
		t.Fatalf("want ErrMalformedBTF for kind 0, got %v", err)
	}
}

// TestRequireCgroupV2AgreesWithTheHost and TestUnescapeMountField are in
// startup_linux_test.go, beside the functions they cover.

func TestValidateRingBufferSize(t *testing.T) {
	page := os.Getpagesize()
	for _, tc := range []struct {
		name string
		size int
		ok   bool
	}{
		{"zero keeps the compiled default", 0, true},
		{"one page", page, true},
		{"four MiB, the compiled default", 1 << 22, true},
		{"not a power of two", page * 3, false},
		{"smaller than a page", page / 2, false},
		{"power of two below a page", 512, false},
		{"negative", -4096, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRingBufferSize(tc.size)
			if tc.ok && err != nil {
				t.Fatalf("validateRingBufferSize(%d) = %v, want nil", tc.size, err)
			}
			if !tc.ok && !errors.Is(err, ErrRingBufferSize) {
				t.Fatalf("validateRingBufferSize(%d) = %v, want ErrRingBufferSize", tc.size, err)
			}
		})
	}
}
