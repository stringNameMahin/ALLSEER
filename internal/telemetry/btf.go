package telemetry

// A very small BTF reader: enough to answer one question about a compiled
// object, and deliberately not enough to be a BTF library.
//
// The question is "how big does this object think struct allseer_event is",
// asked before the object is loaded. internal/telemetry/abi describes the
// loader reading the object "through BTF before it attaches anything", and this
// is that read. Everything else BTF carries -- every other type, the func and
// line info, the CO-RE relocations -- is skipped over, because a reader that
// interprets more than it needs is a reader with more ways to be wrong about an
// object it is supposed to be checking.
//
// The format is in the kernel tree at Documentation/bpf/btf.rst and is stable:
// a header, a type section of variable-length records, and a string section.
// Walking it needs only the per-kind trailer sizes below.

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrMalformedBTF: the object has a .BTF section that does not parse.
//
// Distinct from ErrNoRecordType, which is a well-formed BTF that happens not to
// describe the record. This one means the bytes are not BTF at all, or are
// truncated, and no conclusion about the layout can be drawn from them.
var ErrMalformedBTF = errors.New("telemetry: object .BTF section is malformed")

// btfMagic identifies the section and, by which way round it reads, its byte
// order. Objects are compiled on the host that loads them, so the swapped case
// is not expected -- it is handled because detecting it costs one comparison and
// misreading every u32 in the section costs a wrong answer to a safety check.
const btfMagic = 0xEB9F

// BTF type kinds, from the kernel's uapi/linux/btf.h. Only the ones whose
// trailer size differs are named; the walk needs every kind's trailer, so the
// table below is exhaustive over the range rather than over what is used here.
const (
	btfKindInt       = 1
	btfKindArray     = 3
	btfKindStruct    = 4
	btfKindUnion     = 5
	btfKindEnum      = 6
	btfKindFuncProto = 13
	btfKindVar       = 14
	btfKindDataSec   = 15
	btfKindDeclTag   = 17
	btfKindEnum64    = 19
	btfKindMax       = 19
)

// btfTrailer returns the bytes following a type record's common 12-byte header,
// for a kind with vlen members. An unknown kind is refused rather than assumed
// to have no trailer: guessing zero would silently desynchronise the walk and
// turn every later type into garbage that might still parse.
func btfTrailer(kind, vlen uint32) (int, error) {
	switch kind {
	case btfKindInt, btfKindVar, btfKindDeclTag:
		return 4, nil
	case btfKindArray:
		return 12, nil
	case btfKindStruct, btfKindUnion:
		return int(vlen) * 12, nil
	case btfKindEnum:
		return int(vlen) * 8, nil
	case btfKindFuncProto:
		return int(vlen) * 8, nil
	case btfKindDataSec:
		return int(vlen) * 12, nil
	case btfKindEnum64:
		return int(vlen) * 12, nil
	}
	if kind == 0 || kind > btfKindMax {
		return 0, fmt.Errorf("%w: type kind %d is not one this build knows", ErrMalformedBTF, kind)
	}
	return 0, nil
}

// recordSizeFromObject returns sizeof(struct allseer_event) as the compiled
// object's BTF declares it.
func recordSizeFromObject(objectPath string) (int, error) {
	f, err := elf.Open(objectPath)
	if err != nil {
		return 0, fmt.Errorf("telemetry: opening %s: %w", objectPath, err)
	}
	defer f.Close()

	sec := f.Section(".BTF")
	if sec == nil {
		return 0, fmt.Errorf("%w: %s has no .BTF section", ErrNoRecordType, objectPath)
	}
	raw, err := sec.Data()
	if err != nil {
		return 0, fmt.Errorf("telemetry: reading .BTF from %s: %w", objectPath, err)
	}
	return recordSizeFromBTF(raw)
}

// recordSizeFromBTF is the parse, split out so it can be tested against bytes
// rather than only against a file that has to be compiled first.
func recordSizeFromBTF(raw []byte) (int, error) {
	const hdrSize = 24
	if len(raw) < hdrSize {
		return 0, fmt.Errorf("%w: %d bytes is shorter than the header", ErrMalformedBTF, len(raw))
	}

	var bo binary.ByteOrder = binary.LittleEndian
	switch {
	case binary.LittleEndian.Uint16(raw) == btfMagic:
	case binary.BigEndian.Uint16(raw) == btfMagic:
		bo = binary.BigEndian
	default:
		return 0, fmt.Errorf("%w: magic %#04x is not BTF", ErrMalformedBTF, binary.LittleEndian.Uint16(raw))
	}

	hdrLen := int(bo.Uint32(raw[4:]))
	typeOff := int(bo.Uint32(raw[8:]))
	typeLen := int(bo.Uint32(raw[12:]))
	strOff := int(bo.Uint32(raw[16:]))
	strLen := int(bo.Uint32(raw[20:]))

	types, err := btfSlice(raw, hdrLen, typeOff, typeLen, "type")
	if err != nil {
		return 0, err
	}
	strs, err := btfSlice(raw, hdrLen, strOff, strLen, "string")
	if err != nil {
		return 0, err
	}

	for p := 0; p+12 <= len(types); {
		nameOff := bo.Uint32(types[p:])
		info := bo.Uint32(types[p+4:])
		sizeOrType := bo.Uint32(types[p+8:])
		kind := (info >> 24) & 0x1F
		vlen := info & 0xFFFF

		trailer, err := btfTrailer(kind, vlen)
		if err != nil {
			return 0, err
		}
		next := p + 12 + trailer
		if next > len(types) {
			return 0, fmt.Errorf("%w: type at offset %d runs past the type section", ErrMalformedBTF, p)
		}

		if kind == btfKindStruct && btfString(strs, nameOff) == btfRecordStruct {
			// size_or_type is the size for a struct. The record is a
			// fixed-size struct by construction -- the header forbids pointers
			// and requires fixed-size arrays -- so there is no flexible tail to
			// account for.
			return int(sizeOrType), nil
		}
		p = next
	}
	return 0, fmt.Errorf("%w: no struct named %q in %d bytes of BTF types",
		ErrNoRecordType, btfRecordStruct, len(types))
}

// btfSlice bounds-checks one of the header's declared sub-sections. The offsets
// are attacker-adjacent in the weak sense that they come from a file on disk,
// and a slice expression on unchecked values panics rather than erroring.
func btfSlice(raw []byte, hdrLen, off, length int, what string) ([]byte, error) {
	if hdrLen < 0 || off < 0 || length < 0 {
		return nil, fmt.Errorf("%w: negative %s section bounds", ErrMalformedBTF, what)
	}
	start := hdrLen + off
	if start < 0 || start > len(raw) || start+length > len(raw) {
		return nil, fmt.Errorf("%w: %s section [%d,%d) lies outside %d bytes",
			ErrMalformedBTF, what, start, start+length, len(raw))
	}
	return raw[start : start+length], nil
}

// btfString reads a NUL-terminated name out of the string section. An offset
// past the end yields the empty string, which matches no type name and so
// cannot be mistaken for the record.
func btfString(strs []byte, off uint32) string {
	if int(off) >= len(strs) {
		return ""
	}
	s := strs[off:]
	for i, c := range s {
		if c == 0 {
			return string(s[:i])
		}
	}
	return string(s)
}
