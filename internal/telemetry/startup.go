package telemetry

// Startup checks: the things that must be true before a single event is
// believed, established once at load time rather than per record.
//
// The checks here live outside the `linux && ebpf` build tag for the same
// reason: none of them needs a kernel or libbpfgo to run, and a check that only
// compiles on the host it guards is a check nobody runs until it is too late to
// fix. The loader calls them; `go test ./...` exercises them anywhere.
//
// One check does not qualify and is not here. requireCgroupV2 reads
// /proc/mounts, which is a kernel interface rather than a file that happens to
// be absent elsewhere, so it cannot answer its own question off Linux. It lives
// in startup_linux.go under a `linux` tag, which keeps it compiled and tested by
// every Linux build while removing it from the platforms where it would fail for
// a reason unrelated to what it checks.

import (
	"errors"
	"fmt"
	"os"
)

var (
	// ErrLayoutDrift: the compiled object and this binary disagree about the
	// size of struct allseer_event.
	//
	// This is the check Decoder.EventSize is documented to feed -- "used to
	// catch layout drift between the loaded object and this binary at startup
	// rather than at the first event" -- and internal/telemetry/abi names the
	// loader as one of its two enforcement points, because it is "the only
	// point at which a mismatch costs nothing -- no probes are running and no
	// events have been believed".
	ErrLayoutDrift = errors.New("telemetry: loaded object's event layout differs from this binary's")

	// ErrNoRecordType: the object carries no BTF type for the record at all.
	//
	// Refused rather than skipped. An object whose BTF does not describe
	// struct allseer_event is either not this program or was built without
	// BTF, and both mean the layout cannot be checked -- which is the same
	// position as having no check, arrived at silently.
	ErrNoRecordType = errors.New("telemetry: object BTF declares no struct allseer_event")

	// ErrABIVersionDrift: the compiled object and this binary disagree about
	// ALLSEER_ABI_VERSION.
	//
	// The companion to ErrLayoutDrift and not a duplicate of it. A size
	// comparison catches a layout that changed size; it passes unchanged for a
	// layout that "stayed the same size and changed meaning", as
	// bpf/include/allseer_event.h puts it -- a field retyped, two fields
	// swapped, a bound moved from one array to another -- and those records
	// "decode without complaint into confident nonsense". The version is what
	// the header raises against exactly that case, and this is the version read
	// at the point where a mismatch still costs nothing.
	//
	// Distinct from ErrABIVersionMismatch, which is the same disagreement found
	// one record at a time by the decoder. Reaching that one means the probes
	// are already attached and the loader missed its chance.
	ErrABIVersionDrift = errors.New("telemetry: loaded object's ABI version differs from this binary's")

	// ErrNoObjectGlobal: a read-only global the object was required to carry is
	// absent, or is not the shape it must be to be read.
	//
	// Its own sentinel because it is a different finding from a version that
	// disagrees, and the two want different reactions: a disagreement means the
	// object is the wrong build, while an absence means it is not this program
	// at all, or was compiled by something that discarded the global.
	//
	// Refused rather than defaulted, for the reason ErrNoRecordType is. An
	// unreadable version yielding zero would compare unequal to
	// ALLSEER_ABI_VERSION and so happen to fail closed today, and would start
	// passing silently the moment the version reached whatever a missing read
	// returns. A check that is correct by coincidence is not a check.
	ErrNoObjectGlobal = errors.New("telemetry: object does not carry the read-only global this check needs")

	// ErrRingBufferSize: Config.RingBufferSize violates what the kernel
	// requires of a ring buffer map. Checked before anything is opened,
	// because the kernel's own refusal arrives as a bare EINVAL out of
	// bpf_object__load and names neither the map nor the field.
	ErrRingBufferSize = errors.New("telemetry: ring buffer size must be a power of two and a multiple of the page size")
)

// validateRingBufferSize checks Config.RingBufferSize against what a
// BPF_MAP_TYPE_RINGBUF requires: max_entries is the size in bytes and "must be
// a power of two and a multiple of the page size; the kernel rejects the map at
// creation otherwise", as bpf/include/allseer_maps.h puts it.
//
// Zero is accepted and means "keep ALLSEER_RINGBUF_BYTES", the value compiled
// into the object.
func validateRingBufferSize(size int) error {
	if size == 0 {
		return nil
	}
	page := os.Getpagesize()
	if size < page || size%page != 0 || size&(size-1) != 0 {
		return fmt.Errorf("%w: got %d, page size is %d", ErrRingBufferSize, size, page)
	}
	return nil
}

// btfRecordStruct is the C struct whose size is compared against the decoder.
// The name is the one in bpf/include/allseer_event.h and is the only place the
// Go side has to spell it, since everything else about the layout is generated.
const btfRecordStruct = "allseer_event"

// objectABIVersionGlobal is the read-only global bpf/allseer.bpf.c declares to
// carry ALLSEER_ABI_VERSION out of the compiled object. Spelled here for the
// same reason the struct name is: it is a name shared with C that no compiler
// sees both sides of, so it is written once.
const objectABIVersionGlobal = "allseer_abi_version"

// checkRecordLayout compares sizeof(struct allseer_event) in a compiled object
// against the size this binary decodes.
//
// It reads the object's BTF rather than loading it, so the answer is available
// before anything is in the kernel. That ordering is the whole value of the
// check: refusing to open is free, while discovering the same mismatch from a
// decode error means probes are already attached and records have already been
// interpreted.
//
// What it does not catch is stated plainly because the header states it: a
// layout that "stayed the same size and changed meaning" passes here. That case
// is what the per-record version field exists for, and checkABIVersion below is
// what closes it at load time.
func checkRecordLayout(objectPath string, want int) error {
	got, err := recordSizeFromObject(objectPath)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("%w: object says sizeof(struct %s) is %d, this binary decodes %d",
			ErrLayoutDrift, btfRecordStruct, got, want)
	}
	return nil
}

// checkABIVersion compares ALLSEER_ABI_VERSION as a compiled object carries it
// against the value this binary was generated from.
//
// The other half of the startup layout check, and the half the size comparison
// cannot do. bpf/include/allseer_event.h states why the version exists at all:
// "A reader can compare record lengths, and that catches a layout that changed
// size. It does not catch a layout that stayed the same size and changed
// meaning ... Those records decode without complaint into confident nonsense."
//
// Read out of the object's .rodata rather than out of a record, which is the
// difference between this and the decoder's own version check. The header calls
// the field in the record "the backstop, not the mechanism ... it reports the
// mismatch one event at a time, after the probes are already running, which is
// later than the loader could have known". This is the earlier point, and
// bpf/allseer.bpf.c declares `allseer_abi_version` so that it exists.
//
// Fails closed on all three of the ways this can go wrong -- a global that is
// absent, one that cannot be read, and one that disagrees -- because all three
// leave the same question unanswered.
func checkABIVersion(objectPath string, want uint32) error {
	got, err := readOnlyU32FromObject(objectPath, objectABIVersionGlobal)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("%w: object was compiled against ALLSEER_ABI_VERSION %d, this binary decodes %d",
			ErrABIVersionDrift, got, want)
	}
	return nil
}

// requireCgroupV2 and unescapeMountField are in startup_linux.go. See the note
// at the top of this file: they read /proc/mounts and cannot answer off Linux.
