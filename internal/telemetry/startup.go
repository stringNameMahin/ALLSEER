package telemetry

// Startup checks: the two things that must be true before a single event is
// believed, established once at load time rather than per record.
//
// Both live here, outside the `linux && ebpf` build tag, for the same reason:
// neither needs a kernel or libbpfgo to run, and a check that only compiles on
// the host it guards is a check nobody runs until it is too late to fix. The
// loader calls them; `go test ./...` exercises them anywhere.

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

var (
	// ErrLayoutDrift: the compiled object and this binary disagree about the
	// size of struct allseer_event.
	//
	// This is the check Decoder.EventSize is documented to feed — "used to
	// catch layout drift between the loaded object and this binary at startup
	// rather than at the first event" — and internal/telemetry/abi names the
	// loader as one of its two enforcement points, because it is "the only
	// point at which a mismatch costs nothing — no probes are running and no
	// events have been believed".
	ErrLayoutDrift = errors.New("telemetry: loaded object's event layout differs from this binary's")

	// ErrNoRecordType: the object carries no BTF type for the record at all.
	//
	// Refused rather than skipped. An object whose BTF does not describe
	// struct allseer_event is either not this program or was built without
	// BTF, and both mean the layout cannot be checked — which is the same
	// position as having no check, arrived at silently.
	ErrNoRecordType = errors.New("telemetry: object BTF declares no struct allseer_event")

	// ErrRingBufferSize: Config.RingBufferSize violates what the kernel
	// requires of a ring buffer map. Checked before anything is opened,
	// because the kernel's own refusal arrives as a bare EINVAL out of
	// bpf_object__load and names neither the map nor the field.
	ErrRingBufferSize = errors.New("telemetry: ring buffer size must be a power of two and a multiple of the page size")

	// ErrNoCgroupV2: no cgroup2 filesystem is mounted.
	//
	// Fatal at startup, not a degradation. The probes filter on the value
	// bpf_get_current_cgroup_id() returns, and without a cgroup v2 hierarchy
	// that value cannot identify anything user space can name. Every event
	// would miss the filter and the daemon would run, attach cleanly, and
	// report nothing — which reads downstream as an agent that did nothing.
	// bpf/allseer.bpf.c states where this belongs: "Detecting it belongs to
	// the loader, which is the only side that can refuse to start."
	ErrNoCgroupV2 = errors.New("telemetry: no cgroup2 filesystem is mounted")
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
// is what the per-record version field exists for, and closing it at load time
// needs the read-only ABI-version global that bpf/include/allseer_event.h still
// carries as a TODO.
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

// requireCgroupV2 returns the cgroup2 mount point, or an error if there is none.
//
// The unified hierarchy is what bpf_get_current_cgroup_id() reports on. A v1
// hierarchy mounted alongside is not a substitute and is not looked for: the
// probes key on one ID and v1 has one per controller.
func requireCgroupV2() (string, error) {
	const procMounts = "/proc/mounts"

	b, err := os.ReadFile(procMounts)
	if err != nil {
		return "", fmt.Errorf("telemetry: reading %s: %w", procMounts, err)
	}
	for line := range strings.SplitSeq(strings.TrimRight(string(b), "\n"), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || f[2] != "cgroup2" {
			continue
		}
		return unescapeMountField(f[1]), nil
	}
	return "", ErrNoCgroupV2
}

// unescapeMountField undoes the octal escaping /proc/mounts applies to space,
// tab, newline and backslash in a path. Trivial, and wrong to skip: an escaped
// mount point compared literally would fail to match a real directory.
func unescapeMountField(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			var v byte
			ok := true
			for _, c := range []byte(s[i+1 : i+4]) {
				if c < '0' || c > '7' {
					ok = false
					break
				}
				v = v*8 + (c - '0')
			}
			if ok {
				b.WriteByte(v)
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
