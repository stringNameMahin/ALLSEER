package telemetry

import (
	"encoding/binary"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stringNameMahin/ALLSEER/internal/telemetry/abi"
	"github.com/stringNameMahin/ALLSEER/internal/telemetry/resolve"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// What these tests can and cannot prove.
//
// They prove that the decoder reads the layout the generated ABI describes,
// that every event type it accepts maps to a capability the M1 catalog knows,
// that the types it refuses are refused for a stated reason, and that a
// malformed, truncated, oversized, or adversarial record produces an error
// rather than a plausible event.
//
// They prove **nothing** about what a kernel writes. No probe exists, none can
// be compiled on this host, and every record below is a byte pattern this file
// constructed. The question asked of the decoder is only whether it interprets
// the bytes it claims to interpret — the same limit internal/telemetry/abi
// states about itself, and for the same reason.

// --- record construction -------------------------------------------------------------
//
// Byte-order helpers matching the generated decoder's. NativeEndian on both
// sides is correct rather than convenient: the probe writes these bytes on the
// machine that reads them.

func put16(b []byte, off int, v uint16) { binary.NativeEndian.PutUint16(b[off:], v) }
func put32(b []byte, off int, v uint32) { binary.NativeEndian.PutUint32(b[off:], v) }
func put64(b []byte, off int, v uint64) { binary.NativeEndian.PutUint64(b[off:], v) }

// Signed variants: a constant conversion of a negative value to an unsigned
// type does not compile, and the negative values are the ones that matter. A
// syscall return is -errno, and reading it unsigned turns every failure into a
// large success.
func putI32(b []byte, off int, v int32) { binary.NativeEndian.PutUint32(b[off:], uint32(v)) }
func putI64(b []byte, off int, v int64) { binary.NativeEndian.PutUint64(b[off:], uint64(v)) }

// putStr writes a NUL-terminated string into a fixed-size field. The record is
// zero-filled, so the terminator is already there.
func putStr(b []byte, off int, s string) { copy(b[off:], s) }

// fill writes n bytes with no NUL anywhere in them: the truncation case the
// header describes, where a value filled its field and the rest was lost.
func fill(b []byte, off, n int) {
	for i := range n {
		b[off+i] = 'a'
	}
}

// newRecord returns a zeroed record of exactly one event type.
func newRecord(typ abi.EventType) []byte {
	b := make([]byte, abi.RecordSize)
	put32(b, abi.OffsetEventType, uint32(typ))
	return b
}

// Payload field offsets are relative to the union, which starts at
// OffsetEventPayload. Naming them once keeps the tests from repeating the
// arithmetic and getting it subtly wrong in one place.
const (
	offFileInode   = abi.OffsetEventPayload + abi.OffsetFilePayloadInode
	offFileDevice  = abi.OffsetEventPayload + abi.OffsetFilePayloadDevice
	offFileBytes   = abi.OffsetEventPayload + abi.OffsetFilePayloadBytes
	offFileFlags   = abi.OffsetEventPayload + abi.OffsetFilePayloadFlags
	offFileMode    = abi.OffsetEventPayload + abi.OffsetFilePayloadMode
	offFilePath    = abi.OffsetEventPayload + abi.OffsetFilePayloadPath
	offFileNewPath = abi.OffsetEventPayload + abi.OffsetFilePayloadNewPath

	offNetSaddr    = abi.OffsetEventPayload + abi.OffsetNetPayloadSaddr
	offNetDaddr    = abi.OffsetEventPayload + abi.OffsetNetPayloadDaddr
	offNetBytes    = abi.OffsetEventPayload + abi.OffsetNetPayloadBytes
	offNetSport    = abi.OffsetEventPayload + abi.OffsetNetPayloadSport
	offNetDport    = abi.OffsetEventPayload + abi.OffsetNetPayloadDport
	offNetFamily   = abi.OffsetEventPayload + abi.OffsetNetPayloadFamily
	offNetProtocol = abi.OffsetEventPayload + abi.OffsetNetPayloadProtocol
	offNetSockType = abi.OffsetEventPayload + abi.OffsetNetPayloadSockType

	offExecArgc     = abi.OffsetEventPayload + abi.OffsetExecPayloadArgc
	offExecFilename = abi.OffsetEventPayload + abi.OffsetExecPayloadFilename
	offExecArgv     = abi.OffsetEventPayload + abi.OffsetExecPayloadArgv
)

// offArgv returns the offset of one argv row.
func offArgv(i int) int { return offExecArgv + i*abi.ArgLen }

func decode(t *testing.T, raw []byte) *event.Event {
	t.Helper()
	e, err := NewDecoder().Decode(raw)
	if err != nil {
		t.Fatalf("Decode: unexpected error: %v", err)
	}
	return e
}

// --- EventSize -----------------------------------------------------------------------
//
// The startup layout check compares this number against the size the loaded
// object reports. If it were written down here by hand rather than derived, the
// check would be comparing this file against itself.

func TestEventSizeIsTheGeneratedRecordSize(t *testing.T) {
	got := NewDecoder().EventSize()

	if got != abi.RecordSize {
		t.Errorf("EventSize() = %d, want abi.RecordSize = %d", got, abi.RecordSize)
	}
	if got != abi.SizeofEvent {
		t.Errorf("EventSize() = %d, want abi.SizeofEvent = %d", got, abi.SizeofEvent)
	}

	// The exact value, and the arithmetic behind it, pinned independently of
	// the generator. abi has the same assertion; having it on both sides means
	// a generator bug producing self-consistent nonsense fails here too.
	const want = 848 // 8 timestamp + 4 type + 4 ret + 56 proc + 776 payload union
	if got != want {
		t.Errorf("EventSize() = %d, want %d (8 + 4 + 4 + %d + %d)",
			got, want, abi.SizeofProc, abi.SizeofPayload)
	}
	if abi.OffsetEventPayload+abi.SizeofPayload != got {
		t.Errorf("payload offset %d + union size %d = %d, want EventSize() = %d",
			abi.OffsetEventPayload, abi.SizeofPayload, abi.OffsetEventPayload+abi.SizeofPayload, got)
	}

	// A record of exactly this size is accepted, and it is the only size that
	// is. The two properties together are what make EventSize meaningful as a
	// startup check rather than as documentation.
	if _, err := NewDecoder().Decode(newRecord(abi.EvtProcExit)); err != nil {
		t.Errorf("a record of exactly EventSize() bytes was refused: %v", err)
	}
}

// --- the type-to-capability map --------------------------------------------------------

// Every event type, in one table: what it decodes to, or why it does not.
//
// Driven from abi.AllEventTypes() rather than from a list written here, so a
// type added to the header and regenerated into the ABI fails this test until
// somebody decides what it means. A new event type silently decoding to nothing
// is the drift the generated layer exists to prevent, arriving one level up.
func TestEveryEventTypeIsMapped(t *testing.T) {
	want := map[abi.EventType]struct {
		kind   capability.Kind
		domain capability.Domain
		err    error
	}{
		abi.EvtUnknown:    {err: ErrUnsetEventType},
		abi.EvtFileOpen:   {kind: capability.KindFileRead, domain: capability.DomainFilesystem},
		abi.EvtFileWrite:  {kind: capability.KindFileWrite, domain: capability.DomainFilesystem},
		abi.EvtFileUnlink: {kind: capability.KindFileDelete, domain: capability.DomainFilesystem},
		abi.EvtFileRename: {kind: capability.KindFileRename, domain: capability.DomainFilesystem},
		abi.EvtFileChmod:  {kind: capability.KindFileChmod, domain: capability.DomainFilesystem},
		abi.EvtProcExec:   {kind: capability.KindProcessExec, domain: capability.DomainProcess},
		abi.EvtProcExit:   {kind: capability.KindProcessExit, domain: capability.DomainProcess},
		abi.EvtNetConnect: {kind: capability.KindNetConnect, domain: capability.DomainNetwork},
		abi.EvtNetBind:    {kind: capability.KindNetBind, domain: capability.DomainNetwork},
		abi.EvtNetSend:    {kind: capability.KindNetSend, domain: capability.DomainNetwork},
		abi.EvtPrivChange: {err: ErrUndecidedMapping},
		abi.EvtPtrace:     {kind: capability.KindProcessPtrace, domain: capability.DomainProcess},
	}

	all := abi.AllEventTypes()
	if len(all) != len(want) {
		t.Fatalf("the ABI declares %d event types and this table covers %d; a type was added to "+
			"bpf/include/allseer_event.h and nobody decided what capability it exercises", len(all), len(want))
	}

	for _, typ := range all {
		exp, ok := want[typ]
		if !ok {
			t.Fatalf("event type %s is not in the expectation table", typ)
		}
		t.Run(typ.String(), func(t *testing.T) {
			e, err := NewDecoder().Decode(newRecord(typ))

			if exp.err != nil {
				if !errors.Is(err, exp.err) {
					t.Fatalf("err = %v, want %v", err, exp.err)
				}
				if e != nil {
					t.Error("a refused record returned an event; a caller that ignores the error " +
						"would get a decision out of a record the decoder could not interpret")
				}
				return
			}

			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if e.Capability != exp.kind {
				t.Errorf("Capability = %q, want %q", e.Capability, exp.kind)
			}
			if e.Domain != exp.domain {
				t.Errorf("Domain = %q, want %q", e.Domain, exp.domain)
			}

			// Domain is a denormalized copy of a fact the catalog owns, and the
			// decoder must never be the second place it is decided.
			catalogDomain, known := capability.DomainOf(e.Capability)
			if !known {
				t.Fatalf("capability %q is not in the catalog", e.Capability)
			}
			if e.Domain != catalogDomain {
				t.Errorf("Domain = %q but the catalog says %q", e.Domain, catalogDomain)
			}
		})
	}
}

// Every kind the decoder can emit is in the M1 catalog, is in the domain the
// mapping claims, and is reachable from CapabilitiesFor.
//
// The last part is what makes CapabilitiesFor safe for the daemon's coverage
// report: a kind decode can produce but the coverage list omits would show as
// an unobservable grant that is in fact observed, and the reverse would show as
// a control that does not exist.
func TestEveryDecodableKindIsInTheCatalog(t *testing.T) {
	for _, typ := range abi.AllEventTypes() {
		for _, k := range CapabilitiesFor(typ) {
			if err := capability.ValidateKind(k); err != nil {
				t.Errorf("%s maps to %v", typ, err)
			}
		}
	}

	// The refused types advertise nothing. A probe emitting one cannot make its
	// capability look covered.
	for _, typ := range []abi.EventType{abi.EvtUnknown, abi.EvtPrivChange} {
		if got := CapabilitiesFor(typ); got != nil {
			t.Errorf("CapabilitiesFor(%s) = %v, want nil: this build refuses the type", typ, got)
		}
	}
	// Nor does a type outside the enum.
	if got := CapabilitiesFor(abi.EventType(9999)); got != nil {
		t.Errorf("CapabilitiesFor(unknown) = %v, want nil", got)
	}

	// Every open-flag combination the decoder can see resolves to a kind
	// CapabilitiesFor(EvtFileOpen) advertises. Exhaustive over the bits that
	// participate: the two access-mode bits and O_CREAT.
	advertised := map[capability.Kind]bool{}
	for _, k := range CapabilitiesFor(abi.EvtFileOpen) {
		advertised[k] = true
	}
	for flags := range uint32(0x80) {
		if got := kindForOpenFlags(flags); !advertised[got] {
			t.Fatalf("open flags %#x decode to %q, which CapabilitiesFor(EvtFileOpen) does not list", flags, got)
		}
	}
}

// --- filesystem events -----------------------------------------------------------------

func TestDecodeFileEventReadsEveryField(t *testing.T) {
	raw := newRecord(abi.EvtFileWrite)
	put64(raw, offFileInode, 710120)
	put64(raw, offFileDevice, 2049)
	putI64(raw, offFileBytes, 2410)
	put32(raw, offFileFlags, 0x241) // O_WRONLY|O_CREAT|O_TRUNC, carried verbatim
	put32(raw, offFileMode, 0o644)
	putStr(raw, offFilePath, "/home/dev/project/src/index.js")
	// new_path is set on a type that does not define it, and must not be read:
	// reporting a destination for an operation that has none would put a
	// rename's evidence on a write.
	putStr(raw, offFileNewPath, "/tmp/should-not-appear")

	e := decode(t, raw)

	if e.File == nil {
		t.Fatal("no file payload")
	}
	got := *e.File
	want := event.FilePayload{
		Path:             "/home/dev/project/src/index.js",
		Flags:            0x241,
		Mode:             0o644,
		Inode:            710120,
		Device:           2049,
		BytesTransferred: 2410,
	}
	if got != want {
		t.Errorf("file payload =\n  %+v\nwant\n  %+v", got, want)
	}

	// Resolution is enrichment. resolve.Observe refuses to fall back from
	// ResolvedPath to Path precisely so a pre-resolution path cannot reach
	// selector matching, and the decoder must not defeat that by filling it in.
	if e.File.ResolvedPath != "" {
		t.Errorf("ResolvedPath = %q; the decoder must not resolve paths", e.File.ResolvedPath)
	}
	if e.Network != nil || e.Exec != nil || e.Privil != nil {
		t.Error("a filesystem event carries a payload from another domain")
	}
}

// The rename destination is read for a rename and for nothing else.
func TestRenameCarriesTheDestination(t *testing.T) {
	raw := newRecord(abi.EvtFileRename)
	putStr(raw, offFilePath, "payload.sh")
	putStr(raw, offFileNewPath, "/etc/cron.d/job")

	e := decode(t, raw)
	if e.Capability != capability.KindFileRename {
		t.Fatalf("Capability = %q", e.Capability)
	}
	if e.File.Path != "payload.sh" || e.File.NewPath != "/etc/cron.d/job" {
		t.Errorf("path = %q, new_path = %q", e.File.Path, e.File.NewPath)
	}

	for _, typ := range []abi.EventType{abi.EvtFileOpen, abi.EvtFileWrite, abi.EvtFileUnlink, abi.EvtFileChmod} {
		raw := newRecord(typ)
		putStr(raw, offFilePath, "a")
		putStr(raw, offFileNewPath, "b")
		if e := decode(t, raw); e.File.NewPath != "" {
			t.Errorf("%s reported new_path = %q; the header defines that field for rename only",
				typ, e.File.NewPath)
		}
	}
}

// An open is the one type whose capability the flags decide, and the two
// documents that decide it are the catalog ("open, openat, and openat2 all
// resolve to FileRead or FileWrite") and docs/dataflow.md, which traces
// openat(..., O_WRONLY) through the pipeline as fs.write.
func TestOpenFlagsSelectTheCapability(t *testing.T) {
	const (
		rdonly  = 0x0
		wronly  = 0x1
		rdwr    = 0x2
		creat   = 0x40
		trunc   = 0x200
		oappend = 0x400
		cloexec = 0x80000
	)
	cases := []struct {
		name  string
		flags uint32
		want  capability.Kind
	}{
		{"O_RDONLY", rdonly, capability.KindFileRead},
		{"O_RDONLY|O_CLOEXEC", rdonly | cloexec, capability.KindFileRead},
		{"O_WRONLY", wronly, capability.KindFileWrite},
		{"O_RDWR", rdwr, capability.KindFileWrite},
		{"O_WRONLY|O_TRUNC", wronly | trunc, capability.KindFileWrite},
		{"O_WRONLY|O_APPEND", wronly | oappend, capability.KindFileWrite},
		{"O_WRONLY|O_CREAT", wronly | creat, capability.KindFileCreate},
		{"O_RDONLY|O_CREAT", rdonly | creat, capability.KindFileCreate},
		{"O_RDWR|O_CREAT|O_TRUNC", rdwr | creat | trunc, capability.KindFileCreate},
		// The fourth access-mode encoding has no O_ name and is what an O_PATH
		// open reports. Write is the deliberate answer: reporting a write that
		// was a read raises scrutiny, the reverse lowers it.
		{"O_ACCMODE undefined encoding", 0x3, capability.KindFileWrite},
		// Every bit set. Interesting because O_CREAT is among them, so the
		// precedence rule is what decides, and because it is the boundary
		// value a flags field can hold.
		{"all bits", math.MaxUint32, capability.KindFileCreate},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := newRecord(abi.EvtFileOpen)
			put32(raw, offFileFlags, tc.flags)
			putStr(raw, offFilePath, "/etc/passwd")

			e := decode(t, raw)
			if e.Capability != tc.want {
				t.Errorf("flags %#x → %q, want %q", tc.flags, e.Capability, tc.want)
			}
			if e.Domain != capability.DomainFilesystem {
				t.Errorf("Domain = %q", e.Domain)
			}
			// The flags are carried verbatim regardless of which kind they
			// selected, so the audit record shows what the syscall was given.
			if uint32(e.File.Flags) != tc.flags {
				t.Errorf("Flags = %#x, want %#x", uint32(e.File.Flags), tc.flags)
			}
		})
	}
}

// --- exec ------------------------------------------------------------------------------

func TestDecodeExecEvent(t *testing.T) {
	raw := newRecord(abi.EvtProcExec)
	put32(raw, offExecArgc, 3)
	putStr(raw, offExecFilename, "/usr/bin/git")
	putStr(raw, offArgv(0), "git")
	putStr(raw, offArgv(1), "push")
	putStr(raw, offArgv(2), "origin")
	// A row past argc, which must not be read: argc is what says how many of
	// the eight rows the probe filled.
	putStr(raw, offArgv(3), "--force")

	e := decode(t, raw)

	if e.Exec == nil {
		t.Fatal("no exec payload")
	}
	if e.Exec.Filename != "/usr/bin/git" {
		t.Errorf("Filename = %q", e.Exec.Filename)
	}
	if want := []string{"git", "push", "origin"}; !reflect.DeepEqual(e.Exec.Argv, want) {
		t.Errorf("Argv = %q, want %q", e.Exec.Argv, want)
	}
	// Enrichment fields the decoder must leave alone. EnvKeys in particular:
	// the header states environment values are never captured, and the record
	// carries no environment field at all.
	if e.Exec.Interpreter != "" || e.Exec.BinaryHash != "" || e.Exec.EnvKeys != nil {
		t.Errorf("decoder filled an enrichment field: %+v", *e.Exec)
	}
	if e.Process.Executable != "" {
		t.Errorf("Process.Executable = %q; that is enrichment", e.Process.Executable)
	}
}

// argc against the fixed eight rows, including the boundary and the overflow.
func TestExecArgcBounds(t *testing.T) {
	cases := []struct {
		name string
		argc uint32
		want int
	}{
		{"no arguments", 0, 0},
		{"one", 1, 1},
		{"full array", abi.ArgvMax, abi.ArgvMax},
		{"more arguments than fit", abi.ArgvMax + 1, abi.ArgvMax},
		// A compiler invocation with a dozen flags is ordinary, and refusing it
		// would delete the record of a real exec over an abbreviated argument
		// list. The maximum value is included because argc is attacker-adjacent
		// once a probe exists: it must clamp, never index.
		{"absurd", 4096, abi.ArgvMax},
		{"maximum", math.MaxUint32, abi.ArgvMax},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := newRecord(abi.EvtProcExec)
			put32(raw, offExecArgc, tc.argc)
			putStr(raw, offExecFilename, "/usr/bin/cc")
			for i := range abi.ArgvMax {
				putStr(raw, offArgv(i), "arg")
			}

			e := decode(t, raw)
			if len(e.Exec.Argv) != tc.want {
				t.Fatalf("len(Argv) = %d, want %d", len(e.Exec.Argv), tc.want)
			}
			for i, a := range e.Exec.Argv {
				if a != "arg" {
					t.Errorf("Argv[%d] = %q, want %q", i, a, "arg")
				}
			}
		})
	}
}

// Each argv row is read at its own stride. A row-stride mistake shows up as
// arguments bleeding into one another, which is the kind of defect that reads
// as plausible in an audit log.
func TestExecArgvRowsDoNotBleed(t *testing.T) {
	raw := newRecord(abi.EvtProcExec)
	put32(raw, offExecArgc, abi.ArgvMax)
	putStr(raw, offExecFilename, "/bin/sh")
	want := make([]string, abi.ArgvMax)
	for i := range abi.ArgvMax {
		// 63 bytes plus the terminator: the longest argument a row can hold,
		// so any read past the row picks up the next one.
		want[i] = strings.Repeat(string(rune('a'+i)), abi.ArgLen-1)
		putStr(raw, offArgv(i), want[i])
	}

	e := decode(t, raw)
	if !reflect.DeepEqual(e.Exec.Argv, want) {
		for i := range want {
			if e.Exec.Argv[i] != want[i] {
				t.Errorf("Argv[%d] = %q (len %d), want len %d", i, e.Exec.Argv[i], len(e.Exec.Argv[i]), len(want[i]))
			}
		}
	}
}

// --- network ---------------------------------------------------------------------------

func TestDecodeNetworkEvents(t *testing.T) {
	cases := []struct {
		name   string
		typ    abi.EventType
		family uint16
		proto  uint16
		sock   uint16
		saddr  []byte
		daddr  []byte
		sport  uint16
		dport  uint16
		bytes  int64
		want   event.NetworkPayload
	}{
		{
			name: "IPv4 TCP connect", typ: abi.EvtNetConnect,
			family: 2, proto: 6, sock: 1,
			saddr: []byte{10, 0, 2, 15}, daddr: []byte{192, 0, 2, 55},
			sport: 51000, dport: 443,
			// bytes is set on a connect, where the header gives the field no
			// direction. It must not surface as sent or received: assigning one
			// would invent the volume evidence net.send is scored on.
			bytes: 999,
			want: event.NetworkPayload{
				Protocol: "tcp", SourceAddr: "10.0.2.15", SourcePort: 51000,
				DestAddr: "192.0.2.55", DestPort: 443,
				AddressFamily: "AF_INET", SocketType: "SOCK_STREAM",
			},
		},
		{
			name: "IPv4 UDP send carries bytes", typ: abi.EvtNetSend,
			family: 2, proto: 17, sock: 2,
			daddr: []byte{198, 51, 100, 7}, dport: 53, bytes: 4096,
			want: event.NetworkPayload{
				Protocol: "udp", SourceAddr: "0.0.0.0",
				DestAddr: "198.51.100.7", DestPort: 53,
				AddressFamily: "AF_INET", SocketType: "SOCK_DGRAM",
				BytesSent: 4096,
			},
		},
		{
			name: "IPv6", typ: abi.EvtNetConnect,
			family: 10, proto: 6, sock: 1,
			daddr: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			dport: 8443,
			want: event.NetworkPayload{
				Protocol: "tcp", SourceAddr: "::", DestAddr: "2001:db8::1", DestPort: 8443,
				AddressFamily: "AF_INET6", SocketType: "SOCK_STREAM",
			},
		},
		{
			// Left mapped rather than normalized. The validator unmaps at
			// comparison time with its reasoning recorded, and normalizing here
			// too would mean the record no longer shows what the socket said.
			name: "IPv4-mapped IPv6 is not normalized", typ: abi.EvtNetConnect,
			family: 10, proto: 6, sock: 1,
			daddr: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 93, 184, 216, 34},
			dport: 443,
			want: event.NetworkPayload{
				Protocol: "tcp", SourceAddr: "::", DestAddr: "::ffff:93.184.216.34", DestPort: 443,
				AddressFamily: "AF_INET6", SocketType: "SOCK_STREAM",
			},
		},
		{
			// A unix socket path is not an address and does not fit the field,
			// so no address is reported. The family still is, so the record is
			// not silently emptied.
			name: "AF_UNIX has no address", typ: abi.EvtNetConnect,
			family: 1, sock: 1,
			daddr: []byte{0x2f, 0x74, 0x6d, 0x70}, // "/tmp", which must not be read as 47.116.109.112
			want: event.NetworkPayload{
				AddressFamily: "AF_UNIX", SocketType: "SOCK_STREAM",
			},
		},
		{
			name: "unknown family renders rather than hides", typ: abi.EvtNetConnect,
			family: 40, proto: 132, sock: 5, dport: 1,
			daddr: []byte{1, 2, 3, 4},
			want: event.NetworkPayload{
				Protocol: "IPPROTO(132)", DestPort: 1,
				AddressFamily: "AddressFamily(40)", SocketType: "SOCK_SEQPACKET",
			},
		},
		{
			name: "bind to the wildcard address", typ: abi.EvtNetBind,
			family: 2, proto: 6, sock: 1, sport: 8080,
			want: event.NetworkPayload{
				Protocol: "tcp", SourceAddr: "0.0.0.0", DestAddr: "0.0.0.0", SourcePort: 8080,
				AddressFamily: "AF_INET", SocketType: "SOCK_STREAM",
			},
		},
		{
			// Every numeric field at its maximum. A port is __u16 and the Go
			// field is an int, so 65535 must survive rather than wrap.
			name: "boundary values", typ: abi.EvtNetSend,
			family: 2, proto: 6, sock: 3,
			daddr: []byte{255, 255, 255, 255},
			sport: math.MaxUint16, dport: math.MaxUint16, bytes: math.MaxInt64,
			want: event.NetworkPayload{
				Protocol: "tcp", SourceAddr: "0.0.0.0", DestAddr: "255.255.255.255",
				SourcePort: math.MaxUint16, DestPort: math.MaxUint16,
				AddressFamily: "AF_INET", SocketType: "SOCK_RAW",
				BytesSent: math.MaxInt64,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := newRecord(tc.typ)
			put16(raw, offNetFamily, tc.family)
			put16(raw, offNetProtocol, tc.proto)
			put16(raw, offNetSockType, tc.sock)
			put16(raw, offNetSport, tc.sport)
			put16(raw, offNetDport, tc.dport)
			putI64(raw, offNetBytes, tc.bytes)
			copy(raw[offNetSaddr:], tc.saddr)
			copy(raw[offNetDaddr:], tc.daddr)

			e := decode(t, raw)
			if e.Network == nil {
				t.Fatal("no network payload")
			}
			if *e.Network != tc.want {
				t.Errorf("network payload =\n  %+v\nwant\n  %+v", *e.Network, tc.want)
			}
			// Correlation is best-effort and belongs to DNSCorrelator. A
			// hostname invented here would let a grant written for a name match
			// a connection nobody resolved.
			if e.Network.Hostname != "" {
				t.Errorf("Hostname = %q; the decoder must not correlate", e.Network.Hostname)
			}
			if e.File != nil || e.Exec != nil || e.Privil != nil {
				t.Error("a network event carries a payload from another domain")
			}
		})
	}
}

// A port is a plain __u16 in the header, not a __be16. Reading it as network
// order would turn 443 into 47873 and nothing downstream would notice, so the
// reading is pinned rather than left to a comment.
func TestPortsAreReadInTheRecordsOwnByteOrder(t *testing.T) {
	raw := newRecord(abi.EvtNetConnect)
	put16(raw, offNetFamily, 2)
	put16(raw, offNetProtocol, 6)
	put16(raw, offNetDport, 443)

	e := decode(t, raw)
	if e.Network.DestPort != 443 {
		t.Errorf("DestPort = %d, want 443", e.Network.DestPort)
	}
	const byteSwapped = 47873 // 443 read the other way round
	if e.Network.DestPort == byteSwapped {
		t.Error("the port was byte-swapped")
	}
}

// --- process identity, results, and errno ------------------------------------------------

func TestDecodeProcessIdentity(t *testing.T) {
	raw := newRecord(abi.EvtProcExit)
	put64(raw, abi.OffsetEventTimestamp, 1_234_567_890)
	putI32(raw, abi.OffsetEventRet, 0)
	put64(raw, abi.OffsetEventProc+abi.OffsetProcCgroupID, 9101)
	put64(raw, abi.OffsetEventProc+abi.OffsetProcStartTime, 120_400_000)
	put32(raw, abi.OffsetEventProc+abi.OffsetProcPID, 7100)
	put32(raw, abi.OffsetEventProc+abi.OffsetProcTID, 7101)
	put32(raw, abi.OffsetEventProc+abi.OffsetProcPPID, 7099)
	put32(raw, abi.OffsetEventProc+abi.OffsetProcUID, 1000)
	put32(raw, abi.OffsetEventProc+abi.OffsetProcGID, 1000)
	putStr(raw, abi.OffsetEventProc+abi.OffsetProcComm, "node")

	e := decode(t, raw)

	want := event.Process{
		PID: 7100, TID: 7101, PPID: 7099, UID: 1000, GID: 1000,
		Comm: "node", CgroupID: 9101, StartTime: 120_400_000,
	}
	if e.Process != want {
		t.Errorf("Process =\n  %+v\nwant\n  %+v", e.Process, want)
	}
	if e.KernelTimestamp != 1_234_567_890 {
		t.Errorf("KernelTimestamp = %d", e.KernelTimestamp)
	}
}

// The unsigned-to-signed conversion, at the value where it matters.
//
// (uid_t)-1 is the kernel's "leave this unchanged" marker in the setres*id
// family and arrives as 0xFFFFFFFF. It must survive as -1 rather than being
// clamped, because clamping erases the distinction between "unchanged" and
// "changed to something".
func TestProcessIdentityBoundaryValues(t *testing.T) {
	raw := newRecord(abi.EvtProcExit)
	for _, off := range []int{
		abi.OffsetProcPID, abi.OffsetProcTID, abi.OffsetProcPPID,
		abi.OffsetProcUID, abi.OffsetProcGID,
	} {
		put32(raw, abi.OffsetEventProc+off, math.MaxUint32)
	}
	put64(raw, abi.OffsetEventProc+abi.OffsetProcCgroupID, math.MaxUint64)
	put64(raw, abi.OffsetEventProc+abi.OffsetProcStartTime, math.MaxUint64)
	put64(raw, abi.OffsetEventTimestamp, math.MaxUint64)

	e := decode(t, raw)
	want := event.Process{
		PID: -1, TID: -1, PPID: -1, UID: -1, GID: -1,
		CgroupID: math.MaxUint64, StartTime: math.MaxUint64,
	}
	if e.Process != want {
		t.Errorf("Process =\n  %+v\nwant\n  %+v", e.Process, want)
	}
	if e.KernelTimestamp != math.MaxUint64 {
		t.Errorf("KernelTimestamp = %d, want %d", e.KernelTimestamp, uint64(math.MaxUint64))
	}
}

// comm fills its 16 bytes exactly at 15 characters plus the terminator, which
// is the kernel's own limit. One character more has no terminator and is
// refused with everything else that filled its field.
func TestCommAtTheFieldBoundary(t *testing.T) {
	raw := newRecord(abi.EvtProcExit)
	want := strings.Repeat("c", abi.CommLen-1)
	putStr(raw, abi.OffsetEventProc+abi.OffsetProcComm, want)

	if got := decode(t, raw).Process.Comm; got != want {
		t.Errorf("Comm = %q, want %q", got, want)
	}
}

func TestResultAndErrno(t *testing.T) {
	cases := []struct {
		name string
		ret  int32
		want event.Result
	}{
		{"success with zero", 0, event.Result{ReturnCode: 0, Succeeded: true}},
		{"a file descriptor", 3, event.Result{ReturnCode: 3, Succeeded: true}},
		{"ENOENT", -2, event.Result{ReturnCode: -2, Errno: "ENOENT", Succeeded: false}},
		{"EACCES", -13, event.Result{ReturnCode: -13, Errno: "EACCES", Succeeded: false}},
		{"EPERM", -1, event.Result{ReturnCode: -1, Errno: "EPERM", Succeeded: false}},
		{"ECONNREFUSED", -111, event.Result{ReturnCode: -111, Errno: "ECONNREFUSED", Succeeded: false}},
		{"the last named value", -133, event.Result{ReturnCode: -133, Errno: "EHWPOISON", Succeeded: false}},
		// 41 and 58 are unassigned on Linux. An invented name would read as
		// fact; the number is still there.
		{"unassigned in the range", -41, event.Result{ReturnCode: -41, Succeeded: false}},
		{"past the table", -134, event.Result{ReturnCode: -134, Succeeded: false}},
		// ERESTARTSYS never reaches user space. One appearing in a record means
		// the probe reported something no syscall returned, and naming it would
		// disguise that.
		{"kernel-internal", -512, event.Result{ReturnCode: -512, Succeeded: false}},
		{"the value int32 cannot negate", math.MinInt32,
			event.Result{ReturnCode: math.MinInt32, Succeeded: false}},
		{"largest success", math.MaxInt32, event.Result{ReturnCode: math.MaxInt32, Succeeded: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := newRecord(abi.EvtFileOpen)
			putI32(raw, abi.OffsetEventRet, tc.ret)

			if got := decode(t, raw).Result; got != tc.want {
				t.Errorf("Result = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// The table is data, and data that encodes an ABI gets a shape test.
func TestErrnoTableShape(t *testing.T) {
	if got := errnoNames[0]; got != "" {
		t.Errorf("errno 0 is success and has no name, got %q", got)
	}
	for _, unassigned := range []int64{41, 58} {
		if got := errnoName(unassigned); got != "" {
			t.Errorf("errno %d is unassigned on Linux, got %q", unassigned, got)
		}
	}
	for _, out := range []int64{-1, 134, 512, math.MaxInt64} {
		if got := errnoName(out); got != "" {
			t.Errorf("errnoName(%d) = %q, want \"\"", out, got)
		}
	}

	seen := map[string]int{}
	for i, name := range errnoNames {
		if name == "" {
			continue
		}
		if !strings.HasPrefix(name, "E") {
			t.Errorf("errno %d = %q, which is not an errno name", i, name)
		}
		if prev, dup := seen[name]; dup {
			t.Errorf("%q appears at both %d and %d; the table has an alias where it needs a value", name, prev, i)
		}
		seen[name] = i
	}
	// Spot checks against errno-base.h, at both ends and at the boundary
	// between the base list and the extended one.
	for value, want := range map[int64]string{1: "EPERM", 34: "ERANGE", 35: "EDEADLK", 133: "EHWPOISON"} {
		if got := errnoName(value); got != want {
			t.Errorf("errnoName(%d) = %q, want %q", value, got, want)
		}
	}
}

// --- rejection -----------------------------------------------------------------------

// A record of the wrong length is refused in both directions, and the sentinel
// survives the decoder's wrapping so a caller can still tell a truncated read
// from layout drift.
func TestDecodeRefusesTheWrongSize(t *testing.T) {
	cases := []struct {
		name string
		size int
		want error
	}{
		{"nil", 0, abi.ErrShortRecord},
		{"one byte short", abi.RecordSize - 1, abi.ErrShortRecord},
		{"header only", abi.OffsetEventPayload, abi.ErrShortRecord},
		{"one byte long", abi.RecordSize + 1, abi.ErrLongRecord},
		{"two records", abi.RecordSize * 2, abi.ErrLongRecord},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := make([]byte, tc.size)
			if tc.size >= 12 {
				put32(raw, abi.OffsetEventType, uint32(abi.EvtProcExec))
			}
			e, err := NewDecoder().Decode(raw)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if e != nil {
				t.Error("a refused record returned an event")
			}
		})
	}

	if _, err := NewDecoder().Decode(nil); !errors.Is(err, abi.ErrShortRecord) {
		t.Errorf("Decode(nil) = %v, want %v", err, abi.ErrShortRecord)
	}
}

// An event type outside the enum means the loaded object is newer than this
// binary. That is layout drift, and the value is reported rather than hidden.
func TestDecodeRefusesUnknownEventType(t *testing.T) {
	for _, typ := range []uint32{13, 14, 99, math.MaxUint32} {
		raw := newRecord(abi.EventType(typ))
		e, err := NewDecoder().Decode(raw)
		if !errors.Is(err, ErrUnknownEventType) {
			t.Errorf("type %d: err = %v, want %v", typ, err, ErrUnknownEventType)
		}
		if e != nil {
			t.Errorf("type %d: a refused record returned an event", typ)
		}
		if !strings.Contains(err.Error(), "EventType") {
			t.Errorf("type %d: the error does not name the value: %v", typ, err)
		}
	}
}

// ALLSEER_EVT_UNKNOWN is a declared enumerator, so this is not drift: it is a
// record whose type was never set. It gets its own sentinel because the two
// mean different things about the system.
func TestDecodeRefusesUnsetEventType(t *testing.T) {
	_, err := NewDecoder().Decode(make([]byte, abi.RecordSize))
	if !errors.Is(err, ErrUnsetEventType) {
		t.Fatalf("err = %v, want %v", err, ErrUnsetEventType)
	}
	if errors.Is(err, ErrUnknownEventType) {
		t.Error("an unset type was reported as an unknown one; the first is a probe that did not " +
			"fill its reservation, the second is layout drift")
	}
}

// The privilege payload is refused, and the error says why rather than only
// that. See privilegeMappingIsUndecided: one C type stands in for five catalog
// kinds the shipped rule set treats differently, and the field that would
// separate them has no enumerators.
func TestDecodeRefusesPrivilegeChange(t *testing.T) {
	raw := newRecord(abi.EvtPrivChange)
	put64(raw, abi.OffsetEventPayload+abi.OffsetPrivPayloadCapsEffective, 0x3fffffffff)
	put32(raw, abi.OffsetEventPayload+abi.OffsetPrivPayloadNewUID, 0)
	put32(raw, abi.OffsetEventPayload+abi.OffsetPrivPayloadOldUID, 1000)

	e, err := NewDecoder().Decode(raw)
	if !errors.Is(err, ErrUndecidedMapping) {
		t.Fatalf("err = %v, want %v", err, ErrUndecidedMapping)
	}
	if e != nil {
		t.Fatal("a refused record returned an event")
	}
	// The message has to be actionable: it is the only place a reader learns
	// what would make the type decodable.
	for _, want := range []string{"operation", "allseer_event.h", "priv.setuid"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q: %v", want, err)
		}
	}
}

// A fixed-size string with no NUL in it filled its field, and the header states
// the consequence: truncation "must be treated as an enrichment failure, never
// as a complete path". event.Event has nowhere to carry that fact, so the
// record is refused rather than handed on as a prefix that looks whole.
func TestDecodeRefusesUnterminatedStrings(t *testing.T) {
	cases := []struct {
		name  string
		field string
		build func() []byte
	}{
		{
			name: "comm", field: "proc.comm",
			build: func() []byte {
				raw := newRecord(abi.EvtProcExit)
				fill(raw, abi.OffsetEventProc+abi.OffsetProcComm, abi.CommLen)
				return raw
			},
		},
		{
			name: "file path", field: "file.path",
			build: func() []byte {
				raw := newRecord(abi.EvtFileOpen)
				fill(raw, offFilePath, abi.PathMax)
				return raw
			},
		},
		{
			name: "rename destination", field: "file.new_path",
			build: func() []byte {
				raw := newRecord(abi.EvtFileRename)
				putStr(raw, offFilePath, "/tmp/staged")
				fill(raw, offFileNewPath, abi.PathMax)
				return raw
			},
		},
		{
			name: "exec filename", field: "exec.filename",
			build: func() []byte {
				raw := newRecord(abi.EvtProcExec)
				fill(raw, offExecFilename, abi.PathMax)
				return raw
			},
		},
		{
			name: "an argv row", field: "exec.argv[2]",
			build: func() []byte {
				raw := newRecord(abi.EvtProcExec)
				put32(raw, offExecArgc, 4)
				putStr(raw, offExecFilename, "/bin/sh")
				fill(raw, offArgv(2), abi.ArgLen)
				return raw
			},
		},
	}

	// Every remaining file type, so no path-carrying type is left able to
	// accept a truncated path because its case was written separately.
	for _, typ := range []abi.EventType{abi.EvtFileWrite, abi.EvtFileUnlink, abi.EvtFileChmod} {
		cases = append(cases, struct {
			name  string
			field string
			build func() []byte
		}{
			name: typ.String(), field: "file.path",
			build: func() []byte {
				raw := newRecord(typ)
				fill(raw, offFilePath, abi.PathMax)
				return raw
			},
		})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, err := NewDecoder().Decode(tc.build())
			if !errors.Is(err, ErrTruncatedString) {
				t.Fatalf("err = %v, want %v", err, ErrTruncatedString)
			}
			if e != nil {
				t.Error("a truncated record returned an event")
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Errorf("the error does not name the field %q: %v", tc.field, err)
			}
		})
	}

	// One byte less fills the field with a terminator and is a complete value,
	// so it is accepted. The boundary is where the two behaviours meet and is
	// worth pinning on both sides.
	raw := newRecord(abi.EvtFileOpen)
	fill(raw, offFilePath, abi.PathMax-1)
	e, err := NewDecoder().Decode(raw)
	if err != nil {
		t.Fatalf("a path of exactly PathMax-1 bytes was refused: %v", err)
	}
	if len(e.File.Path) != abi.PathMax-1 {
		t.Errorf("len(Path) = %d, want %d", len(e.File.Path), abi.PathMax-1)
	}

	// A row past argc is never read, so garbage there cannot refuse a record
	// the probe considered complete.
	raw = newRecord(abi.EvtProcExec)
	put32(raw, offExecArgc, 1)
	putStr(raw, offExecFilename, "/bin/sh")
	putStr(raw, offArgv(0), "sh")
	fill(raw, offArgv(1), abi.ArgLen)
	if _, err := NewDecoder().Decode(raw); err != nil {
		t.Errorf("an unread argv row refused the record: %v", err)
	}
}

// --- properties of every decoded event ----------------------------------------------------

// The decoder fills what the record says and nothing else. Everything that
// needs session state, a boot offset, a resolver, or a counter is left zero for
// the stage that owns it.
func TestDecodedEventCarriesNoEnrichmentOrSessionState(t *testing.T) {
	for _, typ := range abi.AllEventTypes() {
		if CapabilitiesFor(typ) == nil {
			continue // refused types produce no event
		}
		t.Run(typ.String(), func(t *testing.T) {
			raw := newRecord(typ)
			putStr(raw, abi.OffsetEventProc+abi.OffsetProcComm, "sh")
			e := decode(t, raw)

			if e.ID != "" {
				t.Errorf("ID = %q; uniqueness needs a counter and Decode is stateless", e.ID)
			}
			if e.SessionID != "" {
				t.Errorf("SessionID = %q; attribution is the collector's, via cgroup and ancestry", e.SessionID)
			}
			if e.Sequence != 0 {
				t.Errorf("Sequence = %d; a per-session counter is the collector's", e.Sequence)
			}
			if !e.WallClock.Equal(time.Time{}) {
				t.Errorf("WallClock = %v; the boot-offset strategy is an open decision in pkg/event, "+
					"and a wall time built on an unmeasured offset reads as observed", e.WallClock)
			}
			if e.Dropped != 0 {
				t.Errorf("Dropped = %d; loss is visible to the reader that saw the gap", e.Dropped)
			}
			if !reflect.DeepEqual(e.Observation, capability.Observation{}) {
				t.Errorf("Observation = %+v; resolution runs after enrichment, on the resolved path", e.Observation)
			}
			if e.Syscall != "" {
				t.Errorf("Syscall = %q; the record carries no syscall identifier, so any name would be a guess", e.Syscall)
			}
		})
	}
}

// Exactly one payload, and it is the one the domain requires. This is the rule
// api/schema/event.v1alpha1.schema.json states as an allOf, asserted against
// the decoder that has to satisfy it.
func TestPayloadMatchesDomain(t *testing.T) {
	for _, typ := range abi.AllEventTypes() {
		if CapabilitiesFor(typ) == nil {
			continue
		}
		t.Run(typ.String(), func(t *testing.T) {
			e := decode(t, newRecord(typ))

			set := 0
			for _, present := range []bool{e.File != nil, e.Network != nil, e.Exec != nil, e.Privil != nil} {
				if present {
					set++
				}
			}
			if set > 1 {
				t.Fatalf("%d payloads set on one event", set)
			}

			switch e.Domain {
			case capability.DomainFilesystem:
				if e.File == nil {
					t.Error("a filesystem event has no file payload, which the event schema requires")
				}
			case capability.DomainNetwork:
				if e.Network == nil {
					t.Error("a network event has no network payload, which the event schema requires")
				}
			case capability.DomainProcess:
				// exec carries a payload; exit and ptrace designate no union
				// member, and the schema requires none for the domain.
				if typ == abi.EvtProcExec && e.Exec == nil {
					t.Error("an exec has no exec payload")
				}
				if typ != abi.EvtProcExec && e.Exec != nil {
					t.Error("a non-exec process event carries an exec payload")
				}
			default:
				t.Errorf("unexpected domain %q", e.Domain)
			}

			// Nothing in this build produces a privilege payload: the one event
			// type that carries one is refused.
			if e.Privil != nil {
				t.Error("a privilege payload was produced, but ALLSEER_EVT_PRIV_CHANGE is refused")
			}
		})
	}
}

// A zeroed record with a type is not an error, and the values it decodes to are
// the zero values rather than anything inferred. The all-zero case is what a
// probe that reserved and filled only the header produces, and what most fuzz
// inputs start from.
func TestZeroValuedRecordDecodesToZeroValues(t *testing.T) {
	e := decode(t, newRecord(abi.EvtFileOpen))

	if e.Capability != capability.KindFileRead {
		t.Errorf("Capability = %q, want %q: flags 0 is O_RDONLY", e.Capability, capability.KindFileRead)
	}
	if e.Process != (event.Process{}) {
		t.Errorf("Process = %+v, want the zero value", e.Process)
	}
	if e.Result != (event.Result{Succeeded: true}) {
		t.Errorf("Result = %+v; ret 0 is a success returning zero", e.Result)
	}
	if *e.File != (event.FilePayload{}) {
		t.Errorf("file payload = %+v, want the zero value", *e.File)
	}

	// A zeroed network record names the family and protocol it has rather than
	// inventing ones it does not.
	n := decode(t, newRecord(abi.EvtNetConnect)).Network
	if n.AddressFamily != "AF_UNSPEC" {
		t.Errorf("AddressFamily = %q, want AF_UNSPEC", n.AddressFamily)
	}
	if n.Protocol != "" || n.SocketType != "" || n.DestAddr != "" {
		t.Errorf("a zeroed network payload claimed a protocol, socket type, or address: %+v", *n)
	}
}

// Decoding is deterministic and does not alias the caller's buffer. The ring
// buffer reader owns that memory and may reuse it for the next record; an event
// holding a view into it would change after the fact.
func TestDecodeIsDeterministicAndCopiesItsInput(t *testing.T) {
	raw := newRecord(abi.EvtProcExec)
	put32(raw, offExecArgc, 2)
	putStr(raw, offExecFilename, "/usr/bin/git")
	putStr(raw, offArgv(0), "git")
	putStr(raw, offArgv(1), "status")
	putStr(raw, abi.OffsetEventProc+abi.OffsetProcComm, "git")

	first := decode(t, raw)
	second := decode(t, raw)
	if !reflect.DeepEqual(first, second) {
		t.Fatal("decoding the same bytes twice gave different events")
	}

	before := *first.Exec
	for i := range raw {
		raw[i] = 0xFF
	}
	if !reflect.DeepEqual(*first.Exec, before) {
		t.Error("the event changed when the source buffer was overwritten; it aliases memory the " +
			"ring buffer reader will reuse")
	}
}

// The decoded event is consumable by the stage that follows it, and yields the
// observation the validator will evaluate.
//
// The unevaluable target is the assertion worth having: before enrichment there
// is no resolved path, resolve.Observe refuses to fall back to the syscall path,
// and so a decoded file event cannot accidentally match a grant. That is the
// fail-closed direction, and it holds because of what the decoder does not do.
func TestDecodedEventsResolveToObservations(t *testing.T) {
	t.Run("file", func(t *testing.T) {
		raw := newRecord(abi.EvtFileOpen)
		putStr(raw, offFilePath, "../../etc/shadow")

		obs, err := resolve.Observe(decode(t, raw))
		if err != nil {
			t.Fatalf("Observe: %v", err)
		}
		if obs.Kind != capability.KindFileRead || obs.Domain != capability.DomainFilesystem {
			t.Errorf("observation = %+v", obs)
		}
		if obs.Target != "" {
			t.Errorf("Target = %q; an unresolved path must not reach selector matching", obs.Target)
		}
	})

	t.Run("exec", func(t *testing.T) {
		raw := newRecord(abi.EvtProcExec)
		put32(raw, offExecArgc, 2)
		putStr(raw, offExecFilename, "/usr/bin/node")
		putStr(raw, offArgv(0), "node")
		putStr(raw, offArgv(1), "tools/publish.js")

		obs, err := resolve.Observe(decode(t, raw))
		if err != nil {
			t.Fatalf("Observe: %v", err)
		}
		if obs.Target != "/usr/bin/node" {
			t.Errorf("Target = %q", obs.Target)
		}
		if got := obs.Attributes[capability.AttrArgv]; got != "node tools/publish.js" {
			t.Errorf("argv attribute = %q", got)
		}
	})

	t.Run("network", func(t *testing.T) {
		raw := newRecord(abi.EvtNetConnect)
		put16(raw, offNetFamily, 2)
		put16(raw, offNetProtocol, 6)
		put16(raw, offNetDport, 443)
		copy(raw[offNetDaddr:], []byte{192, 0, 2, 55})

		obs, err := resolve.Observe(decode(t, raw))
		if err != nil {
			t.Fatalf("Observe: %v", err)
		}
		if obs.Target != "192.0.2.55:443" {
			t.Errorf("Target = %q", obs.Target)
		}
		if obs.Attributes[capability.AttrProtocol] != "tcp" {
			t.Errorf("protocol attribute = %q", obs.Attributes[capability.AttrProtocol])
		}
		// DNS correlation did not happen because the decoder does not do it,
		// and the record says so rather than leaving it to be inferred.
		if obs.Attributes[capability.AttrHostnameCorrelated] != "false" {
			t.Error("an uncorrelated destination was not marked as such")
		}
	})
}

// --- benchmarks ----------------------------------------------------------------------
//
// Decode is hot-path code: it runs once per syscall the probes report.

func BenchmarkDecodeFileOpen(b *testing.B) {
	raw := newRecord(abi.EvtFileOpen)
	put32(raw, offFileFlags, 0x241)
	putStr(raw, offFilePath, "/home/dev/project/internal/middleware/limit.go")
	putStr(raw, abi.OffsetEventProc+abi.OffsetProcComm, "go")
	benchmarkDecode(b, raw)
}

func BenchmarkDecodeExec(b *testing.B) {
	raw := newRecord(abi.EvtProcExec)
	put32(raw, offExecArgc, abi.ArgvMax)
	putStr(raw, offExecFilename, "/usr/bin/gcc")
	for i := range abi.ArgvMax {
		putStr(raw, offArgv(i), "-Wall")
	}
	putStr(raw, abi.OffsetEventProc+abi.OffsetProcComm, "gcc")
	benchmarkDecode(b, raw)
}

func BenchmarkDecodeNetConnect(b *testing.B) {
	raw := newRecord(abi.EvtNetConnect)
	put16(raw, offNetFamily, 2)
	put16(raw, offNetProtocol, 6)
	put16(raw, offNetDport, 443)
	copy(raw[offNetDaddr:], []byte{192, 0, 2, 55})
	putStr(raw, abi.OffsetEventProc+abi.OffsetProcComm, "node")
	benchmarkDecode(b, raw)
}

func benchmarkDecode(b *testing.B, raw []byte) {
	b.Helper()
	d := NewDecoder()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		e, err := d.Decode(raw)
		if err != nil {
			b.Fatal(err)
		}
		_ = e
	}
}
