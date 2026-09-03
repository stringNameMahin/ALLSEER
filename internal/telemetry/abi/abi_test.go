package abi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stringNameMahin/ALLSEER/internal/telemetry/abigen"
)

// headerPath is the ABI contract these tests check the generated file against.
const headerPath = "../../../bpf/include/allseer_event.h"

// What these tests can and cannot prove.
//
// They prove that the generated Go agrees with the committed C header, that the
// layout arithmetic matches values worked out by hand, and that the decoder
// handles well-formed, malformed, and truncated byte slices without panicking.
//
// They prove **nothing** about what a kernel actually writes. No probe exists
// yet, none can be compiled on this host, and a test that synthesized bytes and
// called the result "kernel output" would be asserting the very thing that
// cannot be checked without a kernel. Every record here is a byte pattern
// constructed by the test, and the question asked of it is only whether the
// parser reads the layout it claims to read.

// --- the staleness check -----------------------------------------------------------
//
// The reason the generator exists at all. If this fails, the committed decoder
// and the header have diverged, and the divergence is silent everywhere else:
// the code still compiles, the tests still run, and the fields simply come back
// wrong.

func TestGeneratedFileIsNotStale(t *testing.T) {
	header, err := os.ReadFile(filepath.FromSlash(headerPath))
	if err != nil {
		t.Fatalf("reading the ABI header: %v", err)
	}

	want, err := abigen.Generate(header, "bpf/include/allseer_event.h", "abi")
	if err != nil {
		t.Fatalf("regenerating from the header: %v", err)
	}

	got, err := os.ReadFile("layout_gen.go")
	if err != nil {
		t.Fatalf("reading the committed generated file: %v", err)
	}

	// Normalized on both sides, because .gitattributes leaves Go source to
	// core.autocrlf: this file is CRLF on a Windows checkout and LF on a Linux
	// one, and a line ending is not a layout change.
	if !bytes.Equal(abigen.Normalize(got), abigen.Normalize(want)) {
		t.Fatalf("layout_gen.go is stale relative to %s.\n\n"+
			"The header changed and the generated decoder did not. Regenerate with:\n"+
			"    go generate ./internal/telemetry/abi/\n\n"+
			"then review the diff -- a change here is a change in how kernel bytes are read.", headerPath)
	}
}

// --- layout, against expectations written by hand ------------------------------------
//
// Deliberately duplicated work: these numbers were computed from the C
// declarations by hand and are compared against numbers the generator computed
// from the same declarations by code. The point is that the two derivations are
// independent. A generator bug that produced self-consistent nonsense would
// pass the staleness check above and fail here.

func TestLayoutMatchesHandComputedExpectations(t *testing.T) {
	t.Run("struct sizes", func(t *testing.T) {
		cases := []struct {
			name string
			got  int
			want int
			why  string
		}{
			{"Proc", SizeofProc, 56, "8+8 + 6*4 + 16, already 8-aligned"},
			{"FilePayload", SizeofFilePayload, 544, "3*8 + 2*4 + 2*256"},
			{"NetPayload", SizeofNetPayload, 56, "16+16 + 8 + 6*2 = 52, rounded up to the 8-byte alignment"},
			{"ExecPayload", SizeofExecPayload, 776, "2*4 + 256 + 8*64"},
			{"PrivState", SizeofPrivState, 96, "5*8 + 14*4, already 8-aligned"},
			{"PrivPayload", SizeofPrivPayload, 208, "2*96 + 4*4"},
			{"Payload union", SizeofPayload, 776, "the largest member, ExecPayload"},
			{"Event", SizeofEvent, 856, "8 + 4 + 4 + 4 + 4 + 56 + 776, counting version and its pad"},
		}
		for _, c := range cases {
			if c.got != c.want {
				t.Errorf("%s = %d, want %d (%s)", c.name, c.got, c.want, c.why)
			}
		}
	})

	t.Run("record size is what the startup layout check compares", func(t *testing.T) {
		if RecordSize != SizeofEvent {
			t.Errorf("RecordSize = %d, want SizeofEvent = %d", RecordSize, SizeofEvent)
		}
		// The number that decides how the probe must be written. The header
		// states the eBPF stack is 512 bytes; a record larger than that cannot
		// be built on the stack and has to be written straight into a ring
		// buffer reservation. This assertion is here so that if the record ever
		// shrinks below 512, somebody revisits that conclusion deliberately.
		const ebpfStackLimit = 512
		if RecordSize <= ebpfStackLimit {
			t.Errorf("RecordSize = %d, which now fits the %d-byte eBPF stack; the probe's "+
				"obligation to use a ring buffer reservation instead of a stack copy was "+
				"argued from it not fitting, and that argument needs revisiting",
				RecordSize, ebpfStackLimit)
		}
	})

	t.Run("offsets", func(t *testing.T) {
		cases := []struct {
			name string
			got  int
			want int
		}{
			{"Event.Timestamp", OffsetEventTimestamp, 0},
			{"Event.Type", OffsetEventType, 8},
			{"Event.Ret", OffsetEventRet, 12},
			{"Event.Version", OffsetEventVersion, 16},
			{"Event.Pad", OffsetEventPad, 20},
			{"Event.Proc", OffsetEventProc, 24},
			{"Event.Payload", OffsetEventPayload, 80},

			{"Proc.CgroupID", OffsetProcCgroupID, 0},
			{"Proc.StartTime", OffsetProcStartTime, 8},
			{"Proc.PID", OffsetProcPID, 16},
			{"Proc.Comm", OffsetProcComm, 40},

			{"FilePayload.Path", OffsetFilePayloadPath, 32},
			{"FilePayload.NewPath", OffsetFilePayloadNewPath, 288},

			{"NetPayload.Daddr", OffsetNetPayloadDaddr, 16},
			{"NetPayload.Bytes", OffsetNetPayloadBytes, 32},
			{"NetPayload.Dport", OffsetNetPayloadDport, 42},

			{"ExecPayload.Filename", OffsetExecPayloadFilename, 8},
			{"ExecPayload.Argv", OffsetExecPayloadArgv, 264},

			{"PrivState.CapBounding", OffsetPrivStateCapBounding, 32},
			{"PrivState.UIDEffective", OffsetPrivStateUIDEffective, 44},
			{"PrivState.Ngroups", OffsetPrivStateNgroups, 72},
			{"PrivState.UsernsInum", OffsetPrivStateUsernsInum, 80},
			{"PrivState.SeccompMode", OffsetPrivStateSeccompMode, 84},

			{"PrivPayload.Before", OffsetPrivPayloadBefore, 0},
			{"PrivPayload.After", OffsetPrivPayloadAfter, 96},
			{"PrivPayload.Operation", OffsetPrivPayloadOperation, 192},
			{"PrivPayload.FieldsPresent", OffsetPrivPayloadFieldsPresent, 196},
			{"PrivPayload.NsFlags", OffsetPrivPayloadNsFlags, 200},
		}
		for _, c := range cases {
			if c.got != c.want {
				t.Errorf("offset of %s = %d, want %d", c.name, c.got, c.want)
			}
		}
	})

	t.Run("bounds", func(t *testing.T) {
		if PathMax != 256 || CommLen != 16 || ArgvMax != 8 || ArgLen != 64 {
			t.Errorf("bounds = PathMax %d, CommLen %d, ArgvMax %d, ArgLen %d; want 256, 16, 8, 64",
				PathMax, CommLen, ArgvMax, ArgLen)
		}
	})
}

// --- the ABI version ------------------------------------------------------------------

// The version is a value the two sides compare, not a limit on what fits, and
// the distinction is load-bearing: a reader who takes ABIVersion for a bound has
// misread the contract as badly as one who takes PathMax for a version.
func TestABIVersionIsAValueNotABound(t *testing.T) {
	if ABIVersion != 2 {
		t.Errorf("ABIVersion = %d, want 2; version 1 was the first numbered layout and version 2 "+
			"reshaped struct allseer_priv_payload, and the number changes only when the bytes on "+
			"the wire change", ABIVersion)
	}

	// Where the field sits is the whole point of it. A version a reader has to
	// already know the layout to find cannot tell that reader the layout is
	// wrong, so it has to live in the fixed prologue -- ahead of proc, ahead of
	// the payload union, and ahead of everything whose position a later version
	// is free to move.
	if OffsetEventVersion >= OffsetEventProc || OffsetEventVersion >= OffsetEventPayload {
		t.Errorf("version sits at offset %d, at or past proc (%d) / payload (%d); a version "+
			"reachable only by a reader who already agrees about the layout reports nothing",
			OffsetEventVersion, OffsetEventProc, OffsetEventPayload)
	}

	// The pad is named rather than implicit so the C compiler and the generated
	// decoder account for the same four bytes instead of each deciding
	// separately. It exists either way: proc is 8-aligned and version ends at 20.
	if OffsetEventPad != OffsetEventVersion+4 || OffsetEventProc != OffsetEventPad+4 {
		t.Errorf("version/pad/proc = %d/%d/%d, want the pad to name exactly the gap between "+
			"version and the 8-aligned proc", OffsetEventVersion, OffsetEventPad, OffsetEventProc)
	}
}

// What this layer does with a version it does not recognize: nothing.
//
// Deliberate, and the reason is the same one that keeps pkg/event and
// pkg/capability out of this package. Deciding what a mismatched version *means*
// -- refuse to attach, drop the record, fail the session closed -- is a judgment,
// and the generated layer must stay free of judgments it would have to
// regenerate. The record's version is carried up verbatim so the layer that owns
// that judgment can act on it; see the header's remaining TODO, which puts the
// check in the loader, before any probe is attached.
//
// This test pins the current contract so that adding enforcement here later is a
// deliberate act with a failing test attached, rather than a quiet change of
// behavior at the boundary every downstream conclusion rests on.
func TestDecodeRecordDoesNotJudgeTheVersion(t *testing.T) {
	for _, v := range []uint32{0, ABIVersion, ABIVersion + 1, 0xFFFFFFFF} {
		raw := make([]byte, RecordSize)
		put32(raw, OffsetEventVersion, v)

		rec, err := DecodeRecord(raw)
		if err != nil {
			t.Fatalf("DecodeRecord with version %d: %v; this layer reports the version, it does "+
				"not rule on it", v, err)
		}
		if rec.Version != v {
			t.Errorf("Version = %d, want %d; a version the decoder rewrites or drops cannot be "+
				"compared by the layer that will enforce it", rec.Version, v)
		}
	}
}

// --- the event type enum -------------------------------------------------------------

func TestEventTypeEnum(t *testing.T) {
	// The values are a wire contract the header calls "append only, never
	// renumber". Pinned here so a renumbering is a test failure rather than a
	// silent reinterpretation of every recorded event.
	want := map[EventType]struct {
		value uint32
		name  string
	}{
		EvtUnknown:    {0, "ALLSEER_EVT_UNKNOWN"},
		EvtFileOpen:   {1, "ALLSEER_EVT_FILE_OPEN"},
		EvtFileWrite:  {2, "ALLSEER_EVT_FILE_WRITE"},
		EvtFileUnlink: {3, "ALLSEER_EVT_FILE_UNLINK"},
		EvtFileRename: {4, "ALLSEER_EVT_FILE_RENAME"},
		EvtFileChmod:  {5, "ALLSEER_EVT_FILE_CHMOD"},
		EvtProcExec:   {6, "ALLSEER_EVT_PROC_EXEC"},
		EvtProcExit:   {7, "ALLSEER_EVT_PROC_EXIT"},
		EvtNetConnect: {8, "ALLSEER_EVT_NET_CONNECT"},
		EvtNetBind:    {9, "ALLSEER_EVT_NET_BIND"},
		EvtNetSend:    {10, "ALLSEER_EVT_NET_SEND"},
		EvtPrivChange: {11, "ALLSEER_EVT_PRIV_CHANGE"},
		EvtPtrace:     {12, "ALLSEER_EVT_PTRACE"},
	}

	all := AllEventTypes()
	if len(all) != len(want) {
		t.Fatalf("AllEventTypes has %d members, this test classifies %d", len(all), len(want))
	}
	for _, et := range all {
		w, ok := want[et]
		if !ok {
			t.Fatalf("enumerator %v is not classified by this test; a value added to the header "+
				"is a wire-contract change and has to be acknowledged here", et)
		}
		if uint32(et) != w.value {
			t.Errorf("%s = %d, want %d; these values are append-only and must never be renumbered", w.name, uint32(et), w.value)
		}
		if et.String() != w.name {
			t.Errorf("String() = %q, want %q", et.String(), w.name)
		}
		if !et.IsKnown() {
			t.Errorf("%s reports as unknown", w.name)
		}
	}

	// A value from a newer object is rendered, not hidden. It means the loaded
	// program is ahead of this binary, which is drift a reader needs to see.
	future := EventType(9999)
	if future.IsKnown() {
		t.Error("an unknown enumerator reported as known")
	}
	if got := future.String(); got != "EventType(9999)" {
		t.Errorf("String() of an unknown value = %q, want EventType(9999)", got)
	}
}

// --- decoding ---------------------------------------------------------------------

func TestDecodeRecordReadsEveryHeaderField(t *testing.T) {
	raw := make([]byte, RecordSize)
	put64(raw, OffsetEventTimestamp, 0x1122334455667788)
	put32(raw, OffsetEventType, uint32(EvtFileOpen))
	putI32(raw, OffsetEventRet, -13) // -EACCES, as the probe would report it
	put32(raw, OffsetEventVersion, ABIVersion)
	put32(raw, OffsetEventPad, 0)

	p := OffsetEventProc
	put64(raw, p+OffsetProcCgroupID, 0xCAFEBABE)
	put64(raw, p+OffsetProcStartTime, 0xDEADBEEF)
	put32(raw, p+OffsetProcPID, 4242)
	put32(raw, p+OffsetProcTID, 4243)
	put32(raw, p+OffsetProcPPID, 1)
	put32(raw, p+OffsetProcUID, 1000)
	put32(raw, p+OffsetProcGID, 1001)
	copy(raw[p+OffsetProcComm:], "git\x00")

	rec, err := DecodeRecord(raw)
	if err != nil {
		t.Fatalf("DecodeRecord: %v", err)
	}

	if rec.Timestamp != 0x1122334455667788 {
		t.Errorf("Timestamp = %#x", rec.Timestamp)
	}
	if EventType(rec.Type) != EvtFileOpen {
		t.Errorf("Type = %v, want EvtFileOpen", EventType(rec.Type))
	}
	// The signed return is the field most likely to be read wrongly, and doing
	// so would turn every failed syscall into a large positive number.
	if rec.Ret != -13 {
		t.Errorf("Ret = %d, want -13; a negative return is -errno and must survive decoding", rec.Ret)
	}
	// Read from the record rather than assumed. A version field the decoder
	// silently fills in from its own constant would agree with itself forever and
	// report a mismatch never.
	if rec.Version != ABIVersion {
		t.Errorf("Version = %d, want %d", rec.Version, ABIVersion)
	}
	if rec.Proc.CgroupID != 0xCAFEBABE || rec.Proc.StartTime != 0xDEADBEEF {
		t.Errorf("Proc identity = cgroup %#x start %#x", rec.Proc.CgroupID, rec.Proc.StartTime)
	}
	if rec.Proc.PID != 4242 || rec.Proc.TID != 4243 || rec.Proc.PPID != 1 {
		t.Errorf("Proc pids = %d/%d/%d", rec.Proc.PID, rec.Proc.TID, rec.Proc.PPID)
	}
	if rec.Proc.UID != 1000 || rec.Proc.GID != 1001 {
		t.Errorf("Proc ids = %d/%d", rec.Proc.UID, rec.Proc.GID)
	}
	if s, ok := CString(rec.Proc.Comm[:]); !ok || s != "git" {
		t.Errorf("Comm = %q terminated=%v, want \"git\" true", s, ok)
	}
}

func TestPayloadAccessorsReadTheirMembers(t *testing.T) {
	t.Run("file", func(t *testing.T) {
		raw := make([]byte, RecordSize)
		put32(raw, OffsetEventType, uint32(EvtFileOpen))
		pay := OffsetEventPayload
		put64(raw, pay+OffsetFilePayloadInode, 99)
		put64(raw, pay+OffsetFilePayloadDevice, 2049)
		putI64(raw, pay+OffsetFilePayloadBytes, -1)
		put32(raw, pay+OffsetFilePayloadFlags, 0o100)
		put32(raw, pay+OffsetFilePayloadMode, 0o644)
		copy(raw[pay+OffsetFilePayloadPath:], "/etc/shadow\x00")
		copy(raw[pay+OffsetFilePayloadNewPath:], "/tmp/x\x00")

		rec, err := DecodeRecord(raw)
		if err != nil {
			t.Fatalf("DecodeRecord: %v", err)
		}
		f := rec.File()
		if f.Inode != 99 || f.Device != 2049 || f.Bytes != -1 || f.Flags != 0o100 || f.Mode != 0o644 {
			t.Errorf("file scalars = %+v", f)
		}
		if s, _ := CString(f.Path[:]); s != "/etc/shadow" {
			t.Errorf("Path = %q", s)
		}
		if s, _ := CString(f.NewPath[:]); s != "/tmp/x" {
			t.Errorf("NewPath = %q", s)
		}
	})

	t.Run("net", func(t *testing.T) {
		raw := make([]byte, RecordSize)
		put32(raw, OffsetEventType, uint32(EvtNetConnect))
		pay := OffsetEventPayload
		copy(raw[pay+OffsetNetPayloadDaddr:], []byte{93, 184, 216, 34})
		put64(raw, pay+OffsetNetPayloadBytes, 512)
		put16(raw, pay+OffsetNetPayloadSport, 54321)
		put16(raw, pay+OffsetNetPayloadDport, 443)
		put16(raw, pay+OffsetNetPayloadFamily, 2)   // AF_INET
		put16(raw, pay+OffsetNetPayloadProtocol, 6) // IPPROTO_TCP

		rec, err := DecodeRecord(raw)
		if err != nil {
			t.Fatalf("DecodeRecord: %v", err)
		}
		n := rec.Net()
		// The header notes v4 addresses occupy the first four bytes of a
		// 16-byte field, so the tail must stay zero rather than pick up
		// neighbouring payload bytes.
		if got := n.Daddr[:4]; got[0] != 93 || got[1] != 184 || got[2] != 216 || got[3] != 34 {
			t.Errorf("Daddr[:4] = %v", got)
		}
		for i, b := range n.Daddr[4:] {
			if b != 0 {
				t.Errorf("Daddr[%d] = %d, want 0; a v4 address must not read past its four bytes", i+4, b)
			}
		}
		if n.Bytes != 512 || n.Sport != 54321 || n.Dport != 443 || n.Family != 2 || n.Protocol != 6 {
			t.Errorf("net scalars = %+v", n)
		}
	})

	t.Run("exec", func(t *testing.T) {
		raw := make([]byte, RecordSize)
		put32(raw, OffsetEventType, uint32(EvtProcExec))
		pay := OffsetEventPayload
		put32(raw, pay+OffsetExecPayloadArgc, 3)
		copy(raw[pay+OffsetExecPayloadFilename:], "/usr/bin/git\x00")
		for i, arg := range []string{"git", "clone", "--depth=1"} {
			copy(raw[pay+OffsetExecPayloadArgv+i*ArgLen:], arg+"\x00")
		}

		rec, err := DecodeRecord(raw)
		if err != nil {
			t.Fatalf("DecodeRecord: %v", err)
		}
		e := rec.Exec()
		if e.Argc != 3 {
			t.Errorf("Argc = %d, want 3", e.Argc)
		}
		if s, _ := CString(e.Filename[:]); s != "/usr/bin/git" {
			t.Errorf("Filename = %q", s)
		}
		// The 2-D argv array is where a row-stride mistake would show up, and
		// it would show up as arguments bleeding into one another.
		for i, want := range []string{"git", "clone", "--depth=1"} {
			if s, _ := CString(e.Argv[i][:]); s != want {
				t.Errorf("Argv[%d] = %q, want %q", i, s, want)
			}
		}
		for i := 3; i < ArgvMax; i++ {
			if s, _ := CString(e.Argv[i][:]); s != "" {
				t.Errorf("Argv[%d] = %q, want empty", i, s)
			}
		}
	})

	// The privilege payload is the one member built from a nested struct used
	// twice, so the mistake it exists to catch is a `before` field read at an
	// `after` offset or the reverse. Every scalar below is given a distinct
	// value for that reason: a swap of the two snapshots, or a stride error
	// inside one, cannot produce a passing run.
	t.Run("priv", func(t *testing.T) {
		raw := make([]byte, RecordSize)
		put32(raw, OffsetEventType, uint32(EvtPrivChange))
		pay := OffsetEventPayload
		before := pay + OffsetPrivPayloadBefore
		after := pay + OffsetPrivPayloadAfter

		put64(raw, before+OffsetPrivStateCapEffective, 0x1)
		put64(raw, before+OffsetPrivStateCapPermitted, 0x2)
		put64(raw, before+OffsetPrivStateCapInheritable, 0x4)
		put64(raw, before+OffsetPrivStateCapAmbient, 0x8)
		put64(raw, before+OffsetPrivStateCapBounding, 0x3FFFFFFFFF)
		put32(raw, before+OffsetPrivStateUIDReal, 1000)
		put32(raw, before+OffsetPrivStateUIDEffective, 1001)
		put32(raw, before+OffsetPrivStateUIDSaved, 1002)
		put32(raw, before+OffsetPrivStateUIDFs, 1003)
		put32(raw, before+OffsetPrivStateGIDReal, 2000)
		put32(raw, before+OffsetPrivStateGIDEffective, 2001)
		put32(raw, before+OffsetPrivStateGIDSaved, 2002)
		put32(raw, before+OffsetPrivStateGIDFs, 2003)
		put32(raw, before+OffsetPrivStateNgroups, 7)
		put32(raw, before+OffsetPrivStateSecurebits, 0x21)
		put32(raw, before+OffsetPrivStateUsernsInum, 4026531837)
		put32(raw, before+OffsetPrivStateSeccompMode, 0)

		// Zero is root, not "absent". Reading this field wrongly is how a
		// privilege escalation becomes invisible, which is why the after
		// snapshot lands on 0 for every identity view.
		put64(raw, after+OffsetPrivStateCapEffective, 0x3FFFFFFFFF)
		put32(raw, after+OffsetPrivStateUIDEffective, 0)
		put32(raw, after+OffsetPrivStateNgroups, 0)
		put32(raw, after+OffsetPrivStateUsernsInum, 4026531837)
		put32(raw, after+OffsetPrivStateSeccompMode, 2)

		put32(raw, pay+OffsetPrivPayloadOperation, uint32(OpSetresuid))
		put32(raw, pay+OffsetPrivPayloadFieldsPresent,
			uint32(FieldBeforeCred)|uint32(FieldAfterCred))
		put32(raw, pay+OffsetPrivPayloadNsFlags, 0x10000000)

		rec, err := DecodeRecord(raw)
		if err != nil {
			t.Fatalf("DecodeRecord: %v", err)
		}
		p := rec.Priv()

		wantBefore := PrivState{
			CapEffective: 0x1, CapPermitted: 0x2, CapInheritable: 0x4,
			CapAmbient: 0x8, CapBounding: 0x3FFFFFFFFF,
			UIDReal: 1000, UIDEffective: 1001, UIDSaved: 1002, UIDFs: 1003,
			GIDReal: 2000, GIDEffective: 2001, GIDSaved: 2002, GIDFs: 2003,
			Ngroups: 7, Securebits: 0x21, UsernsInum: 4026531837, SeccompMode: 0,
		}
		if p.Before != wantBefore {
			t.Errorf("before = %+v, want %+v", p.Before, wantBefore)
		}
		wantAfter := PrivState{
			CapEffective: 0x3FFFFFFFFF, UsernsInum: 4026531837, SeccompMode: 2,
		}
		if p.After != wantAfter {
			t.Errorf("after = %+v, want %+v", p.After, wantAfter)
		}
		if p.Operation != uint32(OpSetresuid) {
			t.Errorf("Operation = %d, want %d", p.Operation, OpSetresuid)
		}
		if p.FieldsPresent != uint32(FieldBeforeCred)|uint32(FieldAfterCred) {
			t.Errorf("FieldsPresent = %#x", p.FieldsPresent)
		}
		if p.NsFlags != 0x10000000 {
			t.Errorf("NsFlags = %#x, want CLONE_NEWUSER", p.NsFlags)
		}
	})
}

// A record of the wrong length is refused in both directions. Accepting one is
// how plausible garbage reaches a governance decision.
func TestDecodeRecordRefusesTheWrongSize(t *testing.T) {
	cases := []struct {
		name string
		size int
		want error
	}{
		{"empty", 0, ErrShortRecord},
		{"one byte short", RecordSize - 1, ErrShortRecord},
		{"header only", OffsetEventPayload, ErrShortRecord},
		{"one byte long", RecordSize + 1, ErrLongRecord},
		{"two records", RecordSize * 2, ErrLongRecord},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeRecord(make([]byte, tc.size))
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}

	if _, err := DecodeRecord(make([]byte, RecordSize)); err != nil {
		t.Errorf("an exactly-sized record was refused: %v", err)
	}
}

// --- CString ------------------------------------------------------------------------

func TestCStringReportsTruncation(t *testing.T) {
	cases := []struct {
		name       string
		in         []byte
		want       string
		terminated bool
	}{
		{"terminated", []byte("git\x00\x00\x00"), "git", true},
		{"empty", []byte("\x00\x00"), "", true},
		{"zero length", []byte{}, "", false},
		{"unterminated fills the field", []byte("abcdef"), "abcdef", false},
		{"stops at the first NUL", []byte("a\x00b"), "a", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, term := CString(tc.in)
			if got != tc.want || term != tc.terminated {
				t.Errorf("CString(%q) = %q, %v; want %q, %v", tc.in, got, term, tc.want, tc.terminated)
			}
		})
	}

	// The case the whole second return value exists for: a path that filled its
	// field is truncated, and the header states truncation must be treated as
	// an enrichment failure rather than as a complete path.
	full := bytes.Repeat([]byte("a"), PathMax)
	if _, terminated := CString(full); terminated {
		t.Error("a path filling the whole field reported as terminated; a truncated path that " +
			"reads as complete can match a granted glob the real path would not")
	}
}

// --- fuzz ----------------------------------------------------------------------------

// FuzzDecodeRecord is the parser half of the trust boundary.
//
// The decoder is the one place attacker-influenced bytes cross into a parser,
// and the property asserted here is total: for any input, DecodeRecord either
// returns an error or returns a record, and never panics, reads out of bounds,
// or produces a different answer on a second run.
//
// Note that this is not the fuzz target M5 asks for. That one targets
// telemetry.Decoder.Decode and lives beside it as telemetry.FuzzDecode, where
// the capability-catalog mapping this layer deliberately has none of can be
// asserted. This target covers the layout half: for any input, either an error
// or a record, and never a panic.
func FuzzDecodeRecord(f *testing.F) {
	f.Add(make([]byte, RecordSize))
	f.Add(make([]byte, 0))
	f.Add(make([]byte, RecordSize-1))
	f.Add(make([]byte, RecordSize+1))
	f.Add(bytes.Repeat([]byte{0xFF}, RecordSize))

	valid := make([]byte, RecordSize)
	put32(valid, OffsetEventType, uint32(EvtProcExec))
	putI32(valid, OffsetEventRet, -1)
	copy(valid[OffsetEventPayload+OffsetExecPayloadFilename:], "/bin/sh")
	f.Add(valid)

	f.Fuzz(func(t *testing.T, raw []byte) {
		rec, err := DecodeRecord(raw)
		if err != nil {
			if len(raw) == RecordSize {
				t.Fatalf("an exactly-sized record was refused: %v", err)
			}
			return
		}
		if len(raw) != RecordSize {
			t.Fatalf("accepted a %d-byte record; only %d is valid", len(raw), RecordSize)
		}

		// The accessors index a fixed-size array and must be total.
		_ = rec.File()
		_ = rec.Net()
		_ = rec.Exec()
		_ = rec.Priv()
		_, _ = CString(rec.Proc.Comm[:])

		again, err := DecodeRecord(raw)
		if err != nil {
			t.Fatalf("second decode of the same bytes failed: %v", err)
		}
		if again != rec {
			t.Fatal("decoding is not deterministic")
		}
	})
}

// --- helpers ---------------------------------------------------------------------------
//
// Byte-order helpers matching the generated decoder's. NativeEndian on both
// sides is correct rather than convenient: the probe writes these bytes on the
// machine that reads them, so there is no conversion to perform.

func put16(b []byte, off int, v uint16) { binary.NativeEndian.PutUint16(b[off:], v) }
func put32(b []byte, off int, v uint32) { binary.NativeEndian.PutUint32(b[off:], v) }
func put64(b []byte, off int, v uint64) { binary.NativeEndian.PutUint64(b[off:], v) }

// Signed variants exist because a constant conversion of a negative value to an
// unsigned type does not compile, and the negative values matter: a syscall
// return is -errno, and reading it unsigned turns every failure into a large
// success.
func putI32(b []byte, off int, v int32) { binary.NativeEndian.PutUint32(b[off:], uint32(v)) }
func putI64(b []byte, off int, v int64) { binary.NativeEndian.PutUint64(b[off:], uint64(v)) }
