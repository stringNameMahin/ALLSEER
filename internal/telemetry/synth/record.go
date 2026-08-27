package synth

// The record layer: a Spec becomes the bytes a probe would have submitted.
//
// Every offset below comes from internal/telemetry/abi, which is generated from
// bpf/include/allseer_event.h. Nothing about the layout is written down here —
// no size, no offset, no field order — so a header change moves this file with
// it or fails to compile, and the one thing this package must never become is a
// second statement of the layout. Byte order is the host's, matching the
// generated decoder, because these bytes stand in for bytes a probe wrote on
// this machine.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/stringNameMahin/ALLSEER/internal/telemetry/abi"
)

// Errors reported for a spec that cannot be rendered as a record.
//
// Each is a refusal rather than a repair. The alternative in every case is to
// emit a record that says something other than what the spec said — a truncated
// path, a dropped argument, an address the family cannot describe, a field the
// decoder will not read — and a test fixture that quietly differs from its own
// description is worse than no fixture.
//
// The errors a *record* can carry rather than a spec — an unset event type, a
// type outside this build's enum, the undecided privilege mapping — are not
// here. Those belong to telemetry.EventDecoder and are surfaced from there
// unchanged, because the decoder is the authority on what a record means and a
// second opinion in this package would be exactly the drift it exists to avoid.
var (
	// ErrPayloadMismatch: the spec's payload does not agree with its event
	// type. A record carries one union member and the header designates which
	// one for each type; a payload the decoder would not read is a payload that
	// vanishes between the spec and the event.
	ErrPayloadMismatch = errors.New("synth: payload does not match the event type")

	// ErrValueTooLong: a string does not fit its fixed-size field with room for
	// the terminator. Writing it anyway would produce an unterminated array,
	// which abi.CString reports as truncated and the decoder refuses outright —
	// a real property of the ABI, tested where it belongs, and not something a
	// generator should manufacture by accident.
	ErrValueTooLong = errors.New("synth: value does not fit its fixed-size ABI field")

	// ErrEmbeddedNUL: a string contains a NUL. The record would decode to the
	// prefix before it, so the event would carry a different value than the
	// spec named.
	ErrEmbeddedNUL = errors.New("synth: value contains a NUL, which would truncate it in the record")

	// ErrTooManyArgs: more arguments than ALLSEER_ARGV_MAX rows. The decoder
	// clamps to what the array holds, which is correct for a real exec and
	// wrong for a spec: the extra arguments would be silently absent.
	ErrTooManyArgs = errors.New("synth: more arguments than the record can carry")

	// ErrAddressFamily: the address and the address family disagree. The
	// header states v4 addresses occupy the first 4 bytes, so the family
	// decides how the 16-byte field is written and read; a family that carries
	// no address of this shape cannot be given one.
	ErrAddressFamily = errors.New("synth: address does not match the address family")
)

// Address families, transport protocols and socket types, in the vocabulary
// bpf/include/allseer_event.h names in its own comments.
//
// Provided so a spec reads as what it means rather than as a magic number. The
// values are Linux's on both targets the ABI supports, and they are the same
// numbers decode.go renders back into names — which is asserted by test rather
// than by inspection, since two private tables of the same constants is exactly
// how a synthetic AF_INET quietly becomes something else.
const (
	AFUnspec uint16 = 0
	AFUnix   uint16 = 1
	AFInet   uint16 = 2
	AFInet6  uint16 = 10

	IPProtoTCP uint16 = 6
	IPProtoUDP uint16 = 17

	SockStream    uint16 = 1
	SockDgram     uint16 = 2
	SockRaw       uint16 = 3
	SockSeqpacket uint16 = 5
)

// Spec describes one record for the generator to build.
//
// It is written in the ABI's vocabulary — an allseer_event_type, a syscall
// return, the union member the header designates for that type — and not in the
// event model's. What capability the event exercises, what its domain is, and
// what its errno is called are all decided by the decoder from these fields,
// which is what keeps a synthetic event indistinguishable from a real one.
type Spec struct {
	// Type is the allseer_event_type the probe would have submitted.
	Type abi.EventType

	// Ret is the syscall return; negative is -errno, per the header. A failed
	// action is still a governance signal, so a stream that carries only
	// successes is not a realistic one.
	Ret int32

	// Proc is the acting process. Nil uses Config.Process, which is the common
	// case: a stream is usually one process, or a small tree of them.
	Proc *Proc

	// Exactly one of these is set, and which one is decided by Type. A type
	// that designates no union member — ALLSEER_EVT_PROC_EXIT, ALLSEER_EVT_PTRACE
	// — takes none.
	File *File
	Net  *Net
	Exec *Exec

	// Dropped is how many ring buffer records were lost immediately before this
	// one. It advances the sequence counter and the clock along with the
	// counter it sets on the event, so the gap and the count agree by
	// construction — which is the rule the replay corpus states for a fixture
	// that is about loss, and the property every fail-closed path is tested on.
	//
	// It is not part of the record. Loss is visible to the reader that saw the
	// hole, never to the record that followed it.
	Dropped uint64
}

// Proc is the acting process: the identity struct allseer_proc carries in every
// record, plus the two fields user-space enrichment adds to it.
//
// The signed fields are signed because event.Process is, and the conversion to
// the record's unsigned fields is two's complement and reversible. That matters
// for one value in particular: (uid_t)-1 is the kernel's "leave this unchanged"
// marker and must survive the round trip as -1.
type Proc struct {
	PID  int32
	TID  int32
	PPID int32
	UID  int32
	GID  int32

	// Comm is the kernel's truncated process name, capped at ALLSEER_COMM_LEN.
	Comm string

	CgroupID  uint64
	StartTime uint64

	// Executable and AncestryDepth are enrichment, not record fields. The
	// kernel record carries neither: the first needs a path resolution the
	// probe does not do, and the second needs the process tree ProcessTracker
	// maintains. They sit here because they describe the same actor.
	Executable    string
	AncestryDepth int
}

// File is struct allseer_file_payload, plus the path enrichment resolves.
type File struct {
	// Path is the path as the process passed it, capped at ALLSEER_PATH_MAX.
	// It may be relative and may contain symlinks, exactly as a probe captures
	// it.
	Path string

	// NewPath is the rename or link destination. The header defines it for
	// ALLSEER_EVT_FILE_RENAME alone, and so does the decoder, so setting it on
	// any other type is refused rather than silently discarded.
	NewPath string

	// ResolvedPath is the absolute, symlink-resolved path enrichment would have
	// produced. Selector matching uses it and never falls back to Path, so a
	// spec that leaves it empty produces an event whose target is unevaluable —
	// which is a legitimate thing to generate and the fail-closed direction.
	ResolvedPath string

	// Flags are the open flags. For ALLSEER_EVT_FILE_OPEN they decide the
	// capability: O_CREAT is fs.create, a writable access mode is fs.write, and
	// read-only is fs.read. The generator does not make that choice; the
	// decoder does, from these bits.
	Flags uint32

	Mode   uint32
	Inode  uint64
	Device uint64

	// Bytes is the record's `bytes` field, which the header names for every
	// file type and event.FilePayload calls BytesTransferred.
	Bytes int64
}

// Net is struct allseer_net_payload, plus the hostname DNS correlation
// recovers.
type Net struct {
	// Family, Protocol and SockType are the header's own fields. Use the
	// AF*, IPProto* and Sock* constants above.
	//
	// Zero is meaningful in all three: AF_UNSPEC with no address is what the
	// connect probe writes when the address could not be captured, and an
	// unstated protocol or socket type decodes to the empty string, which the
	// matcher treats as unevaluable rather than as a claim.
	Family   uint16
	Protocol uint16
	SockType uint16

	// SourceAddr and DestAddr are written into the record's 16-byte address
	// fields according to Family. An invalid Addr — the zero value — leaves the
	// field zero, which is how the connect probe reports an address it could
	// not read.
	//
	// One asymmetry is worth knowing before a scenario turns on it, and it is
	// the ABI's rather than this package's: an unset source address under
	// AF_INET decodes to "0.0.0.0" and not to an empty string, because sixteen
	// zero bytes are a real wildcard address. decode.go names the same gap, and
	// the connect probe leaves the field zero on every record it emits, so a
	// generated connect matches a real one in reporting a source it never saw.
	SourceAddr netip.Addr
	DestAddr   netip.Addr

	// Ports are in host byte order, because the header declares them __u16 and
	// not __be16: the probe is the side that converts.
	SourcePort uint16
	DestPort   uint16

	// Bytes is the volume the record carries. The decoder reads it for
	// ALLSEER_EVT_NET_SEND only — it is the one net type the header gives the
	// field a direction for — so setting it on a connect or a bind is refused
	// rather than dropped.
	Bytes int64

	// Hostname is what DNS correlation recovered for DestAddr, and is
	// enrichment rather than a record field. Leaving it empty is the
	// uncorrelated case: the observation carries hostname_correlated=false and
	// a grant naming a host cannot match, which is the behavior a stream about
	// hardcoded addresses needs.
	Hostname string
}

// Exec is struct allseer_exec_payload, plus what enrichment adds to it.
type Exec struct {
	// Filename is the executed binary, capped at ALLSEER_PATH_MAX.
	Filename string

	// Argv is at most ALLSEER_ARGV_MAX arguments of at most ALLSEER_ARG_LEN
	// bytes each. The sched_process_exec tracepoint does not expose argv and the
	// probe writes argc 0, so a stream carrying arguments is describing what the
	// record model can hold rather than what today's probe reports.
	Argv []string

	// Interpreter, BinaryHash and EnvKeys are enrichment. The record carries no
	// environment field at all: the header states values "routinely hold
	// credentials, and an audit log is the last place those should land", so
	// this is names only, by construction.
	Interpreter string
	BinaryHash  string
	EnvKeys     []string
}

// record renders a spec as one ring buffer record.
//
// proc is passed rather than read from the spec so the generator can substitute
// its configured default without mutating the caller's Spec.
func record(s Spec, proc *Proc, timestamp uint64) ([]byte, error) {
	if err := s.check(); err != nil {
		return nil, err
	}

	raw := make([]byte, abi.RecordSize)

	put64(raw, abi.OffsetEventTimestamp, timestamp)
	put32(raw, abi.OffsetEventType, uint32(s.Type))
	putI32(raw, abi.OffsetEventRet, s.Ret)

	// Always this build's version. A record claiming another one is a decoder
	// test, and the decoder already has it: ErrABIVersionMismatch is asserted
	// against bytes written in decode_fuzz_test.go, where the value under test
	// is the version itself.
	put32(raw, abi.OffsetEventVersion, abi.ABIVersion)

	if err := putProc(raw, proc); err != nil {
		return nil, err
	}

	switch {
	case s.File != nil:
		if err := putFile(raw, s.File); err != nil {
			return nil, err
		}
	case s.Net != nil:
		if err := putNet(raw, s.Net); err != nil {
			return nil, err
		}
	case s.Exec != nil:
		if err := putExec(raw, s.Exec); err != nil {
			return nil, err
		}
	}

	return raw, nil
}

// check reports whether the spec's payload agrees with its event type.
//
// The rule is the header's, restated as a refusal: one union member per record,
// chosen by the type, and only the fields the header gives meaning to for that
// type. Everything it rejects would otherwise reach the decoder, be ignored
// there for exactly the documented reason, and produce an event missing
// something the spec asked for.
func (s Spec) check() error {
	set := 0
	for _, present := range []bool{s.File != nil, s.Net != nil, s.Exec != nil} {
		if present {
			set++
		}
	}
	if set > 1 {
		return fmt.Errorf("%w: a record carries one payload, and %s designates one union member",
			ErrPayloadMismatch, s.Type)
	}

	switch s.Type {
	case abi.EvtFileOpen, abi.EvtFileWrite, abi.EvtFileUnlink, abi.EvtFileRename, abi.EvtFileChmod:
		if s.File == nil {
			return fmt.Errorf("%w: %s carries struct allseer_file_payload and the spec has none",
				ErrPayloadMismatch, s.Type)
		}
		if s.File.NewPath != "" && s.Type != abi.EvtFileRename {
			return fmt.Errorf("%w: the header defines new_path as the rename/link destination, so %s "+
				"would not carry it", ErrPayloadMismatch, s.Type)
		}

	case abi.EvtProcExec:
		if s.Exec == nil {
			return fmt.Errorf("%w: %s carries struct allseer_exec_payload and the spec has none",
				ErrPayloadMismatch, s.Type)
		}

	case abi.EvtNetConnect, abi.EvtNetBind, abi.EvtNetSend:
		if s.Net == nil {
			return fmt.Errorf("%w: %s carries struct allseer_net_payload and the spec has none",
				ErrPayloadMismatch, s.Type)
		}
		if s.Net.Bytes != 0 && s.Type != abi.EvtNetSend {
			return fmt.Errorf("%w: the header gives `bytes` a direction on %s alone, so %s would not "+
				"carry it", ErrPayloadMismatch, abi.EvtNetSend, s.Type)
		}

	default:
		// Every remaining type designates no union member this generator can
		// fill: ALLSEER_EVT_PROC_EXIT and ALLSEER_EVT_PTRACE by the header,
		// ALLSEER_EVT_UNKNOWN because the decoder refuses it, and an undeclared
		// value because this build knows nothing about it. A payload on any of
		// them is a payload nothing would read.
		//
		// ALLSEER_EVT_PRIV_CHANGE is in this branch for a different reason than
		// the rest, and it is a gap rather than a rule: the header does
		// designate struct allseer_priv_payload for it, and the decoder does
		// read it, but Spec has no member to describe one with. So a privilege
		// spec renders a cleared payload, whose operation is
		// ALLSEER_PRIV_OP_UNKNOWN, and telemetry.EventDecoder refuses it with
		// ErrUnsetPrivOp — which is the correct refusal for those bytes and is
		// not the same as the type being undecodable. Giving Spec a privilege
		// member belongs with the probe that emits the type.
		if set > 0 {
			return fmt.Errorf("%w: %s designates no union member the decoder reads",
				ErrPayloadMismatch, s.Type)
		}
	}
	return nil
}

func putProc(raw []byte, p *Proc) error {
	base := abi.OffsetEventProc

	put64(raw, base+abi.OffsetProcCgroupID, p.CgroupID)
	put64(raw, base+abi.OffsetProcStartTime, p.StartTime)
	put32(raw, base+abi.OffsetProcPID, uint32(p.PID))
	put32(raw, base+abi.OffsetProcTID, uint32(p.TID))
	put32(raw, base+abi.OffsetProcPPID, uint32(p.PPID))
	put32(raw, base+abi.OffsetProcUID, uint32(p.UID))
	put32(raw, base+abi.OffsetProcGID, uint32(p.GID))

	return putString(raw, base+abi.OffsetProcComm, abi.CommLen, p.Comm, "proc.comm")
}

func putFile(raw []byte, f *File) error {
	base := abi.OffsetEventPayload

	put64(raw, base+abi.OffsetFilePayloadInode, f.Inode)
	put64(raw, base+abi.OffsetFilePayloadDevice, f.Device)
	putI64(raw, base+abi.OffsetFilePayloadBytes, f.Bytes)
	put32(raw, base+abi.OffsetFilePayloadFlags, f.Flags)
	put32(raw, base+abi.OffsetFilePayloadMode, f.Mode)

	if err := putString(raw, base+abi.OffsetFilePayloadPath, abi.PathMax, f.Path, "file.path"); err != nil {
		return err
	}
	return putString(raw, base+abi.OffsetFilePayloadNewPath, abi.PathMax, f.NewPath, "file.new_path")
}

func putNet(raw []byte, n *Net) error {
	base := abi.OffsetEventPayload

	putI64(raw, base+abi.OffsetNetPayloadBytes, n.Bytes)
	put16(raw, base+abi.OffsetNetPayloadSport, n.SourcePort)
	put16(raw, base+abi.OffsetNetPayloadDport, n.DestPort)
	put16(raw, base+abi.OffsetNetPayloadFamily, n.Family)
	put16(raw, base+abi.OffsetNetPayloadProtocol, n.Protocol)
	put16(raw, base+abi.OffsetNetPayloadSockType, n.SockType)

	if err := putAddr(raw, base+abi.OffsetNetPayloadSaddr, n.Family, n.SourceAddr, "net.saddr"); err != nil {
		return err
	}
	return putAddr(raw, base+abi.OffsetNetPayloadDaddr, n.Family, n.DestAddr, "net.daddr")
}

func putExec(raw []byte, x *Exec) error {
	base := abi.OffsetEventPayload

	if len(x.Argv) > abi.ArgvMax {
		return fmt.Errorf("%w: %d arguments, and struct allseer_exec_payload holds %d",
			ErrTooManyArgs, len(x.Argv), abi.ArgvMax)
	}

	put32(raw, base+abi.OffsetExecPayloadArgc, uint32(len(x.Argv)))
	if err := putString(raw, base+abi.OffsetExecPayloadFilename, abi.PathMax, x.Filename, "exec.filename"); err != nil {
		return err
	}
	for i, arg := range x.Argv {
		off := base + abi.OffsetExecPayloadArgv + i*abi.ArgLen
		if err := putString(raw, off, abi.ArgLen, arg, fmt.Sprintf("exec.argv[%d]", i)); err != nil {
			return err
		}
	}
	return nil
}

// putAddr writes one of the two 16-byte address fields according to the family.
//
// The mirror of decode.go's addressString, and it has to be: a v4 address
// occupies the first 4 bytes and a v6 address all sixteen, so writing an
// address the family does not describe produces a record that decodes to a
// different address than the spec named — or, for AF_UNIX, to a wildcard the
// decoder would render as an empty string while the spec claimed an endpoint.
//
// An invalid Addr is not an error. It is the ordinary case of a probe that
// could not read the address, which the connect probe reports as AF_UNSPEC with
// the field left zero.
func putAddr(raw []byte, off int, family uint16, a netip.Addr, field string) error {
	if !a.IsValid() {
		return nil
	}
	switch family {
	case AFInet:
		if !a.Is4() {
			return fmt.Errorf("%w: %s is %s, and AF_INET occupies the first 4 bytes of the field",
				ErrAddressFamily, field, a)
		}
		v := a.As4()
		copy(raw[off:], v[:])
	case AFInet6:
		if !a.Is6() {
			return fmt.Errorf("%w: %s is %s, and AF_INET6 occupies all 16 bytes of the field",
				ErrAddressFamily, field, a)
		}
		v := a.As16()
		copy(raw[off:], v[:])
	default:
		return fmt.Errorf("%w: %s is %s, and address family %d carries no address of that shape",
			ErrAddressFamily, field, a, family)
	}
	return nil
}

// putString writes a NUL-terminated value into a fixed-size character array.
//
// The array is already zero, so the terminator is written by not filling the
// last byte. Both refusals are about the same thing: abi.CString reads up to
// the first NUL and reports whether it found one, so a value that fills its
// field or carries an interior NUL decodes to something other than itself.
func putString(raw []byte, off, size int, s, field string) error {
	if strings.IndexByte(s, 0) >= 0 {
		return fmt.Errorf("%w: %s", ErrEmbeddedNUL, field)
	}
	if len(s) >= size {
		return fmt.Errorf("%w: %s is %d bytes and the field holds %d including the terminator",
			ErrValueTooLong, field, len(s), size)
	}
	copy(raw[off:], s)
	return nil
}

// Byte-order helpers matching the generated decoder's. NativeEndian on both
// sides, because a record stands in for bytes written on this machine.
func put16(b []byte, off int, v uint16) { binary.NativeEndian.PutUint16(b[off:], v) }
func put32(b []byte, off int, v uint32) { binary.NativeEndian.PutUint32(b[off:], v) }
func put64(b []byte, off int, v uint64) { binary.NativeEndian.PutUint64(b[off:], v) }
func putI32(b []byte, off int, v int32) { binary.NativeEndian.PutUint32(b[off:], uint32(v)) }
func putI64(b []byte, off int, v int64) { binary.NativeEndian.PutUint64(b[off:], uint64(v)) }
