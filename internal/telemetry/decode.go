package telemetry

// The decoder: the interpretation boundary.
//
//	BPF event bytes → internal/telemetry/abi → telemetry.Decoder → pkg/event.Event
//
// The abi package stops at the ABI shape. It turns 856 bytes into the C structs
// the header declares and refuses to say what any of it *means*, because
// meaning is a judgment and a generated file must hold nothing a regeneration
// would overwrite. This file holds those judgments, and only those: which
// allseer_event_type exercised which capability.Kind, what a negative ret is
// called, how a 16-byte address field is read for a given address family.
//
// # What it does not do
//
// It makes no policy decision, computes no risk, reads no session state, and
// imports neither internal/pipeline nor internal/risk. It never invents a field
// the record does not carry: an unresolved path stays unresolved, an
// uncorrelated address stays an address, and a capability.Observation is not
// built here at all — that is internal/telemetry/resolve, and it runs after
// enrichment because it must match on the *resolved* path.
//
// Several fields of event.Event are deliberately left zero, because filling
// them would mean inventing:
//
//   - ID and Sequence. Both need per-session state and a counter; Decode is
//     stateless by signature and must be deterministic to be fuzzable. The
//     collector owns the session and assigns them (M6).
//   - SessionID. Attribution is by cgroup and PID ancestry and lives in
//     ProcessTracker; Process.CgroupID and Process.StartTime are decoded here
//     so the collector can do it.
//   - WallClock. It is KernelTimestamp plus a measured boot offset, and the
//     strategy for that offset is an open decision recorded in pkg/event.
//     Synthesizing a wall time from an unmeasured offset would fabricate a
//     timestamp that reads as observed.
//   - Dropped. Ring buffer loss is visible to the reader that saw the gap, not
//     to a function handed one record.
//   - Observation, Process.Executable, Process.AncestryDepth,
//     File.ResolvedPath, Network.Hostname, Exec.Interpreter, Exec.BinaryHash,
//     Exec.EnvKeys. All enrichment, all M6. The header states environment
//     values are never captured at all.
//
// # Rejection
//
// A record this build cannot interpret is refused, never approximated. The
// header's preamble states the failure mode being avoided: a mismatch "does not
// produce a clean error; it produces plausible garbage that flows straight into
// governance decisions". A decode error is loud — it lands in
// event.SourceStats.DecodeErrors and the collector decides whether the session
// can continue — while a plausible-looking event is silent.

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/stringNameMahin/ALLSEER/internal/telemetry/abi"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// Errors reported for a record that cannot be interpreted.
//
// Separate sentinels because they mean different things about the system, and a
// caller deciding whether collection can continue needs to tell them apart.
// Size errors arrive wrapped from the generated layer (abi.ErrShortRecord,
// abi.ErrLongRecord) and are not restated here.
var (
	// ErrUnsetEventType: the record's type is ALLSEER_EVT_UNKNOWN. That is a
	// declared enumerator, so it is not drift; it is a record whose type was
	// never set, which means a probe submitted a reservation it did not fill.
	// There is nothing to interpret and no safe default: choosing a type would
	// attribute an operation nobody observed.
	ErrUnsetEventType = errors.New("telemetry: record carries ALLSEER_EVT_UNKNOWN, so it states no operation")

	// ErrUnknownEventType: the type is outside the enum this build was
	// generated from. It means the loaded object is newer than this binary —
	// layout drift, the exact condition the generated ABI exists to surface.
	// The value is rendered rather than hidden, per abi.EventType.String.
	ErrUnknownEventType = errors.New("telemetry: event type is not in this build's ABI")

	// ErrUndecidedMapping: a declared event type whose capability mapping this
	// build will not guess at. See privilegeMappingIsUndecided.
	ErrUndecidedMapping = errors.New("telemetry: event type has no decided capability mapping in this build")

	// ErrTruncatedString: a fixed-size character array with no NUL in it.
	//
	// The header caps every string because "eBPF stack space is limited to 512
	// bytes and the verifier rejects unbounded copies", and it states the
	// consequence: "The user-space enricher must treat truncation as an
	// enrichment failure, never as a complete path."
	//
	// This is the last place that fact exists. abi.CString reports it, and
	// event.Event has no field in which to carry it onward, so the choice is to
	// refuse the record or to hand a later enricher a prefix that looks like a
	// whole path. A prefix that matches a granted glob while the real path does
	// not is the cheapest possible way past a selector, so the record is
	// refused.
	//
	// The cost is real and is not hidden: a legitimately long path or argument
	// becomes a counted decode error rather than an event. The honest fix is a
	// truncation flag on the wire — see the TODO(event) at the end of this file
	// — and that is a wire-format change which does not belong inside a decoder
	// issue.
	ErrTruncatedString = errors.New("telemetry: fixed-size string field is not NUL-terminated, so the value is truncated")
)

// EventDecoder implements Decoder over the generated ABI.
//
// It holds no state. Decoding one record must not depend on any record before
// it: a decoder with memory gives two answers for the same bytes, which makes
// both the fuzz property here and the replay-equals-live property in
// docs/roadmap.md unprovable.
type EventDecoder struct{}

var _ Decoder = (*EventDecoder)(nil)

// NewDecoder returns a decoder for the ABI this binary was generated against.
func NewDecoder() *EventDecoder { return &EventDecoder{} }

// EventSize returns sizeof(struct allseer_event) for this build.
//
// It is the derived constant rather than a number written down again here: the
// startup layout check compares it against the size the loaded object reports,
// and a hand-copied constant would make that check compare this file against
// itself.
func (*EventDecoder) EventSize() int { return abi.RecordSize }

// Decode parses one ring buffer record into an event.
//
// The record must be exactly EventSize() bytes. The generated layer refuses
// both directions, because a short record is a truncated read while a long one
// is layout drift that reading fewer bytes cannot repair.
func (*EventDecoder) Decode(raw []byte) (*event.Event, error) {
	rec, err := abi.DecodeRecord(raw)
	if err != nil {
		return nil, fmt.Errorf("telemetry: decoding record: %w", err)
	}

	// comm is checked before anything is allocated for the payload, so a
	// malformed record costs as little as possible.
	comm, terminated := abi.CString(rec.Proc.Comm[:])
	if !terminated {
		return nil, fmt.Errorf("%w: proc.comm", ErrTruncatedString)
	}

	e := &event.Event{
		KernelTimestamp: rec.Timestamp,
		Result:          resultOf(rec.Ret),
		Process: event.Process{
			// The C fields are unsigned and the Go fields are signed. The
			// conversion is two's complement and reversible, which matters for
			// one value in particular: (uid_t)-1 is the kernel's "leave this
			// unchanged" marker in the setres*id family and arrives as
			// 0xFFFFFFFF. Clamping it would erase the marker; widening the Go
			// field is a wire-format change.
			PID:       int32(rec.Proc.PID),
			TID:       int32(rec.Proc.TID),
			PPID:      int32(rec.Proc.PPID),
			UID:       int32(rec.Proc.UID),
			GID:       int32(rec.Proc.GID),
			Comm:      comm,
			CgroupID:  rec.Proc.CgroupID,
			StartTime: rec.Proc.StartTime,
		},
	}

	if err := decodePayload(&rec, e); err != nil {
		return nil, err
	}

	// Domain comes from the catalog, never from a second table here. It is the
	// rule resolve.Observe follows for the same reason: Domain is a
	// denormalized copy of a fact pkg/capability owns, and two tables that
	// disagree produce an event whose domain contradicts its kind.
	domain, known := capability.DomainOf(e.Capability)
	if !known {
		// Unreachable while TestEveryDecodableKindIsInTheCatalog passes: every
		// Kind this file can emit is checked against the catalog by test. Kept
		// because "unreachable" is a claim about today's table, and what it
		// guards against is an event carrying a kind nothing can validate.
		return nil, fmt.Errorf("telemetry: capability %q is not in this build's catalog", e.Capability)
	}
	e.Domain = domain

	return e, nil
}

// decodePayload sets Capability and the one payload the event type defines.
//
// One switch, not two: choosing the capability and reading the payload are the
// same decision, and splitting them would copy the 776-byte union twice per
// event on the hot path.
//
// Only the fields the header gives meaning to *for that type* are read. A field
// the header does not define for a type is left alone rather than guessed at —
// `bytes` on a connect, `new_path` on a chmod — and the union's tail beyond the
// active member is never touched, since a probe that writes one member is under
// no obligation to have zeroed the rest.
func decodePayload(rec *abi.Event, e *event.Event) error {
	switch typ := abi.EventType(rec.Type); typ {

	case abi.EvtFileOpen:
		p := rec.File()
		f, err := filePayload(&p, false)
		if err != nil {
			return err
		}
		e.Capability = kindForOpenFlags(p.Flags)
		e.File = f

	case abi.EvtFileWrite:
		p := rec.File()
		f, err := filePayload(&p, false)
		if err != nil {
			return err
		}
		e.Capability = capability.KindFileWrite
		e.File = f

	case abi.EvtFileUnlink:
		p := rec.File()
		f, err := filePayload(&p, false)
		if err != nil {
			return err
		}
		e.Capability = capability.KindFileDelete
		e.File = f

	case abi.EvtFileRename:
		p := rec.File()
		// The only type for which the header defines new_path: "rename/link
		// destination". Reading it elsewhere would report a destination for an
		// operation that has none.
		f, err := filePayload(&p, true)
		if err != nil {
			return err
		}
		e.Capability = capability.KindFileRename
		e.File = f

	case abi.EvtFileChmod:
		p := rec.File()
		f, err := filePayload(&p, false)
		if err != nil {
			return err
		}
		e.Capability = capability.KindFileChmod
		e.File = f

	case abi.EvtProcExec:
		p := rec.Exec()
		x, err := execPayload(&p)
		if err != nil {
			return err
		}
		e.Capability = capability.KindProcessExec
		e.Exec = x

	case abi.EvtProcExit:
		// No union member is designated for an exit, so none is read. The
		// process identity and the return are the whole record, and both are
		// already decoded.
		e.Capability = capability.KindProcessExit

	case abi.EvtNetConnect:
		p := rec.Net()
		e.Capability = capability.KindNetConnect
		e.Network = netPayload(&p, false)

	case abi.EvtNetBind:
		p := rec.Net()
		e.Capability = capability.KindNetBind
		e.Network = netPayload(&p, false)

	case abi.EvtNetSend:
		p := rec.Net()
		// The one net type for which `bytes` has a direction. Volume is the
		// exfiltration signal the catalog names on net.send, so it is carried;
		// on connect and bind the header defines no direction for the field,
		// and assigning one would invent the evidence.
		e.Capability = capability.KindNetSend
		e.Network = netPayload(&p, true)

	case abi.EvtPtrace:
		// process.ptrace, from the type name alone. No union member is
		// designated, and the record carries no field for the *target* process
		// — which is the resource a grant would want to constrain. That gap is
		// already recorded in internal/telemetry/resolve.
		e.Capability = capability.KindProcessPtrace

	case abi.EvtPrivChange:
		return privilegeMappingIsUndecided()

	case abi.EvtUnknown:
		return ErrUnsetEventType

	default:
		return fmt.Errorf("%w: %s", ErrUnknownEventType, typ)
	}
	return nil
}

// privilegeMappingIsUndecided refuses ALLSEER_EVT_PRIV_CHANGE, and says why.
//
// This is the one declared event type with no honest mapping, and the reason is
// in the header: struct allseer_priv_payload carries `__u32 operation` with no
// enumerators anywhere in the repository. internal/risk/privilege.go states the
// same thing from the other side — every field of the privilege payload is
// "either free text with no vocabulary defined anywhere in the repository
// (Operation, NamespaceType), one-sided (CapabilitiesAdded), or ambiguous on
// its most important value".
//
// So one C type stands in for five catalog kinds — priv.escalate, priv.setuid,
// priv.capset, priv.namespace, priv.seccomp — and nothing in the record
// distinguishes them. Choosing one would not be a small inaccuracy.
// configs/rules.default.yaml blocks priv.escalate, priv.setuid and priv.capset
// terminally and does not name priv.namespace or priv.seccomp at all, so the
// guess would decide the action. A decoder that decides the action by guessing
// is precisely what this boundary exists to prevent.
//
// Refusing costs nothing today: no probe emits this type. The four tracepoints
// M5 specifies are exec, exit, openat and connect, and none of them is a
// privilege hook. When one is written, the mapping becomes decidable in the
// only place it can be — the header, by declaring `enum allseer_priv_op`
// alongside the operations the probe can actually distinguish. That is a C edit
// for the Linux host and it belongs with the `version` field issue already open
// for the same reason.
func privilegeMappingIsUndecided() error {
	return fmt.Errorf("%w: %s carries struct allseer_priv_payload, whose `operation` field has "+
		"no enumerators in bpf/include/allseer_event.h; priv.escalate, priv.setuid, priv.capset, "+
		"priv.namespace and priv.seccomp are indistinguishable in the record, and the shipped rule "+
		"set treats them differently",
		ErrUndecidedMapping, abi.EvtPrivChange)
}

// kindForOpenFlags decides which filesystem capability an open exercised.
//
// An open is the one event type whose capability is not fixed by its name, and
// the repository settles it in two places rather than leaving it open: the
// catalog lists open/openat/openat2 under fs.read, fs.write *and* fs.create —
// "Kinds are coarser than syscalls" — and docs/dataflow.md traces
// `openat(..., O_WRONLY)` through the pipeline as `Kind: fs.write`. The flags
// are what separate them, which is why the M5 issue for the openat probe
// specifies that it emits "flags, mode, and the syscall return".
//
// Precedence is O_CREAT, then the access mode. The constants are the
// asm-generic values, which both targets the ABI supports use; O_CREAT differs
// on alpha and sparc, and neither is a target.
//
// The residual ambiguity is stated rather than papered over: O_CREAT on a file
// that already exists is reported as fs.create, because the record carries
// nothing that distinguishes creation from opening an existing file. Resolving
// it needs a convention agreed with the probe — O_EXCL, or the inode's
// existence before the call — and inventing one here would decide on the
// probe's behalf before the probe exists.
func kindForOpenFlags(flags uint32) capability.Kind {
	const (
		oAccMode = 0x3
		oRdOnly  = 0x0
		oWrOnly  = 0x1
		oRdWr    = 0x2
		oCreat   = 0x40 // 0100 octal
	)
	switch {
	case flags&oCreat != 0:
		return capability.KindFileCreate
	case flags&oAccMode == oWrOnly, flags&oAccMode == oRdWr:
		return capability.KindFileWrite
	case flags&oAccMode == oRdOnly:
		return capability.KindFileRead
	default:
		// The access mode is a two-bit field with a fourth encoding
		// (O_ACCMODE == 3) that has no O_ name and is used by O_PATH opens.
		// Read is the wrong answer for it and write is the safer one:
		// reporting a write that was a read raises scrutiny, while reporting a
		// read that was a write lowers it.
		return capability.KindFileWrite
	}
}

// filePayload reads struct allseer_file_payload.
//
// ResolvedPath is deliberately not set. Resolution is an enricher's job, and
// resolve.Observe refuses to fall back from ResolvedPath to Path precisely so
// that a pre-resolution path can never reach selector matching. An event
// leaving this function therefore has an unevaluable target until enrichment
// runs, which is the fail-closed direction.
func filePayload(p *abi.FilePayload, withNewPath bool) (*event.FilePayload, error) {
	path, terminated := abi.CString(p.Path[:])
	if !terminated {
		return nil, fmt.Errorf("%w: file.path", ErrTruncatedString)
	}

	out := &event.FilePayload{
		Path:  path,
		Flags: int32(p.Flags),
		Mode:  p.Mode,
		Inode: p.Inode,
		// Device is the raw dev_t. It is carried undecomposed: the major/minor
		// split is a kernel encoding detail, nothing downstream reads it, and
		// splitting it here would add a representation nobody asked for.
		Device: p.Device,
		// One signed count on each side and no direction to decide. The header
		// calls it `bytes` for every file type; event.FilePayload calls it
		// BytesTransferred, which is the same shape.
		BytesTransferred: p.Bytes,
	}

	if withNewPath {
		newPath, terminated := abi.CString(p.NewPath[:])
		if !terminated {
			return nil, fmt.Errorf("%w: file.new_path", ErrTruncatedString)
		}
		out.NewPath = newPath
	}
	return out, nil
}

// execPayload reads struct allseer_exec_payload.
//
// The environment is not read because it is not written: the header states that
// values "routinely hold credentials, and an audit log is the last place those
// should land", and the struct carries no environment field at all.
func execPayload(p *abi.ExecPayload) (*event.ExecPayload, error) {
	filename, terminated := abi.CString(p.Filename[:])
	if !terminated {
		return nil, fmt.Errorf("%w: exec.filename", ErrTruncatedString)
	}

	// argc is the count the probe reports; the array holds at most
	// ALLSEER_ARGV_MAX of them. An exec with more arguments than fit is
	// ordinary — a compiler invocation with a dozen flags — so the record is
	// decoded to what it carries rather than refused. That loss is currently
	// invisible downstream, which is a gap rather than a choice; see the
	// TODO(event) below. It is tolerable only because the repository already
	// states that Selector.ArgPatterns is "a convenience for readable
	// envelopes, not a security boundary".
	n := int(p.Argc)
	if n > abi.ArgvMax {
		n = abi.ArgvMax
	}

	out := &event.ExecPayload{Filename: filename}
	if n > 0 {
		out.Argv = make([]string, n)
		for i := range n {
			arg, terminated := abi.CString(p.Argv[i][:])
			if !terminated {
				return nil, fmt.Errorf("%w: exec.argv[%d]", ErrTruncatedString, i)
			}
			out.Argv[i] = arg
		}
	}
	return out, nil
}

// netPayload reads struct allseer_net_payload.
//
// Hostname is not set. Correlating an address back to the name it was resolved
// from is DNSCorrelator's job and is best-effort by construction; an
// uncorrelated destination must raise scrutiny rather than be assumed to match
// a granted host, and resolve.Observe already marks that case explicitly.
func netPayload(p *abi.NetPayload, withBytes bool) *event.NetworkPayload {
	out := &event.NetworkPayload{
		Protocol:      protocolName(p.Protocol),
		SourceAddr:    addressString(p.Saddr, p.Family),
		DestAddr:      addressString(p.Daddr, p.Family),
		AddressFamily: familyName(p.Family),
		SocketType:    socketTypeName(p.SockType),
		// The header declares these __u16, not __be16. A kernel structure that
		// holds a port in network order says so in its type, so the probe is
		// the side that converts and the record is read in the machine's own
		// byte order like every other field. Stated because the alternative
		// reading turns 443 into 47873 and nothing downstream would notice.
		SourcePort: int(p.Sport),
		DestPort:   int(p.Dport),
	}
	if withBytes {
		out.BytesSent = p.Bytes
	}
	return out
}

// Address family, transport protocol, and socket type values.
//
// The header names AF_INET, AF_INET6, AF_UNIX, IPPROTO_TCP and IPPROTO_UDP in
// its own comments, so this is the header's vocabulary rather than an invented
// one. The numeric values are Linux's, on the two targets the ABI supports.
const (
	afUnix  = 1
	afInet  = 2
	afInet6 = 10

	ipprotoTCP = 6
	ipprotoUDP = 17

	sockStream    = 1
	sockDgram     = 2
	sockRaw       = 3
	sockSeqpacket = 5
)

// familyName renders the address family.
//
// An unrecognized value is rendered rather than dropped, following
// abi.EventType.String: an unknown value means the object saw something this
// build does not know, and that is exactly what a reader needs to see.
func familyName(family uint16) string {
	switch family {
	case afInet:
		return "AF_INET"
	case afInet6:
		return "AF_INET6"
	case afUnix:
		return "AF_UNIX"
	case 0:
		// AF_UNSPEC, which is also what an unfilled field holds. Named rather
		// than rendered as unknown, so a zeroed record stays legible.
		return "AF_UNSPEC"
	}
	return fmt.Sprintf("AddressFamily(%d)", family)
}

// protocolName renders the transport protocol in the vocabulary the rest of the
// system already uses.
//
// Lowercase "tcp" and "udp", because that is what the committed envelopes and
// replay fixtures contain and what SelectorMatcher compares against
// Selector.Protocols. That comparison is case-insensitive, so this is
// consistency rather than a requirement.
//
// A protocol number with no name is rendered numerically. It will not match a
// grant naming "tcp", which is the correct outcome: it is not tcp.
func protocolName(proto uint16) string {
	switch proto {
	case ipprotoTCP:
		return "tcp"
	case ipprotoUDP:
		return "udp"
	case 0:
		// IPPROTO_IP, which is also what an unfilled field holds. Left empty
		// rather than named, because claiming a protocol for a record that
		// stated none is the invention this boundary exists to avoid — and
		// because the matcher already treats an empty protocol as unevaluable
		// against a grant that constrains protocols.
		return ""
	}
	return fmt.Sprintf("IPPROTO(%d)", proto)
}

// socketTypeName renders the socket type.
//
// The header declares `sock_type` without naming its enumerators, unlike the
// family and protocol fields directly above it. The SOCK_* names are Linux's
// and are the same on both supported targets, and the field is carried for
// forensics only: nothing in the validator reads NetworkPayload.SocketType.
// Reporting it under the kernel's own names is a smaller step than reporting a
// bare integer a reader would have to look up.
func socketTypeName(t uint16) string {
	switch t {
	case sockStream:
		return "SOCK_STREAM"
	case sockDgram:
		return "SOCK_DGRAM"
	case sockRaw:
		return "SOCK_RAW"
	case sockSeqpacket:
		return "SOCK_SEQPACKET"
	case 0:
		return ""
	}
	return fmt.Sprintf("SockType(%d)", t)
}

// addressString renders one of the two 16-byte address fields.
//
// The family decides how many of the bytes mean anything: the header states "v4
// addresses occupy the first 4 bytes", so reading all sixteen for an AF_INET
// record would append whatever the probe left in the rest of the field to the
// address.
//
// A v4-mapped v6 address is left mapped rather than normalized. The validator
// unmaps at comparison time, deliberately and with its reasoning recorded, and
// normalizing here as well would mean the audit record no longer shows what the
// socket reported.
//
// AF_UNIX yields the empty string: a socket path is not an address and does not
// fit in the field. Anything else also yields empty, because without knowing the
// family there is no way to know how many bytes to read. The family itself is
// still reported, so the record is not silently emptied.
func addressString(raw [16]uint8, family uint16) string {
	switch family {
	case afInet:
		return netip.AddrFrom4([4]byte{raw[0], raw[1], raw[2], raw[3]}).String()
	case afInet6:
		return netip.AddrFrom16(raw).String()
	}
	return ""
}

// resultOf translates the raw syscall return.
//
// The header states the convention: "syscall return; negative is -errno". A
// failed action is still a governance signal — pkg/event says so directly, and
// the credential-egress fixture turns on it, where a read of a key that failed
// with ENOENT must not be treated as a disclosure.
//
// Widened to int64 before negation so the one value int32 cannot negate,
// math.MinInt32, does not wrap back onto itself and yield a nonsensical errno.
func resultOf(ret int32) event.Result {
	r := event.Result{ReturnCode: int64(ret), Succeeded: ret >= 0}
	if ret < 0 {
		r.Errno = errnoName(-int64(ret))
	}
	return r
}

// CapabilitiesFor reports every capability.Kind a record of the given event type
// can decode to, in catalog order.
//
// It exists so the daemon can answer the coverage question the catalog is built
// for — ProbeInfo.Capabilities, and through it MemoryCatalog.SetObservable —
// from the event types a probe emits, rather than from a second table written
// beside this file. A grant with no probe behind it is a blind spot that reads
// as a control, and that check is only as good as the list feeding it.
//
// ALLSEER_EVT_FILE_OPEN is the one type with more than one answer: which of
// fs.read, fs.write and fs.create it exercised depends on the open flags. The
// types this build refuses — ALLSEER_EVT_UNKNOWN and ALLSEER_EVT_PRIV_CHANGE —
// return nil, so a probe emitting one cannot make its capability look covered.
func CapabilitiesFor(t abi.EventType) []capability.Kind {
	switch t {
	case abi.EvtFileOpen:
		return []capability.Kind{capability.KindFileRead, capability.KindFileWrite, capability.KindFileCreate}
	case abi.EvtFileWrite:
		return []capability.Kind{capability.KindFileWrite}
	case abi.EvtFileUnlink:
		return []capability.Kind{capability.KindFileDelete}
	case abi.EvtFileRename:
		return []capability.Kind{capability.KindFileRename}
	case abi.EvtFileChmod:
		return []capability.Kind{capability.KindFileChmod}
	case abi.EvtProcExec:
		return []capability.Kind{capability.KindProcessExec}
	case abi.EvtProcExit:
		return []capability.Kind{capability.KindProcessExit}
	case abi.EvtNetConnect:
		return []capability.Kind{capability.KindNetConnect}
	case abi.EvtNetBind:
		return []capability.Kind{capability.KindNetBind}
	case abi.EvtNetSend:
		return []capability.Kind{capability.KindNetSend}
	case abi.EvtPtrace:
		return []capability.Kind{capability.KindProcessPtrace}
	}
	return nil
}

// Done: Decoder.Decode and EventSize are implemented above, over the generated
// ABI, with each allseer_event_type mapped to a capability.Kind whose domain
// comes from the M1 catalog rather than from a second table.
//
// TODO(event): carry truncation on the wire. A path or argument that filled its
// fixed-size field is refused here (ErrTruncatedString) because event.Event has
// nowhere to record that it was cut short, and handing an enricher a prefix that
// looks whole is worse than losing the record. A `Truncated bool` on FilePayload
// and ExecPayload, plus the argument count, would let the decoder accept these
// and let the validator treat them as unevaluable — which is the behaviour the
// header actually asks for. It is a wire-format change and belongs to pkg/event.
// TODO(telemetry): the record carries no syscall identifier, so Event.Syscall is
// left empty. ALLSEER_EVT_FILE_OPEN could be open, openat, or openat2, and
// naming one of them would be a guess in a field kept for forensics. A __u32
// syscall number on struct allseer_event would settle it, alongside the version
// field already open in the header.
// TODO(telemetry): decide whether ALLSEER_EVT_NET_CONNECT with AF_UNIX should
// resolve to ipc.unixsocket rather than net.connect. The catalog lists `connect`
// under both, so the catalog does not settle it, and the difference is a
// high-severity network egress versus a medium-severity IPC channel on every
// unix socket a build touches. Deferred rather than guessed: it is a judgment
// about what a family value means for governance, and it should be made with the
// connect probe in front of it.
