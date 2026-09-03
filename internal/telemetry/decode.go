package telemetry

// The decoder: the interpretation boundary.
//
//	BPF event bytes -> internal/telemetry/abi -> telemetry.Decoder -> pkg/event.Event
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
// built here at all -- that is internal/telemetry/resolve, and it runs after
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
// governance decisions". A decode error is loud -- it lands in
// event.SourceStats.DecodeErrors and the collector decides whether the session
// can continue -- while a plausible-looking event is silent.
//
// The first thing refused is a record from a different ABI. Every offset below
// is correct only under ALLSEER_ABI_VERSION, so the version field is compared
// before any other field is believed, and a mismatch leaves this function as an
// error rather than as an event. That is what keeps drift a telemetry fault the
// collector counts, instead of an ordinary event that reaches the validator
// carrying somebody else's bytes in this build's field names.

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

	// ErrABIVersionMismatch: the record's ALLSEER_ABI_VERSION is not the one
	// this build decodes.
	//
	// The check the size check cannot make, and the second of the two
	// enforcement points internal/telemetry/abi names. That package surfaces
	// the constant and the field and compares neither, because "deciding what a
	// mismatch *means* is a judgment, and the judgments differ by layer" -- the
	// loader's is per-object and free, this one is per-record and is the only
	// one that can see a record at all.
	//
	// What it catches is what the loader's BTF size comparison provably cannot:
	// "a layout that kept its size and changed meaning". Two same-width fields
	// exchanged, a flags word that gained an enumerator, a timestamp that
	// changed from nanoseconds to microseconds -- every one of those passes
	// sizeof(struct allseer_event) unchanged and then produces a fully
	// plausible event, which is the failure mode the header's preamble names:
	// "it produces plausible garbage that flows straight into governance
	// decisions". The two checks are complements and neither replaces the
	// other; a version match says nothing about size, and this build could
	// still be handed a record of the right size by an object it never saw.
	//
	// Refused, never coerced. There is no reading of a record from a different
	// ABI that is safe to guess at: the version is the statement that the
	// offsets mean what this build thinks they mean, and without it every field
	// below -- comm included -- is an unchecked reinterpretation of somebody
	// else's bytes.
	ErrABIVersionMismatch = errors.New("telemetry: record's ABI version is not the one this build decodes")

	// ErrUnknownEventType: the type is outside the enum this build was
	// generated from. It means the loaded object is newer than this binary --
	// layout drift, the exact condition the generated ABI exists to surface.
	// The value is rendered rather than hidden, per abi.EventType.String.
	ErrUnknownEventType = errors.New("telemetry: event type is not in this build's ABI")

	// ErrUnsetPrivOp: a privilege record whose `operation` is
	// ALLSEER_PRIV_OP_UNKNOWN.
	//
	// The counterpart to ErrUnsetEventType, one level down, and it exists for
	// the reason the header gives at the enum: every probe clears the payload
	// union before filling it, so a probe that failed to write `operation`
	// leaves a zero there. Zero names no operation, and the alternative to
	// refusing it is deciding which of five privilege capabilities a
	// zero-initialised record exercised.
	ErrUnsetPrivOp = errors.New("telemetry: privilege record states no operation")

	// ErrUnknownPrivOp: the operation is outside the enum this build was
	// generated from.
	//
	// The counterpart to ErrUnknownEventType, and it means the same thing: the
	// loaded object is newer than this binary. Refused rather than mapped to
	// some default, because the operation is what selects the capability, and
	// configs/rules.default.yaml blocks three of the five privilege kinds
	// terminally while not naming the other two at all. A guess here decides
	// the action.
	ErrUnknownPrivOp = errors.New("telemetry: privilege operation is not in this build's ABI")

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
	// truncation flag on the wire -- see the TODO(event) at the end of this file
	// -- and that is a wire-format change which does not belong inside a decoder
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

	// The version before anything else is read out of the record, because
	// everything else read out of it means what it means only under this
	// build's ABI. Checking comm or the event type first would be interpreting
	// bytes whose interpretation is exactly what is in doubt.
	if rec.Version != abi.ABIVersion {
		return nil, fmt.Errorf("%w: record says %d, this build decodes %d",
			ErrABIVersionMismatch, rec.Version, abi.ABIVersion)
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
// the header does not define for a type is left alone rather than guessed at --
// `bytes` on a connect, `new_path` on a chmod -- and the union's tail beyond the
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
		e.Capability = kindForConnectFamily(p.Family)
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
		// -- which is the resource a grant would want to constrain. That gap is
		// already recorded in internal/telemetry/resolve.
		e.Capability = capability.KindProcessPtrace

	case abi.EvtPrivChange:
		p := rec.Priv()
		k, err := kindForPrivOp(abi.PrivOp(p.Operation))
		if err != nil {
			return err
		}
		e.Capability = k
		e.Privil = privPayload(&p)

	case abi.EvtUnknown:
		return ErrUnsetEventType

	default:
		return fmt.Errorf("%w: %s", ErrUnknownEventType, typ)
	}
	return nil
}

// kindForPrivOp decides which privilege capability an operation exercised.
//
// The mapping the header's `enum allseer_priv_op` was added to make possible.
// Before it, struct allseer_priv_payload carried a `__u32 operation` with no
// enumerators anywhere in the repository, one C type stood in for five catalog
// kinds, and this function's predecessor refused the whole event type rather
// than choose between them. The enum is what makes the choice a lookup instead
// of a guess.
//
// Every arm is the catalog's own grouping rather than a second opinion about
// it. pkg/capability/table.go places setuid, setgid and their re- and res-
// variants under priv.setuid, whose summary is "Change the process's user or
// group identity"; setgroups joins them there because supplementary groups are
// group identity, which is the catalog correction that landed with this ABI.
// capset is priv.capset, unshare and setns are priv.namespace, seccomp is
// priv.seccomp.
//
// priv.escalate is never returned, and its absence is the design rather than an
// omission. The catalog describes it as "Gain privileges, by any mechanism",
// which is a claim about the difference between two states and not about which
// syscall was called -- no operation value implies it, and the header says so at
// the enum. Deriving it belongs downstream, where both snapshots are in hand
// and where the user-namespace scope of a capability set can be taken into
// account: unshare(CLONE_NEWUSER) hands the caller a full capability set inside
// the namespace it just created, and a consumer that read that as escalation
// would block every containerized build step on the host, because
// configs/rules.default.yaml blocks priv.escalate terminally.
//
// Two values are refused rather than mapped. ALLSEER_PRIV_OP_UNKNOWN is the
// zero a cleared payload holds, and an operation outside the enum means the
// loaded object is newer than this binary. Both are layout or probe faults, and
// neither has a safe default: the operation selects the capability, and the
// capability selects the action.
func kindForPrivOp(op abi.PrivOp) (capability.Kind, error) {
	switch op {
	case abi.OpSetuid, abi.OpSetreuid, abi.OpSetresuid,
		abi.OpSetgid, abi.OpSetregid, abi.OpSetresgid,
		abi.OpSetgroups:
		return capability.KindPrivSetuid, nil
	case abi.OpCapset:
		return capability.KindPrivCapSet, nil
	case abi.OpUnshare, abi.OpSetns:
		return capability.KindPrivNamespace, nil
	case abi.OpSeccomp:
		return capability.KindPrivSeccomp, nil
	case abi.OpUnknown:
		return "", ErrUnsetPrivOp
	}
	return "", fmt.Errorf("%w: %s", ErrUnknownPrivOp, op)
}

// privOpNames is the operation vocabulary as event.PrivPayload.Operation spells
// it.
//
// Short lower-case names rather than abi.PrivOp.String(), which renders the C
// enumerator -- "ALLSEER_PRIV_OP_SETUID" -- because Operation is a field a human
// reads in an audit record and a rule author may one day match on. The names
// here are the ones internal/risk/privilege.go's tests already use for the
// field: "setuid", "capset", "unshare", "seccomp". That vocabulary predates the
// enum and this table adopts it rather than introducing a second one.
//
// Keyed by abi.PrivOp so a value added to the header without a name here yields
// the empty string, which privEvidenceState already reads as a malformed
// payload rather than as an absent one. It cannot silently become some other
// operation's name.
var privOpNames = map[abi.PrivOp]string{
	abi.OpSetuid:    "setuid",
	abi.OpSetreuid:  "setreuid",
	abi.OpSetresuid: "setresuid",
	abi.OpSetgid:    "setgid",
	abi.OpSetregid:  "setregid",
	abi.OpSetresgid: "setresgid",
	abi.OpSetgroups: "setgroups",
	abi.OpCapset:    "capset",
	abi.OpUnshare:   "unshare",
	abi.OpSetns:     "setns",
	abi.OpSeccomp:   "seccomp",
}

// CLONE_* values, as the kernel's uapi defines them.
//
// Only the namespace bits, because ns_flags is documented in the header as
// carrying unshare's flags or setns's nstype and both name namespaces. The
// other CLONE_ bits can appear in an unshare argument -- CLONE_FILES and
// CLONE_FS are legal there -- and they are deliberately not named, because they
// are not namespaces and namespaceName would be claiming otherwise.
const (
	cloneNewTime   = 0x00000080
	cloneNewNS     = 0x00020000
	cloneNewCgroup = 0x02000000
	cloneNewUTS    = 0x04000000
	cloneNewIPC    = 0x08000000
	cloneNewUser   = 0x10000000
	cloneNewPID    = 0x20000000
	cloneNewNet    = 0x40000000
)

// namespaceName renders ns_flags as event.PrivPayload.NamespaceType.
//
// The user namespace is reported ahead of every other bit when several are set,
// and that ordering is a judgment worth stating rather than an artifact of the
// switch. unshare accepts a mask, so `unshare(CLONE_NEWUSER|CLONE_NEWNS)` is one
// call carrying two namespaces, and NamespaceType is a single string. The user
// namespace is the one that is a credential -- it lives in struct cred, where
// the rest live in task->nsproxy -- and it is the one that changes what the
// process may do rather than what it can see. Naming the mount namespace on
// that call and dropping the user namespace would report the less consequential
// half.
//
// A mask with no namespace bit set, which is what an unshare of CLONE_FILES
// alone produces, renders as the empty string. So does a zero, which is what
// setns(fd, 0) supplies when the caller names no type -- and there the
// before/after userns_inum pair in the payload is what says whether a user
// namespace was entered. The empty string is the honest rendering of both:
// nothing in the argument named a namespace.
func namespaceName(flags uint32) string {
	switch {
	case flags&cloneNewUser != 0:
		return "user"
	case flags&cloneNewPID != 0:
		return "pid"
	case flags&cloneNewNet != 0:
		return "net"
	case flags&cloneNewNS != 0:
		return "mount"
	case flags&cloneNewIPC != 0:
		return "ipc"
	case flags&cloneNewUTS != 0:
		return "uts"
	case flags&cloneNewCgroup != 0:
		return "cgroup"
	case flags&cloneNewTime != 0:
		return "time"
	}
	return ""
}

// capabilityNames maps a bit position in a capability mask to its CAP_ name.
//
// Index is the bit number, which is what the kernel's CAP_TO_INDEX/CAP_TO_MASK
// pair computes and what the header's note on kernel_cap_t explains is
// identical between the pre-6.3 __u32[2] representation and the u64 that
// replaced it on a little-endian target.
//
// The list stops at CAP_CHECKPOINT_RESTORE, which is CAP_LAST_CAP on every
// kernel this build targets. A bit above the end of the list is rendered
// numerically by capabilityDelta rather than dropped, because a capability this
// binary has no name for is still a capability that was gained, and losing it
// from the audit record would be the one direction that matters.
var capabilityNames = [...]string{
	"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER",
	"CAP_FSETID", "CAP_KILL", "CAP_SETGID", "CAP_SETUID",
	"CAP_SETPCAP", "CAP_LINUX_IMMUTABLE", "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST",
	"CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_IPC_LOCK", "CAP_IPC_OWNER",
	"CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT", "CAP_SYS_PTRACE",
	"CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE",
	"CAP_SYS_RESOURCE", "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD",
	"CAP_LEASE", "CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL", "CAP_SETFCAP",
	"CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN", "CAP_SYSLOG", "CAP_WAKE_ALARM",
	"CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ", "CAP_PERFMON", "CAP_BPF",
	"CAP_CHECKPOINT_RESTORE",
}

// capabilityDelta names every capability set in after and not in before.
//
// The one thing the two-snapshot payload was designed to make computable.
// internal/risk/privilege.go states the defect it closes: "A delta needs a
// before and an after. The repository has neither", and it labels every
// capability report it emits CapabilityDeltaAddedOnly because the previous
// payload snapshotted one absolute set from which "added" was unrecoverable.
// Both operands are now in the record.
//
// Additions only, which is what event.PrivPayload.CapabilitiesAdded is declared
// to hold. A dropped capability is visible to anything reading the raw payload
// and is not representable in this field, which is exactly the one-sidedness
// that risk labels; this function does not pretend otherwise by folding
// removals in.
func capabilityDelta(before, after uint64) []string {
	gained := after &^ before
	if gained == 0 {
		return nil
	}
	var names []string
	for bit := 0; bit < 64; bit++ {
		if gained&(1<<uint(bit)) == 0 {
			continue
		}
		if bit < len(capabilityNames) {
			names = append(names, capabilityNames[bit])
			continue
		}
		names = append(names, fmt.Sprintf("CAP_%d", bit))
	}
	return names
}

// privPayload builds the user-space view of a privilege record.
//
// Every field it fills is gated on the fields_present bit that covers it, and
// that gating is the whole reason the bitmap is on the wire. The header explains
// it at enum allseer_priv_field: uid 0 is root and is also what an unwritten
// field holds, so without an explicit statement of what was observed the single
// most consequential transition this record can carry is indistinguishable from
// a record that carried no identity at all. A decoder that read the fields
// anyway would launder an unfilled struct into a claim about privilege.
//
// # Which uid the pair reports
//
// OldUID and NewUID are the *effective* uids. The payload carries four views of
// each identity and event.PrivPayload has room for one pair, so this is a
// choice: euid is the one that governs what a process may do, which is what a
// privilege record is about. The other three views are not lost -- they are in
// the record the probe wrote, and reach anything reading the ABI struct -- they
// are simply not what this two-field summary reports.
//
// Both are int32 in pkg/event and uint32 here, so a uid above 2^31 wraps
// negative. That range holds no real account: the kernel's overflow uid is
// 65534 and systemd-style dynamic users sit far below the boundary. The
// conversion is stated rather than hidden because the field is signed for
// reasons that predate this decoder.
//
// # What is not filled
//
// The capability delta is computed only when both snapshots were observed and
// only when the user namespace did not change across the call. A capability set
// is scoped to the namespace it was granted in, so sets from two namespaces are
// not the same quantity: unshare(CLONE_NEWUSER) hands the caller a full set in
// the namespace it just created, and subtracting one from the other would
// report every such call as a gain of nearly every capability in Linux. The
// header carries the same warning at userns_inum, and the guard is the reason
// that field is in the payload at all.
//
// When either userns bit is clear the namespaces cannot be compared, and the
// delta is withheld on the same grounds: unknown is not the same as unchanged.
func privPayload(p *abi.PrivPayload) *event.PrivPayload {
	present := func(f abi.PrivField) bool { return p.FieldsPresent&uint32(f) != 0 }

	out := &event.PrivPayload{Operation: privOpNames[abi.PrivOp(p.Operation)]}

	if present(abi.FieldNsFlags) {
		out.NamespaceType = namespaceName(p.NsFlags)
	}
	if present(abi.FieldBeforeCred) {
		out.OldUID = int32(p.Before.UIDEffective)
	}
	if present(abi.FieldAfterCred) {
		out.NewUID = int32(p.After.UIDEffective)
	}

	comparableCreds := present(abi.FieldBeforeCred) && present(abi.FieldAfterCred)
	comparableNS := present(abi.FieldBeforeUserns) && present(abi.FieldAfterUserns) &&
		p.Before.UsernsInum == p.After.UsernsInum
	if comparableCreds && comparableNS {
		out.CapabilitiesAdded = capabilityDelta(p.Before.CapEffective, p.After.CapEffective)
	}
	return out
}

// kindForConnectFamily decides which capability a connect exercised.
//
// AF_UNIX is ipc.unixsocket; everything else is net.connect. This is the
// decision the open TODO in internal/telemetry asked for, and the family is
// what settles it -- the one field the probe reliably fills for a unix socket.
//
// # Why the family is enough, and why net.connect was wrong
//
// pkg/capability defines net.connect as "Open an outbound connection to a
// remote endpoint", and the network block's rationale is that "an outbound
// connection is how data leaves, and that cannot be undone after the fact". An
// AF_UNIX socket has no remote endpoint and nothing leaves the host through
// one. Classifying it as net.connect is therefore not a conservative choice; it
// is a false statement about an observed fact, made in the field the validator
// matches on.
//
// ipc.unixsocket is defined as "Connect to or create a Unix domain socket" and
// already lists `connect` among its syscalls, so this is the catalog's own
// answer rather than a new one. The catalog listing `connect` under both kinds
// is what left the question open; the family is what closes it.
//
// The family is not inferred. bpf/allseer.bpf.c reads it out of the sockaddr the
// process passed and writes it into the record for every family, including the
// ones whose address it cannot represent -- its default arm sets family and
// nothing else, which is exactly the AF_UNIX case. So this reads a captured
// value rather than deducing one from an absence.
//
// # What this does not establish
//
// Which unix socket. sun_path is 108 bytes, struct allseer_net_payload's daddr
// is 16, and ABI v2 has no field for a path -- decode.go already states the
// reading side of that as "a socket path is not an address and does not fit in
// the field". So resolve.Observe produces an empty Target and no envelope can
// say "may connect to /run/docker.sock" while saying no to the rest.
//
// That limit is not introduced here. Under net.connect the target was equally
// empty, because addressString renders nothing for AF_UNIX and the port is
// zero, so nothing that was matchable has stopped being matchable. What changes
// is the kind, the domain and the severity -- and those change because they were
// wrong, not because more is now known.
//
// # The consequence worth stating rather than discovering
//
// configs/rules.default.yaml matches unexpected-network-egress on the
// capability, so today every ungranted unix-socket connect is requested for
// approval regardless of score. No shipped rule names any IPC capability, so
// after this change such an event falls through to the score-based rules and is
// warned rather than prompted. That is a real reduction in what the shipped
// policy does about it, and it belongs in a policy decision rather than in this
// one: the rule set's own closing TODO says "Any rule that fires on routine
// work needs tightening or removal before enforce mode is credible", and a
// prompt on every connect to the journal, the resolver and the session bus is
// that rule. Whether IPC deserves a rule of its own is a question for the rule
// set, which is where it can be answered with the reasoning visible.
func kindForConnectFamily(family uint16) capability.Kind {
	if family == afUnix {
		return capability.KindIPCUnixSock
	}
	return capability.KindNetConnect
}

// kindForOpenFlags decides which filesystem capability an open exercised.
//
// An open is the one event type whose capability is not fixed by its name, and
// the repository settles it in two places rather than leaving it open: the
// catalog lists open/openat/openat2 under fs.read, fs.write *and* fs.create --
// "Kinds are coarser than syscalls" -- and docs/dataflow.md traces
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
// it needs a convention agreed with the probe -- O_EXCL, or the inode's
// existence before the call -- and inventing one here would decide on the
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
	// ordinary -- a compiler invocation with a dozen flags -- so the record is
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
		// stated none is the invention this boundary exists to avoid -- and
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
// failed action is still a governance signal -- pkg/event says so directly, and
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
// for -- ProbeInfo.Capabilities, and through it MemoryCatalog.SetObservable --
// from the event types a probe emits, rather than from a second table written
// beside this file. A grant with no probe behind it is a blind spot that reads
// as a control, and that check is only as good as the list feeding it.
//
// Three types have more than one answer, and for the same reason in all three:
// the payload decides. Which of fs.read, fs.write and fs.create an
// ALLSEER_EVT_FILE_OPEN exercised depends on the open flags; which of four
// privilege kinds an ALLSEER_EVT_PRIV_CHANGE exercised depends on its
// `operation`; and whether an ALLSEER_EVT_NET_CONNECT is net.connect or
// ipc.unixsocket depends on its address family -- see kindForOpenFlags,
// kindForPrivOp and kindForConnectFamily.
//
// ALLSEER_EVT_NET_CONNECT is the one whose two answers land in different
// *domains*, which is worth naming because it is the thing a reader would
// otherwise assume cannot happen: a connect over AF_UNIX is an IPC event
// carrying a network payload. api/schema/event.v1alpha1.schema.json permits
// that -- it requires a network payload when the domain is network, and says
// nothing that forbids one elsewhere.
//
// priv.escalate is absent from the privilege list even though the catalog
// grades it, because kindForPrivOp never returns it: no operation implies
// escalation, which is a comparison of the record's two snapshots rather than a
// property of the syscall. Listing it here would report a capability as
// observable that no record can decode to, which is the opposite of what this
// function exists for.
//
// ALLSEER_EVT_UNKNOWN returns nil, so a probe emitting it cannot make any
// capability look covered.
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
		return []capability.Kind{capability.KindNetConnect, capability.KindIPCUnixSock}
	case abi.EvtNetBind:
		return []capability.Kind{capability.KindNetBind}
	case abi.EvtNetSend:
		return []capability.Kind{capability.KindNetSend}
	case abi.EvtPrivChange:
		return []capability.Kind{
			capability.KindPrivSetuid,
			capability.KindPrivCapSet,
			capability.KindPrivNamespace,
			capability.KindPrivSeccomp,
		}
	case abi.EvtPtrace:
		return []capability.Kind{capability.KindProcessPtrace}
	}
	return nil
}

// TODO(event): carry truncation on the wire. A path or argument that filled its
// fixed-size field is refused here (ErrTruncatedString) because event.Event has
// nowhere to record that it was cut short, and handing an enricher a prefix that
// looks whole is worse than losing the record. A `Truncated bool` on FilePayload
// and ExecPayload, plus the argument count, would let the decoder accept these
// and let the validator treat them as unevaluable -- which is the behaviour the
// header actually asks for. It is a wire-format change and belongs to pkg/event.
// TODO(telemetry): the record carries no syscall identifier, so Event.Syscall is
// left empty. ALLSEER_EVT_FILE_OPEN could be open, openat, or openat2, and
// naming one of them would be a guess in a field kept for forensics. A __u32
// syscall number on struct allseer_event would settle it, alongside the version
// field already open in the header.
