package telemetry

import (
	"fmt"
	"strings"

	"github.com/stringNameMahin/ALLSEER/internal/telemetry/abi"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
)

// Program names, as bpf/allseer.bpf.c declares them, for Attach. libbpf
// resolves the attach point from each program's SEC(), so the tracepoint is
// named in one place — the C file — and not restated here.
//
// Attaching is per program and the caller chooses which: the loader has no list
// of "all probes" and deliberately does not honour Config.EnabledProbes, for
// the reason recorded at the foot of this file.
const (
	// ProgProcExec is the sched_process_exec program, emitting
	// ALLSEER_EVT_PROC_EXEC.
	ProgProcExec = "proc_exec"

	// ProgProcExit is the sched_process_exit program, emitting
	// ALLSEER_EVT_PROC_EXIT. The pair to ProgProcExec: attaching one without
	// the other gives a governed process a beginning with no end, which is what
	// telemetry.ProcessTracker.Untrack has no signal for until both are on.
	ProgProcExit = "proc_exit"

	// ProgOpenatEnter is the fentry program on do_sys_openat2. It emits
	// nothing.
	//
	// It performs the cgroup filter decision for every open the pair reports
	// and captures the path, the flags, the mode and the base directory, then
	// stores them in openat_scratch for ProgOpenatExit to complete. do_sys_openat2
	// is the function open, creat, openat and openat2 all reach, which is why
	// the pair is attached there and not to a syscall tracepoint: on one kernel
	// update sys_enter_openat stopped firing for governed processes while every
	// probe still reported attached, and a tracepoint on openat never saw the
	// other three entry points anyway. The name still says openat because the
	// scratch protocol was written for it.
	ProgOpenatEnter = "openat_enter"

	// ProgOpenatExit is the fexit program on do_sys_openat2, emitting
	// ALLSEER_EVT_FILE_OPEN with the return value, so a refused or failed open
	// is reported with its errno.
	//
	// Useless apart from ProgOpenatEnter: the entry side never emits, and the
	// exit side emits only what it finds a scratch entry for. A caller that
	// attaches one and not the other has a blind spot that looks exactly like a
	// quiet host - which is the failure the daemon's startup self-test exists
	// to catch, because it is also what a kernel that stops calling one of the
	// two hooks looks like.
	ProgOpenatExit = "openat_exit"

	// ProgConnectEnter is the sys_enter_connect program. It emits nothing.
	//
	// The entry half of the second syscall pair, and the same shape as
	// ProgOpenatEnter: it performs the cgroup filter decision for every connect
	// this object reports, captures the destination out of user memory, and
	// stores it in connect_scratch for ProgConnectExit to complete.
	ProgConnectEnter = "connect_enter"

	// ProgConnectExit is the sys_exit_connect program, emitting
	// ALLSEER_EVT_NET_CONNECT.
	//
	// Useless apart from ProgConnectEnter in the same way ProgOpenatExit is
	// from its own entry side: attaching either alone yields no events rather
	// than half of them, which looks exactly like a host that made no outbound
	// connections. For a capability the catalog rates SeverityHigh — "it is how
	// data leaves, and it cannot be undone after the fact" — that is the blind
	// spot most worth not having by accident.
	ProgConnectExit = "connect_exit"

	// ProgFileOpen is the fentry/security_file_open program, emitting
	// ALLSEER_EVT_FILE_OPEN.
	//
	// Not a pair and not a syscall probe: one hook the kernel reaches from
	// every entry point that opens a file, which is the only place io_uring
	// opens can be seen at all. It needs no scratch map because the kernel
	// hands it the opened file, and it reports no outcome because it runs
	// before there is one. bpf/allseer.bpf.c states the whole argument.
	//
	// Attached alone it observes every open without a return value; attached
	// with the openat family it leaves openat to that pair and covers what the
	// pair cannot see. Either way it is additive, so there is no half of it to
	// be missing.
	ProgFileOpen = "file_open"

	// ProgSocketConnect is the fentry/security_socket_connect program, emitting
	// ALLSEER_EVT_NET_CONNECT.
	//
	// The connect counterpart of ProgFileOpen: one hook that connect(2) and an
	// io_uring connect both reach. With the connect pair attached it gives a
	// connect(2) in flight the kernel's copy of the address and the socket's
	// protocol and type, and emits only for connects the pair cannot see.
	// Attached alone it reports every connect without a return value.
	ProgSocketConnect = "socket_connect"

	// ProgPathLink is the fentry/security_path_link program, emitting
	// ALLSEER_EVT_FILE_LINK: a hard link, named by the file it points at and
	// the name it creates.
	ProgPathLink = "path_link"
)

// The privilege programs, one enter/exit pair per credential syscall, all
// emitting ALLSEER_EVT_PRIV_CHANGE.
//
// Eleven pairs rather than one program, because the syscall is what names the
// operation: struct allseer_event carries no syscall identifier, so the
// `operation` field in the payload is the only thing that separates a setuid
// record from a capset one, and a program attached to a single tracepoint knows
// its own answer as a compile-time constant.
//
// Every pair behaves like the openat and connect pairs and fails the same way
// when half-attached: the entry side never emits and the exit side emits only
// what it finds a scratch entry for, so one without the other is a blind spot
// that looks exactly like a process that never changed its credentials. All
// five privilege capabilities in the M1 catalog are graded critical or high, so
// that is a blind spot worth not having by accident — which is why
// ProgPrivPairs exists rather than leaving each caller to assemble the list.
const (
	ProgPrivSetuidEnter = "priv_enter_setuid"
	ProgPrivSetuidExit  = "priv_exit_setuid"

	ProgPrivSetreuidEnter = "priv_enter_setreuid"
	ProgPrivSetreuidExit  = "priv_exit_setreuid"

	ProgPrivSetresuidEnter = "priv_enter_setresuid"
	ProgPrivSetresuidExit  = "priv_exit_setresuid"

	ProgPrivSetgidEnter = "priv_enter_setgid"
	ProgPrivSetgidExit  = "priv_exit_setgid"

	ProgPrivSetregidEnter = "priv_enter_setregid"
	ProgPrivSetregidExit  = "priv_exit_setregid"

	ProgPrivSetresgidEnter = "priv_enter_setresgid"
	ProgPrivSetresgidExit  = "priv_exit_setresgid"

	ProgPrivSetgroupsEnter = "priv_enter_setgroups"
	ProgPrivSetgroupsExit  = "priv_exit_setgroups"

	ProgPrivCapsetEnter = "priv_enter_capset"
	ProgPrivCapsetExit  = "priv_exit_capset"

	ProgPrivUnshareEnter = "priv_enter_unshare"
	ProgPrivUnshareExit  = "priv_exit_unshare"

	ProgPrivSetnsEnter = "priv_enter_setns"
	ProgPrivSetnsExit  = "priv_exit_setns"

	ProgPrivSeccompEnter = "priv_enter_seccomp"
	ProgPrivSeccompExit  = "priv_exit_seccomp"
)

// ProgPrivPairs is every privilege program, entry before its own exit.
//
// A list rather than a set of loose constants, because the failure it prevents
// is arithmetic: twenty-two names attached by hand is twenty-two chances to
// omit one, and an omitted exit program is silent — it produces no error, no
// event, and no way to tell the difference between "this syscall was never
// called" and "this half was never attached".
//
// It is not a general "all probes" list and does not make one: the loader still
// has no such concept, still attaches per program, and still does not honour
// Config.EnabledProbes. A caller that wants exec, exit, openat and connect
// without privilege telemetry simply does not range over this.
func ProgPrivPairs() []string {
	return []string{
		ProgPrivSetuidEnter, ProgPrivSetuidExit,
		ProgPrivSetreuidEnter, ProgPrivSetreuidExit,
		ProgPrivSetresuidEnter, ProgPrivSetresuidExit,
		ProgPrivSetgidEnter, ProgPrivSetgidExit,
		ProgPrivSetregidEnter, ProgPrivSetregidExit,
		ProgPrivSetresgidEnter, ProgPrivSetresgidExit,
		ProgPrivSetgroupsEnter, ProgPrivSetgroupsExit,
		ProgPrivCapsetEnter, ProgPrivCapsetExit,
		ProgPrivUnshareEnter, ProgPrivUnshareExit,
		ProgPrivSetnsEnter, ProgPrivSetnsExit,
		ProgPrivSeccompEnter, ProgPrivSeccompExit,
	}
}

// The eBPF program types in this object. Named rather than repeated so the
// table below says what it means.
//
// fentry needs kernel BTF and a function the kernel exposes to tracing, so an
// fentry program can fail to load on a kernel where every tracepoint program
// loads. That is a per-program property the loader reports rather than a reason
// to withhold the hook: the capability it covers is unobservable without it.
const (
	probeTypeTracepoint = "tracepoint"
	probeTypeFentry     = "fentry"
	probeTypeFexit      = "fexit"
)

// Probe families, the unit that loads, attaches and degrades together.
//
// Eighteen units rather than thirty-one programs: two sched singletons,
// thirteen enter/exit pairs and three fentry singletons. A pair shares a
// scratch map, so dropping one half leaks the scratch entry and emits nothing
// at all, which is worse than dropping both.
const (
	FamilyProcExec = "proc_exec"
	FamilyProcExit = "proc_exit"
	FamilyOpenat   = "openat"
	FamilyConnect  = "connect"

	// FamilyFileOpen is the one-program family over security_file_open. It
	// degrades on its own: dropping it costs the entry points no syscall
	// tracepoint reaches, and costs nothing the openat family already covers.
	FamilyFileOpen = "file_open"

	// FamilySocketConnect is the one-program family over
	// security_socket_connect, on the same terms as FamilyFileOpen.
	FamilySocketConnect = "socket_connect"

	// FamilyPathLink is the one-program family over security_path_link.
	FamilyPathLink = "path_link"
)

// PrivFamilyFor names the family carrying one credential syscall.
func PrivFamilyFor(syscall string) string {
	return "priv_" + syscall
}

// privSyscall pairs a credential syscall with the operation its exit program
// reports, in the order bpf/allseer.bpf.c declares the pairs.
//
// The operation is carried because a family needs a finer capability answer
// than its event type gives. See capabilitiesFor.
type privSyscall struct {
	name string
	op   abi.PrivOp
}

func privSyscalls() []privSyscall {
	return []privSyscall{
		{"setuid", abi.OpSetuid},
		{"setreuid", abi.OpSetreuid},
		{"setresuid", abi.OpSetresuid},
		{"setgid", abi.OpSetgid},
		{"setregid", abi.OpSetregid},
		{"setresgid", abi.OpSetresgid},
		{"setgroups", abi.OpSetgroups},
		{"capset", abi.OpCapset},
		{"unshare", abi.OpUnshare},
		{"setns", abi.OpSetns},
		{"seccomp", abi.OpSeccomp},
	}
}

// ProbeDescriptor is the static description of one program in the object.
//
// Every field is a property of bpf/allseer.bpf.c rather than of a running
// kernel, so this table is portable and its tests need no root, no libbpf and
// no compiled object.
type ProbeDescriptor struct {
	// Name is the program name, as Attach takes it.
	Name string

	// Family is the degradation unit this program belongs to.
	Family string

	// Type is the eBPF program type.
	Type string

	// AttachPoint is the kernel hook without the SEC() prefix, matching the
	// form ProbeInfo.AttachPoint documents.
	AttachPoint string

	// Emits is the event type this program writes to the ring buffer, or
	// abi.EvtUnknown for an entry-side program that only fills scratch.
	Emits abi.EventType

	// PrivOp is the credential operation a privilege program reports, and
	// abi.OpUnknown for every other program.
	PrivOp abi.PrivOp

	// Optional marks a program the object may be loaded without.
	//
	// Only the fentry hooks are: each needs kernel BTF to carry the function
	// it attaches to, and a kernel that does not expose it (security_path_link
	// needs CONFIG_SECURITY_PATH) cannot load it at all. libbpf fails the whole object when any program fails to
	// load, so without this the hook would turn every such kernel from
	// "governed, with the entry points no tracepoint reaches unwatched" into
	// "refuses to govern". The loader drops it and reports the loss; coverage
	// is what says the entry points went with it.
	Optional bool

	// SuccessOnly marks a program that observes an operation only once the
	// kernel has permitted it. security_file_open is the case: it runs after
	// path resolution and the permission check, so an open that was refused or
	// named nothing never reaches it. An entry point watched by such programs
	// alone is reported as watched for successes only, because a refused
	// attempt through it leaves no record - and a refused attempt on a
	// credential file is exactly what a denial exists to catch.
	SuccessOnly bool

	// Syscalls names the kernel entry points this program observes, in the
	// spelling pkg/capability's descriptors use.
	//
	// It exists so coverage can answer the question a capability name cannot:
	// fs.read is reachable through open, openat, openat2, creat and io_uring,
	// and a probe on one of them observes one of them. Reporting the kind as
	// observable without saying which entry points were watched is how a blind
	// spot gets dressed as a control, so ComputeCoverage subtracts this from
	// what the catalog declares and names the difference.
	//
	// A sched tracepoint lists the syscalls whose effect it observes even
	// though it is not attached to them: sched_process_exit sees a process end
	// however it ended, which includes exit and exit_group and more besides.
	Syscalls []string
}

// AllProbes returns every program in the object, in declaration order.
func AllProbes() []ProbeDescriptor {
	out := []ProbeDescriptor{
		{
			Name:        ProgProcExec,
			Family:      FamilyProcExec,
			Type:        probeTypeTracepoint,
			AttachPoint: "sched/sched_process_exec",
			Emits:       abi.EvtProcExec,
			Syscalls:    []string{"execve", "execveat"},
		},
		{
			Name:        ProgProcExit,
			Family:      FamilyProcExit,
			Type:        probeTypeTracepoint,
			AttachPoint: "sched/sched_process_exit",
			Emits:       abi.EvtProcExit,
			Syscalls:    []string{"exit", "exit_group"},
		},
		{
			Name:        ProgOpenatEnter,
			Family:      FamilyOpenat,
			Type:        probeTypeFentry,
			AttachPoint: "do_sys_openat2",
			Emits:       abi.EvtUnknown,
			Syscalls:    []string{"open", "openat", "openat2", "creat"},
		},
		{
			Name:        ProgOpenatExit,
			Family:      FamilyOpenat,
			Type:        probeTypeFexit,
			AttachPoint: "do_sys_openat2",
			Emits:       abi.EvtFileOpen,
			Syscalls:    []string{"open", "openat", "openat2", "creat"},
		},
		{
			Name:        ProgConnectEnter,
			Family:      FamilyConnect,
			Type:        probeTypeTracepoint,
			AttachPoint: "syscalls/sys_enter_connect",
			Emits:       abi.EvtUnknown,
			Syscalls:    []string{"connect"},
		},
		{
			Name:        ProgConnectExit,
			Family:      FamilyConnect,
			Type:        probeTypeTracepoint,
			AttachPoint: "syscalls/sys_exit_connect",
			Emits:       abi.EvtNetConnect,
			Syscalls:    []string{"connect"},
		},
		{
			Name:        ProgFileOpen,
			Family:      FamilyFileOpen,
			Type:        probeTypeFentry,
			AttachPoint: "security_file_open",
			Emits:       abi.EvtFileOpen,
			Optional:    true,
			SuccessOnly: true,
			// Every entry point that reaches do_dentry_open. open and creat do
			// not exist on arm64, where glibc calls openat for both; listing
			// them costs nothing there and is the truth on amd64.
			Syscalls: []string{"open", "openat", "openat2", "creat", "open_by_handle_at", "io_uring"},
		},
		{
			Name:        ProgSocketConnect,
			Family:      FamilySocketConnect,
			Type:        probeTypeFentry,
			AttachPoint: "security_socket_connect",
			Emits:       abi.EvtNetConnect,
			Optional:    true,
			// Not SuccessOnly: it runs before any LSM verdict and before the
			// network answers, so a refused or failed connect reaches it too.
			// sendto and sendmsg are not listed: an unconnected datagram and
			// TCP Fast Open never call it.
			Syscalls: []string{"connect", "io_uring"},
		},
		{
			Name:        ProgPathLink,
			Family:      FamilyPathLink,
			Type:        probeTypeFentry,
			AttachPoint: "security_path_link",
			Emits:       abi.EvtFileLink,
			Optional:    true,
			// protected_hardlinks is checked before the hook, so a refused
			// link leaves no record. Symlinks never reach it.
			SuccessOnly: true,
			Syscalls:    []string{"link", "linkat", "io_uring"},
		},
	}

	// The twenty-two privilege programs are generated from the syscall list for
	// the reason ProgPrivPairs gives: naming them by hand is a chance to omit
	// one, and an omitted exit program is silent.
	for _, s := range privSyscalls() {
		family := PrivFamilyFor(s.name)
		out = append(out,
			ProbeDescriptor{
				Name:        "priv_enter_" + s.name,
				Family:      family,
				Type:        probeTypeTracepoint,
				AttachPoint: "syscalls/sys_enter_" + s.name,
				Emits:       abi.EvtUnknown,
				PrivOp:      s.op,
				Syscalls:    []string{s.name},
			},
			ProbeDescriptor{
				Name:        "priv_exit_" + s.name,
				Family:      family,
				Type:        probeTypeTracepoint,
				AttachPoint: "syscalls/sys_exit_" + s.name,
				Emits:       abi.EvtPrivChange,
				PrivOp:      s.op,
				Syscalls:    []string{s.name},
			},
		)
	}
	return out
}

// ProbeFamily describes one degradation unit.
type ProbeFamily struct {
	Name string

	// Programs is every program in the family, entry before its own exit.
	Programs []string

	// Floor marks the attribution backbone. proc_exec and proc_exit are not a
	// family to be dropped quietly: every other probe hangs its attribution off
	// them, so a host that cannot load them must refuse to govern rather than
	// degrade. That refusal is the M7 requirement; this flag is what it reads.
	Floor bool

	// Capabilities is what the family observes with every program attached.
	Capabilities []capability.Kind

	// Syscalls is every kernel entry point the family's programs observe.
	Syscalls []string

	// SuccessOnly reports that every emitting program in the family sees an
	// operation only once the kernel permitted it.
	SuccessOnly bool
}

// AllProbeFamilies returns the eighteen degradation units, in declaration order.
func AllProbeFamilies() []ProbeFamily {
	var order []string
	members := make(map[string][]ProbeDescriptor)
	for _, d := range AllProbes() {
		if _, seen := members[d.Family]; !seen {
			order = append(order, d.Family)
		}
		members[d.Family] = append(members[d.Family], d)
	}

	out := make([]ProbeFamily, 0, len(order))
	for _, name := range order {
		descs := members[name]
		programs := make([]string, 0, len(descs))
		for _, d := range descs {
			programs = append(programs, d.Name)
		}
		out = append(out, ProbeFamily{
			Name:         name,
			Programs:     programs,
			Floor:        name == FamilyProcExec || name == FamilyProcExit,
			Capabilities: capabilitiesFor(descs),
			Syscalls:     syscallsOf(descs),
			SuccessOnly:  successOnly(descs),
		})
	}
	return out
}

// capabilitiesFor derives what a set of programs observes from what they emit,
// through the decoder's own mapping rather than a list kept beside it.
//
// The privilege families need the finer answer. CapabilitiesFor(EvtPrivChange)
// returns all four kinds a privilege record can decode to, which is correct for
// the event type and wrong for any one family: a host with only the setuid pair
// attached cannot observe priv.capset, and saying otherwise is exactly the
// blind spot dressed as a control that this reporting exists to prevent.
// kindForPrivOp is what the decoder applies per record, so asking it per family
// keeps one mapping rather than introducing a second.
func capabilitiesFor(descs []ProbeDescriptor) []capability.Kind {
	var out []capability.Kind
	seen := make(map[capability.Kind]bool)

	add := func(k capability.Kind) {
		if k != "" && !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}

	for _, d := range descs {
		if d.Emits == abi.EvtUnknown {
			continue
		}
		if d.Emits == abi.EvtPrivChange {
			k, err := kindForPrivOp(d.PrivOp)
			if err != nil {
				continue
			}
			add(k)
			continue
		}
		for _, k := range CapabilitiesFor(d.Emits) {
			add(k)
		}
	}
	return out
}

// OptionalPrograms names every program the object may be loaded without, in
// declaration order. The loader disables these and retries when a load fails,
// so a kernel missing one hook loses that hook rather than all telemetry.
func OptionalPrograms() []string {
	var out []string
	for _, d := range AllProbes() {
		if d.Optional {
			out = append(out, d.Name)
		}
	}
	return out
}

// successOnly reports whether every emitting program in descs observes only
// permitted operations. An entry-side program emits nothing and says nothing
// about outcomes, so it does not count either way.
func successOnly(descs []ProbeDescriptor) bool {
	emitting := 0
	for _, d := range descs {
		if d.Emits == abi.EvtUnknown {
			continue
		}
		emitting++
		if !d.SuccessOnly {
			return false
		}
	}
	return emitting > 0
}

// syscallsOf is the union of what a family's programs observe, first-seen
// order. An entry program and its exit program name the same syscall, so a
// family's list is shorter than the sum of its parts.
func syscallsOf(descs []ProbeDescriptor) []string {
	var out []string
	seen := make(map[string]bool)
	for _, d := range descs {
		for _, sc := range d.Syscalls {
			if !seen[sc] {
				seen[sc] = true
				out = append(out, sc)
			}
		}
	}
	return out
}

// EntryPointGap is one capability's entry-point coverage: which of the kernel
// entry points the catalog declares for it were watched by this load, and which
// were not.
//
// It exists because "observable" is a claim about a capability and a probe is
// attached to an entry point, and those are not the same statement. A load with
// only the openat family attached observes fs.read through openat and not
// through openat2 or io_uring, and an agent that reads a key through io_uring
// leaves no record at all. Reporting the kind as observable and stopping there
// would describe that load as governing something it cannot see.
//
// Missing is not always a defect to be closed. ALLSEER observes a file by the
// open that reached it, so the read and mmap entry points of fs.read are listed
// as unwatched because they are: a process reading through a descriptor it
// already holds produces no further record. Naming them is the point - the
// operator learns where the evidence comes from rather than inferring it.
type EntryPointGap struct {
	Kind capability.Kind `json:"kind"`

	// Observed and Missing partition the catalog's declared entry points for
	// the kind, both in declaration order.
	Observed []string `json:"observed,omitempty"`
	Missing  []string `json:"missing,omitempty"`

	// SuccessOnly is the part of Observed watched only for operations the
	// kernel permitted. A refused or failed attempt through one of these
	// produces no record, so "observed" there means "a successful use is
	// recorded", not "an attempt is". io_uring is the standing case for file
	// opens: its successes reach security_file_open and nothing reaches its
	// refusals.
	SuccessOnly []string `json:"success_only,omitempty"`
}

// Coverage is what an attached probe set can actually observe.
//
// This is the value the reporting destinations share. allseerctl renders it,
// the audit record embeds it so a later reader cannot mistake "observed
// nothing" for "failed to observe", and a bug report carries it because the two
// triggers that would reopen the reversed object split are field-observable
// only: they fire on somebody else's kernel or not at all, and a gap that stops
// at an operator's status query is not evidence that reaches whoever decides
// about the architecture.
type Coverage struct {
	// Probes is per-program status, in declaration order.
	Probes []ProbeInfo `json:"probes"`

	// Families is per-unit status, in declaration order.
	Families []FamilyCoverage `json:"families"`

	// Observable is what the attached set can produce, in catalog order.
	Observable []capability.Kind `json:"observable"`

	// Unobservable is the gap that matters: kinds this object carries programs
	// for, which the attached set cannot produce. A grant for one of these
	// reads as governance and enforces nothing.
	Unobservable []capability.Kind `json:"unobservable,omitempty"`

	// Unsupported is what no program in this object emits at all. A property of
	// the build rather than of this load, reported separately so a capability
	// nothing was ever written to watch is not mistaken for one lost to
	// degradation.
	Unsupported []capability.Kind `json:"unsupported,omitempty"`

	// FloorIntact reports whether proc_exec and proc_exit both attached. False
	// means attribution has no backbone, which M7 must treat as a refusal to
	// govern rather than as a degraded session.
	FloorIntact bool `json:"floor_intact"`

	// Degraded reports whether any family is incomplete.
	Degraded bool `json:"degraded"`

	// EntryPoints is per-capability entry-point coverage, for every observable
	// kind that some declared entry point was not watched for. A kind absent
	// from this list is either fully watched or not observable at all, and the
	// lists above say which.
	EntryPoints []EntryPointGap `json:"entry_points,omitempty"`
}

// FamilyCoverage is one degradation unit's status.
type FamilyCoverage struct {
	Name  string `json:"name"`
	Floor bool   `json:"floor"`

	// Complete reports whether every program in the family attached. A family
	// is all or nothing: half a pair emits no events, so a partially attached
	// family contributes no capabilities.
	Complete bool `json:"complete"`

	// Missing names the programs that did not attach.
	Missing []string `json:"missing,omitempty"`

	// Capabilities is what the family observes when complete. Reported even
	// when it is not, because that is the gap.
	Capabilities []capability.Kind `json:"capabilities"`

	// Syscalls is every kernel entry point the family observes.
	Syscalls []string `json:"syscalls,omitempty"`
}

// DegradedEntryPoints is the part of EntryPoints a fully attached build would
// have watched, per capability.
//
// The distinction it draws is the one an operator has to act on. fs.read lists
// read and mmap as unwatched in every load, because ALLSEER observes the open
// that reached a file and not each later use of a descriptor - that is the
// design, and no amount of attaching changes it. openat2 and io_uring are
// unwatched only when the hook that covers them is missing, and that is a
// kernel or configuration problem with a fix. Reporting both in one list would
// leave the fixable case indistinguishable from the permanent one.
func (c Coverage) DegradedEntryPoints() []EntryPointGap {
	watchable := make(map[capability.Kind]map[string]bool)
	fullyWatchable := make(map[capability.Kind]map[string]bool)
	for _, f := range AllProbeFamilies() {
		for _, k := range f.Capabilities {
			if watchable[k] == nil {
				watchable[k] = make(map[string]bool)
				fullyWatchable[k] = make(map[string]bool)
			}
			for _, sc := range f.Syscalls {
				watchable[k][sc] = true
				if !f.SuccessOnly {
					fullyWatchable[k][sc] = true
				}
			}
		}
	}

	// Two kinds of loss. An entry point no attached program watches, where a
	// full build would; and one watched only for successes, where a full build
	// would also record refused attempts. The second is what an openat family
	// that failed to attach leaves behind: the hook still reports successful
	// opens, so the kind stays observable, and a refused read of a credential
	// file goes unrecorded.
	var out []EntryPointGap
	for _, g := range c.EntryPoints {
		var lost, weakened []string
		for _, sc := range g.Missing {
			if watchable[g.Kind][sc] {
				lost = append(lost, sc)
			}
		}
		for _, sc := range g.SuccessOnly {
			if fullyWatchable[g.Kind][sc] {
				weakened = append(weakened, sc)
			}
		}
		if len(lost) > 0 || len(weakened) > 0 {
			out = append(out, EntryPointGap{Kind: g.Kind, Observed: g.Observed, Missing: lost, SuccessOnly: weakened})
		}
	}
	return out
}

// ComputeCoverage derives coverage from per-probe status.
//
// A probe absent from the input counts as not attached, so a caller that
// reports only what it tried still gets an honest answer about the rest.
func ComputeCoverage(probes []ProbeInfo) Coverage {
	attached := make(map[string]bool, len(probes))
	for _, p := range probes {
		attached[p.Name] = p.Attached
	}

	cov := Coverage{Probes: probes, FloorIntact: true}

	observable := make(map[capability.Kind]bool)
	emitted := make(map[capability.Kind]bool)
	watched := make(map[capability.Kind]map[string]bool)
	fully := make(map[capability.Kind]map[string]bool)
	for _, k := range capability.AllKinds() {
		watched[k] = make(map[string]bool)
		fully[k] = make(map[string]bool)
	}

	for _, f := range AllProbeFamilies() {
		fc := FamilyCoverage{
			Name:         f.Name,
			Floor:        f.Floor,
			Complete:     true,
			Capabilities: f.Capabilities,
			Syscalls:     f.Syscalls,
		}
		for _, name := range f.Programs {
			if !attached[name] {
				fc.Complete = false
				fc.Missing = append(fc.Missing, name)
			}
		}

		for _, k := range f.Capabilities {
			emitted[k] = true
			if fc.Complete {
				observable[k] = true
				for _, sc := range f.Syscalls {
					watched[k][sc] = true
					if !f.SuccessOnly {
						fully[k][sc] = true
					}
				}
			}
		}

		if !fc.Complete {
			cov.Degraded = true
			if f.Floor {
				cov.FloorIntact = false
			}
		}
		cov.Families = append(cov.Families, fc)
	}

	// Catalog order throughout, so two reports of the same state compare equal.
	for _, k := range capability.AllKinds() {
		switch {
		case observable[k]:
			cov.Observable = append(cov.Observable, k)
		case emitted[k]:
			cov.Unobservable = append(cov.Unobservable, k)
		default:
			cov.Unsupported = append(cov.Unsupported, k)
		}
	}

	// Entry points for the observable kinds only. For a kind nothing observes,
	// Unobservable and Unsupported already say so, and repeating it here as
	// "every entry point missing" would bury the loads where some were watched
	// and some were not - which is the case this reporting exists for.
	for _, k := range cov.Observable {
		d, ok := capability.Describe(k)
		if !ok {
			continue
		}
		gap := EntryPointGap{Kind: k}
		for _, sc := range d.Syscalls {
			switch {
			case !watched[k][sc]:
				gap.Missing = append(gap.Missing, sc)
			case !fully[k][sc]:
				gap.Observed = append(gap.Observed, sc)
				gap.SuccessOnly = append(gap.SuccessOnly, sc)
			default:
				gap.Observed = append(gap.Observed, sc)
			}
		}
		if len(gap.Missing) > 0 || len(gap.SuccessOnly) > 0 {
			cov.EntryPoints = append(cov.EntryPoints, gap)
		}
	}
	return cov
}

// ObservableSetter is the catalog surface Coverage writes to.
//
// Narrower than capability.Catalog, which is read-only, and narrower than
// *MemoryCatalog so a caller can substitute one in a test.
type ObservableSetter interface {
	SetObservable(kinds []capability.Kind)
}

// Apply records the observable set on a catalog.
//
// The one call that closes the chain: which programs attached decides which
// families are complete, which decides what the catalog will admit is
// observable, which decides whether an envelope's grant is enforceable.
func (c Coverage) Apply(cat ObservableSetter) {
	cat.SetObservable(c.Observable)
}

// GrantGap returns the granted kinds this coverage cannot observe, in the order
// given.
//
// The governance check the milestone calls out in its own right: if degradation
// leaves a capability the active envelope grants unobservable, the session is
// not a degraded one to continue quietly. What to do about it is a decision for
// the daemon, which is M7; naming it is this function.
func (c Coverage) GrantGap(granted []capability.Kind) []capability.Kind {
	observable := make(map[capability.Kind]bool, len(c.Observable))
	for _, k := range c.Observable {
		observable[k] = true
	}

	var gap []capability.Kind
	for _, k := range granted {
		if !observable[k] {
			gap = append(gap, k)
		}
	}
	return gap
}

// BugReport renders coverage as a diagnostic for a bug report.
//
// A destination in its own right rather than a convenience. Both triggers that
// would reopen the reversed object split are field-observable only: no 5.8-6.2
// kernel is available here, the pre-6.3 capability path has never executed, and
// no consumer exists that could need a probe set replaced in place. They fire
// on somebody else's kernel or not at all, so what a user can paste into an
// issue is the evidence channel that reaches whoever decides.
//
// Plain text because it is pasted by a human. The machine-readable form is the
// value itself, which marshals to JSON.
func (c Coverage) BugReport() string {
	var b strings.Builder

	b.WriteString("ALLSEER telemetry coverage\n")
	fmt.Fprintf(&b, "  degraded:     %t\n", c.Degraded)
	fmt.Fprintf(&b, "  floor intact: %t", c.FloorIntact)
	if !c.FloorIntact {
		b.WriteString("  <- proc_exec/proc_exit are the attribution backbone")
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "  observable:   %d of %d known capabilities\n",
		len(c.Observable), len(capability.AllKinds()))

	var incomplete []FamilyCoverage
	for _, f := range c.Families {
		if !f.Complete {
			incomplete = append(incomplete, f)
		}
	}

	if len(incomplete) == 0 {
		fmt.Fprintf(&b, "\nAll %d probe families attached.\n", len(c.Families))
	} else {
		fmt.Fprintf(&b, "\nIncomplete families (%d of %d):\n", len(incomplete), len(c.Families))
		for _, f := range incomplete {
			fmt.Fprintf(&b, "  %-18s missing %s", f.Name, strings.Join(f.Missing, ", "))
			if f.Floor {
				b.WriteString("   [FLOOR]")
			}
			b.WriteString("\n")
		}
	}

	// The errors are the part a maintainer reads first: a verifier rejection
	// reads differently from a missing tracepoint, and only the message says
	// which.
	var failures []ProbeInfo
	for _, p := range c.Probes {
		if p.Error != "" {
			failures = append(failures, p)
		}
	}
	if len(failures) > 0 {
		b.WriteString("\nAttach failures:\n")
		for _, p := range failures {
			fmt.Fprintf(&b, "  %-22s %s\n", p.Name, p.Error)
		}
	}

	// The entry-point gaps come before the kind-level ones because they are the
	// subtler reading: a kind listed as observable here is one an agent can
	// still exercise unobserved, by asking the kernel a different way.
	if len(c.EntryPoints) > 0 {
		b.WriteString("\nObservable capabilities with unwatched entry points:\n")
		for _, g := range c.EntryPoints {
			fmt.Fprintf(&b, "  %-18s watched %s; successes only %s; unwatched %s\n",
				g.Kind, joinOrNone(g.Observed), joinOrNone(g.SuccessOnly), joinOrNone(g.Missing))
		}
	}

	// The fixable subset, named separately: these are the ones a fully attached
	// build would have watched.
	if lost := c.DegradedEntryPoints(); len(lost) > 0 {
		b.WriteString("\nEntry points this load lost that this build can watch:\n")
		for _, g := range lost {
			fmt.Fprintf(&b, "  %-18s unwatched %s; reduced to successes only %s\n",
				g.Kind, joinOrNone(g.Missing), joinOrNone(g.SuccessOnly))
		}
	}

	if len(c.Unobservable) > 0 {
		b.WriteString("\nCapabilities this build observes but this load does not:\n")
		for _, k := range c.Unobservable {
			fmt.Fprintf(&b, "  %s\n", k)
		}
	}

	// Kept apart from the gap above. A capability nothing was ever written to
	// watch is not a load failure, and reading it as one sends a maintainer
	// looking for a kernel problem that is not there.
	if len(c.Unsupported) > 0 {
		b.WriteString("\nCapabilities no probe in this build observes:\n")
		for _, k := range c.Unsupported {
			fmt.Fprintf(&b, "  %s\n", k)
		}
	}
	return b.String()
}

// joinOrNone renders an entry-point list for a report, naming an empty one
// rather than printing nothing where a reader expects names.
func joinOrNone(in []string) string {
	if len(in) == 0 {
		return "none"
	}
	return strings.Join(in, ", ")
}
