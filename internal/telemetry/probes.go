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

	// ProgOpenatEnter is the sys_enter_openat program. It emits nothing.
	//
	// Named as a probe anyway because it is one: it performs the cgroup filter
	// decision for every open this object reports, and it is what captures the
	// path, the flags and the mode. What it does with them is store them, in
	// openat_scratch, for ProgOpenatExit to complete — the entry has the
	// arguments and no return, and struct allseer_event has a `ret` field the
	// header defines as a syscall return.
	ProgOpenatEnter = "openat_enter"

	// ProgOpenatExit is the sys_exit_openat program, emitting
	// ALLSEER_EVT_FILE_OPEN.
	//
	// A pair in a stronger sense than ProgProcExec and ProgProcExit are, which
	// are two probes reporting two different things. These two are one probe
	// split across two hooks by the shape of a syscall, and attaching either
	// alone yields no events at all rather than half of them: the entry side
	// never emits, and the exit side emits only what it finds a scratch entry
	// for. A caller that attaches one and not the other has a blind spot that
	// looks exactly like a quiet host.
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

// probeTypeTracepoint is the eBPF program type of every program in this object.
// Named rather than repeated so the table below says what it means.
const probeTypeTracepoint = "tracepoint"

// Probe families, the unit that loads, attaches and degrades together.
//
// Fifteen units rather than twenty-eight programs: two sched singletons and
// thirteen syscall enter/exit pairs. A pair shares a scratch map, so dropping
// one half leaks the scratch entry and emits nothing at all, which is worse
// than dropping both.
const (
	FamilyProcExec = "proc_exec"
	FamilyProcExit = "proc_exit"
	FamilyOpenat   = "openat"
	FamilyConnect  = "connect"
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
		},
		{
			Name:        ProgProcExit,
			Family:      FamilyProcExit,
			Type:        probeTypeTracepoint,
			AttachPoint: "sched/sched_process_exit",
			Emits:       abi.EvtProcExit,
		},
		{
			Name:        ProgOpenatEnter,
			Family:      FamilyOpenat,
			Type:        probeTypeTracepoint,
			AttachPoint: "syscalls/sys_enter_openat",
			Emits:       abi.EvtUnknown,
		},
		{
			Name:        ProgOpenatExit,
			Family:      FamilyOpenat,
			Type:        probeTypeTracepoint,
			AttachPoint: "syscalls/sys_exit_openat",
			Emits:       abi.EvtFileOpen,
		},
		{
			Name:        ProgConnectEnter,
			Family:      FamilyConnect,
			Type:        probeTypeTracepoint,
			AttachPoint: "syscalls/sys_enter_connect",
			Emits:       abi.EvtUnknown,
		},
		{
			Name:        ProgConnectExit,
			Family:      FamilyConnect,
			Type:        probeTypeTracepoint,
			AttachPoint: "syscalls/sys_exit_connect",
			Emits:       abi.EvtNetConnect,
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
			},
			ProbeDescriptor{
				Name:        "priv_exit_" + s.name,
				Family:      family,
				Type:        probeTypeTracepoint,
				AttachPoint: "syscalls/sys_exit_" + s.name,
				Emits:       abi.EvtPrivChange,
				PrivOp:      s.op,
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
}

// AllProbeFamilies returns the fifteen degradation units, in declaration order.
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

	for _, f := range AllProbeFamilies() {
		fc := FamilyCoverage{
			Name:         f.Name,
			Floor:        f.Floor,
			Complete:     true,
			Capabilities: f.Capabilities,
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
