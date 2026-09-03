// Package capability defines the shared vocabulary of ALLSEER.
//
// A capability is a single kernel-observable ability a process may exercise:
// reading a file, opening a socket, spawning a child. Three stages speak this
// vocabulary, which is what keeps them decoupled:
//
//   - The Expected Capability Envelope declares capabilities as grants.
//   - The telemetry collector resolves each kernel event to the capability it
//     exercised.
//   - The validator compares observed capabilities against granted ones.
//
// Adding a probe therefore requires no validator change; the probe just
// resolves its events to an existing Kind.
//
// Nothing here makes decisions. This package defines what can be said, not what
// should be allowed.
package capability

// Domain is a coarse grouping of capabilities, so that policy and risk rules
// can address broad areas ("any network egress") without enumerating Kinds.
type Domain string

const (
	DomainFilesystem Domain = "filesystem"
	DomainProcess    Domain = "process"
	DomainNetwork    Domain = "network"
	DomainPrivilege  Domain = "privilege"
	DomainIPC        Domain = "ipc"
	DomainKernel     Domain = "kernel"
)

// Kind is a specific capability within a Domain.
//
// Kinds are coarser than syscalls: open, openat, and openat2 all resolve to
// FileRead or FileWrite. An envelope written from user intent should say "reads
// source files", not "may call openat2". Syscall detail stays on the raw event
// for forensics; the Kind is what gets validated.
//
// Kind values are a wire contract. They appear in ECE documents, event streams,
// and audit logs. Add new Kinds freely; never repurpose an existing one.
//
// The set is closed, fixed at compile time by the table in table.go. Unknown
// Kinds are rejected where grants are admitted rather than in an unmarshaler;
// see catalog.go.
type Kind string

const (
	// Filesystem.
	KindFileRead     Kind = "fs.read"
	KindFileWrite    Kind = "fs.write"
	KindFileCreate   Kind = "fs.create"
	KindFileDelete   Kind = "fs.delete"
	KindFileRename   Kind = "fs.rename"
	KindFileChmod    Kind = "fs.chmod"
	KindFileChown    Kind = "fs.chown"
	KindFileTruncate Kind = "fs.truncate"
	KindFileLink     Kind = "fs.link"
	KindFileMount    Kind = "fs.mount"

	// Process lifecycle.
	KindProcessExec   Kind = "process.exec"
	KindProcessFork   Kind = "process.fork"
	KindProcessExit   Kind = "process.exit"
	KindProcessSignal Kind = "process.signal"
	KindProcessPtrace Kind = "process.ptrace"

	// Network.
	KindNetConnect Kind = "net.connect"
	KindNetBind    Kind = "net.bind"
	KindNetListen  Kind = "net.listen"
	KindNetAccept  Kind = "net.accept"
	KindNetSend    Kind = "net.send"
	KindNetReceive Kind = "net.receive"
	KindNetDNS     Kind = "net.dns"
	KindNetRawSock Kind = "net.rawsocket"

	// Privilege and credentials.
	KindPrivEscalate  Kind = "priv.escalate"
	KindPrivSetuid    Kind = "priv.setuid"
	KindPrivCapSet    Kind = "priv.capset"
	KindPrivNamespace Kind = "priv.namespace"
	KindPrivSeccomp   Kind = "priv.seccomp"

	// Inter-process communication.
	KindIPCPipe      Kind = "ipc.pipe"
	KindIPCSharedMem Kind = "ipc.sharedmem"
	KindIPCUnixSock  Kind = "ipc.unixsocket"

	// Kernel surface. Anything here is high-consequence by construction.
	KindKernelModuleLoad Kind = "kernel.moduleload"
	KindKernelBPFLoad    Kind = "kernel.bpfload"
	KindKernelKallsyms   Kind = "kernel.kallsyms"
)

// Selector narrows a Kind to the resources it may touch.
//
// A grant of fs.write with no selector is unbounded and almost always wrong.
// Only the fields meaningful to a given Kind are populated; a network Kind
// ignores PathPatterns. Checking which fields apply to which Kind is the
// envelope package's job, not this one's.
type Selector struct {
	// PathPatterns is glob syntax evaluated against the resolved absolute path,
	// so a symlink escape cannot slip past a pattern written for the
	// pre-resolution path.
	PathPatterns []string `json:"path_patterns,omitempty"`

	// Hosts accepts hostnames, CIDR blocks, or literal IPs.
	Hosts []string `json:"hosts,omitempty"`

	// Ports is empty for any port.
	Ports []int `json:"ports,omitempty"`

	// Protocols is e.g. "tcp", "udp", "https".
	Protocols []string `json:"protocols,omitempty"`

	// Executables constrains process.exec, matched against the resolved binary
	// path.
	Executables []string `json:"executables,omitempty"`

	// ArgPatterns further constrains process.exec by command line. This is a
	// convenience for readable envelopes, not a security boundary: argument
	// matching is trivially evaded and must never be the only control.
	ArgPatterns []string `json:"arg_patterns,omitempty"`

	// MaxCount caps how many times the capability may be exercised. Zero means
	// no limit.
	MaxCount int `json:"max_count,omitempty"`
}

// Grant is a permission entry inside an ECE: one Kind, optionally narrowed by a
// Selector, with a justification.
//
// Rationale is required by convention rather than by type. A generated grant
// that cannot explain itself signals that intent analysis went wrong, and a
// human reviewing a blocked action needs to know why the capability was ever
// expected.
type Grant struct {
	Kind      Kind     `json:"kind"`
	Domain    Domain   `json:"domain"`
	Selector  Selector `json:"selector,omitempty"`
	Rationale string   `json:"rationale,omitempty"`

	// Optional means the agent may legitimately never exercise this. Absence of
	// a non-optional grant at session end is worth reporting: the task may not
	// have done what the user asked.
	Optional bool `json:"optional,omitempty"`
}

// Observation is a capability actually exercised, resolved from a kernel event.
// It is the observed-side mirror of Grant, and the validator's core question is
// whether an Observation is covered by some Grant.
type Observation struct {
	Kind   Kind   `json:"kind"`
	Domain Domain `json:"domain"`

	// Target is the primary resource acted upon: an absolute path, a
	// "host:port", or a binary path, depending on Domain.
	Target string `json:"target,omitempty"`

	// Attributes carries resolved Kind-specific detail used for matching
	// (protocol, resolved IP, argv). A map, so new probes can enrich
	// observations without a type change here.
	//
	// The keys the validator reads are named below and are a wire contract:
	// enrichment writes them and selector matching reads them, so a typo on
	// either side silently disables a selector dimension rather than failing.
	Attributes map[string]string `json:"attributes,omitempty"`
}

// Attribute keys carried on an Observation.
//
// Only the keys the validator matches on are fixed here. Probes may add
// anything else for forensics; unknown keys are ignored by matching, which is
// what lets a new probe enrich observations without a coordinated change.
const (
	// AttrProtocol is the transport or application protocol of a network
	// observation ("tcp", "udp", "https"), matched against Selector.Protocols.
	AttrProtocol = "protocol"

	// AttrDestIP is the literal destination address of a network observation.
	//
	// It is distinct from the host in Target, which carries the correlated
	// hostname when DNS correlation succeeded. Both are recorded because a
	// grant may name either, and the address is the one the kernel is certain
	// of: correlation is best-effort, the address is not.
	AttrDestIP = "dest_ip"

	// AttrPort is the destination port as a decimal string. Redundant with
	// Target, which carries "host:port", and kept because reading a field is
	// less error-prone than re-splitting a string.
	AttrPort = "port"

	// AttrHostnameCorrelated is "false" when DNS correlation failed, so the
	// destination is known only by address. Absent when correlation succeeded.
	//
	// Selector matching does not read it -- it derives the same fact from the
	// target's shape -- but risk scoring and audit both want it stated rather
	// than inferred.
	AttrHostnameCorrelated = "hostname_correlated"

	// AttrArgv is the command line of a process.exec observation, arguments
	// joined by a single space, matched against Selector.ArgPatterns.
	//
	// Lossy by construction: an argument containing a space is
	// indistinguishable from two arguments. That is tolerable only because
	// ArgPatterns is a readability convenience and never a security boundary.
	AttrArgv = "argv"

	// AttrInterpreter names the script runner when the executed binary is one
	// (sh, python, node), because the meaningful action is the script rather
	// than the interpreter.
	AttrInterpreter = "interpreter"

	// AttrNewPath is the destination of a rename or link, whose source is the
	// Target.
	//
	// It is carried but not matched: an Observation has one Target, and
	// selector matching evaluates only that. A rename *into* a protected path
	// is therefore not caught by a path selector on the destination. See
	// docs/selector-matching.md.
	AttrNewPath = "new_path"
)

// Catalog is the authoritative registry of known capabilities.
//
// It tells the ECE generator what vocabulary is available, so it cannot invent
// Kinds, and it lets the daemon reject an envelope referencing a Kind this
// build cannot observe. A grant with no probe behind it is a blind spot that
// reads as a control.
type Catalog interface {
	// Kinds returns every capability this build knows about.
	Kinds() []Kind

	// Lookup reports the metadata for a Kind, and whether the Kind is known.
	Lookup(k Kind) (Descriptor, bool)

	// Observable reports whether a probe backing this Kind is loaded. An
	// envelope granting an unobservable Kind cannot be enforced.
	Observable(k Kind) bool
}

// Descriptor is the static metadata describing a Kind.
type Descriptor struct {
	Kind    Kind   `json:"kind"`
	Domain  Domain `json:"domain"`
	Summary string `json:"summary"`

	// BaselineSeverity is the consequence of exercising this capability at all,
	// before context is applied. The risk engine treats it as a starting point,
	// not a verdict: fs.write is unremarkable in a scratch directory and
	// alarming in /etc.
	BaselineSeverity Severity `json:"baseline_severity"`

	// Syscalls is documentation and coverage auditing only; never used for
	// matching.
	Syscalls []string `json:"syscalls,omitempty"`
}

// Severity is the inherent consequence of a capability, independent of context.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)
