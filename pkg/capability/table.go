package capability

// This table is the single source of truth for the capability vocabulary. Every
// Kind constant in capability.go appears here once, and everything else that
// enumerates Kinds derives from it: the Catalog, the JSON Schema enum in
// api/schema/ece.v1alpha1.schema.json, and the probe coverage report.
//
// It lives in Go source rather than an embedded data file because the table is
// effectively security policy. BaselineSeverity feeds risk scoring, and a
// Kind's presence here is what makes it grantable at all.
//
// Rules for editing:
//
//   - Adding a Kind: add the constant in capability.go, add its row here, and
//     add it to the schema enum. TestSchemaEnumMatchesTable fails until the
//     schema is updated, which is the intended reminder.
//   - Never remove or repurpose a Kind. Values are a wire contract appearing in
//     sealed envelopes and archived audit logs. A Kind nobody observes simply
//     has no probe backing it, which Catalog.Observable already reports.
//   - Syscalls is documentation and coverage auditing only. Matching never
//     consults it; that is the whole point of the Kind abstraction.
//
// The severity gradient:
//
//	info      observation-only; carries no consequence by itself
//	low       routine for a coding agent; the common case
//	medium    consequential but ordinary in some tasks
//	high      rarely part of a coding task; a step in most attack narratives
//	critical  an attack on the host or on the monitoring system itself
var descriptors = []Descriptor{
	// --- Filesystem ---------------------------------------------------------
	//
	// Reads are low and writes medium because the asymmetry is real: a wrong
	// read discloses information bounded by what the agent can then do with it,
	// while a wrong write mutates state the user did not consent to changing.
	// Deletion outranks both, being the least recoverable of the three.
	{
		Kind:             KindFileRead,
		Domain:           DomainFilesystem,
		Summary:          "Read the contents of a file.",
		BaselineSeverity: SeverityLow,
		Syscalls:         []string{"open", "openat", "openat2", "read", "pread64", "readv", "preadv", "mmap"},
	},
	{
		Kind:             KindFileWrite,
		Domain:           DomainFilesystem,
		Summary:          "Modify the contents of an existing file.",
		BaselineSeverity: SeverityMedium,
		Syscalls:         []string{"open", "openat", "openat2", "write", "pwrite64", "writev", "pwritev"},
	},
	{
		Kind:             KindFileCreate,
		Domain:           DomainFilesystem,
		Summary:          "Create a new file or directory.",
		BaselineSeverity: SeverityMedium,
		Syscalls:         []string{"open", "openat", "openat2", "creat", "mkdir", "mkdirat", "mknod", "mknodat"},
	},
	{
		Kind:             KindFileDelete,
		Domain:           DomainFilesystem,
		Summary:          "Remove a file or directory.",
		BaselineSeverity: SeverityHigh,
		Syscalls:         []string{"unlink", "unlinkat", "rmdir"},
	},
	{
		Kind:             KindFileRename,
		Domain:           DomainFilesystem,
		Summary:          "Rename or move a file, changing what a path refers to.",
		BaselineSeverity: SeverityMedium,
		Syscalls:         []string{"rename", "renameat", "renameat2"},
	},
	{
		// High rather than medium: making a dropped file executable is a
		// standard persistence step, and almost never part of a coding task.
		Kind:             KindFileChmod,
		Domain:           DomainFilesystem,
		Summary:          "Change a file's permission bits.",
		BaselineSeverity: SeverityHigh,
		Syscalls:         []string{"chmod", "fchmod", "fchmodat", "fchmodat2"},
	},
	{
		Kind:             KindFileChown,
		Domain:           DomainFilesystem,
		Summary:          "Change a file's owning user or group.",
		BaselineSeverity: SeverityHigh,
		Syscalls:         []string{"chown", "fchown", "lchown", "fchownat"},
	},
	{
		Kind:             KindFileTruncate,
		Domain:           DomainFilesystem,
		Summary:          "Discard part or all of a file's contents in place.",
		BaselineSeverity: SeverityHigh,
		Syscalls:         []string{"truncate", "ftruncate"},
	},
	{
		// The mechanism behind the symlink escape PathMatcher defends against:
		// a link inside a granted directory can point anywhere on the disk.
		Kind:             KindFileLink,
		Domain:           DomainFilesystem,
		Summary:          "Create a hard or symbolic link.",
		BaselineSeverity: SeverityHigh,
		Syscalls:         []string{"link", "linkat", "symlink", "symlinkat"},
	},
	{
		Kind:             KindFileMount,
		Domain:           DomainFilesystem,
		Summary:          "Attach or detach a filesystem, changing what paths resolve to.",
		BaselineSeverity: SeverityCritical,
		Syscalls:         []string{"mount", "umount2", "move_mount", "fsmount", "pivot_root"},
	},

	// --- Process lifecycle --------------------------------------------------
	//
	// Exec is medium: a coding agent spawning a compiler is the expected case,
	// and the interesting question is which binary, which the selector carries.
	// Fork and exit are info. They are the substrate of ordinary work and
	// matter for attribution and depth tracking, not as findings themselves.
	{
		Kind:             KindProcessExec,
		Domain:           DomainProcess,
		Summary:          "Execute a new program image.",
		BaselineSeverity: SeverityMedium,
		Syscalls:         []string{"execve", "execveat"},
	},
	{
		Kind:             KindProcessFork,
		Domain:           DomainProcess,
		Summary:          "Create a child process.",
		BaselineSeverity: SeverityInfo,
		Syscalls:         []string{"fork", "vfork", "clone", "clone3"},
	},
	{
		Kind:             KindProcessExit,
		Domain:           DomainProcess,
		Summary:          "Process termination.",
		BaselineSeverity: SeverityInfo,
		Syscalls:         []string{"exit", "exit_group"},
	},
	{
		Kind:             KindProcessSignal,
		Domain:           DomainProcess,
		Summary:          "Send a signal to another process.",
		BaselineSeverity: SeverityMedium,
		Syscalls:         []string{"kill", "tkill", "tgkill", "pidfd_send_signal"},
	},
	{
		// Reading another process's memory is how credentials get stolen from
		// a running agent, or from the daemon itself.
		Kind:             KindProcessPtrace,
		Domain:           DomainProcess,
		Summary:          "Attach to another process to inspect or control it.",
		BaselineSeverity: SeverityCritical,
		Syscalls:         []string{"ptrace", "process_vm_readv", "process_vm_writev"},
	},

	// --- Network ------------------------------------------------------------
	//
	// Egress outranks ingress throughout. A listening socket exposes the host;
	// an outbound connection is how data leaves, and that cannot be undone
	// after the fact. For this threat model connect and send are therefore the
	// highest-consequence common capabilities.
	{
		Kind:             KindNetConnect,
		Domain:           DomainNetwork,
		Summary:          "Open an outbound connection to a remote endpoint.",
		BaselineSeverity: SeverityHigh,
		Syscalls:         []string{"connect"},
	},
	{
		Kind:             KindNetBind,
		Domain:           DomainNetwork,
		Summary:          "Bind a socket to a local address and port.",
		BaselineSeverity: SeverityMedium,
		Syscalls:         []string{"bind"},
	},
	{
		Kind:             KindNetListen,
		Domain:           DomainNetwork,
		Summary:          "Mark a socket as accepting inbound connections.",
		BaselineSeverity: SeverityMedium,
		Syscalls:         []string{"listen"},
	},
	{
		Kind:             KindNetAccept,
		Domain:           DomainNetwork,
		Summary:          "Accept an inbound connection.",
		BaselineSeverity: SeverityMedium,
		Syscalls:         []string{"accept", "accept4"},
	},
	{
		Kind:             KindNetSend,
		Domain:           DomainNetwork,
		Summary:          "Transmit data over a socket. Volume is the exfiltration signal.",
		BaselineSeverity: SeverityHigh,
		Syscalls:         []string{"send", "sendto", "sendmsg", "sendmmsg", "write"},
	},
	{
		Kind:             KindNetReceive,
		Domain:           DomainNetwork,
		Summary:          "Receive data over a socket.",
		BaselineSeverity: SeverityMedium,
		Syscalls:         []string{"recv", "recvfrom", "recvmsg", "recvmmsg", "read"},
	},
	{
		// Observed so DNSCorrelator can map later connections back to the
		// hostname they were resolved from. Low on its own.
		Kind:             KindNetDNS,
		Domain:           DomainNetwork,
		Summary:          "Resolve a hostname. Observed mainly to correlate later connections.",
		BaselineSeverity: SeverityLow,
		Syscalls:         []string{"sendto", "sendmsg", "recvfrom", "recvmsg"},
	},
	{
		// A raw socket bypasses normal protocol handling. Nothing a coding task
		// produces, and it defeats port- and protocol-based selectors.
		Kind:             KindNetRawSock,
		Domain:           DomainNetwork,
		Summary:          "Create a raw or packet socket, bypassing normal protocol handling.",
		BaselineSeverity: SeverityCritical,
		Syscalls:         []string{"socket"},
	},

	// --- Privilege and credentials -----------------------------------------
	//
	// All critical. An envelope granting any of these to a coding agent is a
	// generation failure rather than a requirement, which is why
	// configs/rules.default.yaml blocks them whatever the envelope says.
	{
		Kind:             KindPrivEscalate,
		Domain:           DomainPrivilege,
		Summary:          "Gain privileges, by any mechanism.",
		BaselineSeverity: SeverityCritical,
		Syscalls:         []string{"setuid", "setreuid", "setresuid", "capset"},
	},
	{
		// setgroups belongs here on the summary's own terms: supplementary
		// groups are group identity. It was missing from the list rather than
		// excluded from the kind, and the omission mattered — setgroups(0, NULL)
		// is the step that drops supplementary groups before dropping
		// privilege, and failing to call it before a setuid is a textbook
		// privilege-retention bug. It is named by ALLSEER_PRIV_OP_SETGROUPS,
		// which internal/telemetry/decode.go maps to this kind.
		Kind:             KindPrivSetuid,
		Domain:           DomainPrivilege,
		Summary:          "Change the process's user or group identity.",
		BaselineSeverity: SeverityCritical,
		Syscalls: []string{
			"setuid", "setgid", "setreuid", "setregid", "setresuid", "setresgid",
			"setgroups",
		},
	},
	{
		Kind:             KindPrivCapSet,
		Domain:           DomainPrivilege,
		Summary:          "Modify the process's Linux capability sets.",
		BaselineSeverity: SeverityCritical,
		Syscalls:         []string{"capset"},
	},
	{
		// How a process escapes the attribution the collector depends on: a new
		// cgroup or PID namespace puts work outside the probes' filter map.
		Kind:             KindPrivNamespace,
		Domain:           DomainPrivilege,
		Summary:          "Create or enter a namespace, changing the process's view of the system.",
		BaselineSeverity: SeverityCritical,
		Syscalls:         []string{"unshare", "setns", "clone", "clone3"},
	},
	{
		// Installing a seccomp filter is legitimate for a sandbox and is also
		// how a process blinds syscall-based observation of its own children.
		Kind:             KindPrivSeccomp,
		Domain:           DomainPrivilege,
		Summary:          "Install a seccomp filter, altering syscall behavior for the process tree.",
		BaselineSeverity: SeverityHigh,
		Syscalls:         []string{"seccomp", "prctl"},
	},

	// --- Inter-process communication ---------------------------------------
	//
	// Low to medium. IPC is ubiquitous in ordinary tooling. It matters here as
	// a channel that can move data between a governed process and an ungoverned
	// one, which is a sequence concern rather than a per-event one.
	{
		Kind:             KindIPCPipe,
		Domain:           DomainIPC,
		Summary:          "Create a pipe or FIFO.",
		BaselineSeverity: SeverityLow,
		Syscalls:         []string{"pipe", "pipe2", "mkfifo", "mknod", "mknodat"},
	},
	{
		Kind:             KindIPCSharedMem,
		Domain:           DomainIPC,
		Summary:          "Create or attach shared memory.",
		BaselineSeverity: SeverityMedium,
		Syscalls:         []string{"shmget", "shmat", "memfd_create", "mmap"},
	},
	{
		// Separate from ipc.pipe because a Unix socket is how a governed process
		// reaches an ungoverned daemon, including allseerd's own control socket.
		Kind:             KindIPCUnixSock,
		Domain:           DomainIPC,
		Summary:          "Connect to or create a Unix domain socket.",
		BaselineSeverity: SeverityMedium,
		Syscalls:         []string{"socket", "connect", "bind"},
	},

	// --- Kernel surface -----------------------------------------------------
	//
	// Critical by construction. A coding agent has no legitimate reason to
	// touch the kernel's own attack surface, and one doing so may be attacking
	// the monitor rather than merely exceeding its envelope. The default rule
	// set treats the whole domain as terminal.
	{
		Kind:             KindKernelModuleLoad,
		Domain:           DomainKernel,
		Summary:          "Load a kernel module.",
		BaselineSeverity: SeverityCritical,
		Syscalls:         []string{"init_module", "finit_module", "delete_module"},
	},
	{
		Kind:             KindKernelBPFLoad,
		Domain:           DomainKernel,
		Summary:          "Load an eBPF program or map. An agent doing this may be attacking the monitor.",
		BaselineSeverity: SeverityCritical,
		Syscalls:         []string{"bpf"},
	},
	{
		Kind:             KindKernelKallsyms,
		Domain:           DomainKernel,
		Summary:          "Read kernel symbol addresses, the usual precursor to kernel memory manipulation.",
		BaselineSeverity: SeverityCritical,
		Syscalls:         []string{"open", "openat", "openat2"},
	},
}
