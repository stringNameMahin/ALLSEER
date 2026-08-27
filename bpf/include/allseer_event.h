/* ALLSEER shared kernel/user event definitions.
 *
 * This header is the ABI contract between the eBPF programs and the Go decoder.
 * Both sides must agree on it byte for byte. A mismatch does not produce a
 * clean error; it produces plausible garbage that flows straight into
 * governance decisions.
 *
 * So this file is meant to be the single source of truth: generate the Go
 * decoder from it rather than writing one by hand, because hand-maintained
 * duplicates drift.
 *
 * Layout rules for anything added here:
 *   - Explicit fixed-width types only (__u32, not unsigned int).
 *   - Fields ordered largest-first to avoid implicit padding.
 *   - Fixed-size char arrays for strings; the kernel side must not allocate.
 *   - No pointers. Nothing that means anything only inside kernel address space.
 */

#ifndef __ALLSEER_EVENT_H
#define __ALLSEER_EVENT_H

/* The layout version, written into every record and compared against the
 * reader's own copy of this number.
 *
 * Bumped whenever anything in this file changes the bytes on the wire: a field
 * added, removed, reordered or retyped, or a bound changed. It is not a release
 * number and not a feature flag. It answers exactly one question — "was the
 * loaded object compiled against the layout this binary was generated from" —
 * and the answer has to become no the moment the two layouts differ.
 *
 * It earns its place because the cheap check cannot cover the dangerous case. A
 * reader can compare record lengths, and that catches a layout that changed
 * size. It does not catch a layout that stayed the same size and changed
 * meaning: a field retyped, two fields swapped, a bound moved from one array to
 * another. Those records decode without complaint into confident nonsense. */
#define ALLSEER_ABI_VERSION  2

/* Bounded because eBPF stack space is limited to 512 bytes and the verifier
 * rejects unbounded copies. These caps are a real constraint on what a probe
 * can report, and long paths will be truncated. The user-space enricher must
 * treat truncation as an enrichment failure, never as a complete path. */
#define ALLSEER_PATH_MAX     256
#define ALLSEER_COMM_LEN     16
#define ALLSEER_ARGV_MAX     8
#define ALLSEER_ARG_LEN      64

/* Event type discriminates the payload union. Values are a wire contract:
 * append only, never renumber. */
enum allseer_event_type {
    ALLSEER_EVT_UNKNOWN     = 0,
    ALLSEER_EVT_FILE_OPEN   = 1,
    ALLSEER_EVT_FILE_WRITE  = 2,
    ALLSEER_EVT_FILE_UNLINK = 3,
    ALLSEER_EVT_FILE_RENAME = 4,
    ALLSEER_EVT_FILE_CHMOD  = 5,
    ALLSEER_EVT_PROC_EXEC   = 6,
    ALLSEER_EVT_PROC_EXIT   = 7,
    ALLSEER_EVT_NET_CONNECT = 8,
    ALLSEER_EVT_NET_BIND    = 9,
    ALLSEER_EVT_NET_SEND    = 10,
    ALLSEER_EVT_PRIV_CHANGE = 11,
    ALLSEER_EVT_PTRACE      = 12,
};

/* Which credential operation an ALLSEER_EVT_PRIV_CHANGE record reports.
 *
 * One enumerator per syscall a probe hooks, because the syscall *is* the
 * operation and struct allseer_event carries no syscall number. Values are a
 * wire contract on the same terms as allseer_event_type: append only, never
 * renumber.
 *
 * ALLSEER_PRIV_OP_UNKNOWN = 0 is load-bearing rather than decorative. Every
 * probe in this design clears the payload union before filling it, so a probe
 * that failed to set `operation` writes a zero — and a zero that named a real
 * operation would decode as a confident setuid. The decoder refuses it, exactly
 * as it refuses ALLSEER_EVT_UNKNOWN.
 *
 * There is no ALLSEER_PRIV_OP_ESCALATE, and that absence is deliberate.
 * Escalation is not a syscall and no kernel hook reports one: it is a comparison
 * of `before` against `after`, and a comparison is a judgment. This file
 * publishes mechanisms; internal/telemetry/decode.go decides what they mean, for
 * the reason internal/telemetry/abi gives about staying free of judgments it
 * would have to regenerate. In particular, unshare(CLONE_NEWUSER) is not
 * escalation here — see the note on capability scope in struct
 * allseer_priv_state.
 *
 * Four mechanisms are knowingly absent, and each is absent for a reason that
 * outlives this version:
 *
 *   setfsuid, setfsgid  no capability in pkg/capability/table.go names them.
 *                       Their effect is still reported: uid_fs and gid_fs are in
 *                       both snapshots, so an fsuid moved as a side effect of a
 *                       setuid arrives in the record. Only the dedicated syscall
 *                       is unhooked.
 *   prctl               the hottest candidate on a Linux host — PR_SET_NAME
 *                       fires on every thread that names itself — so it needs an
 *                       argument filter to be affordable. Its privilege-relevant
 *                       effects (ambient capabilities, bounding-set drops,
 *                       securebits, seccomp mode) are all already visible as
 *                       differences between the two snapshots, so appending an
 *                       operation for it later costs no layout change.
 *   clone, clone3       these create namespaces for the *child*. The caller's
 *                       credentials do not change, so there is no credential
 *                       change to report. pkg/capability lists them under
 *                       priv.namespace, which is an imprecision in that table
 *                       rather than a requirement on this one.
 *   exec-triggered      a setuid binary, or a file carrying capabilities,
 *                       changes credentials inside execve. sched_process_exec
 *                       fires after those credentials are committed and there is
 *                       no earlier hook in this design to have captured a
 *                       `before` from, so the transition is invisible to a
 *                       syscall enter/exit pair. This is a permanent blind spot
 *                       of the hook family rather than a gap to be filled by a
 *                       later enumerator: closing it needs an LSM hook or a
 *                       kprobe on the credential commit path, which is a
 *                       separate decision from this one. */
enum allseer_priv_op {
    ALLSEER_PRIV_OP_UNKNOWN   = 0,
    ALLSEER_PRIV_OP_SETUID    = 1,
    ALLSEER_PRIV_OP_SETREUID  = 2,
    ALLSEER_PRIV_OP_SETRESUID = 3,
    ALLSEER_PRIV_OP_SETGID    = 4,
    ALLSEER_PRIV_OP_SETREGID  = 5,
    ALLSEER_PRIV_OP_SETRESGID = 6,
    ALLSEER_PRIV_OP_SETGROUPS = 7,
    ALLSEER_PRIV_OP_CAPSET    = 8,
    ALLSEER_PRIV_OP_UNSHARE   = 9,
    ALLSEER_PRIV_OP_SETNS     = 10,
    ALLSEER_PRIV_OP_SECCOMP   = 11,
};

/* Which groups of struct allseer_priv_payload hold values a probe observed,
 * OR'd together into `fields_present`.
 *
 * This exists because the most consequential values in that payload have no
 * spare encoding left to say "not filled". uid 0 is root and is also what an
 * unwritten field holds. gid 0 is the same. An all-zero capability set is a task
 * holding no capabilities and is also a read that failed. Without an explicit
 * statement of what was observed, the single most important transition this
 * record can carry — a process arriving at uid 0 — is indistinguishable from a
 * record that carried no identity at all.
 *
 * The device is not new here. allseer_maps.h reaches for the same one at the
 * foot of the file, where struct allseer_net_payload "cannot say that an address
 * field was never filled" and sixteen zero bytes under AF_INET are the wildcard
 * 0.0.0.0 rather than an absence. internal/risk/privilege.go documents what
 * going without it costs: UIDTransitionAmbiguous exists solely because zero
 * means two incompatible things at once, and it is described there as "the
 * honest answer to the most important privilege transition there is".
 *
 * The bits are per read group and not per field, because that is the granularity
 * a probe actually has. ALLSEER_PRIV_FIELD_BEFORE_CRED covers all eight identity
 * fields, all five capability sets and securebits together: they come from one
 * read of task->cred, which either succeeded or did not, and splitting them
 * would advertise a distinction the probe cannot make. It also groups them
 * correctly on causation — the kernel recalculates capabilities across a uid
 * transition, so a setuid away from root drops capabilities as a side effect,
 * and identity and capability are one event as well as one read. The user
 * namespace, the supplementary group count and the seccomp mode each get their
 * own pair of bits because each is a further dereference that can fail on its
 * own: cred->user_ns, cred->group_info and task->seccomp respectively.
 *
 * Values are decimal powers of two, and that is a constraint rather than a
 * style. internal/telemetry/abigen parses enum values with strconv.Atoi, so
 * neither 0x100 nor (1 << 8) is accepted, and it emits every enum as a Go uint32,
 * so bit 31 is the ceiling. Twenty-three bits remain. */
enum allseer_priv_field {
    ALLSEER_PRIV_FIELD_BEFORE_CRED    = 1,
    ALLSEER_PRIV_FIELD_AFTER_CRED     = 2,
    ALLSEER_PRIV_FIELD_BEFORE_USERNS  = 4,
    ALLSEER_PRIV_FIELD_AFTER_USERNS   = 8,
    ALLSEER_PRIV_FIELD_BEFORE_GROUPS  = 16,
    ALLSEER_PRIV_FIELD_AFTER_GROUPS   = 32,
    ALLSEER_PRIV_FIELD_BEFORE_SECCOMP = 64,
    ALLSEER_PRIV_FIELD_AFTER_SECCOMP  = 128,
    ALLSEER_PRIV_FIELD_NS_FLAGS       = 256,
};

/* Process identity, captured at event time. Read in the kernel because
 * consulting /proc afterwards races with process exit and returns nothing for
 * short-lived processes, which are the ones worth watching. */
struct allseer_proc {
    __u64 cgroup_id;    /* primary attribution key; survives PID reuse */
    __u64 start_time;   /* with pid, uniquely identifies a process per boot */
    __u32 pid;
    __u32 tid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u32 _pad;
    char  comm[ALLSEER_COMM_LEN];
};

struct allseer_file_payload {
    __u64 inode;
    __u64 device;
    __s64 bytes;
    __u32 flags;
    __u32 mode;
    char  path[ALLSEER_PATH_MAX];
    char  new_path[ALLSEER_PATH_MAX];  /* rename/link destination */
};

struct allseer_net_payload {
    __u8  saddr[16];        /* v4 addresses occupy the first 4 bytes */
    __u8  daddr[16];
    __s64 bytes;
    __u16 sport;
    __u16 dport;
    __u16 family;           /* AF_INET, AF_INET6, AF_UNIX */
    __u16 protocol;         /* IPPROTO_TCP, IPPROTO_UDP */
    __u16 sock_type;
    __u16 _pad;
};

struct allseer_exec_payload {
    __u32 argc;
    __u32 _pad;
    char  filename[ALLSEER_PATH_MAX];
    char  argv[ALLSEER_ARGV_MAX][ALLSEER_ARG_LEN];
    /* Environment values are never captured. They routinely hold credentials,
     * and an audit log is the last place those should land. Key names, if ever
     * needed, are collected in user space from /proc. */
};

/* One snapshot of a task's privilege state.
 *
 * Declared once and used twice, as `before` and `after` below. That is the whole
 * point of it being a struct: the two have to be the same shape to be
 * comparable, and one declaration used twice makes that true by construction
 * rather than by a reviewer checking two parallel lists of fields against each
 * other. allseer_maps.h makes the same argument for the scratch prologue, where
 * a field inserted into one struct's head and not the other's must stop the
 * build instead of quietly giving two probes different ideas of where identity
 * lives.
 *
 * # Capabilities: five sets, absolute, both sides
 *
 * All five, because they answer different questions. `effective` is what the
 * task may do at this instant. `permitted` is the ceiling it can raise effective
 * to with no exec, so it is the escalation *potential* rather than its exercise.
 * `inheritable` and `ambient` are what survives an exec, and ambient is the one
 * that grants capabilities across an exec of a file that carries none.
 * `bounding` can only ever shrink, so a drop is a sandbox narrowing itself and
 * its absence in a process claiming to be hardened is the interesting reading.
 *
 * Absolute sets and not a delta. A delta answers "what changed" and destroys
 * "what does this task hold now", and the second is the question a governance
 * decision actually asks. Subtraction is cheap in user space; the operand a
 * delta discarded is not recoverable there. internal/risk/privilege.go states
 * the defect this closes from the other side: "A delta needs a before and an
 * after. The repository has neither."
 *
 * __u64 per set, and this is correct on every kernel rather than only on recent
 * ones. Linux 6.3 replaced `struct kernel_cap_struct { __u32 cap[2]; }` with
 * `struct { u64 val; }`, and the two are byte-identical on a little-endian
 * target: cap[0] holds capabilities 0-31 in bytes 0-3 and cap[1] holds 32-63 in
 * bytes 4-7, which is exactly where bits 0-31 and 32-63 of the u64 sit. Both
 * targets this ABI is generated for are little-endian — internal/telemetry/
 * abigen states the model as LP64 little-endian — so no field here is contingent
 * on a kernel version. What does depend on the kernel is the *source expression*
 * a probe writes, because vmlinux.h is generated from the build host's BTF; that
 * is why the build host minimum is 6.3 and the runtime floor is unchanged at the
 * 5.8 the ring buffer already requires.
 *
 * # Identity: four views each, in init_user_ns
 *
 * setresuid sets three of the uid views in one call, so a single old/new pair
 * could not say which one moved. `effective` governs what is permitted, `real`
 * identifies the account, `saved` is what answers whether the change can be
 * undone, and `fs` is how a task reads another user's files without changing its
 * euid.
 *
 * Every one of them is an init_user_ns value. A kuid_t is namespace-independent
 * by construction and its `.val` is the init-namespace uid, which is also
 * exactly what bpf_get_current_uid_gid() returns — so uid_real here and
 * struct allseer_proc.uid are the same number and a record cannot disagree with
 * itself about who acted. The consequence is worth stating because it surprises:
 * a task inside a user namespace reports its *host* uid. A container's "root",
 * uid 0 as the container sees it, appears here as whatever it is on the host —
 * 100000, say — and that is the correct answer for a host-level governance
 * system rather than a bug in the field.
 *
 * # ngroups: a count, and only a count
 *
 * struct group_info carries `int ngroups` and a flexible array of kgid_t bounded
 * by NGROUPS_MAX, which is 65536. The list is not carried and will not be: a
 * bounded loop over even a prefix of it is verifier pressure paid on every
 * credential syscall for a field with no consumer, and the eBPF stack is 512
 * bytes against a worst case of 256 KiB.
 *
 * So the count answers what a count can. setgroups(0, NULL) — the classic step
 * that drops supplementary groups before dropping privilege, and whose *absence*
 * before a setuid is a textbook privilege-retention bug — is reported exactly,
 * as ngroups N to 0. A change that keeps the size, {100,200} to {100,300}, is
 * not visible here. It is not silent, though: `operation` still says the task
 * changed its supplementary groups and `ret` still says the kernel allowed it,
 * which is the granularity the rest of the system works at anyway —
 * internal/telemetry/resolve is explicit that for this domain "exercising the
 * capability is the whole observation", because a privilege event names no
 * resource.
 *
 * # userns_inum: a discriminator within one record, not an identity
 *
 * The user namespace is the only namespace here, because it is the only one that
 * lives in struct cred. The other seven hang off task->nsproxy and change what a
 * task can see rather than what it may do, which is a different claim from a
 * credential change.
 *
 * It is what makes the capability sets comparable at all. A capability set is
 * scoped to the namespace it was granted in: CAP_SYS_ADMIN in a child user
 * namespace is not CAP_SYS_ADMIN over the host, and unshare(CLONE_NEWUSER)
 * hands the caller a full set in the namespace it just created. A consumer that
 * compared `before` against `after` across such a call would read every one of
 * them as total capability escalation — and configs/rules.default.yaml blocks
 * priv.escalate terminally, so the result would be a hard block on every
 * containerized build step on the host. The sets are comparable only when
 * before.userns_inum equals after.userns_inum, and that condition is the reason
 * this field is in the payload.
 *
 * An inum is allocated from a shared IDA and is recycled once a namespace is
 * freed, so it is not a stable identity across a boot and two records carrying
 * the same value are not evidence of the same namespace. Within one record it is
 * sound for a structural reason rather than a probabilistic one: unshare
 * allocates the new namespace while the task still holds a reference to the old,
 * so the two cannot collide, and setns has the target pinned by the caller's fd.
 * Inequality within one record is reliable; equality across records is not an
 * identity claim.
 *
 * # seccomp_mode
 *
 * From task->seccomp rather than from cred: 0 disabled, 1 strict, 2 filtered.
 * The filter count is deliberately not carried beside it. It would separate "a
 * second filter was installed" from "seccomp(2) was asked a question" when the
 * mode is already 2, and that distinction sits below the granularity of the
 * capability catalog, which grades priv.seccomp as one kind and treats
 * exercising it as the whole observation. A seccomp call that changed nothing
 * arrives with the two snapshots equal and a non-negative `ret`, which says so.
 */
struct allseer_priv_state {
    __u64 cap_effective;
    __u64 cap_permitted;
    __u64 cap_inheritable;
    __u64 cap_ambient;
    __u64 cap_bounding;
    __u32 uid_real;
    __u32 uid_effective;
    __u32 uid_saved;
    __u32 uid_fs;
    __u32 gid_real;
    __u32 gid_effective;
    __u32 gid_saved;
    __u32 gid_fs;
    __u32 ngroups;      /* cred->group_info->ngroups; the list is not carried */
    __u32 securebits;
    __u32 userns_inum;  /* cred->user_ns->ns.inum; see the note above */
    __u32 seccomp_mode; /* task->seccomp.mode: 0 disabled, 1 strict, 2 filtered */
    __u32 _pad;
};

/* A credential operation, as two snapshots and what was asked for.
 *
 * `before` is read on the way into the syscall, ahead of any change; `after` on
 * the way out, once the kernel has answered. Both are filled on every record,
 * including one whose `ret` is negative, and filling `after` on a failure is the
 * point of it rather than waste: it turns "nothing changed" from an absence into
 * an assertion the record makes and a reader can check against `before`.
 *
 * struct allseer_event.ret keeps the meaning that struct already gives it and
 * needs no special case here. A non-negative return is a privilege change that
 * happened, and `after` differs from `before`. A negative return is one that was
 * attempted and refused: the kernel committed nothing, the two snapshots are
 * equal, and the errno says why. Both are emitted, because a failed action is a
 * governance signal in its own right — an agent that repeatedly fails to reach
 * uid 0 has said something about itself, on the same terms as the credential
 * -egress fixture where a read of a key that failed with ENOENT must not be
 * treated as a disclosure.
 *
 * `ns_flags` is the CLONE_* argument as the caller supplied it: unshare's flags,
 * setns's nstype. One field because both name the same vocabulary, and the
 * constants are Linux's rather than this file's, so they are named here and not
 * redefined — the same way struct allseer_net_payload names AF_INET and
 * IPPROTO_TCP without declaring them. It is zero, with its bit clear, for every
 * operation that is not a namespace one.
 *
 * Intent and effect are both carried because neither alone is enough. setns(fd,
 * 0) is legal and common and names no type at all, so only the userns_inum pair
 * can say what happened; and of the unshare flags only CLONE_NEWUSER touches
 * credentials, so an unshare(CLONE_NEWNET) leaves both snapshots identical and
 * ns_flags is the only thing in the record that reports it. Between them the two
 * cover both cases without either having to guess.
 *
 * 208 bytes against the payload union's 776, which struct allseer_exec_payload
 * sets. Deliberately well under it: struct allseer_event stays 856 bytes, so
 * this layout costs no ring buffer space, moves no offset outside this struct,
 * and leaves 568 bytes of headroom for a later privilege field to be appended
 * without a record-size change. */
struct allseer_priv_payload {
    struct allseer_priv_state before;
    struct allseer_priv_state after;
    __u32 operation;      /* enum allseer_priv_op */
    __u32 fields_present; /* enum allseer_priv_field, OR'd together */
    __u32 ns_flags;       /* CLONE_* as supplied; 0 when not a namespace op */
    __u32 _pad;
};

/* The record written to the ring buffer.
 *
 * version sits in the fixed header, ahead of proc and the payload union, and
 * must never move or change type. That position is the whole point of it: a
 * version a reader has to already know the layout to find cannot tell that
 * reader the layout is wrong. Everything up to and including this field is the
 * part of the record whose position is promised across versions; everything
 * after it is only meaningful once the version has been agreed.
 *
 * The explicit _pad after it is the same device the payload structs use. The
 * layout rules above call for largest-first ordering to avoid implicit padding,
 * and proc is 8-aligned, so the four bytes between version and proc exist
 * either way. Naming them means the C compiler and the generated Go decoder
 * agree about them rather than each deciding separately.
 *
 * TODO(bpf): a union of payloads keeps the record small but forces a
 * fixed-size worst-case reservation. Per-type ring buffers would be tighter but
 * multiply the reader complexity. Measure before choosing. */
struct allseer_event {
    __u64 timestamp;        /* bpf_ktime_get_ns(), monotonic since boot */
    __u32 type;             /* enum allseer_event_type */
    __s32 ret;              /* syscall return; negative is -errno */
    __u32 version;          /* ALLSEER_ABI_VERSION, as compiled into the probe */
    __u32 _pad;
    struct allseer_proc proc;

    union {
        struct allseer_file_payload file;
        struct allseer_net_payload  net;
        struct allseer_exec_payload exec;
        struct allseer_priv_payload priv;
    } payload;
};

/* Done: struct allseer_event carries a version field, and ALLSEER_ABI_VERSION
 * above is the value every probe writes into it.
 *
 * Done: that constant is also exposed from the compiled object, so a mismatch is
 * refused before a single program reaches the kernel. bpf/allseer.bpf.c declares
 * `allseer_abi_version` as a read-only global; telemetry.checkABIVersion reads it
 * out of the object's .rodata through the ELF symbol table and refuses to load on
 * a disagreement. The field in each record remains the backstop rather than the
 * mechanism — it reports the mismatch one event at a time, after the probes are
 * already running, which is later than the loader could have known — and
 * internal/telemetry/decode.go still checks it before it believes any other
 * field. The two are complements: the loader's check is per-object and free, the
 * decoder's is per-record and is the only one that can see a record at all. */

#endif /* __ALLSEER_EVENT_H */
