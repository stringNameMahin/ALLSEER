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
#define ALLSEER_ABI_VERSION  1

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

struct allseer_priv_payload {
    __u64 caps_effective;
    __u64 caps_permitted;
    __u32 old_uid;
    __u32 new_uid;
    __u32 operation;
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
 * TODO(bpf): expose that constant from the compiled object — a read-only global
 * the loader can read through BTF before it attaches anything — and refuse to
 * attach on a mismatch. The field in the record is the backstop, not the
 * mechanism: it reports the mismatch one event at a time, after the probes are
 * already running, which is later than the loader could have known. */

#endif /* __ALLSEER_EVENT_H */
