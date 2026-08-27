//go:build linux && ebpf

package telemetry

// Runtime tests for the eleven privilege pairs.
//
// The openat tests established the shape of these and the connect tests reused
// it; this file does the same. lockedThread, scratchKey, scratchEntry,
// collectUntil, trackThisCgroup, loadAndAttachPrograms, requireRoot and
// objectOrSkip all come from openat_linux_test.go and loader_linux_test.go.
//
// What privilege telemetry adds that neither of those had is that the syscalls
// under test change the credentials of the process running the test. Every
// transition here is therefore either performed on a thread the test owns and
// restored before that thread is released, or performed in a subprocess that
// exits immediately afterwards. Nothing touches the host's persistent
// configuration, and nothing leaves this process holding credentials it did not
// start with.
//
// The raw syscalls are made with syscall.RawSyscall and never with the
// syscall package's Setuid and friends. Since Go 1.16 those implement the POSIX
// whole-process semantics the kernel does not have, by signalling every thread
// to make the call itself — which is precisely the behaviour these probes are
// designed to observe one thread at a time, and precisely what a test asserting
// per-thread identity must not go through.

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/stringNameMahin/ALLSEER/internal/telemetry/abi"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
)

// CLONE_* values the tests pass to unshare and setns, and the seccomp and
// capability constants they need. Spelled out rather than taken from
// golang.org/x/sys, which this repository does not depend on.
const (
	cloneNewUserTest = 0x10000000
	cloneNewUTSTest  = 0x04000000

	seccompGetActionAvail = 2
	seccompActionAllow    = 0x7fff0000

	capVersion3 = 0x20080522
	capChownBit = 0 // CAP_CHOWN
)

// --- raw syscalls, made on a thread the test controls --------------------------

// rawPriv makes a syscall and returns 0 or a negative errno, which is the
// convention struct allseer_event.ret declares and the one the probe copies.
func rawPriv(nr uintptr, a1, a2, a3 uintptr) int {
	_, _, errno := syscall.RawSyscall(nr, a1, a2, a3)
	if errno != 0 {
		return -int(errno)
	}
	return 0
}

// priv runs one raw syscall on the pinned thread and returns its result.
func (lt *lockedThread) priv(nr uintptr, a1, a2, a3 uintptr) int {
	var ret int
	lt.do(func() { ret = rawPriv(nr, a1, a2, a3) })
	return ret
}

// capHeader and capData mirror the two structs capget and capset exchange.
type capHeader struct {
	version uint32
	pid     int32
}

type capData struct {
	effective   uint32
	permitted   uint32
	inheritable uint32
}

// capsOfSelf reads this thread's capability sets through capget(2).
func capsOfSelf(t *testing.T) (capHeader, [2]capData) {
	t.Helper()

	hdr := capHeader{version: capVersion3, pid: 0}
	var data [2]capData
	if ret := rawPriv(syscall.SYS_CAPGET,
		uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0); ret != 0 {
		t.Fatalf("capget: %v", syscall.Errno(-ret))
	}
	return hdr, data
}

// --- the privilege scratch map, from user space --------------------------------

// Offsets into struct allseer_priv_scratch, which allseer_maps.h declares.
//
// Written out rather than derived, for the reason the openat file gives about
// its own: this is the user-space mirror of a kernel-side struct that no
// generator covers, so the numbers are the test's own claim about the layout and
// privScratchMap checks the total against what the object reports.
const (
	privScratchTimestamp     = 0
	privScratchTaskStartTime = 8
	privScratchProc          = 16
	privScratchBefore        = 16 + abi.SizeofProc
	privScratchOperation     = privScratchBefore + abi.SizeofPrivState
	privScratchNsFlags       = privScratchOperation + 4
	privScratchFieldsPresent = privScratchOperation + 8
	privScratchSize          = privScratchOperation + 16
)

// privScratchMap returns priv_scratch, checking that it is the map the protocol
// describes before any test asserts on its contents.
func privScratchMap(t *testing.T, l *BPFLoader) *bpf.BPFMap {
	t.Helper()

	m, err := l.module.GetMap(MapPrivScratch)
	if err != nil {
		t.Fatalf("map %q: %v", MapPrivScratch, err)
	}
	if m.Type() != bpf.MapTypeLRUHash {
		t.Errorf("%s is a %s; allseer_maps.h declares an LRU hash, and a plain hash would stop "+
			"correlating privilege changes for good once orphans filled it", MapPrivScratch, m.Type())
	}
	if got, want := m.KeySize(), 8; got != want {
		t.Errorf("%s key is %d bytes, want %d for allseer_syscall_key_t; the key has to be the "+
			"thread, because every thread of a process can be inside setuid at once",
			MapPrivScratch, got, want)
	}
	if got := m.ValueSize(); got != privScratchSize {
		t.Fatalf("%s value is %d bytes, but this test reads struct allseer_priv_scratch as %d; "+
			"the struct changed and the offsets above have to change with it",
			MapPrivScratch, got, privScratchSize)
	}
	if got, want := m.MaxEntries(), uint32(1024); got != want {
		t.Errorf("%s holds %d entries, want ALLSEER_MAX_PRIV_SCRATCH = %d", MapPrivScratch, got, want)
	}
	return m
}

// requireNoPrivScratchEntry asserts that a thread has no half-built privilege
// change left behind.
//
// The assertion the deletion rule reduces to. An entry that outlives its syscall
// is invisible from the event stream, costs nothing until the map is full, and
// then silently stops privilege changes being observed at all.
func requireNoPrivScratchEntry(t *testing.T, m *bpf.BPFMap, key []byte, when string) {
	t.Helper()

	if _, err := m.GetValue(unsafe.Pointer(&key[0])); err == nil {
		t.Errorf("a privilege scratch entry survived %s; the exit side must delete on every path "+
			"it finds one", when)
	} else if !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("looking up %s: %v", MapPrivScratch, err)
	}
}

// --- collecting privilege events -----------------------------------------------

// collectPrivs drains records for a bounded time and returns every privilege
// event a given thread produced.
//
// Filtered by TID rather than by PID, because the whole point of these probes is
// that a credential change belongs to the thread that made it. Filtering by PID
// would let one thread's event satisfy an assertion about another's, which is
// the confusion TestRuntimePrivEventsAreDistinguishablePerThread exists to rule
// out.
func collectPrivs(t *testing.T, records <-chan []byte, tid, want int, d time.Duration) []decoded {
	t.Helper()

	var got []decoded
	collectUntil(t, records, d, func(e decoded) bool {
		if e.event.Domain != capability.DomainPrivilege {
			return false
		}
		if int(e.raw.Proc.TID) != tid {
			return false
		}
		got = append(got, e)
		return len(got) >= want
	})
	return got
}

// onePriv drains for exactly one privilege event from a thread.
func onePriv(t *testing.T, records <-chan []byte, tid int, d time.Duration) decoded {
	t.Helper()

	got := collectPrivs(t, records, tid, 1, d)
	if len(got) != 1 {
		t.Fatalf("want 1 privilege event from tid %d, got %d", tid, len(got))
	}
	return got[0]
}

// attachPrivPairs brings a loader up with every privilege program and nothing
// else, so a record on the ring can only have come from one of them.
func attachPrivPairs(t *testing.T) (*BPFLoader, <-chan []byte) {
	t.Helper()
	return loadAndAttachPrograms(t, ProgPrivPairs()...)
}

// privOp reads the operation out of a decoded record.
func privOp(e decoded) abi.PrivOp { return abi.PrivOp(e.raw.Priv().Operation) }

// hasField reports whether a fields_present bit is set.
func hasField(e decoded, f abi.PrivField) bool {
	return e.raw.Priv().FieldsPresent&uint32(f) != 0
}

// --- a process that enters a user namespace -----------------------------------

// unshareUserNamespace starts a child that calls unshare(CLONE_NEWUSER), waits
// for it, and returns its PID.
//
// # Why the syscall cannot be made by this process, or by any Go process
//
// unshare(CLONE_NEWUSER) requires the caller to be single-threaded. ksys_unshare
// ORs CLONE_THREAD and CLONE_FS into the flags whenever CLONE_NEWUSER is
// present, and check_unshare_flags then refuses unless thread_group_empty(),
// so the call returns EINVAL for a caller with siblings. A Go program always has
// siblings — the runtime starts several Ms before main does — and
// runtime.LockOSThread does not help, because the restriction is about the
// thread group rather than about which thread is calling. The same gate closes
// setns(fd, CLONE_NEWUSER) for a Go process, by way of the CLONE_FS sharing
// between runtime threads. So there is no arrangement of goroutines, locked
// threads or re-executed test binaries that lets Go make this call itself.
//
// What works is a child that is single-threaded at the moment it calls. Go
// provides exactly that: SysProcAttr.Unshareflags makes the forked child issue
// unshare(2) with those flags after the clone and before the exec, and when
// CLONE_NEWUSER is among them the fork is a plain clone(SIGCHLD) rather than the
// usual CLONE_VM|CLONE_VFORK, so the child is a real process with one thread and
// its own fs_struct. The syscall it makes is an ordinary unshare(CLONE_NEWUSER)
// on a task inside the tracked cgroup, which is precisely what the probes are
// meant to observe.
//
// The child execs /bin/true only because it has to exec something; the event
// under test happens before that.
func unshareUserNamespace(t *testing.T) int {
	t.Helper()

	cmd := exec.Command("/bin/true")
	cmd.SysProcAttr = &syscall.SysProcAttr{Unshareflags: cloneNewUserTest}
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting a child in a new user namespace: %v", err)
	}
	pid := cmd.Process.Pid
	if err := cmd.Wait(); err != nil {
		t.Fatalf("the child failed to unshare into a new user namespace: %v", err)
	}
	return pid
}

// --- every operation, and the enum it produces ----------------------------------

// Each of the eleven syscalls produces a record carrying its own
// allseer_priv_op, and no two of them produce the same one.
//
// The single most important claim this feature makes. struct allseer_event
// carries no syscall identifier, so `operation` is the only thing that separates
// a setuid record from a capset one — and configs/rules.default.yaml blocks
// three of the five privilege capabilities terminally while not naming the other
// two at all, so an operation attributed to the wrong syscall decides the wrong
// action.
//
// Every call here is chosen to succeed and to change nothing that outlives it.
// The identity syscalls are given the credentials the thread already holds,
// which is a real call into the kernel's setuid path that commits the same
// values back; unshare is given no flags; setns is pointed at the namespace the
// caller is already in; seccomp is asked a question rather than told to install
// a filter. What is under test is the correlation and the operation, and none of
// those needs a transition to exercise it — the transitions are asserted
// separately below.
func TestRuntimePrivEveryOperationCarriesItsOwnEnum(t *testing.T) {
	l, records := attachPrivPairs(t)
	trackThisCgroup(t, l)
	thread := newLockedThread(t)

	utsFD := openSelfNS(t, "uts")
	defer syscall.Close(utsFD)

	var action uint32 = seccompActionAllow

	cases := []struct {
		name string
		op   abi.PrivOp
		kind capability.Kind
		call func() int
	}{
		{"setuid", abi.OpSetuid, capability.KindPrivSetuid, func() int {
			return thread.priv(syscall.SYS_SETUID, uintptr(os.Getuid()), 0, 0)
		}},
		{"setreuid", abi.OpSetreuid, capability.KindPrivSetuid, func() int {
			// -1 in both positions is the kernel's "leave this one alone".
			return thread.priv(syscall.SYS_SETREUID, ^uintptr(0), ^uintptr(0), 0)
		}},
		{"setresuid", abi.OpSetresuid, capability.KindPrivSetuid, func() int {
			return thread.priv(syscall.SYS_SETRESUID, ^uintptr(0), ^uintptr(0), ^uintptr(0))
		}},
		{"setgid", abi.OpSetgid, capability.KindPrivSetuid, func() int {
			return thread.priv(syscall.SYS_SETGID, uintptr(os.Getgid()), 0, 0)
		}},
		{"setregid", abi.OpSetregid, capability.KindPrivSetuid, func() int {
			return thread.priv(syscall.SYS_SETREGID, ^uintptr(0), ^uintptr(0), 0)
		}},
		{"setresgid", abi.OpSetresgid, capability.KindPrivSetuid, func() int {
			return thread.priv(syscall.SYS_SETRESGID, ^uintptr(0), ^uintptr(0), ^uintptr(0))
		}},
		{"setgroups", abi.OpSetgroups, capability.KindPrivSetuid, func() int {
			// The set this thread already has, written back unchanged.
			return setgroupsOfSelf(t, thread)
		}},
		{"capset", abi.OpCapset, capability.KindPrivCapSet, func() int {
			hdr, data := capsOfSelf(t)
			return thread.priv(syscall.SYS_CAPSET,
				uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0)
		}},
		{"unshare", abi.OpUnshare, capability.KindPrivNamespace, func() int {
			return thread.priv(syscall.SYS_UNSHARE, 0, 0, 0)
		}},
		{"setns", abi.OpSetns, capability.KindPrivNamespace, func() int {
			// Entering the UTS namespace this thread is already in: a real
			// setns that commits nothing.
			return thread.priv(sysSetns, uintptr(utsFD), cloneNewUTSTest, 0)
		}},
		{"seccomp", abi.OpSeccomp, capability.KindPrivSeccomp, func() int {
			return thread.priv(sysSeccomp, seccompGetActionAvail, 0,
				uintptr(unsafe.Pointer(&action)))
		}},
	}

	seen := make(map[abi.PrivOp]string, len(cases))
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if ret := c.call(); ret != 0 {
				t.Fatalf("%s returned %v; this test needs a call that succeeds", c.name, syscall.Errno(-ret))
			}
			e := onePriv(t, records, thread.tid, 2*time.Second)

			if got := privOp(e); got != c.op {
				t.Fatalf("operation = %s, want %s", got, c.op)
			}
			if prev, dup := seen[c.op]; dup {
				t.Fatalf("%s produced the same operation as %s", c.name, prev)
			}
			seen[c.op] = c.name

			if e.event.Capability != c.kind {
				t.Errorf("capability = %q, want %q", e.event.Capability, c.kind)
			}
			if !e.event.Result.Succeeded {
				t.Errorf("Succeeded = false on a call that returned 0")
			}
			if e.raw.Version != abi.ABIVersion {
				t.Errorf("version = %d, want %d", e.raw.Version, abi.ABIVersion)
			}
			if int(e.raw.Proc.PID) != os.Getpid() {
				t.Errorf("pid = %d, want %d", e.raw.Proc.PID, os.Getpid())
			}
			if e.raw.Proc.CgroupID == 0 {
				t.Error("cgroup_id = 0 on a record the filter admitted")
			}
		})
	}

	// Every enumerator the ABI declares apart from UNKNOWN was produced, which
	// is what makes the "no two the same" check above exhaustive rather than
	// merely consistent.
	for _, op := range abi.AllPrivOps() {
		if op == abi.OpUnknown {
			continue
		}
		if _, ok := seen[op]; !ok {
			t.Errorf("no syscall in this test produced %s; the ABI declares an operation "+
				"nothing emits", op)
		}
	}
}

// openSelfNS opens one of this thread's own namespace files.
func openSelfNS(t *testing.T, kind string) int {
	t.Helper()

	fd, err := syscall.Open("/proc/self/ns/"+kind, syscall.O_RDONLY, 0)
	if err != nil {
		t.Skipf("cannot open /proc/self/ns/%s: %v", kind, err)
	}
	return fd
}

// setgroupsOfSelf writes back the supplementary group set the thread already
// holds, which is a real setgroups that changes nothing.
func setgroupsOfSelf(t *testing.T, thread *lockedThread) int {
	t.Helper()

	groups, err := syscall.Getgroups()
	if err != nil {
		t.Fatalf("getgroups: %v", err)
	}
	if len(groups) == 0 {
		return thread.priv(syscall.SYS_SETGROUPS, 0, 0, 0)
	}
	gids := make([]uint32, len(groups))
	for i, g := range groups {
		gids[i] = uint32(g)
	}
	return thread.priv(syscall.SYS_SETGROUPS, uintptr(len(gids)), uintptr(unsafe.Pointer(&gids[0])), 0)
}

// --- the snapshots -------------------------------------------------------------

// A real uid transition is reported as a difference between the two snapshots,
// and the snapshots come from the kernel rather than from the syscall's
// arguments.
//
// This is the claim that makes the whole two-snapshot design worth its bytes.
// setresuid(-1, uid, -1) moves only the effective uid and leaves real and saved
// alone, and no argument in the call says so — a probe that had guessed "the
// new uid is the argument" would have reported all three as changed. The record
// has to show euid moving and the other two standing still.
//
// Reversible by construction: the saved uid stays 0, which is what lets the
// thread restore itself afterwards. The transition is performed on a thread this
// test owns and is undone before the thread is released.
func TestRuntimePrivSnapshotsReportTheRealTransition(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("dropping and restoring the effective uid needs root")
	}

	l, records := attachPrivPairs(t)
	trackThisCgroup(t, l)
	thread := newLockedThread(t)

	const dropTo = 65534 // nobody, on every distribution this runs on

	if ret := thread.priv(syscall.SYS_SETRESUID, ^uintptr(0), dropTo, ^uintptr(0)); ret != 0 {
		t.Fatalf("setresuid(-1, %d, -1): %v", dropTo, syscall.Errno(-ret))
	}
	t.Cleanup(func() {
		if ret := thread.priv(syscall.SYS_SETRESUID, ^uintptr(0), 0, ^uintptr(0)); ret != 0 {
			t.Fatalf("restoring euid: %v", syscall.Errno(-ret))
		}
	})

	e := onePriv(t, records, thread.tid, 2*time.Second)
	p := e.raw.Priv()

	if got := privOp(e); got != abi.OpSetresuid {
		t.Fatalf("operation = %s, want %s", got, abi.OpSetresuid)
	}
	if p.Before.UIDEffective != 0 {
		t.Errorf("before.uid_effective = %d, want 0", p.Before.UIDEffective)
	}
	if p.After.UIDEffective != dropTo {
		t.Errorf("after.uid_effective = %d, want %d", p.After.UIDEffective, dropTo)
	}
	// The two the call did not touch. A probe reading arguments instead of
	// kernel state would have moved these too.
	if p.Before.UIDReal != 0 || p.After.UIDReal != 0 {
		t.Errorf("uid_real = %d -> %d, want 0 -> 0; setresuid(-1, ...) leaves the real uid alone",
			p.Before.UIDReal, p.After.UIDReal)
	}
	if p.Before.UIDSaved != 0 || p.After.UIDSaved != 0 {
		t.Errorf("uid_saved = %d -> %d, want 0 -> 0", p.Before.UIDSaved, p.After.UIDSaved)
	}
	// fsuid follows euid in the kernel's setresuid path, which is a fact about
	// the kernel that only a read of the post-change state can report.
	if p.After.UIDFs != dropTo {
		t.Errorf("after.uid_fs = %d, want %d; fsuid follows euid", p.After.UIDFs, dropTo)
	}

	// proc.uid is the real uid from bpf_get_current_uid_gid, and before.uid_real
	// is cred->uid.val. The header says they are the same number by
	// construction; this is where that stops being a claim.
	if e.raw.Proc.UID != p.Before.UIDReal {
		t.Errorf("proc.uid = %d but before.uid_real = %d; a record disagreed with itself about "+
			"who acted", e.raw.Proc.UID, p.Before.UIDReal)
	}
}

// A gid transition is reported the same way, on the gid half of the snapshot.
func TestRuntimePrivSnapshotsReportGidTransition(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("dropping and restoring the effective gid needs root")
	}

	l, records := attachPrivPairs(t)
	trackThisCgroup(t, l)
	thread := newLockedThread(t)

	const dropTo = 65534

	if ret := thread.priv(syscall.SYS_SETRESGID, ^uintptr(0), dropTo, ^uintptr(0)); ret != 0 {
		t.Fatalf("setresgid(-1, %d, -1): %v", dropTo, syscall.Errno(-ret))
	}
	t.Cleanup(func() {
		if ret := thread.priv(syscall.SYS_SETRESGID, ^uintptr(0), 0, ^uintptr(0)); ret != 0 {
			t.Fatalf("restoring egid: %v", syscall.Errno(-ret))
		}
	})

	e := onePriv(t, records, thread.tid, 2*time.Second)
	p := e.raw.Priv()

	if got := privOp(e); got != abi.OpSetresgid {
		t.Fatalf("operation = %s, want %s", got, abi.OpSetresgid)
	}
	if p.Before.GIDEffective != 0 || p.After.GIDEffective != dropTo {
		t.Errorf("gid_effective = %d -> %d, want 0 -> %d",
			p.Before.GIDEffective, p.After.GIDEffective, dropTo)
	}
	if p.Before.GIDReal != 0 || p.After.GIDReal != 0 {
		t.Errorf("gid_real = %d -> %d, want 0 -> 0", p.Before.GIDReal, p.After.GIDReal)
	}
	// The uid half must not move on a gid call.
	if p.Before.UIDEffective != p.After.UIDEffective {
		t.Errorf("uid_effective moved %d -> %d on a setresgid",
			p.Before.UIDEffective, p.After.UIDEffective)
	}
}

// setgroups is reported through ngroups, which is the only thing the ABI carries
// about the supplementary set.
//
// The count changing is what the record can say; the membership changing at a
// constant count is what it cannot, and that limit was decided in the ABI rather
// than here. This asserts the half that exists.
func TestRuntimePrivSetgroupsReportsGroupCount(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("setgroups needs CAP_SETGID")
	}

	l, records := attachPrivPairs(t)
	trackThisCgroup(t, l)
	thread := newLockedThread(t)

	original, err := syscall.Getgroups()
	if err != nil {
		t.Fatalf("getgroups: %v", err)
	}
	t.Cleanup(func() { restoreGroups(t, thread, original) })

	// Drop to none, which is the transition that matters: it is the step a
	// process takes before dropping privilege, and failing to take it is a
	// textbook privilege-retention bug.
	if ret := thread.priv(syscall.SYS_SETGROUPS, 0, 0, 0); ret != 0 {
		t.Fatalf("setgroups(0, NULL): %v", syscall.Errno(-ret))
	}

	e := onePriv(t, records, thread.tid, 2*time.Second)
	p := e.raw.Priv()

	if got := privOp(e); got != abi.OpSetgroups {
		t.Fatalf("operation = %s, want %s", got, abi.OpSetgroups)
	}
	if !hasField(e, abi.FieldBeforeGroups) || !hasField(e, abi.FieldAfterGroups) {
		t.Fatalf("fields_present = %#x; both group bits must be set when group_info was read",
			p.FieldsPresent)
	}
	if p.After.Ngroups != 0 {
		t.Errorf("after.ngroups = %d, want 0 after setgroups(0, NULL)", p.After.Ngroups)
	}
	if p.Before.Ngroups != uint32(len(original)) {
		t.Errorf("before.ngroups = %d, want %d", p.Before.Ngroups, len(original))
	}
}

func restoreGroups(t *testing.T, thread *lockedThread, groups []int) {
	t.Helper()

	if len(groups) == 0 {
		return
	}
	gids := make([]uint32, len(groups))
	for i, g := range groups {
		gids[i] = uint32(g)
	}
	if ret := thread.priv(syscall.SYS_SETGROUPS,
		uintptr(len(gids)), uintptr(unsafe.Pointer(&gids[0])), 0); ret != 0 {
		t.Fatalf("restoring groups: %v", syscall.Errno(-ret))
	}
}

// capset is reported as a change between the two capability snapshots, read from
// the kernel and not from the caller's buffer.
//
// The probe never reads the struct capset was given. It does not have to: the
// before snapshot holds the sets as they were and the after snapshot holds them
// as they became, so what changed is a subtraction rather than an interpretation
// of a user-space pointer that could have been freed under it.
func TestRuntimePrivCapsetReportsCapabilityChange(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("changing this thread's capability sets needs root")
	}

	l, records := attachPrivPairs(t)
	trackThisCgroup(t, l)
	thread := newLockedThread(t)

	hdr, original := capsOfSelf(t)
	if original[0].effective&(1<<capChownBit) == 0 {
		t.Skip("this thread does not hold CAP_CHOWN, so dropping it proves nothing")
	}

	t.Cleanup(func() {
		restore := original
		if ret := thread.priv(syscall.SYS_CAPSET,
			uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&restore[0])), 0); ret != 0 {
			t.Fatalf("restoring capabilities: %v", syscall.Errno(-ret))
		}
	})

	dropped := original
	dropped[0].effective &^= 1 << capChownBit
	if ret := thread.priv(syscall.SYS_CAPSET,
		uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&dropped[0])), 0); ret != 0 {
		t.Fatalf("capset: %v", syscall.Errno(-ret))
	}

	e := onePriv(t, records, thread.tid, 2*time.Second)
	p := e.raw.Priv()

	if got := privOp(e); got != abi.OpCapset {
		t.Fatalf("operation = %s, want %s", got, abi.OpCapset)
	}
	if p.Before.CapEffective&(1<<capChownBit) == 0 {
		t.Errorf("before.cap_effective = %#x; CAP_CHOWN was held before the call", p.Before.CapEffective)
	}
	if p.After.CapEffective&(1<<capChownBit) != 0 {
		t.Errorf("after.cap_effective = %#x; CAP_CHOWN was dropped by the call", p.After.CapEffective)
	}
	// Permitted was not touched, so the two sets must now differ — which is
	// also what makes the effective read above a read rather than a copy.
	if p.After.CapPermitted&(1<<capChownBit) == 0 {
		t.Errorf("after.cap_permitted = %#x; capset dropped CAP_CHOWN from effective only",
			p.After.CapPermitted)
	}
	// A drop is not an addition, and the decoder must not report one.
	if len(e.event.Privil.CapabilitiesAdded) != 0 {
		t.Errorf("CapabilitiesAdded = %v on a call that only dropped a capability",
			e.event.Privil.CapabilitiesAdded)
	}
}

// --- namespaces -----------------------------------------------------------------

// unshare and setns carry the CLONE_* word the caller supplied, and say so
// through fields_present.
func TestRuntimePrivNamespaceFlags(t *testing.T) {
	l, records := attachPrivPairs(t)
	trackThisCgroup(t, l)
	thread := newLockedThread(t)

	utsFD := openSelfNS(t, "uts")
	defer syscall.Close(utsFD)

	t.Run("setns carries nstype", func(t *testing.T) {
		if ret := thread.priv(sysSetns, uintptr(utsFD), cloneNewUTSTest, 0); ret != 0 {
			t.Fatalf("setns: %v", syscall.Errno(-ret))
		}
		e := onePriv(t, records, thread.tid, 2*time.Second)
		if got := privOp(e); got != abi.OpSetns {
			t.Fatalf("operation = %s, want %s", got, abi.OpSetns)
		}
		if !hasField(e, abi.FieldNsFlags) {
			t.Error("fields_present does not carry NS_FLAGS on a setns")
		}
		if got := e.raw.Priv().NsFlags; got != cloneNewUTSTest {
			t.Errorf("ns_flags = %#x, want CLONE_NEWUTS %#x", got, cloneNewUTSTest)
		}
		if e.event.Privil.NamespaceType != "uts" {
			t.Errorf("NamespaceType = %q, want %q", e.event.Privil.NamespaceType, "uts")
		}
	})

	t.Run("unshare with no flags names nothing", func(t *testing.T) {
		if ret := thread.priv(syscall.SYS_UNSHARE, 0, 0, 0); ret != 0 {
			t.Fatalf("unshare(0): %v", syscall.Errno(-ret))
		}
		e := onePriv(t, records, thread.tid, 2*time.Second)
		if got := privOp(e); got != abi.OpUnshare {
			t.Fatalf("operation = %s, want %s", got, abi.OpUnshare)
		}
		// The bit is set and the value is zero: the caller named no namespace,
		// which is different from the probe not having captured the argument.
		if !hasField(e, abi.FieldNsFlags) {
			t.Error("fields_present does not carry NS_FLAGS on an unshare")
		}
		if got := e.raw.Priv().NsFlags; got != 0 {
			t.Errorf("ns_flags = %#x, want 0", got)
		}
		if e.event.Privil.NamespaceType != "" {
			t.Errorf("NamespaceType = %q, want empty", e.event.Privil.NamespaceType)
		}
	})
}

// unshare(CLONE_NEWUSER) does not become a capability-escalation signal.
//
// Creating a user namespace hands the caller a full capability set inside the
// namespace it just created — set_cred_user_ns writes CAP_FULL_SET into
// permitted, effective and the bounding set, and empties inheritable and
// ambient. configs/rules.default.yaml blocks priv.escalate terminally, so a
// consumer that subtracted the two snapshots across that call would hard-block
// every containerized build step on the host.
//
// # What this test proves, and what proves the rest
//
// The guard has two halves and they are testable in different places, so this
// test deliberately covers one of them.
//
// The probe's half is the input condition: report a userns inode on both sides,
// set both presence bits, and let the two differ when the namespace really
// changed. That is what a kernel can be asked for and what a BPF bug would
// break, so it is asserted here.
//
// The decoder's half is the response to that input — withholding the delta when
// the inodes differ. Asserting it *here* is not possible against a root caller,
// and the reason is worth stating rather than leaving as a weak assertion: root
// already holds CAP_FULL_SET before the call, so the after snapshot is not a
// gain over the before one and `after &^ before` is zero whether the guard
// exists or not. A test that read a passing result as proof of the guard would
// be reading a tautology. The case where the sets genuinely appear to grow needs
// a before-state the kernel will not hand a root caller, so it is constructed
// directly in TestDecodePrivilegeComputesCapabilityDelta — the
// "a user namespace change withholds the delta" subtest, which feeds the decoder
// before=0, after=nearly-everything and differing inodes.
//
// CapabilitiesAdded is still asserted empty below. It is necessary rather than
// sufficient, and it is the regression that would fire if the probe ever stopped
// reporting the inode change this test's other assertions pin down.
func TestRuntimePrivUserNamespaceProducesNoFalseCapabilityDelta(t *testing.T) {
	l, records := attachPrivPairs(t)
	trackThisCgroup(t, l)

	pid := unshareUserNamespace(t)

	var got *decoded
	collectUntil(t, records, 5*time.Second, func(e decoded) bool {
		if e.event.Domain != capability.DomainPrivilege {
			return false
		}
		if int(e.raw.Proc.PID) != pid || privOp(e) != abi.OpUnshare {
			return false
		}
		got = &e
		return true
	})
	if got == nil {
		t.Fatalf("no unshare event from the child (pid %d)", pid)
	}
	p := got.raw.Priv()

	if p.NsFlags != cloneNewUserTest {
		t.Errorf("ns_flags = %#x, want CLONE_NEWUSER %#x", p.NsFlags, cloneNewUserTest)
	}
	if !hasField(*got, abi.FieldBeforeUserns) || !hasField(*got, abi.FieldAfterUserns) {
		t.Fatalf("fields_present = %#x; both userns bits must be set, or the decoder cannot "+
			"tell that the two capability sets are incomparable", p.FieldsPresent)
	}
	if p.Before.UsernsInum == p.After.UsernsInum {
		t.Fatalf("userns_inum = %d -> %d; unshare(CLONE_NEWUSER) must land in a different "+
			"namespace", p.Before.UsernsInum, p.After.UsernsInum)
	}

	// Recorded rather than asserted, because which way it goes depends on the
	// caller's credentials and not on the code under test. A root caller
	// already holds CAP_FULL_SET, so the new namespace grants it nothing it
	// lacked and this is zero; an unprivileged caller would see it become
	// nearly every capability in Linux. Only the second is a case where the
	// assertion below could fail for the right reason, which is why the
	// decoder-side proof lives in a unit test that can construct it.
	t.Logf("cap_effective across the transition: before %#x, after %#x, naive delta %#x",
		p.Before.CapEffective, p.After.CapEffective,
		p.After.CapEffective&^p.Before.CapEffective)

	if got.event.Privil == nil {
		t.Fatal("a privilege event carried no privilege payload")
	}
	if len(got.event.Privil.CapabilitiesAdded) != 0 {
		t.Errorf("CapabilitiesAdded = %v across a user-namespace transition; capability sets "+
			"from two namespaces are not the same quantity, and reporting a delta here would "+
			"hard-block every container on the host",
			got.event.Privil.CapabilitiesAdded)
	}
	if got.event.Capability != capability.KindPrivNamespace {
		t.Errorf("capability = %q, want %q", got.event.Capability, capability.KindPrivNamespace)
	}
}

// --- failure --------------------------------------------------------------------

// A refused privilege change is a record, not a silence, and it says the two
// snapshots are equal.
//
// The ABI's attempted-change semantics, asserted end to end. A negative ret
// means the kernel committed nothing, so `after` must equal `before` — and the
// record saying so is a stronger statement than the record being absent. An
// agent repeatedly failing to reach uid 0 has said something about itself.
func TestRuntimePrivFailedSyscallIsReportedAsAnAttempt(t *testing.T) {
	l, records := attachPrivPairs(t)
	trackThisCgroup(t, l)
	thread := newLockedThread(t)

	// setns on a descriptor that is not open. It fails in the kernel before any
	// credential is touched, which is exactly the shape being asserted.
	ret := thread.priv(sysSetns, ^uintptr(0), cloneNewUTSTest, 0)
	if ret != -int(syscall.EBADF) {
		t.Fatalf("setns(-1, CLONE_NEWUTS) = %d, want -EBADF", ret)
	}

	e := onePriv(t, records, thread.tid, 2*time.Second)
	p := e.raw.Priv()

	if got := privOp(e); got != abi.OpSetns {
		t.Fatalf("operation = %s, want %s", got, abi.OpSetns)
	}
	if e.event.Result.Succeeded {
		t.Error("Succeeded = true on a syscall that returned -EBADF")
	}
	if e.event.Result.Errno != "EBADF" {
		t.Errorf("Errno = %q, want EBADF", e.event.Result.Errno)
	}
	if e.event.Result.ReturnCode != int64(-int(syscall.EBADF)) {
		t.Errorf("ReturnCode = %d, want %d", e.event.Result.ReturnCode, -int(syscall.EBADF))
	}
	if p.Before != p.After {
		t.Errorf("the snapshots differ across a syscall the kernel refused:\nbefore %+v\nafter  %+v",
			p.Before, p.After)
	}
	// The capability is the one that was attempted. A failed action is a
	// governance signal in its own right and must not be downgraded.
	if e.event.Capability != capability.KindPrivNamespace {
		t.Errorf("capability = %q, want %q", e.event.Capability, capability.KindPrivNamespace)
	}

	requireNoPrivScratchEntry(t, privScratchMap(t, l), scratchKey(os.Getpid(), thread.tid),
		"a privilege syscall the kernel refused")
}

// --- fields_present ---------------------------------------------------------------

// Every group the probe can read is reported as read, on both sides.
//
// fields_present is what separates "this field holds zero" from "this field was
// never filled", and the header is explicit that without it the most important
// transition the record can carry — a process arriving at uid 0 — would be
// indistinguishable from a record that carried no identity at all. On a live
// task every group is reachable, so this is the case where all eight bits must
// be set; a bit missing here would mean the probe silently failed a read.
func TestRuntimePrivFieldsPresentReportsEveryGroup(t *testing.T) {
	l, records := attachPrivPairs(t)
	trackThisCgroup(t, l)
	thread := newLockedThread(t)

	if ret := thread.priv(syscall.SYS_SETRESUID, ^uintptr(0), ^uintptr(0), ^uintptr(0)); ret != 0 {
		t.Fatalf("setresuid(-1,-1,-1): %v", syscall.Errno(-ret))
	}
	e := onePriv(t, records, thread.tid, 2*time.Second)

	for _, f := range []abi.PrivField{
		abi.FieldBeforeCred, abi.FieldAfterCred,
		abi.FieldBeforeUserns, abi.FieldAfterUserns,
		abi.FieldBeforeGroups, abi.FieldAfterGroups,
		abi.FieldBeforeSeccomp, abi.FieldAfterSeccomp,
	} {
		if !hasField(e, f) {
			t.Errorf("fields_present is missing %s (= %#x); the probe read every group on a "+
				"live task, so a clear bit means a read silently failed", f, uint32(f))
		}
	}
	// NS_FLAGS is the one bit that must NOT be set: setresuid has no namespace
	// argument, and a bit set here would be the probe claiming to have captured
	// something the syscall never carried.
	if hasField(e, abi.FieldNsFlags) {
		t.Error("fields_present carries NS_FLAGS on a setresuid, which has no CLONE_* argument")
	}
	if got := e.raw.Priv().NsFlags; got != 0 {
		t.Errorf("ns_flags = %#x on a setresuid, want 0", got)
	}
}

// --- per-thread identity ------------------------------------------------------------

// Two threads changing credentials produce two records that name them apart.
//
// Credentials on Linux are per-task, so proc_exit's leader-only filter would be
// wrong here: a worker thread's setuid is a real credential change on a real
// task, and collapsing it into the group leader's identity would lose it. Both
// records carry this process's pid and each carries its own tid, which is what
// struct allseer_proc declares those fields to mean.
func TestRuntimePrivEventsAreDistinguishablePerThread(t *testing.T) {
	l, records := attachPrivPairs(t)
	trackThisCgroup(t, l)

	a := newLockedThread(t)
	b := newLockedThread(t)
	if a.tid == b.tid {
		t.Fatal("the two locked threads share a TID")
	}

	var wg sync.WaitGroup
	for _, th := range []*lockedThread{a, b} {
		wg.Add(1)
		go func(th *lockedThread) {
			defer wg.Done()
			if ret := th.priv(syscall.SYS_SETRESUID, ^uintptr(0), ^uintptr(0), ^uintptr(0)); ret != 0 {
				t.Errorf("setresuid on tid %d: %v", th.tid, syscall.Errno(-ret))
			}
		}(th)
	}
	wg.Wait()

	seen := map[uint32]int{}
	collectUntil(t, records, 3*time.Second, func(e decoded) bool {
		if e.event.Domain != capability.DomainPrivilege {
			return false
		}
		if privOp(e) != abi.OpSetresuid {
			return false
		}
		if e.raw.Proc.TID == uint32(a.tid) || e.raw.Proc.TID == uint32(b.tid) {
			seen[e.raw.Proc.TID]++
		}
		return len(seen) == 2
	})

	if len(seen) != 2 {
		t.Fatalf("saw records from %d of the 2 threads (%v); a per-thread credential change "+
			"must not be collapsed by TGID", len(seen), seen)
	}
	for tid, n := range seen {
		if n != 1 {
			t.Errorf("tid %d produced %d records for one syscall, want 1", tid, n)
		}
	}

	// Both name the same process. The tid is what separates them; the pid is
	// what joins them to the exec and exit records for the same process.
	collectUntil(t, records, 10*time.Millisecond, func(decoded) bool { return false })
}

// --- the filter -----------------------------------------------------------------

// A privilege change in a cgroup nobody declared produces nothing at all.
//
// The invariant every probe in this object carries, asserted for the eleven new
// ones. It is checked before the tracked case rather than after, so a failure
// cannot be explained by a stale record from an earlier phase.
func TestRuntimeUntrackedCgroupProducesNoPrivEvent(t *testing.T) {
	l, records := attachPrivPairs(t)
	thread := newLockedThread(t)

	if ret := thread.priv(syscall.SYS_SETRESUID, ^uintptr(0), ^uintptr(0), ^uintptr(0)); ret != 0 {
		t.Fatalf("setresuid: %v", syscall.Errno(-ret))
	}

	if got := collectPrivs(t, records, thread.tid, 1, 500*time.Millisecond); len(got) != 0 {
		t.Fatalf("a privilege change in an untracked cgroup produced %d event(s); no untracked "+
			"cgroup may ever be observed", len(got))
	}
	// Nothing was stored either: the filter runs before the scratch write, so a
	// filtered call costs a hash lookup and a return.
	requireNoPrivScratchEntry(t, privScratchMap(t, l), scratchKey(os.Getpid(), thread.tid),
		"a privilege syscall the cgroup filter rejected")

	// And the same call, once the cgroup is declared, does produce one — which
	// is what rules out the probe simply being broken.
	trackThisCgroup(t, l)
	if ret := thread.priv(syscall.SYS_SETRESUID, ^uintptr(0), ^uintptr(0), ^uintptr(0)); ret != 0 {
		t.Fatalf("setresuid: %v", syscall.Errno(-ret))
	}
	if got := collectPrivs(t, records, thread.tid, 1, 2*time.Second); len(got) != 1 {
		t.Fatalf("the same call in a tracked cgroup produced %d event(s), want 1", len(got))
	}
}

// --- the seam between the two programs --------------------------------------------

// The scratch entry exists between the two halves and is gone after a successful
// one.
func TestRuntimePrivScratchIsDeletedAfterSuccess(t *testing.T) {
	l, records := attachPrivPairs(t)
	trackThisCgroup(t, l)
	thread := newLockedThread(t)

	if ret := thread.priv(syscall.SYS_SETRESUID, ^uintptr(0), ^uintptr(0), ^uintptr(0)); ret != 0 {
		t.Fatalf("setresuid: %v", syscall.Errno(-ret))
	}
	onePriv(t, records, thread.tid, 2*time.Second)

	requireNoPrivScratchEntry(t, privScratchMap(t, l), scratchKey(os.Getpid(), thread.tid),
		"a privilege syscall that succeeded")
}

// An exit with no entry emits nothing and fabricates nothing.
//
// Rule 3 of the protocol: what the exit side has on its own is a return value
// and no idea what produced it. Only the exit programs are attached here, so
// every credential syscall the test makes reaches a program that has no entry to
// find.
func TestRuntimePrivExitWithoutEntryProducesNoEvent(t *testing.T) {
	l, records := loadAndAttachPrograms(t,
		ProgPrivSetresuidExit, ProgPrivSetnsExit, ProgPrivUnshareExit)
	trackThisCgroup(t, l)
	thread := newLockedThread(t)

	if ret := thread.priv(syscall.SYS_SETRESUID, ^uintptr(0), ^uintptr(0), ^uintptr(0)); ret != 0 {
		t.Fatalf("setresuid: %v", syscall.Errno(-ret))
	}
	if ret := thread.priv(syscall.SYS_UNSHARE, 0, 0, 0); ret != 0 {
		t.Fatalf("unshare(0): %v", syscall.Errno(-ret))
	}

	if got := collectPrivs(t, records, thread.tid, 1, 500*time.Millisecond); len(got) != 0 {
		t.Fatalf("an exit program with no entry emitted %d event(s); it has a return value and "+
			"no idea what syscall produced it", len(got))
	}
	requireNoPrivScratchEntry(t, privScratchMap(t, l), scratchKey(os.Getpid(), thread.tid),
		"an exit with no entry")
}

// An entry written by one syscall is not completed by another's exit.
//
// The tag check a shared scratch map needs, and the reason allseer_maps.h says a
// shared map "would have needed a syscall tag and a check on it". Only the
// unshare entry program and the setresuid exit program are attached, so the
// unshare leaves an entry that no unshare exit will collect and the setresuid
// exit finds an entry whose operation is not its own.
//
// Without the check that exit would emit an unshare record carrying a
// setresuid's return.
func TestRuntimePrivMismatchedOperationIsRejectedAndDeleted(t *testing.T) {
	l, records := loadAndAttachPrograms(t, ProgPrivUnshareEnter, ProgPrivSetresuidExit)
	trackThisCgroup(t, l)
	thread := newLockedThread(t)

	// Leaves an entry tagged ALLSEER_PRIV_OP_UNSHARE, uncollected.
	if ret := thread.priv(syscall.SYS_UNSHARE, 0, 0, 0); ret != 0 {
		t.Fatalf("unshare(0): %v", syscall.Errno(-ret))
	}
	m := privScratchMap(t, l)
	key := scratchKey(os.Getpid(), thread.tid)
	v, err := m.GetValue(unsafe.Pointer(&key[0]))
	if err != nil {
		t.Fatalf("the unshare entry side stored nothing: %v", err)
	}
	if got := binary.NativeEndian.Uint32(v[privScratchOperation:]); got != uint32(abi.OpUnshare) {
		t.Fatalf("the stored operation is %d, want %d", got, abi.OpUnshare)
	}

	// A different syscall's exit runs on the same thread and finds it.
	if ret := thread.priv(syscall.SYS_SETRESUID, ^uintptr(0), ^uintptr(0), ^uintptr(0)); ret != 0 {
		t.Fatalf("setresuid: %v", syscall.Errno(-ret))
	}

	if got := collectPrivs(t, records, thread.tid, 1, 500*time.Millisecond); len(got) != 0 {
		t.Fatalf("an exit program completed another syscall's entry, emitting %d event(s); the "+
			"record would have carried one syscall's operation and another's return", len(got))
	}
	requireNoPrivScratchEntry(t, m, key, "an entry whose operation did not match the exit that found it")
}

// --- loss -------------------------------------------------------------------------

// The privilege pairs carry the drop-counting obligation and delete their
// scratch entry on that path too.
//
// Only privilege programs are attached and nothing drains the one-page ring, so
// every counted drop is a record a privilege exit wanted to emit. The second
// assertion is the one this test exists for: a failed reservation is the
// terminal path most likely to be written as a bare return, and an entry left
// behind there accumulates precisely when the host is already losing records.
func TestRuntimePrivProbeCountsDropsAndStillDeletesScratch(t *testing.T) {
	requireRoot(t)
	obj := objectOrSkip(t)
	ctx := context.Background()

	l := NewLoader(Config{ObjectPath: obj, RingBufferSize: os.Getpagesize()}, nil)
	t.Cleanup(func() {
		if err := l.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	if err := l.Load(ctx, obj); err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, prog := range []string{ProgPrivSetresuidEnter, ProgPrivSetresuidExit} {
		if err := l.Attach(ctx, prog); err != nil {
			t.Fatalf("Attach %s: %v", prog, err)
		}
	}

	if n, err := l.ReadCounter(ctx, MapRingbufDrops); err != nil {
		t.Fatalf("ReadCounter: %v", err)
	} else if n != 0 {
		t.Fatalf("a freshly loaded object reports %d drops, want 0", n)
	}

	thread := newLockedThread(t)
	noop := func() {
		for range 64 {
			rawPriv(syscall.SYS_SETRESUID, ^uintptr(0), ^uintptr(0), ^uintptr(0))
		}
	}

	// Filtered: nothing tracked, so nothing is reserved and nothing is lost.
	thread.do(noop)
	if n, err := l.ReadCounter(ctx, MapRingbufDrops); err != nil {
		t.Fatalf("ReadCounter: %v", err)
	} else if n != 0 {
		t.Fatalf("64 privilege syscalls the cgroup filter rejected were counted as %d drop(s); "+
			"a filtered event is not a lost one", n)
	}

	trackThisCgroup(t, l)

	const burst = 512
	thread.do(func() {
		for range burst {
			rawPriv(syscall.SYS_SETRESUID, ^uintptr(0), ^uintptr(0), ^uintptr(0))
		}
	})

	dropped, err := l.ReadCounter(ctx, MapRingbufDrops)
	if err != nil {
		t.Fatalf("ReadCounter: %v", err)
	}
	if dropped == 0 {
		t.Fatalf("%d privilege syscalls into a %d-byte ring buffer nobody is draining produced 0 "+
			"counted drops; a privilege exit is losing records without calling "+
			"count_ringbuf_drop()", burst, os.Getpagesize())
	}
	t.Logf("burst of %d setresuid into a %d-byte ring, privilege probes only: %d records counted as lost",
		burst, os.Getpagesize(), dropped)

	requireNoPrivScratchEntry(t, privScratchMap(t, l), scratchKey(os.Getpid(), thread.tid),
		"a privilege change whose record could not be reserved")
}

// --- coexistence and lifecycle -------------------------------------------------------

// Every privilege program attaches and detaches together with the rest.
//
// Twenty-two programs is enough that an omission would be easy to miss, so this
// ranges over ProgPrivPairs rather than a list written here — the same list the
// production caller would use.
func TestRuntimePrivProgramsAttachAndDetachTogether(t *testing.T) {
	requireRoot(t)
	obj := objectOrSkip(t)
	ctx := context.Background()

	l := NewLoader(Config{ObjectPath: obj, RingBufferSize: 1 << 20}, nil)
	if err := l.Load(ctx, obj); err != nil {
		t.Fatalf("Load: %v", err)
	}

	pairs := ProgPrivPairs()
	if len(pairs) != 22 {
		t.Fatalf("ProgPrivPairs lists %d programs, want 22 for eleven syscalls", len(pairs))
	}
	for _, prog := range pairs {
		if err := l.Attach(ctx, prog); err != nil {
			t.Fatalf("Attach %s: %v", prog, err)
		}
	}
	// Attaching twice is refused, per the loader's contract.
	if err := l.Attach(ctx, pairs[0]); !errors.Is(err, ErrAlreadyAttached) {
		t.Errorf("re-attaching %s: err = %v, want ErrAlreadyAttached", pairs[0], err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close with %d privilege programs attached: %v", len(pairs), err)
	}
}

// The privilege programs share the object's one ring buffer with the probes that
// were there before them, and the payload union is read as the type each record
// declares.
//
// The object has one ring buffer and one filter map by design, and four record
// shapes now travel through them together. A privilege payload read as an exec
// filename, or an open path read as a credential snapshot, is the failure this
// rules out: they occupy the same bytes.
func TestRuntimePrivAndOtherProbesShareOneRingBuffer(t *testing.T) {
	l, records := loadAndAttachPrograms(t,
		ProgProcExec, ProgProcExit,
		ProgOpenatEnter, ProgOpenatExit,
		ProgPrivSetresuidEnter, ProgPrivSetresuidExit)
	trackThisCgroup(t, l)
	thread := newLockedThread(t)

	marker := openMarkerPath(t, "allseer-priv-coexist")
	thread.open(marker, syscall.O_RDONLY, 0)
	if ret := thread.priv(syscall.SYS_SETRESUID, ^uintptr(0), ^uintptr(0), ^uintptr(0)); ret != 0 {
		t.Fatalf("setresuid: %v", syscall.Errno(-ret))
	}
	path, _ := execMarker(t, "allseer-priv-coexist-exec")

	var sawOpen, sawPriv, sawExec bool
	collectUntil(t, records, 5*time.Second, func(e decoded) bool {
		switch {
		case e.event.File != nil && e.event.File.Path == marker:
			sawOpen = true
		case e.event.Domain == capability.DomainPrivilege &&
			int(e.raw.Proc.TID) == thread.tid:
			sawPriv = true
			// A privilege record must not carry another type's payload.
			if e.event.File != nil || e.event.Exec != nil || e.event.Network != nil {
				t.Error("a privilege record decoded with a non-privilege payload")
			}
		case e.event.Exec != nil && e.event.Exec.Filename == path:
			sawExec = true
		}
		return sawOpen && sawPriv && sawExec
	})

	if !sawOpen || !sawPriv || !sawExec {
		t.Fatalf("open %v, privilege %v, exec %v; all three shapes must survive one ring buffer",
			sawOpen, sawPriv, sawExec)
	}
}
