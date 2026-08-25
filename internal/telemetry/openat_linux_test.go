//go:build linux && ebpf

package telemetry

// Runtime tests for the openat pair.
//
// These are the first tests of a probe that is two programs rather than one,
// and most of what is asserted here is about the seam between them rather than
// about either half. An open event is only correct if the arguments captured at
// sys_enter and the return captured at sys_exit belong to the same syscall, made
// by the same thread, in the cgroup that admitted it — and every way of getting
// that wrong produces an event that arrives, decodes, and reads as ordinary.
//
// Same tag and the same skip discipline as loader_linux_test.go: without root
// none of this can run, and each test says so rather than passing vacuously.
//
// # The test-only map access
//
// Several tests below read and write `openat_scratch` directly, through
// l.module. That is deliberately not available on Loader, and
// telemetry.MapOpenatScratch says why: a user-space write into the scratch map
// is a fabricated syscall entry, and the exit side would complete it into a
// real-looking event. Nothing in the daemon should be able to do that.
//
// The tests do it because two of the contract's claims are claims about the map
// and cannot be observed from the event stream at all. "The entry is deleted on
// every terminal path" is invisible from outside — a leak looks exactly like
// correct behaviour until the map fills — and "a stale entry is rejected rather
// than completed" needs a stale entry to exist, which no sequence of ordinary
// syscalls can produce on demand. These live in the test package, on an
// unexported field, and nothing outside this file uses them.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"context"
	"encoding/binary"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/stringNameMahin/ALLSEER/internal/telemetry/abi"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
)

// --- openat, performed exactly as written -------------------------------------

// atFDCWD is openat's "resolve a relative path against the working directory"
// dirfd. A variable rather than a constant because a negative untyped constant
// cannot be converted to uintptr.
var atFDCWD = -100

// rawOpenat calls openat(2) directly and returns the kernel's return value: a
// file descriptor, or a negative errno.
//
// syscall.Open is deliberately not used. It ORs O_LARGEFILE into the flags
// before calling openat, so a test asserting that the probe captured the flags
// the process passed would be asserting against flags the process did not pass.
// These tests are about a field the probe copies out of the syscall's arguments,
// so the arguments have to be exactly what the test chose.
//
// The descriptor is not closed here: the caller decides, because for some of
// these tests the interesting number is the descriptor itself.
func rawOpenat(path string, flags int, mode uint32) int {
	p, err := syscall.BytePtrFromString(path)
	if err != nil {
		return -int(syscall.EINVAL)
	}
	fd, _, errno := syscall.Syscall6(syscall.SYS_OPENAT,
		uintptr(atFDCWD), uintptr(unsafe.Pointer(p)), uintptr(flags), uintptr(mode), 0, 0)
	// The pointer must stay alive across the syscall; Syscall6 keeps it, but
	// the string it came from is what owns the bytes.
	runtime.KeepAlive(p)
	if errno != 0 {
		return -int(errno)
	}
	return int(fd)
}

// --- a thread whose TID the test knows ----------------------------------------

// lockedThread runs closures on one dedicated OS thread.
//
// The scratch map is keyed by thread, so a test that wants to assert anything
// about a particular entry has to know which thread wrote it. A goroutine is not
// a thread and does not have a stable one, so this pins one and reports its TID.
// It also outlives a loader, which one test below needs: the identity stamp the
// probe checks is a property of the thread, so learning it under one loaded
// object and using it under another is only sound if the thread is the same.
type lockedThread struct {
	tid   int
	calls chan func()
	done  chan struct{}
}

func newLockedThread(t *testing.T) *lockedThread {
	t.Helper()

	lt := &lockedThread{calls: make(chan func()), done: make(chan struct{})}
	ready := make(chan int, 1)

	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		ready <- syscall.Gettid()
		for fn := range lt.calls {
			fn()
		}
		close(lt.done)
	}()

	lt.tid = <-ready
	t.Cleanup(func() {
		close(lt.calls)
		<-lt.done
	})
	return lt
}

// do runs fn on the pinned thread and waits for it.
func (lt *lockedThread) do(fn func()) {
	finished := make(chan struct{})
	lt.calls <- func() {
		defer close(finished)
		fn()
	}
	<-finished
}

// open performs one openat on the pinned thread and returns the kernel's return
// value, closing any descriptor it obtained.
func (lt *lockedThread) open(path string, flags int, mode uint32) int {
	var ret int
	lt.do(func() {
		ret = rawOpenat(path, flags, mode)
		if ret >= 0 {
			syscall.Close(ret)
		}
	})
	return ret
}

// --- the scratch map, from user space -----------------------------------------

// struct allseer_open_scratch, as bpf/include/allseer_maps.h declares it.
//
// Written out here rather than generated, because abigen parses
// allseer_event.h alone — the record ABI — and the scratch value is deliberately
// not part of that file. scratchMap below checks the total against the loaded
// map's ValueSize, so a field added to the struct fails these tests loudly
// instead of shifting what they read.
const (
	scratchOffTimestamp     = 0
	scratchOffTaskStartTime = 8
	scratchOffProc          = 16
	scratchOffFlags         = 72
	scratchOffMode          = 76
	scratchOffPath          = 80
	scratchSize             = scratchOffPath + abi.PathMax
)

// scratchMap returns the loaded object's openat_scratch, and fails the test if
// it is not the shape allseer_maps.h declares.
//
// l.module is read without l.mu. These tests drive the loader from one
// goroutine, so there is no concurrent mutation to race with; the lock exists
// for a daemon that attaches and detaches from several.
func scratchMap(t *testing.T, l *BPFLoader) *bpf.BPFMap {
	t.Helper()

	m, err := l.module.GetMap(MapOpenatScratch)
	if err != nil {
		t.Fatalf("map %q: %v", MapOpenatScratch, err)
	}
	if m.Type() != bpf.MapTypeLRUHash {
		t.Errorf("%s is a %s; allseer_maps.h declares an LRU hash, and a plain hash "+
			"would stop correlating opens for good once orphans filled it", MapOpenatScratch, m.Type())
	}
	if got, want := m.KeySize(), 8; got != want {
		t.Errorf("%s key is %d bytes, want %d for allseer_syscall_key_t", MapOpenatScratch, got, want)
	}
	if got := m.ValueSize(); got != scratchSize {
		t.Fatalf("%s value is %d bytes, but this test reads struct allseer_open_scratch as %d; "+
			"the struct changed and the offsets above have to change with it",
			MapOpenatScratch, got, scratchSize)
	}
	if got, want := m.MaxEntries(), uint32(4096); got != want {
		t.Errorf("%s holds %d entries, want ALLSEER_MAX_OPEN_SCRATCH = %d", MapOpenatScratch, got, want)
	}
	return m
}

// scratchKey encodes allseer_syscall_key_t: bpf_get_current_pid_tgid(), which is
// the thread group ID in the high 32 bits and the thread ID in the low 32.
func scratchKey(pid, tid int) []byte {
	return binary.NativeEndian.AppendUint64(nil, uint64(uint32(pid))<<32|uint64(uint32(tid)))
}

// scratchEntry returns the scratch entry for a thread, and whether there is one.
func scratchEntry(t *testing.T, m *bpf.BPFMap, key []byte) ([]byte, bool) {
	t.Helper()

	v, err := m.GetValue(unsafe.Pointer(&key[0]))
	if err == nil {
		return v, true
	}
	if errors.Is(err, syscall.ENOENT) {
		return nil, false
	}
	t.Fatalf("looking up %s: %v", MapOpenatScratch, err)
	return nil, false
}

// requireNoScratchEntry asserts that a thread has no half-built open left behind.
//
// This is the assertion the design's deletion rule reduces to, and it is worth
// making at every terminal path rather than once: an entry that outlives its
// syscall is invisible from the event stream, costs nothing until the map is
// full, and then silently stops openat being observed at all.
func requireNoScratchEntry(t *testing.T, m *bpf.BPFMap, key []byte, when string) {
	t.Helper()
	if _, ok := scratchEntry(t, m, key); ok {
		t.Errorf("a scratch entry survived %s; the exit side must delete on every path it finds one", when)
	}
}

// --- collecting open events ---------------------------------------------------

// collectOpens drains records for a bounded time and returns every file event
// whose path matches.
//
// The path is the only handle. Unlike an exec, an open says nothing about which
// binary made it, and unlike an exit it is not one-per-process — this process's
// cgroup is the tracked one and the Go runtime opens files constantly, so a test
// that matched on PID alone would be reading its own noise.
func collectOpens(t *testing.T, records <-chan []byte, want string, d time.Duration) []decoded {
	t.Helper()

	dec := NewDecoder()
	deadline := time.After(d)
	refused := 0
	var found []decoded

	for {
		select {
		case raw, ok := <-records:
			if !ok {
				return found
			}
			rec, err := abi.DecodeRecord(raw)
			if err != nil {
				t.Errorf("abi.DecodeRecord on a %d-byte record: %v", len(raw), err)
				continue
			}
			ev, err := dec.Decode(raw)
			if err != nil {
				// Counted rather than logged per record: this process's whole
				// cgroup is tracked, so an unrelated refusal is somebody else's
				// business and there can be many of them.
				refused++
				continue
			}
			if ev.File != nil && ev.File.Path == want {
				found = append(found, decoded{raw: rec, event: ev})
			}
		case <-deadline:
			if refused > 0 {
				t.Logf("the decoder refused %d unrelated record(s) during this drain", refused)
			}
			return found
		}
	}
}

// collectUntil drains the record stream once, handing every decoded event to
// visit, and stops when visit reports it has seen enough or the time runs out.
//
// It exists because reading the stream is destructive and the helpers above run
// to their deadline rather than stopping at their first match. A test whose
// records were all emitted before it started reading therefore cannot drain
// twice: the first drain consumes the whole stream and discards everything it
// was not looking for, and the second finds an empty channel. Anything looking
// for more than one thing in one stream has to look for all of them in one pass,
// which is what visit is for.
//
// The early stop is not a shortcut. A drain that has already seen everything the
// test asserts on has nothing left to wait for, and the deadline stays as the
// bound for the case where it has not.
func collectUntil(t *testing.T, records <-chan []byte, d time.Duration, visit func(decoded) bool) {
	t.Helper()

	dec := NewDecoder()
	deadline := time.After(d)
	refused := 0

	for {
		select {
		case raw, ok := <-records:
			if !ok {
				return
			}
			rec, err := abi.DecodeRecord(raw)
			if err != nil {
				t.Errorf("abi.DecodeRecord on a %d-byte record: %v", len(raw), err)
				continue
			}
			ev, err := dec.Decode(raw)
			if err != nil {
				refused++
				continue
			}
			if visit(decoded{raw: rec, event: ev}) {
				return
			}
		case <-deadline:
			if refused > 0 {
				t.Logf("the decoder refused %d unrelated record(s) during this drain", refused)
			}
			return
		}
	}
}

// trackThisCgroup puts the calling process's cgroup in the filter map and
// returns its ID.
func trackThisCgroup(t *testing.T, l *BPFLoader) uint64 {
	t.Helper()

	id := currentCgroupID(t)
	key, value := trackedKV(id)
	if err := l.UpdateMap(context.Background(), MapTrackedCgroups, key, value); err != nil {
		t.Fatalf("UpdateMap: %v", err)
	}
	return id
}

// selfComm returns this process's comm, truncated the way the record's
// fixed-size field truncates it.
func selfComm(t *testing.T) string {
	t.Helper()

	b, err := os.ReadFile("/proc/self/comm")
	if err != nil {
		t.Fatalf("reading /proc/self/comm: %v", err)
	}
	comm := strings.TrimSuffix(string(b), "\n")
	if len(comm) > abi.CommLen-1 {
		comm = comm[:abi.CommLen-1]
	}
	return comm
}

// openMarkerPath returns a path unique to this test that no other process on the
// machine will open.
func openMarkerPath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(t.TempDir(), name)
}

// --- the event ----------------------------------------------------------------

// A tracked openat reaches user space as a complete ALLSEER_EVT_FILE_OPEN, with
// the arguments from one tracepoint and the return from another.
func TestRuntimeOpenEventReachesUserspace(t *testing.T) {
	l, records := loadAndAttachPrograms(t, ProgOpenatEnter, ProgOpenatExit)

	// Created before the cgroup is tracked, so the O_CREAT open that creates it
	// is filtered and cannot be mistaken for the read below.
	path := openMarkerPath(t, "allseer-open-probe")
	if err := os.WriteFile(path, []byte("allseer"), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}

	cgroupID := trackThisCgroup(t, l)
	thread := newLockedThread(t)

	ret := thread.open(path, syscall.O_RDONLY, 0)
	if ret < 0 {
		t.Fatalf("openat(%s) failed: %v", path, syscall.Errno(-ret))
	}

	found := collectOpens(t, records, path, 3*time.Second)
	if len(found) == 0 {
		t.Fatalf("no open event for %s reached user space", path)
	}
	got := found[0]

	t.Run("event type", func(t *testing.T) {
		if abi.EventType(got.raw.Type) != abi.EvtFileOpen {
			t.Errorf("type = %s, want %s", abi.EventType(got.raw.Type), abi.EvtFileOpen)
		}
		// O_RDONLY, so kindForOpenFlags must say fs.read. The kind is the one
		// thing about an open that the flags decide rather than the type.
		if got.event.Capability != capability.KindFileRead {
			t.Errorf("capability = %s, want %s", got.event.Capability, capability.KindFileRead)
		}
		if got.event.Domain != capability.DomainFilesystem {
			t.Errorf("domain = %s, want %s", got.event.Domain, capability.DomainFilesystem)
		}
	})

	t.Run("ABI version", func(t *testing.T) {
		if got.raw.Version != abi.ABIVersion {
			t.Errorf("version = %d, want %d", got.raw.Version, abi.ABIVersion)
		}
	})

	t.Run("process identity", func(t *testing.T) {
		if int(got.event.Process.PID) != os.Getpid() {
			t.Errorf("pid = %d, want %d", got.event.Process.PID, os.Getpid())
		}
		// The thread, not the process. An open is made by a thread and the
		// record has a field for which one; a probe that wrote the tgid into
		// both would pass every other assertion here.
		if int(got.event.Process.TID) != thread.tid {
			t.Errorf("tid = %d, want the thread that called openat, %d", got.event.Process.TID, thread.tid)
		}
		if int(got.event.Process.PPID) != os.Getppid() {
			t.Errorf("ppid = %d, want %d", got.event.Process.PPID, os.Getppid())
		}
		if int(got.event.Process.UID) != os.Geteuid() {
			t.Errorf("uid = %d, want %d", got.event.Process.UID, os.Geteuid())
		}
		// start_time is the thread group leader's, so that (PID, StartTime) is
		// the pair proc_exec and proc_exit report for this process rather than
		// one only this thread's records would carry.
		if got.event.Process.StartTime == 0 {
			t.Error("start_time is zero; (pid, start_time) cannot disambiguate a recycled pid")
		}
		// This process's own comm, read from /proc rather than written down:
		// the test binary's name depends on how the tests were invoked, and
		// what is being asserted is that the probe reported the caller rather
		// than any particular string.
		if got.event.Process.Comm != selfComm(t) {
			t.Errorf("comm = %q, want %q", got.event.Process.Comm, selfComm(t))
		}
	})

	t.Run("cgroup id", func(t *testing.T) {
		// The value the entry side matched on, not a second reading. This is
		// the assertion that the record's attribution and the decision that
		// produced the record are the same fact.
		if got.event.Process.CgroupID != cgroupID {
			t.Errorf("cgroup_id = %d, want %d", got.event.Process.CgroupID, cgroupID)
		}
	})

	t.Run("path", func(t *testing.T) {
		if got.event.File == nil {
			t.Fatal("no file payload on an open event")
		}
		if got.event.File.Path != path {
			t.Errorf("path = %q, want %q", got.event.File.Path, path)
		}
		// Resolution is M6's. The decoder is documented never to set it, and an
		// enricher that has not run must leave the event unevaluable rather
		// than let an unresolved path reach selector matching.
		if got.event.File.ResolvedPath != "" {
			t.Errorf("resolved_path = %q; resolution is an enricher's job, not a probe's", got.event.File.ResolvedPath)
		}
	})

	t.Run("flags and mode", func(t *testing.T) {
		if got.event.File.Flags != syscall.O_RDONLY {
			t.Errorf("flags = %#x, want %#x", got.event.File.Flags, syscall.O_RDONLY)
		}
		if got.event.File.Mode != 0 {
			t.Errorf("mode = %#o, want the 0 this call passed", got.event.File.Mode)
		}
	})

	t.Run("syscall return", func(t *testing.T) {
		// The whole reason for the two-program design. The entry side had no
		// return to report, and this is the field it could not have filled.
		if !got.event.Result.Succeeded {
			t.Errorf("result = %+v, want success for an open that returned fd %d", got.event.Result, ret)
		}
		if got.event.Result.ReturnCode != int64(ret) {
			t.Errorf("return code = %d, want the descriptor openat returned, %d", got.event.Result.ReturnCode, ret)
		}
		if got.event.Result.Errno != "" {
			t.Errorf("errno = %q on a successful open", got.event.Result.Errno)
		}
	})

	t.Run("fields the tracepoints do not carry", func(t *testing.T) {
		// Left at zero deliberately: openat's tracepoints carry no inode, no
		// device and no byte count, and a plausible zero in a field the probe
		// cannot answer for would be a claim about a file it never saw.
		if got.event.File.Inode != 0 || got.event.File.Device != 0 || got.event.File.BytesTransferred != 0 {
			t.Errorf("inode/device/bytes = %d/%d/%d, want zeroes",
				got.event.File.Inode, got.event.File.Device, got.event.File.BytesTransferred)
		}
		if got.event.File.NewPath != "" {
			t.Errorf("new_path = %q; the header defines it for rename only", got.event.File.NewPath)
		}
	})

	t.Run("kernel timestamp", func(t *testing.T) {
		if got.event.KernelTimestamp == 0 {
			t.Error("kernel timestamp is zero")
		}
	})

	t.Run("the scratch entry is gone", func(t *testing.T) {
		requireNoScratchEntry(t, scratchMap(t, l), scratchKey(os.Getpid(), thread.tid),
			"an open that completed and was reported")
	})
}

// The flags and the mode are the arguments the decoder turns into a capability,
// and the return is what separates an access from an attempted one. All three
// come from the syscall and none of them can be inferred from the event type.
func TestRuntimeOpenCarriesFlagsModeAndReturn(t *testing.T) {
	l, records := loadAndAttachPrograms(t, ProgOpenatEnter, ProgOpenatExit)

	dir := t.TempDir()
	existing := filepath.Join(dir, "allseer-open-existing")
	if err := os.WriteFile(existing, []byte("x"), 0o600); err != nil {
		t.Fatalf("writing %s: %v", existing, err)
	}

	trackThisCgroup(t, l)
	thread := newLockedThread(t)

	for _, tc := range []struct {
		name      string
		path      string
		flags     int
		mode      uint32
		wantKind  capability.Kind
		wantOK    bool
		wantErrno string
	}{
		{
			// O_CREAT takes precedence over the access mode in
			// kindForOpenFlags, and mode is only meaningful when a file may be
			// created — which is the case that has to carry it correctly.
			name: "create", path: filepath.Join(dir, "allseer-open-created"),
			flags: syscall.O_CREAT | syscall.O_WRONLY, mode: 0o640,
			wantKind: capability.KindFileCreate, wantOK: true,
		},
		{
			name: "write", path: existing,
			flags: syscall.O_WRONLY, mode: 0,
			wantKind: capability.KindFileWrite, wantOK: true,
		},
		{
			// A failed open is a governance signal in its own right, which is
			// the whole reason the record waits for a return instead of being
			// emitted at entry.
			name: "missing", path: filepath.Join(dir, "allseer-open-absent"),
			flags: syscall.O_RDONLY, mode: 0,
			wantKind: capability.KindFileRead, wantOK: false, wantErrno: "ENOENT",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ret := thread.open(tc.path, tc.flags, tc.mode)

			found := collectOpens(t, records, tc.path, 3*time.Second)
			if len(found) == 0 {
				t.Fatalf("no open event for %s reached user space", tc.path)
			}
			got := found[0].event

			if got.File.Flags != int32(tc.flags) {
				t.Errorf("flags = %#x, want %#x", got.File.Flags, tc.flags)
			}
			if got.File.Mode != tc.mode {
				t.Errorf("mode = %#o, want %#o", got.File.Mode, tc.mode)
			}
			if got.Capability != tc.wantKind {
				t.Errorf("capability = %s, want %s", got.Capability, tc.wantKind)
			}
			if got.Result.Succeeded != tc.wantOK {
				t.Errorf("succeeded = %v, want %v (openat returned %d)", got.Result.Succeeded, tc.wantOK, ret)
			}
			if got.Result.ReturnCode != int64(ret) {
				t.Errorf("return code = %d, want %d", got.Result.ReturnCode, ret)
			}
			if got.Result.Errno != tc.wantErrno {
				t.Errorf("errno = %q, want %q", got.Result.Errno, tc.wantErrno)
			}

			requireNoScratchEntry(t, scratchMap(t, l), scratchKey(os.Getpid(), thread.tid),
				"an open that returned "+fmt.Sprint(ret))
		})
	}
}

// A path longer than the record's field arrives truncated and NUL-terminated,
// which is what the decoder is written against.
//
// The behaviour is worth pinning because it is the one truncation case
// ErrTruncatedString cannot catch, and both sides say so already:
// bpf_probe_read_user_str terminates within the destination even when it cuts
// the string short, so abi.CString sees a terminated array and reports the
// prefix as whole. If the probe ever filled the field without a terminator the
// decoder would start refusing these records instead, which is a different and
// louder failure — so this asserts the contract that exists rather than the one
// the TODO(event) in decode.go would like.
func TestRuntimeOpenPathTruncation(t *testing.T) {
	l, records := loadAndAttachPrograms(t, ProgOpenatEnter, ProgOpenatExit)
	trackThisCgroup(t, l)
	thread := newLockedThread(t)

	// Two components well inside NAME_MAX, joined into a path well past
	// ALLSEER_PATH_MAX. The file does not exist and is not created: openat
	// still fires both tracepoints, and the argument is captured before the
	// kernel has decided the path resolves to nothing.
	dir := filepath.Join(t.TempDir(), strings.Repeat("d", 200))
	path := filepath.Join(dir, strings.Repeat("f", 200))
	if len(path) <= abi.PathMax {
		t.Fatalf("this test needs a path longer than %d bytes; built one of %d", abi.PathMax, len(path))
	}
	want := path[:abi.PathMax-1]

	if ret := thread.open(path, syscall.O_RDONLY, 0); ret >= 0 {
		t.Fatalf("openat(%s) unexpectedly succeeded", path)
	}

	found := collectOpens(t, records, want, 3*time.Second)
	if len(found) == 0 {
		t.Fatalf("no open event carrying the first %d bytes of a %d-byte path reached user space; "+
			"either the path was not truncated to a terminated prefix or the record was refused",
			len(want), len(path))
	}
	if got := found[0].event.File.Path; got != want {
		t.Errorf("path = %q (%d bytes), want the first %d bytes of the argument", got, len(got), len(want))
	}
	requireNoScratchEntry(t, scratchMap(t, l), scratchKey(os.Getpid(), thread.tid), "an open with a truncated path")
}

// --- the filter ---------------------------------------------------------------

// The per-probe filter obligation, proven for the openat pair rather than
// inherited from the two probes that already carry it.
//
// Both legs matter for the same reason they do elsewhere: a negative result on
// its own is also what a probe that never fires produces.
func TestRuntimeUntrackedCgroupProducesNoOpenEvent(t *testing.T) {
	l, records := loadAndAttachPrograms(t, ProgOpenatEnter, ProgOpenatExit)
	ctx := context.Background()

	mine := currentCgroupID(t)
	other := mine ^ 0xDEADBEEF // certainly not a cgroup this process is in
	key, value := trackedKV(other)
	if err := l.UpdateMap(ctx, MapTrackedCgroups, key, value); err != nil {
		t.Fatalf("UpdateMap: %v", err)
	}

	thread := newLockedThread(t)
	untracked := openMarkerPath(t, "allseer-open-untracked")

	thread.open(untracked, syscall.O_RDONLY, 0)
	if found := collectOpens(t, records, untracked, 2*time.Second); len(found) != 0 {
		t.Fatalf("an open in an untracked cgroup produced %d event(s); the kernel filter did not hold", len(found))
	}

	// And nothing was stored for the exit side to find, which is the stronger
	// statement: the filter is not merely suppressing the event at the end, it
	// is stopping the syscall being tracked at all.
	requireNoScratchEntry(t, scratchMap(t, l), scratchKey(os.Getpid(), thread.tid),
		"an open the cgroup filter rejected (the entry side must store nothing)")

	trackThisCgroup(t, l)
	tracked := openMarkerPath(t, "allseer-open-tracked")
	thread.open(tracked, syscall.O_RDONLY, 0)
	if found := collectOpens(t, records, tracked, 3*time.Second); len(found) == 0 {
		t.Fatal("an open in a tracked cgroup produced no event, so the negative case above proves nothing")
	}
}

// --- the seam between the two programs ----------------------------------------

// An exit with no matching entry emits nothing, and in particular does not
// invent an open out of the return value it does have.
//
// Only the exit program is attached, so every openat on this host reaches a
// program holding a return value and no arguments. A probe that emitted anyway
// would produce a stream of file events with an empty path, a zero flags word —
// which kindForOpenFlags reads as fs.read — and a real descriptor, all
// attributed to whatever process happened to be opening a file.
func TestRuntimeOpenExitWithoutEntryProducesNoEvent(t *testing.T) {
	l, records := loadAndAttachPrograms(t, ProgOpenatExit)
	trackThisCgroup(t, l)
	thread := newLockedThread(t)

	orphan := openMarkerPath(t, "allseer-open-orphan")
	thread.open(orphan, syscall.O_RDONLY, 0)

	// Nothing at all, not merely nothing for this path: a fabricated record
	// would not carry the path, so matching on it would miss exactly the
	// failure this test is for.
	deadline := time.After(2 * time.Second)
	dec := NewDecoder()
	opens := 0
drain:
	for {
		select {
		case raw, ok := <-records:
			if !ok {
				break drain
			}
			ev, err := dec.Decode(raw)
			if err == nil && ev.File != nil {
				opens++
				t.Errorf("an exit with no scratch entry produced a file event: path=%q flags=%#x ret=%d",
					ev.File.Path, ev.File.Flags, ev.Result.ReturnCode)
			}
		case <-deadline:
			break drain
		}
	}
	if opens > 0 {
		t.Fatalf("%d fabricated open event(s)", opens)
	}

	// The control: with the entry side attached as well, the same call is
	// reported. Without this the result above is also what a program that never
	// loaded would produce.
	if err := l.Attach(context.Background(), ProgOpenatEnter); err != nil {
		t.Fatalf("Attach %s: %v", ProgOpenatEnter, err)
	}
	paired := openMarkerPath(t, "allseer-open-paired")
	thread.open(paired, syscall.O_RDONLY, 0)
	if found := collectOpens(t, records, paired, 3*time.Second); len(found) == 0 {
		t.Fatal("with both programs attached the open produced no event, so the negative case above proves nothing")
	}
}

// A scratch entry that belongs to a dead thread is rejected and removed, not
// completed.
//
// This is the PID-reuse guard, and it is the one part of the design that cannot
// be exercised by making syscalls: a stale entry only exists after a thread has
// been killed inside openat and its TID reused, which no test can arrange on
// demand. So the entry is written from user space instead — see the note at the
// top of this file about why nothing outside a test may do that.
//
// The two legs are the whole test. The rejected entry proves the guard fires;
// the accepted one, differing only in the stamp, proves the rejection was the
// guard's doing and not a program that ignores injected entries or bytes this
// test assembled wrongly.
//
// The correct stamp is not computable from user space — start_boottime is
// nanoseconds since boot and /proc reports a task's start in clock ticks — so it
// is learned from the probe itself, under a first loaded object with only the
// entry side attached, and then used under a second. That is sound because the
// stamp is a property of the thread rather than of the object, and lockedThread
// keeps the same thread alive across both.
func TestRuntimeStaleScratchEntryIsRejectedAndDeleted(t *testing.T) {
	requireRoot(t)
	obj := objectOrSkip(t)
	ctx := context.Background()
	thread := newLockedThread(t)
	key := scratchKey(os.Getpid(), thread.tid)

	// Phase 1: learn what the entry side writes for this thread. With no exit
	// program attached, the entry it writes is never deleted.
	learn := NewLoader(Config{ObjectPath: obj, RingBufferSize: 1 << 22}, nil)
	if err := learn.Load(ctx, obj); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := learn.Attach(ctx, ProgOpenatEnter); err != nil {
		t.Fatalf("Attach %s: %v", ProgOpenatEnter, err)
	}
	trackThisCgroup(t, learn)
	thread.open(openMarkerPath(t, "allseer-open-learn"), syscall.O_RDONLY, 0)

	genuine, ok := scratchEntry(t, scratchMap(t, learn), key)
	if !ok {
		t.Fatal("the entry side stored nothing for a tracked open, so there is no stamp to learn")
	}
	if err := learn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Phase 2: a second object, with only the exit side attached, so nothing
	// overwrites what this test injects.
	l, records := loadAndAttachPrograms(t, ProgOpenatExit)
	trackThisCgroup(t, l)
	m := scratchMap(t, l)

	inject := func(t *testing.T, path string, stampDelta uint64) {
		t.Helper()
		v := make([]byte, len(genuine))
		copy(v, genuine)

		stamp := binary.NativeEndian.Uint64(v[scratchOffTaskStartTime:])
		binary.NativeEndian.PutUint64(v[scratchOffTaskStartTime:], stamp+stampDelta)

		for i := scratchOffPath; i < scratchOffPath+abi.PathMax; i++ {
			v[i] = 0
		}
		copy(v[scratchOffPath:scratchOffPath+abi.PathMax-1], path)

		if err := m.Update(unsafe.Pointer(&key[0]), unsafe.Pointer(&v[0])); err != nil {
			t.Fatalf("injecting a scratch entry: %v", err)
		}
	}

	t.Run("a matching stamp is completed", func(t *testing.T) {
		marker := openMarkerPath(t, "allseer-open-stamp-ok")
		inject(t, marker, 0)

		// The path the thread actually opens is irrelevant: the record's path
		// comes from the scratch entry, which is the point being made.
		thread.open("/dev/null", syscall.O_RDONLY, 0)

		found := collectOpens(t, records, marker, 3*time.Second)
		if len(found) == 0 {
			t.Fatal("an entry carrying this thread's own stamp produced no event; " +
				"the negative leg below would then prove nothing")
		}
		if got := int(found[0].event.Process.TID); got != thread.tid {
			t.Errorf("tid = %d, want %d — the record's identity comes from the entry", got, thread.tid)
		}
		requireNoScratchEntry(t, m, key, "an entry that was accepted and reported")
	})

	t.Run("a stale stamp is refused", func(t *testing.T) {
		marker := openMarkerPath(t, "allseer-open-stamp-stale")
		inject(t, marker, 1) // a thread created one nanosecond later: not this one

		thread.open("/dev/null", syscall.O_RDONLY, 0)

		if found := collectOpens(t, records, marker, 2*time.Second); len(found) != 0 {
			t.Errorf("an entry whose stamp is not this thread's produced %d event(s); "+
				"a reused TID would complete a dead thread's open, in a cgroup nobody tracked", len(found))
		}
		requireNoScratchEntry(t, m, key, "an entry the identity check refused")
	})
}

// Concurrent opens from several threads are correlated per thread.
//
// The key is bpf_get_current_pid_tgid() and every thread here shares a TGID, so
// a key that used only the process — or a per-CPU slot, which is the other
// tempting shape for scratch state — would have these calls overwrite each
// other. The failure that produces is not a missing event: it is an event with
// one thread's path and another thread's return, which arrives and decodes and
// reads as ordinary.
//
// The threads are released together rather than run in sequence, so their calls
// genuinely overlap.
func TestRuntimeConcurrentOpensCorrelatePerThread(t *testing.T) {
	l, records := loadAndAttachPrograms(t, ProgOpenatEnter, ProgOpenatExit)
	trackThisCgroup(t, l)

	const threads = 6
	dir := t.TempDir()

	type call struct {
		path string
		tid  int
		ret  int
	}
	calls := make([]call, threads)

	var ready, done sync.WaitGroup
	start := make(chan struct{})
	ready.Add(threads)
	done.Add(threads)

	for i := range threads {
		go func() {
			defer done.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			c := &calls[i]
			// A distinct flags word per thread as well as a distinct path, so a
			// crossed correlation shows up in two independent fields.
			c.path = filepath.Join(dir, fmt.Sprintf("allseer-open-concurrent-%d", i))
			c.tid = syscall.Gettid()

			ready.Done()
			<-start
			c.ret = rawOpenat(c.path, syscall.O_CREAT|syscall.O_WRONLY, uint32(0o600+i))
			if c.ret >= 0 {
				syscall.Close(c.ret)
			}
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()

	// One drain for all six, for the reason collectUntil states: every one of
	// these opens happened before the stream was read, and a drain per thread
	// would have the first thread's drain consume the other five.
	found := make(map[string]decoded, threads)
	collectUntil(t, records, 5*time.Second, func(d decoded) bool {
		if d.event.File == nil {
			return false
		}
		if _, seen := found[d.event.File.Path]; !seen {
			for _, c := range calls {
				if d.event.File.Path == c.path {
					found[d.event.File.Path] = d
					break
				}
			}
		}
		return len(found) == threads
	})

	m := scratchMap(t, l)
	for i, c := range calls {
		match, ok := found[c.path]
		if !ok {
			t.Errorf("thread %d (tid %d): no open event for %s", i, c.tid, c.path)
			continue
		}
		got := match.event
		if int(got.Process.TID) != c.tid {
			t.Errorf("%s: tid = %d, want %d — this record was correlated to the wrong thread",
				c.path, got.Process.TID, c.tid)
		}
		if got.File.Mode != uint32(0o600+i) {
			t.Errorf("%s: mode = %#o, want %#o — this record carries another call's arguments",
				c.path, got.File.Mode, 0o600+i)
		}
		if got.Result.ReturnCode != int64(c.ret) {
			t.Errorf("%s: return code = %d, want %d — this record carries another call's return",
				c.path, got.Result.ReturnCode, c.ret)
		}
		requireNoScratchEntry(t, m, scratchKey(os.Getpid(), c.tid), "a concurrent open that completed")
	}
}

// --- loss --------------------------------------------------------------------

// The openat pair carries the drop-counting obligation, and deletes its scratch
// entry on that path too.
//
// Only the two openat programs are attached and nothing drains the one-page
// ring, so every counted drop is a record openat_exit wanted to emit. The second
// assertion is the one this test exists for: the reservation failing is the
// terminal path most likely to be written as a bare `return`, and an entry left
// behind there accumulates precisely when the host is already losing records.
func TestRuntimeOpenProbeCountsDropsAndStillDeletesScratch(t *testing.T) {
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
	for _, prog := range []string{ProgOpenatEnter, ProgOpenatExit} {
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
	absent := openMarkerPath(t, "allseer-open-drops")

	// Filtered: nothing tracked, so nothing is reserved and nothing is lost.
	thread.do(func() {
		for range 64 {
			if fd := rawOpenat(absent, syscall.O_RDONLY, 0); fd >= 0 {
				syscall.Close(fd)
			}
		}
	})
	if n, err := l.ReadCounter(ctx, MapRingbufDrops); err != nil {
		t.Fatalf("ReadCounter: %v", err)
	} else if n != 0 {
		t.Fatalf("64 opens the cgroup filter rejected were counted as %d drop(s); "+
			"a filtered event is not a lost one", n)
	}

	trackThisCgroup(t, l)

	const burst = 512
	thread.do(func() {
		for range burst {
			if fd := rawOpenat(absent, syscall.O_RDONLY, 0); fd >= 0 {
				syscall.Close(fd)
			}
		}
	})

	dropped, err := l.ReadCounter(ctx, MapRingbufDrops)
	if err != nil {
		t.Fatalf("ReadCounter: %v", err)
	}
	if dropped == 0 {
		t.Fatalf("%d opens into a %d-byte ring buffer nobody is draining produced 0 counted drops; "+
			"openat_exit is losing records without calling count_ringbuf_drop()", burst, os.Getpagesize())
	}
	t.Logf("burst of %d opens into a %d-byte ring, openat probes only: %d records counted as lost",
		burst, os.Getpagesize(), dropped)

	requireNoScratchEntry(t, scratchMap(t, l), scratchKey(os.Getpid(), thread.tid),
		"an open whose record could not be reserved")
}

// --- coexistence and lifecycle ------------------------------------------------

// All four programs on one ring buffer, reporting one process's exec, its exit,
// and an open it made in between.
//
// The object has one ring buffer and one filter map by design, and the three
// record shapes travel through them together. A payload union written by one
// probe and read for another type is the shape of failure this rules out: the
// exec record's filename and the open record's path occupy the same bytes.
func TestRuntimeExecExitAndOpenShareOneRingBuffer(t *testing.T) {
	l, records := loadAndAttachPrograms(t, ProgProcExec, ProgProcExit, ProgOpenatEnter, ProgOpenatExit)
	trackThisCgroup(t, l)

	thread := newLockedThread(t)
	openPath := openMarkerPath(t, "allseer-coexist-open")
	thread.open(openPath, syscall.O_RDONLY, 0)

	execPath, pid := execMarker(t, "allseer-coexist-exec")

	// One drain, three record shapes. All three were emitted before any of them
	// was read — the open, then the exec and exit of a process execMarker waits
	// for — and reading the stream removes what it reads, so a drain looking for
	// the open would consume the exec and the exit on its way past them. Two
	// sequential drains here find the first thing and nothing else, which is not
	// a property of the probes but of the channel.
	var opens, byPID []decoded
	collectUntil(t, records, 5*time.Second, func(d decoded) bool {
		if d.event.File != nil && d.event.File.Path == openPath {
			opens = append(opens, d)
		}
		if int(d.event.Process.PID) == pid {
			byPID = append(byPID, d)
		}
		_, haveExec := firstOfKind(byPID, capability.KindProcessExec)
		_, haveExit := firstOfKind(byPID, capability.KindProcessExit)
		return len(opens) > 0 && haveExec && haveExit
	})

	if len(opens) == 0 {
		t.Errorf("no open event for %s with all four programs attached", openPath)
	} else {
		if got := opens[0].event.Capability; got != capability.KindFileRead {
			t.Errorf("open capability = %s, want %s", got, capability.KindFileRead)
		}
		if opens[0].event.Exec != nil {
			t.Error("an open event carries an exec payload; the union was read for the wrong type")
		}
	}

	execEv, ok := firstOfKind(byPID, capability.KindProcessExec)
	if !ok {
		t.Fatalf("no process.exec event for pid %d; collected %d event(s)", pid, len(byPID))
	}
	if execEv.event.Exec == nil || execEv.event.Exec.Filename != execPath {
		t.Errorf("the exec event does not name %s: %+v", execPath, execEv.event.Exec)
	}
	if execEv.event.File != nil {
		t.Error("an exec event carries a file payload; the union was read for the wrong type")
	}
	if _, ok := firstOfKind(byPID, capability.KindProcessExit); !ok {
		t.Errorf("no process.exit event for pid %d with all four programs attached", pid)
	}
}

// Both openat programs attach, refuse a second attach by name, and are released
// together by DetachAll.
//
// The same lifecycle TestRuntimeBothProbesAttachAndDetachTogether establishes
// for the scheduler probes, asserted for the pair because these two are the
// first programs in the object that are useless apart: a DetachAll that dropped
// one and kept the other would leave a hook running that can never produce an
// event, writing scratch entries nothing will ever consume.
func TestRuntimeOpenatProbesAttachAndDetachTogether(t *testing.T) {
	requireRoot(t)
	obj := objectOrSkip(t)
	ctx := context.Background()

	l := NewLoader(Config{ObjectPath: obj, RingBufferSize: 1 << 22}, nil)
	t.Cleanup(func() {
		if err := l.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	if err := l.Load(ctx, obj); err != nil {
		t.Fatalf("Load: %v", err)
	}
	records, err := l.RingBuffer(ctx, MapEvents)
	if err != nil {
		t.Fatalf("RingBuffer: %v", err)
	}

	pair := []string{ProgOpenatEnter, ProgOpenatExit}
	for _, prog := range pair {
		if err := l.Attach(ctx, prog); err != nil {
			t.Fatalf("Attach %s: %v", prog, err)
		}
	}
	for _, prog := range pair {
		if err := l.Attach(ctx, prog); !errors.Is(err, ErrAlreadyAttached) {
			t.Errorf("second Attach %s = %v, want ErrAlreadyAttached", prog, err)
		}
	}

	// Both are really running: one openat yields one event, which needs both.
	trackThisCgroup(t, l)
	thread := newLockedThread(t)
	path := openMarkerPath(t, "allseer-open-lifecycle")
	thread.open(path, syscall.O_RDONLY, 0)
	if found := collectOpens(t, records, path, 3*time.Second); len(found) == 0 {
		t.Error("no open event with both openat programs attached")
	}

	if err := l.DetachAll(ctx); err != nil {
		t.Fatalf("DetachAll: %v", err)
	}
	select {
	case _, ok := <-records:
		for ok {
			_, ok = <-records
		}
	case <-time.After(2 * time.Second):
		t.Error("record channel did not close after DetachAll")
	}

	for _, prog := range pair {
		if err := l.Attach(ctx, prog); err != nil {
			t.Errorf("Attach %s after DetachAll = %v; the link was not released", prog, err)
		}
	}
}
