//go:build linux && ebpf

package telemetry

// Runtime tests for the security_socket_connect hook: the connects the
// tracepoint pair cannot see, and what the hook adds to the ones it can.

import (
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/stringNameMahin/ALLSEER/internal/telemetry/abi"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
)

const ioringOpConnect = 16

// connect submits one IORING_OP_CONNECT on fd and returns its result: 0, or a
// negative errno. No connect syscall is made at all.
func (r *uring) connect(t *testing.T, fd int, sa []byte) int {
	t.Helper()
	sqe := r.sqes[:sqeSize]
	for i := range sqe {
		sqe[i] = 0
	}
	sqe[0] = ioringOpConnect
	*(*int32)(unsafe.Pointer(&sqe[4])) = int32(fd)
	*(*uint64)(unsafe.Pointer(&sqe[8])) = uint64(len(sa)) // addrlen goes in off
	*(*uint64)(unsafe.Pointer(&sqe[16])) = uint64(uintptr(unsafe.Pointer(&sa[0])))
	*(*uint64)(unsafe.Pointer(&sqe[32])) = 2 // user_data

	res := r.submitOne(t)
	runtime.KeepAlive(sa)
	return int(res)
}

// streamSocket opens a socket the test closes when it ends.
func streamSocket(t *testing.T, domain int) int {
	t.Helper()
	fd, err := syscall.Socket(domain, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socket(%d): %v", domain, err)
	}
	t.Cleanup(func() { syscall.Close(fd) })
	return fd
}

// connectsTo drains the stream once and returns every connect record from this
// process to port. It stops early only on a second record, so a count of one
// means one record arrived in the whole window.
func connectsTo(t *testing.T, records <-chan []byte, port uint16, d time.Duration) []decoded {
	t.Helper()
	var found []decoded
	collectUntil(t, records, d, func(rec decoded) bool {
		n := rec.event.Network
		if n == nil || int(rec.event.Process.PID) != os.Getpid() || n.DestPort != int(port) {
			return false
		}
		found = append(found, rec)
		return len(found) > 1
	})
	return found
}

// assertHookConnect checks a record the hook emitted itself: the destination
// and socket properties from the kernel, and no claim about the outcome.
func assertHookConnect(t *testing.T, got decoded, cgroupID uint64, family, addr string, port uint16) {
	t.Helper()
	n := got.event.Network
	if abi.EventType(got.raw.Type) != abi.EvtNetConnect || got.event.Capability != capability.KindNetConnect {
		t.Errorf("type %s capability %s, want a net.connect record",
			abi.EventType(got.raw.Type), got.event.Capability)
	}
	if n.AddressFamily != family || n.DestAddr != addr || n.DestPort != int(port) {
		t.Errorf("destination %s %s:%d, want %s %s:%d",
			n.AddressFamily, n.DestAddr, n.DestPort, family, addr, port)
	}
	if n.Protocol != "tcp" || n.SocketType != "SOCK_STREAM" {
		t.Errorf("protocol %q socket type %q, want tcp and SOCK_STREAM from the socket",
			n.Protocol, n.SocketType)
	}
	if got.raw.Flags&uint32(abi.AllseerEvtFOutcomeUnknown) == 0 ||
		!got.event.Result.OutcomeUnobserved || !got.event.Result.Succeeded || got.event.Result.Errno != "" {
		t.Errorf("flags %#x result %+v, want the outcome marked unobserved", got.raw.Flags, got.event.Result)
	}
	if got.event.Process.CgroupID != cgroupID {
		t.Errorf("cgroup_id = %d, want %d", got.event.Process.CgroupID, cgroupID)
	}
	if got.event.Process.StartTime == 0 {
		t.Error("start_time is zero")
	}
}

// The case the hook exists for. An IORING_OP_CONNECT never enters connect(2),
// so the tracepoint pair cannot see it.
//
// Exactly one record: io_uring issues the connect non-blocking, gets
// EINPROGRESS on loopback and calls the same path again once the socket is
// writable. The second call must not produce a second record.
func TestRuntimeIoUringConnectIsObserved(t *testing.T) {
	l, records := loadAndAttachPrograms(t, ProgSocketConnect)
	port := listenerPort(t, "tcp4", "127.0.0.1:0")
	cgroupID := trackThisCgroup(t, l)

	fd := streamSocket(t, syscall.AF_INET)
	r := newUring(t)
	if res := r.connect(t, fd, sockaddrIn([4]byte{127, 0, 0, 1}, port)); res != 0 {
		t.Fatalf("io_uring connect to 127.0.0.1:%d: %v", port, syscall.Errno(-res))
	}

	found := connectsTo(t, records, port, 2*time.Second)
	if len(found) != 1 {
		t.Fatalf("got %d records for one io_uring connect, want 1", len(found))
	}
	assertHookConnect(t, found[0], cgroupID, "AF_INET", "127.0.0.1", port)
}

// The other family through the kernel copy, which takes a different branch and
// a different read length in the parser.
func TestRuntimeIoUringConnectToIPv6IsObserved(t *testing.T) {
	l, records := loadAndAttachPrograms(t, ProgSocketConnect)
	port := listenerPort(t, "tcp6", "[::1]:0")
	cgroupID := trackThisCgroup(t, l)

	var loopback [16]byte
	loopback[15] = 1
	fd := streamSocket(t, syscall.AF_INET6)
	r := newUring(t)
	if res := r.connect(t, fd, sockaddrIn6(loopback, port)); res != 0 {
		t.Fatalf("io_uring connect to [::1]:%d: %v", port, syscall.Errno(-res))
	}

	found := connectsTo(t, records, port, 2*time.Second)
	if len(found) != 1 {
		t.Fatalf("got %d records for one io_uring connect, want 1", len(found))
	}
	assertHookConnect(t, found[0], cgroupID, "AF_INET6", "::1", port)
}

// The hook filters on the cgroup like every other program.
func TestRuntimeIoUringConnectFromAnUntrackedCgroupIsNotReported(t *testing.T) {
	l, records := loadAndAttachPrograms(t, ProgSocketConnect)
	port := listenerPort(t, "tcp4", "127.0.0.1:0")
	key, value := trackedKV(currentCgroupID(t) ^ 0xDEADBEEF)
	if err := l.UpdateMap(t.Context(), MapTrackedCgroups, key, value); err != nil {
		t.Fatalf("UpdateMap: %v", err)
	}

	r := newUring(t)
	sa := sockaddrIn([4]byte{127, 0, 0, 1}, port)
	if res := r.connect(t, streamSocket(t, syscall.AF_INET), sa); res != 0 {
		t.Fatalf("io_uring connect: %v", syscall.Errno(-res))
	}
	if found := connectsTo(t, records, port, 2*time.Second); len(found) != 0 {
		t.Fatalf("an untracked cgroup produced %d record(s)", len(found))
	}

	// And the same connect from a tracked cgroup is reported, so the
	// negative case above is not a hook that never fires.
	trackThisCgroup(t, l)
	if res := r.connect(t, streamSocket(t, syscall.AF_INET), sa); res != 0 {
		t.Fatalf("io_uring connect: %v", syscall.Errno(-res))
	}
	if found := connectsTo(t, records, port, 3*time.Second); len(found) != 1 {
		t.Fatalf("a tracked io_uring connect produced %d records, want 1", len(found))
	}
}

// One connect(2), one record, with the pair and the hook both attached. The
// pair keeps the record because only it has the return value; the hook adds
// the protocol and socket type it alone can read.
func TestRuntimeConnectIsReportedOnceWithBothAttached(t *testing.T) {
	l, records := loadAndAttachPrograms(t, ProgConnectEnter, ProgConnectExit, ProgSocketConnect)
	port := listenerPort(t, "tcp4", "127.0.0.1:0")
	trackThisCgroup(t, l)
	thread := newLockedThread(t)

	sa := sockaddrIn([4]byte{127, 0, 0, 1}, port)
	if ret := thread.connectFrom(t, syscall.AF_INET, sa, len(sa)); ret != 0 {
		t.Fatalf("connect: %v", syscall.Errno(-ret))
	}

	found := connectsTo(t, records, port, 2*time.Second)
	if len(found) != 1 {
		t.Fatalf("got %d records for one connect(2), want 1", len(found))
	}
	got := found[0]
	if int(got.event.Process.TID) != thread.tid {
		t.Errorf("tid = %d, want %d", got.event.Process.TID, thread.tid)
	}
	if got.event.Result.OutcomeUnobserved || !got.event.Result.Succeeded || got.event.Result.ReturnCode != 0 {
		t.Errorf("result = %+v, want the pair's observed success", got.event.Result)
	}
	n := got.event.Network
	if n.DestAddr != "127.0.0.1" || n.DestPort != int(port) {
		t.Errorf("destination %s:%d, want 127.0.0.1:%d", n.DestAddr, n.DestPort, port)
	}
	if n.Protocol != "tcp" || n.SocketType != "SOCK_STREAM" {
		t.Errorf("protocol %q socket type %q, want what the hook read from the socket", n.Protocol, n.SocketType)
	}
	requireNoScratchEntry(t, connectScratchMap(t, l), scratchKey(os.Getpid(), thread.tid),
		"a connect the pair reported")
}

// coldSockaddr returns sa in a private file mapping whose page table entries
// have been zapped, so the first read of it from this process faults.
func coldSockaddr(t *testing.T, sa []byte) []byte {
	t.Helper()
	m := coldName(t, string(sa))
	return m[:len(sa)]
}

// The record carries the address the kernel connected to, not the one user
// memory held when the tracepoint read it. A cold page makes the two differ
// deterministically: sys_enter_connect cannot fault it in, the kernel's copy
// can. On a kernel whose syscall tracepoints may fault, the pair captures the
// address itself and this test cannot tell the two apart.
func TestRuntimeConnectReportsTheKernelsCopyOfTheAddress(t *testing.T) {
	l, records := loadAndAttachPrograms(t, ProgConnectEnter, ProgConnectExit, ProgSocketConnect)
	port := listenerPort(t, "tcp4", "127.0.0.1:0")
	trackThisCgroup(t, l)
	thread := newLockedThread(t)

	sa := coldSockaddr(t, sockaddrIn([4]byte{127, 0, 0, 1}, port))
	if ret := thread.connectPtrFrom(t, syscall.AF_INET, uintptr(unsafe.Pointer(&sa[0])), len(sa)); ret != 0 {
		t.Fatalf("connect: %v", syscall.Errno(-ret))
	}
	runtime.KeepAlive(sa)

	found := collectConnects(t, records, thread.tid, 2, 2*time.Second)
	if len(found) != 1 {
		t.Fatalf("got %d records for one connect(2), want 1", len(found))
	}
	n := found[0].event.Network
	if n.AddressFamily != "AF_INET" || n.DestAddr != "127.0.0.1" || n.DestPort != int(port) {
		t.Errorf("destination %s %s:%d, want AF_INET 127.0.0.1:%d from the kernel's copy",
			n.AddressFamily, n.DestAddr, n.DestPort, port)
	}
	if found[0].event.Result.OutcomeUnobserved || found[0].event.Result.ReturnCode != 0 {
		t.Errorf("result = %+v, want the pair's observed success", found[0].event.Result)
	}
}
