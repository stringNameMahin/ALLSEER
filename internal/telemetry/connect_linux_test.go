//go:build linux && ebpf

package telemetry

// Runtime tests for the connect pair.
//
// The openat tests established the shape of these -- a pinned thread whose TID
// the test knows, a single non-destructive drain, and assertions on the scratch
// map for the claims the event stream cannot make -- and this file reuses that
// machinery rather than restating it. lockedThread, scratchKey, scratchEntry,
// requireNoScratchEntry, collectUntil, trackThisCgroup and loadAndAttachPrograms
// all come from openat_linux_test.go; what is new here is a map accessor for
// connect_scratch, a way to make a connect(2) call with exact control over the
// sockaddr bytes, and the assertions particular to a network record.
//
// What connect adds that openat did not have is a *user-supplied structure*
// rather than a string: a family the process chooses, a length the process
// declares, and an address that may or may not be there. Most of what follows
// is about the cases where those three disagree.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/stringNameMahin/ALLSEER/internal/telemetry/abi"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
)

// Address families, as the probe and decode.go both spell them.
const (
	afUnixTest  = 1
	afInetTest  = 2
	afInet6Test = 10
)

// --- connect(2), performed exactly as written ---------------------------------

// rawConnectAt calls connect(2) with a raw address and length and returns the
// kernel's return value: 0, or a negative errno.
//
// The address and the length are separate parameters on purpose. Half of what
// this file tests is what the probe does when the length the process declares
// does not match the family it declared, and no wrapper that derives one from
// the other can express that.
func rawConnectAt(fd int, addr uintptr, addrlen int) int {
	_, _, errno := syscall.Syscall(syscall.SYS_CONNECT, uintptr(fd), addr, uintptr(addrlen))
	if errno != 0 {
		return -int(errno)
	}
	return 0
}

// rawConnect calls connect(2) with a sockaddr held in a byte slice.
func rawConnect(fd int, sa []byte, addrlen int) int {
	var addr uintptr
	if len(sa) > 0 {
		addr = uintptr(unsafe.Pointer(&sa[0]))
	}
	ret := rawConnectAt(fd, addr, addrlen)
	runtime.KeepAlive(sa)
	return ret
}

// connectFrom performs one connect on the pinned thread: socket, connect,
// close. It returns the kernel's return value from the connect itself.
//
// All three calls run on the pinned thread so that the TID the test knows is
// the TID the record will carry.
func (lt *lockedThread) connectFrom(t *testing.T, domain int, sa []byte, addrlen int) int {
	t.Helper()

	var ret int
	lt.do(func() {
		fd, err := syscall.Socket(domain, syscall.SOCK_STREAM, 0)
		if err != nil {
			t.Errorf("socket(%d): %v", domain, err)
			return
		}
		defer syscall.Close(fd)
		ret = rawConnect(fd, sa, addrlen)
	})
	return ret
}

// connectPtrFrom is connectFrom for a sockaddr the test does not own -- a null
// or unmapped pointer.
func (lt *lockedThread) connectPtrFrom(t *testing.T, domain int, addr uintptr, addrlen int) int {
	t.Helper()

	var ret int
	lt.do(func() {
		fd, err := syscall.Socket(domain, syscall.SOCK_STREAM, 0)
		if err != nil {
			t.Errorf("socket(%d): %v", domain, err)
			return
		}
		defer syscall.Close(fd)
		ret = rawConnectAt(fd, addr, addrlen)
	})
	return ret
}

// --- sockaddr construction ----------------------------------------------------
//
// Built byte by byte rather than through syscall.SockaddrInet4, because the
// point of most of these tests is to hand the kernel and the probe a structure
// that is deliberately wrong, and a helper that only produces correct ones
// cannot do that.
//
// The family is native-endian (it is a plain unsigned short) and the port is
// big-endian (it is on the wire). Getting that pair backwards is the mistake
// decode.go warns about from the other side, so the two orders are written out
// explicitly here rather than hidden.

func sockaddrIn(ip [4]byte, port uint16) []byte {
	sa := make([]byte, 16) // sizeof(struct sockaddr_in)
	binary.NativeEndian.PutUint16(sa[0:], afInetTest)
	binary.BigEndian.PutUint16(sa[2:], port)
	copy(sa[4:8], ip[:])
	return sa
}

func sockaddrIn6(ip [16]byte, port uint16) []byte {
	sa := make([]byte, 28) // sizeof(struct sockaddr_in6)
	binary.NativeEndian.PutUint16(sa[0:], afInet6Test)
	binary.BigEndian.PutUint16(sa[2:], port)
	// sa[4:8] is sin6_flowinfo, left zero.
	copy(sa[8:24], ip[:])
	// sa[24:28] is sin6_scope_id, left zero.
	return sa
}

func sockaddrUnix(path string) []byte {
	sa := make([]byte, 2+108) // sizeof(struct sockaddr_un)
	binary.NativeEndian.PutUint16(sa[0:], afUnixTest)
	copy(sa[2:], path)
	return sa
}

// --- listeners ----------------------------------------------------------------

// listenerPort returns a port on the loopback address that is accepting
// connections for the life of the test.
func listenerPort(t *testing.T, network, addr string) uint16 {
	t.Helper()

	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Skipf("cannot listen on %s %s: %v", network, addr, err)
	}
	t.Cleanup(func() { ln.Close() })

	_, p, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("parsing %s: %v", ln.Addr(), err)
	}
	var port uint16
	if _, err := fmt.Sscanf(p, "%d", &port); err != nil {
		t.Fatalf("parsing port %q: %v", p, err)
	}
	return port
}

// refusedPort returns a loopback port that nothing is listening on, by taking
// one and giving it back.
func refusedPort(t *testing.T) uint16 {
	t.Helper()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen on loopback: %v", err)
	}
	_, p, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		ln.Close()
		t.Fatalf("parsing %s: %v", ln.Addr(), err)
	}
	ln.Close()

	var port uint16
	if _, err := fmt.Sscanf(p, "%d", &port); err != nil {
		t.Fatalf("parsing port %q: %v", p, err)
	}
	return port
}

// --- the scratch map, from user space -----------------------------------------

// struct allseer_connect_scratch, as bpf/include/allseer_maps.h declares it.
//
// The first three offsets are openat's, and that is the point: the header
// asserts the shared prologue in C with _Static_assert, and these constants are
// the same claim from the Go side. connectScratchMap checks the total against
// the loaded map, so a field added to the struct fails here loudly rather than
// shifting what the tests read.
const (
	connectScratchOffTimestamp     = scratchOffTimestamp
	connectScratchOffTaskStartTime = scratchOffTaskStartTime
	connectScratchOffProc          = scratchOffProc
	connectScratchOffDaddr         = 72
	connectScratchOffFamily        = 88
	connectScratchOffDport         = 90
	connectScratchSize             = 96
)

// connectScratchMap returns the loaded object's connect_scratch, and fails the
// test if it is not the shape allseer_maps.h declares.
func connectScratchMap(t *testing.T, l *BPFLoader) *bpf.BPFMap {
	t.Helper()

	m, err := l.module.GetMap(MapConnectScratch)
	if err != nil {
		t.Fatalf("map %q: %v", MapConnectScratch, err)
	}
	if m.Type() != bpf.MapTypeLRUHash {
		t.Errorf("%s is a %s; the scratch protocol requires an LRU hash, for the reason "+
			"allseer_maps.h gives: a plain hash filled with orphans stops correlating for good",
			MapConnectScratch, m.Type())
	}
	if got, want := m.KeySize(), 8; got != want {
		t.Errorf("%s key is %d bytes, want %d for allseer_syscall_key_t -- the key is shared "+
			"with openat and must stay so", MapConnectScratch, got, want)
	}
	if got := m.ValueSize(); got != connectScratchSize {
		t.Fatalf("%s value is %d bytes, but this test reads struct allseer_connect_scratch as %d; "+
			"the struct changed and the offsets above have to change with it",
			MapConnectScratch, got, connectScratchSize)
	}
	if got, want := m.MaxEntries(), uint32(4096); got != want {
		t.Errorf("%s holds %d entries, want ALLSEER_MAX_CONNECT_SCRATCH = %d",
			MapConnectScratch, got, want)
	}
	return m
}

// --- collecting connect events ------------------------------------------------

// collectConnects drains the stream once and returns up to `want` network
// events made by one thread.
//
// The thread is the handle, where openat used the path. A connect carries
// nothing that names the caller's intent -- two processes connecting to the same
// port produce identical payloads -- but a TID is unique across the system at any
// instant, and the pinned thread makes exactly the calls the test tells it to.
//
// One drain, stopping as soon as `want` are in hand. The openat tests learned
// this the hard way: reading the record channel is destructive and the drain
// helpers run to their deadline, so two sequential drains over one stream cannot
// both find anything.
func collectConnects(t *testing.T, records <-chan []byte, tid, want int, d time.Duration) []decoded {
	t.Helper()

	var found []decoded
	collectUntil(t, records, d, func(rec decoded) bool {
		if rec.event.Network == nil || int(rec.event.Process.TID) != tid {
			return false
		}
		found = append(found, rec)
		return len(found) >= want
	})
	return found
}

// oneConnect drains for a single connect event from a thread and fails if none
// arrives.
func oneConnect(t *testing.T, records <-chan []byte, tid int, d time.Duration) decoded {
	t.Helper()

	found := collectConnects(t, records, tid, 1, d)
	if len(found) == 0 {
		t.Fatalf("no connect event from thread %d reached user space", tid)
	}
	return found[0]
}

// --- the event ----------------------------------------------------------------

// A tracked connect reaches user space as a complete ALLSEER_EVT_NET_CONNECT,
// with the destination from one tracepoint and the return from another.
func TestRuntimeConnectEventReachesUserspace(t *testing.T) {
	l, records := loadAndAttachPrograms(t, ProgConnectEnter, ProgConnectExit)

	port := listenerPort(t, "tcp4", "127.0.0.1:0")
	cgroupID := trackThisCgroup(t, l)
	thread := newLockedThread(t)

	sa := sockaddrIn([4]byte{127, 0, 0, 1}, port)
	if ret := thread.connectFrom(t, syscall.AF_INET, sa, len(sa)); ret != 0 {
		t.Fatalf("connect to 127.0.0.1:%d returned %v", port, syscall.Errno(-ret))
	}

	got := oneConnect(t, records, thread.tid, 3*time.Second)

	t.Run("event type", func(t *testing.T) {
		if abi.EventType(got.raw.Type) != abi.EvtNetConnect {
			t.Errorf("type = %s, want %s", abi.EventType(got.raw.Type), abi.EvtNetConnect)
		}
		if got.event.Capability != capability.KindNetConnect {
			t.Errorf("capability = %s, want %s", got.event.Capability, capability.KindNetConnect)
		}
		if got.event.Domain != capability.DomainNetwork {
			t.Errorf("domain = %s, want %s", got.event.Domain, capability.DomainNetwork)
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
		if int(got.event.Process.TID) != thread.tid {
			t.Errorf("tid = %d, want the thread that called connect, %d", got.event.Process.TID, thread.tid)
		}
		if int(got.event.Process.PPID) != os.Getppid() {
			t.Errorf("ppid = %d, want %d", got.event.Process.PPID, os.Getppid())
		}
		if int(got.event.Process.UID) != os.Geteuid() {
			t.Errorf("uid = %d, want %d", got.event.Process.UID, os.Geteuid())
		}
		// The group leader's start time, so that (PID, StartTime) is the pair
		// proc_exec and proc_exit report for this process rather than one only
		// this thread's records would carry.
		if got.event.Process.StartTime == 0 {
			t.Error("start_time is zero; (pid, start_time) cannot disambiguate a recycled pid")
		}
		if got.event.Process.Comm != selfComm(t) {
			t.Errorf("comm = %q, want %q", got.event.Process.Comm, selfComm(t))
		}
	})

	t.Run("cgroup id", func(t *testing.T) {
		// The value the entry side matched on, carried through the scratch
		// entry. The record's attribution and the decision that produced the
		// record are the same fact.
		if got.event.Process.CgroupID != cgroupID {
			t.Errorf("cgroup_id = %d, want %d", got.event.Process.CgroupID, cgroupID)
		}
	})

	t.Run("destination", func(t *testing.T) {
		if got.event.Network == nil {
			t.Fatal("no network payload on a connect event")
		}
		if got.event.Network.AddressFamily != "AF_INET" {
			t.Errorf("address family = %q, want AF_INET", got.event.Network.AddressFamily)
		}
		if got.event.Network.DestAddr != "127.0.0.1" {
			t.Errorf("dest addr = %q, want 127.0.0.1", got.event.Network.DestAddr)
		}
		// The port the process passed, in host order. A probe that forwarded
		// the big-endian bytes unchanged would report 65282 for port 8080 and
		// nothing downstream would notice.
		if got.event.Network.DestPort != int(port) {
			t.Errorf("dest port = %d, want %d", got.event.Network.DestPort, port)
		}
	})

	t.Run("fields the tracepoints do not carry", func(t *testing.T) {
		// The local address, the protocol and the socket type are properties of
		// the socket rather than of the call, and reaching them means walking
		// task->files. allseer_maps.h names each one. These assertions pin what
		// the record actually contains so the gap cannot close by accident and
		// cannot widen unnoticed.
		raw := got.raw.Net()
		if raw.Saddr != ([16]uint8{}) {
			t.Errorf("saddr = %v, want zeroes: connect does not carry a local address", raw.Saddr)
		}
		if raw.Sport != 0 || raw.Protocol != 0 || raw.SockType != 0 || raw.Bytes != 0 {
			t.Errorf("sport/protocol/sock_type/bytes = %d/%d/%d/%d, want zeroes",
				raw.Sport, raw.Protocol, raw.SockType, raw.Bytes)
		}

		// And what those zeroes decode to. Protocol and socket type have an
		// "unavailable" rendering and use it; the source address does not, and
		// renders as the wildcard. That last one is a known ABI gap -- see the
		// TODO(event) at the foot of allseer_maps.h -- and it is asserted rather
		// than ignored so that a reader of this test learns it is not an
		// observation.
		if got.event.Network.Protocol != "" {
			t.Errorf("protocol = %q, want empty: the matcher treats that as unevaluable",
				got.event.Network.Protocol)
		}
		if got.event.Network.SocketType != "" {
			t.Errorf("socket type = %q, want empty", got.event.Network.SocketType)
		}
		if got.event.Network.SourceAddr != "0.0.0.0" {
			t.Errorf("source addr = %q; a zero saddr under AF_INET renders as the wildcard, "+
				"which is the ABI gap this test pins", got.event.Network.SourceAddr)
		}
		if got.event.Network.SourcePort != 0 {
			t.Errorf("source port = %d, want 0", got.event.Network.SourcePort)
		}
		if got.event.Network.Hostname != "" {
			t.Errorf("hostname = %q; DNS correlation is not this probe's", got.event.Network.Hostname)
		}
	})

	t.Run("syscall return", func(t *testing.T) {
		// The field the entry side could not have filled. connect returns 0 on
		// success, and decode.go reads ret >= 0 as Succeeded.
		if !got.event.Result.Succeeded || got.event.Result.ReturnCode != 0 {
			t.Errorf("result = %+v, want a zero success", got.event.Result)
		}
		if got.event.Result.Errno != "" {
			t.Errorf("errno = %q on a successful connect", got.event.Result.Errno)
		}
	})

	t.Run("kernel timestamp", func(t *testing.T) {
		if got.event.KernelTimestamp == 0 {
			t.Error("kernel timestamp is zero")
		}
	})

	t.Run("the scratch entry is gone", func(t *testing.T) {
		requireNoScratchEntry(t, connectScratchMap(t, l), scratchKey(os.Getpid(), thread.tid),
			"a connect that completed and was reported")
	})
}

// AF_INET6 decodes to the address the process passed.
//
// Its own test rather than a subtree of the one above, because the two families
// take different branches in the probe: a different minimum length, a different
// structure, and sixteen address bytes instead of four written into the same
// field. A probe that copied four bytes for both would pass every IPv4
// assertion in this file.
func TestRuntimeConnectToIPv6(t *testing.T) {
	l, records := loadAndAttachPrograms(t, ProgConnectEnter, ProgConnectExit)

	port := listenerPort(t, "tcp6", "[::1]:0")
	trackThisCgroup(t, l)
	thread := newLockedThread(t)

	var loopback [16]byte
	loopback[15] = 1 // ::1
	sa := sockaddrIn6(loopback, port)
	if ret := thread.connectFrom(t, syscall.AF_INET6, sa, len(sa)); ret != 0 {
		t.Fatalf("connect to [::1]:%d returned %v", port, syscall.Errno(-ret))
	}

	got := oneConnect(t, records, thread.tid, 3*time.Second)

	if abi.EventType(got.raw.Type) != abi.EvtNetConnect {
		t.Errorf("type = %s, want %s", abi.EventType(got.raw.Type), abi.EvtNetConnect)
	}
	if got.event.Network.AddressFamily != "AF_INET6" {
		t.Errorf("address family = %q, want AF_INET6", got.event.Network.AddressFamily)
	}
	if got.event.Network.DestAddr != "::1" {
		t.Errorf("dest addr = %q, want ::1", got.event.Network.DestAddr)
	}
	if got.event.Network.DestPort != int(port) {
		t.Errorf("dest port = %d, want %d", got.event.Network.DestPort, port)
	}
	if !got.event.Result.Succeeded {
		t.Errorf("result = %+v, want success", got.event.Result)
	}
	requireNoScratchEntry(t, connectScratchMap(t, l), scratchKey(os.Getpid(), thread.tid),
		"an IPv6 connect that completed")
}

// A connect that fails is reported as one, with the errno the kernel returned.
//
// This is the whole reason the record waits for sys_exit rather than being
// emitted at sys_enter. An agent that tried to reach an endpoint and was refused
// is a different governance fact from one that reached it, and a record emitted
// at entry would have to claim one of the two before either was true.
func TestRuntimeConnectReturnSemantics(t *testing.T) {
	l, records := loadAndAttachPrograms(t, ProgConnectEnter, ProgConnectExit)

	open := listenerPort(t, "tcp4", "127.0.0.1:0")
	closed := refusedPort(t)
	trackThisCgroup(t, l)
	thread := newLockedThread(t)

	for _, tc := range []struct {
		name      string
		port      uint16
		wantOK    bool
		wantErrno string
	}{
		{"accepted", open, true, ""},
		{"refused", closed, false, "ECONNREFUSED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sa := sockaddrIn([4]byte{127, 0, 0, 1}, tc.port)
			ret := thread.connectFrom(t, syscall.AF_INET, sa, len(sa))

			got := oneConnect(t, records, thread.tid, 3*time.Second)

			if got.event.Result.ReturnCode != int64(ret) {
				t.Errorf("return code = %d, want the kernel's %d", got.event.Result.ReturnCode, ret)
			}
			if got.event.Result.Succeeded != tc.wantOK {
				t.Errorf("succeeded = %v, want %v (connect returned %d)",
					got.event.Result.Succeeded, tc.wantOK, ret)
			}
			if got.event.Result.Errno != tc.wantErrno {
				t.Errorf("errno = %q, want %q", got.event.Result.Errno, tc.wantErrno)
			}
			// A refused connection still names where it was going. Losing the
			// destination on failure would make the most interesting connects
			// the least legible.
			if got.event.Network.DestPort != int(tc.port) {
				t.Errorf("dest port = %d, want %d", got.event.Network.DestPort, tc.port)
			}
			if got.event.Network.DestAddr != "127.0.0.1" {
				t.Errorf("dest addr = %q, want 127.0.0.1", got.event.Network.DestAddr)
			}

			requireNoScratchEntry(t, connectScratchMap(t, l), scratchKey(os.Getpid(), thread.tid),
				"a connect that returned "+fmt.Sprint(ret))
		})
	}
}

// A family the record cannot carry an address for is reported as itself, with
// no address invented for it.
//
// AF_UNIX is the case that matters in practice: a governed process reaching a
// local daemon does it this way, and the socket path does not fit in a 16-byte
// address field. The event still exists -- a connect happened -- and says which
// family it was, which is everything the ABI can honestly hold.
func TestRuntimeConnectUnsupportedFamily(t *testing.T) {
	l, records := loadAndAttachPrograms(t, ProgConnectEnter, ProgConnectExit)
	trackThisCgroup(t, l)
	thread := newLockedThread(t)

	// A path nothing is listening on, so the call fails and the test does not
	// depend on any daemon being present.
	sa := sockaddrUnix(openMarkerPath(t, "allseer-connect-unix"))
	ret := thread.connectFrom(t, syscall.AF_UNIX, sa, len(sa))
	if ret == 0 {
		t.Fatal("connect to a nonexistent unix socket succeeded")
	}

	got := oneConnect(t, records, thread.tid, 3*time.Second)

	if got.event.Network.AddressFamily != "AF_UNIX" {
		t.Errorf("address family = %q, want AF_UNIX", got.event.Network.AddressFamily)
	}
	// decode.go: "AF_UNIX yields the empty string: a socket path is not an
	// address and does not fit in the field."
	if got.event.Network.DestAddr != "" {
		t.Errorf("dest addr = %q, want empty for AF_UNIX", got.event.Network.DestAddr)
	}
	if got.event.Network.DestPort != 0 {
		t.Errorf("dest port = %d, want 0 for AF_UNIX", got.event.Network.DestPort)
	}
	if raw := got.raw.Net(); raw.Daddr != ([16]uint8{}) {
		t.Errorf("daddr = %v, want zeroes: no address was captured, so none may be claimed", raw.Daddr)
	}
	if got.event.Result.Succeeded {
		t.Errorf("result = %+v, want the failure the kernel returned", got.event.Result)
	}
	// The capability mapping is the decoder's, and the open question this test
	// used to record has since been answered: kindForConnectFamily maps AF_UNIX
	// to ipc.unixsocket, because pkg/capability defines net.connect as reaching
	// "a remote endpoint" and a unix socket has none. Asserted here as well as
	// in the decoder's own tests because this is the path that proves the
	// family reaching the decoder is one a kernel actually wrote.
	if got.event.Capability != capability.KindIPCUnixSock {
		t.Errorf("capability = %s, want %s", got.event.Capability, capability.KindIPCUnixSock)
	}
	if got.event.Domain != capability.DomainIPC {
		t.Errorf("domain = %s, want %s; the kind carries the domain with it",
			got.event.Domain, capability.DomainIPC)
	}

	requireNoScratchEntry(t, connectScratchMap(t, l), scratchKey(os.Getpid(), thread.tid),
		"a connect to a unix socket")
}

// A sockaddr the probe cannot read produces an event with no destination, never
// a fabricated one.
//
// Three ways for that to happen, and all three must land in the same place:
// family AF_UNSPEC, no address, no port, and the kernel's own refusal in `ret`.
// The failure this rules out is the one that would matter most -- a record
// claiming AF_INET and 0.0.0.0, which is a real address a process can connect
// to and would be indistinguishable from an observation.
func TestRuntimeConnectMalformedSockaddr(t *testing.T) {
	l, records := loadAndAttachPrograms(t, ProgConnectEnter, ProgConnectExit)
	trackThisCgroup(t, l)
	thread := newLockedThread(t)
	m := connectScratchMap(t, l)

	full := sockaddrIn([4]byte{127, 0, 0, 1}, 80)

	t.Run("length below the family's minimum", func(t *testing.T) {
		// Eight bytes: enough for the family and the port, short of what the
		// kernel demands for AF_INET. The probe declines to claim a family it
		// cannot back with an address, and the kernel declines the call.
		got := connectAndCollect(t, thread, records, syscall.AF_INET, full, 8)

		if got.event.Network.AddressFamily != "AF_UNSPEC" {
			t.Errorf("address family = %q, want AF_UNSPEC: the address could not be captured, "+
				"so AF_INET must not be claimed", got.event.Network.AddressFamily)
		}
		if got.event.Network.DestAddr != "" || got.event.Network.DestPort != 0 {
			t.Errorf("destination = %q:%d, want nothing",
				got.event.Network.DestAddr, got.event.Network.DestPort)
		}
		if got.event.Result.Succeeded {
			t.Errorf("result = %+v, want the kernel's refusal", got.event.Result)
		}
	})

	t.Run("length too short to hold a family", func(t *testing.T) {
		got := connectAndCollect(t, thread, records, syscall.AF_INET, full, 1)

		if got.event.Network.AddressFamily != "AF_UNSPEC" {
			t.Errorf("address family = %q, want AF_UNSPEC", got.event.Network.AddressFamily)
		}
		if got.event.Network.DestAddr != "" {
			t.Errorf("dest addr = %q, want nothing", got.event.Network.DestAddr)
		}
	})

	t.Run("null pointer", func(t *testing.T) {
		ret := thread.connectPtrFrom(t, syscall.AF_INET, 0, len(full))
		if ret != -int(syscall.EFAULT) {
			t.Logf("connect(NULL) returned %v rather than EFAULT", syscall.Errno(-ret))
		}
		got := oneConnect(t, records, thread.tid, 3*time.Second)

		if got.event.Network.AddressFamily != "AF_UNSPEC" {
			t.Errorf("address family = %q, want AF_UNSPEC", got.event.Network.AddressFamily)
		}
		if got.event.Network.DestAddr != "" {
			t.Errorf("dest addr = %q, want nothing", got.event.Network.DestAddr)
		}
		requireNoScratchEntry(t, m, scratchKey(os.Getpid(), thread.tid), "a connect with a null sockaddr")
	})

	t.Run("unmapped pointer", func(t *testing.T) {
		// A non-null address the process does not own, which takes the
		// bpf_probe_read_user failure branch rather than the null check. The
		// assertion is deliberately the weaker "no address is claimed": if this
		// address were somehow mapped, the family read would return whatever
		// was there, and the probe must still not publish a destination it did
		// not capture.
		const unmapped = 0xdeadbeef0000
		ret := thread.connectPtrFrom(t, syscall.AF_INET, unmapped, len(full))
		if ret == 0 {
			t.Fatal("connect through an unmapped pointer succeeded")
		}
		got := oneConnect(t, records, thread.tid, 3*time.Second)

		if got.event.Network.DestAddr != "" {
			t.Errorf("dest addr = %q, want nothing: no sockaddr was readable",
				got.event.Network.DestAddr)
		}
		if raw := got.raw.Net(); raw.Daddr != ([16]uint8{}) || raw.Dport != 0 {
			t.Errorf("daddr/dport = %v/%d, want zeroes", raw.Daddr, raw.Dport)
		}
		requireNoScratchEntry(t, m, scratchKey(os.Getpid(), thread.tid),
			"a connect with an unreadable sockaddr")
	})
}

// connectAndCollect performs one connect and returns the event it produced.
func connectAndCollect(t *testing.T, thread *lockedThread, records <-chan []byte,
	domain int, sa []byte, addrlen int,
) decoded {
	t.Helper()

	thread.connectFrom(t, domain, sa, addrlen)
	return oneConnect(t, records, thread.tid, 3*time.Second)
}

// --- the filter ---------------------------------------------------------------

// The per-probe filter obligation, proven for the connect pair rather than
// inherited from the four probes that already carry it.
func TestRuntimeUntrackedCgroupProducesNoConnectEvent(t *testing.T) {
	l, records := loadAndAttachPrograms(t, ProgConnectEnter, ProgConnectExit)
	ctx := context.Background()

	port := listenerPort(t, "tcp4", "127.0.0.1:0")
	thread := newLockedThread(t)

	mine := currentCgroupID(t)
	other := mine ^ 0xDEADBEEF // certainly not a cgroup this process is in
	key, value := trackedKV(other)
	if err := l.UpdateMap(ctx, MapTrackedCgroups, key, value); err != nil {
		t.Fatalf("UpdateMap: %v", err)
	}

	sa := sockaddrIn([4]byte{127, 0, 0, 1}, port)
	thread.connectFrom(t, syscall.AF_INET, sa, len(sa))
	if found := collectConnects(t, records, thread.tid, 1, 2*time.Second); len(found) != 0 {
		t.Fatalf("a connect in an untracked cgroup produced %d event(s); the kernel filter did not hold",
			len(found))
	}

	// And nothing was stored for the exit side to find. The stronger statement:
	// the filter does not merely suppress the event at the end, it stops the
	// syscall being tracked at all.
	requireNoScratchEntry(t, connectScratchMap(t, l), scratchKey(os.Getpid(), thread.tid),
		"a connect the cgroup filter rejected (the entry side must store nothing)")

	trackThisCgroup(t, l)
	thread.connectFrom(t, syscall.AF_INET, sa, len(sa))
	if found := collectConnects(t, records, thread.tid, 1, 3*time.Second); len(found) == 0 {
		t.Fatal("a connect in a tracked cgroup produced no event, so the negative case above proves nothing")
	}
}

// --- the seam between the two programs ----------------------------------------

// An exit with no matching entry emits nothing, and in particular does not
// invent a connection out of the return value it does have.
//
// Only the exit program is attached, so every connect on this host reaches a
// program holding a return and no destination. A probe that emitted anyway would
// produce a stream of net.connect events -- the catalog's highest-severity common
// capability -- with no address, attributed to whatever process happened to be
// opening a socket.
func TestRuntimeConnectExitWithoutEntryProducesNoEvent(t *testing.T) {
	l, records := loadAndAttachPrograms(t, ProgConnectExit)
	port := listenerPort(t, "tcp4", "127.0.0.1:0")
	trackThisCgroup(t, l)
	thread := newLockedThread(t)

	sa := sockaddrIn([4]byte{127, 0, 0, 1}, port)
	thread.connectFrom(t, syscall.AF_INET, sa, len(sa))

	// Nothing at all, not merely nothing from this thread: a fabricated record
	// would carry whatever identity the exit side read, so matching narrowly
	// would miss exactly the failure this test is for.
	fabricated := 0
	collectUntil(t, records, 2*time.Second, func(rec decoded) bool {
		if rec.event.Network != nil {
			fabricated++
			t.Errorf("an exit with no scratch entry produced a network event: "+
				"family=%q addr=%q port=%d ret=%d",
				rec.event.Network.AddressFamily, rec.event.Network.DestAddr,
				rec.event.Network.DestPort, rec.event.Result.ReturnCode)
		}
		return false
	})
	if fabricated > 0 {
		t.Fatalf("%d fabricated connect event(s)", fabricated)
	}

	// The control: with the entry side attached too, the same call is reported.
	if err := l.Attach(context.Background(), ProgConnectEnter); err != nil {
		t.Fatalf("Attach %s: %v", ProgConnectEnter, err)
	}
	thread.connectFrom(t, syscall.AF_INET, sa, len(sa))
	if found := collectConnects(t, records, thread.tid, 1, 3*time.Second); len(found) == 0 {
		t.Fatal("with both programs attached the connect produced no event, " +
			"so the negative case above proves nothing")
	}
}

// A scratch entry that belongs to a dead thread is rejected and removed, not
// completed.
//
// The PID-reuse guard, proven for connect the way it was proven for openat:
// by writing the entry from user space, because a stale entry only exists after
// a thread has been killed inside connect and its TID reused, which no test can
// arrange on demand. The correct identity stamp is learned from the probe itself
// under a first loaded object, then used under a second -- sound because the
// stamp is a property of the thread rather than of the object, and lockedThread
// keeps the same thread alive across both.
func TestRuntimeStaleConnectScratchEntryIsRejectedAndDeleted(t *testing.T) {
	requireRoot(t)
	obj := objectOrSkip(t)
	ctx := context.Background()

	port := listenerPort(t, "tcp4", "127.0.0.1:0")
	sa := sockaddrIn([4]byte{127, 0, 0, 1}, port)
	thread := newLockedThread(t)
	key := scratchKey(os.Getpid(), thread.tid)

	// Phase 1: learn what the entry side writes for this thread. With no exit
	// program attached, the entry it writes is never deleted.
	learn := NewLoader(Config{ObjectPath: obj, RingBufferSize: 1 << 22}, nil)
	if err := learn.Load(ctx, obj); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := learn.Attach(ctx, ProgConnectEnter); err != nil {
		t.Fatalf("Attach %s: %v", ProgConnectEnter, err)
	}
	trackThisCgroup(t, learn)
	thread.connectFrom(t, syscall.AF_INET, sa, len(sa))

	genuine, ok := scratchEntry(t, connectScratchMap(t, learn), key)
	if !ok {
		t.Fatal("the entry side stored nothing for a tracked connect, so there is no stamp to learn")
	}
	if err := learn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Phase 2: a second object with only the exit side attached, so nothing
	// overwrites what this test injects.
	l, records := loadAndAttachPrograms(t, ProgConnectExit)
	trackThisCgroup(t, l)
	m := connectScratchMap(t, l)

	inject := func(t *testing.T, dport uint16, stampDelta uint64) {
		t.Helper()
		v := make([]byte, len(genuine))
		copy(v, genuine)

		stamp := binary.NativeEndian.Uint64(v[connectScratchOffTaskStartTime:])
		binary.NativeEndian.PutUint64(v[connectScratchOffTaskStartTime:], stamp+stampDelta)

		// A destination this test can recognise, and a family that makes the
		// decoder render it.
		binary.NativeEndian.PutUint16(v[connectScratchOffFamily:], afInetTest)
		binary.NativeEndian.PutUint16(v[connectScratchOffDport:], dport)
		copy(v[connectScratchOffDaddr:connectScratchOffDaddr+4], []byte{127, 0, 0, 1})

		if err := m.Update(unsafe.Pointer(&key[0]), unsafe.Pointer(&v[0])); err != nil {
			t.Fatalf("injecting a scratch entry: %v", err)
		}
	}

	// A port no connect in this test actually uses, so a match can only have
	// come from the injected entry.
	const markerPort = 59991

	t.Run("a matching stamp is completed", func(t *testing.T) {
		inject(t, markerPort, 0)
		thread.connectFrom(t, syscall.AF_INET, sa, len(sa))

		found := collectConnects(t, records, thread.tid, 1, 3*time.Second)
		if len(found) == 0 {
			t.Fatal("an entry carrying this thread's own stamp produced no event; " +
				"the negative leg below would then prove nothing")
		}
		if got := found[0].event.Network.DestPort; got != markerPort {
			t.Errorf("dest port = %d, want the injected %d -- the record's destination comes "+
				"from the entry, not from the call", got, markerPort)
		}
		requireNoScratchEntry(t, m, key, "an entry that was accepted and reported")
	})

	t.Run("a stale stamp is refused", func(t *testing.T) {
		inject(t, markerPort+1, 1) // a thread created one nanosecond later: not this one
		thread.connectFrom(t, syscall.AF_INET, sa, len(sa))

		for _, rec := range collectConnects(t, records, thread.tid, 1, 2*time.Second) {
			if rec.event.Network.DestPort == markerPort+1 {
				t.Error("an entry whose stamp is not this thread's was completed; a reused TID " +
					"would finish a dead thread's connect, in a cgroup nobody tracked")
			}
		}
		requireNoScratchEntry(t, m, key, "an entry the identity check refused")
	})
}

// Concurrent connects from several threads are correlated per thread.
//
// Every thread here shares a TGID, so a key that used only the process -- or a
// per-CPU slot -- would have these calls overwrite each other. The failure that
// produces is not a missing event: it is an event carrying one thread's
// destination and another thread's return, which arrives and decodes and reads
// as ordinary.
//
// The threads are released together so their calls genuinely overlap, and each
// is given its own listener so the destination port identifies which call a
// record came from independently of the TID it claims.
func TestRuntimeConcurrentConnectsCorrelatePerThread(t *testing.T) {
	l, records := loadAndAttachPrograms(t, ProgConnectEnter, ProgConnectExit)
	trackThisCgroup(t, l)

	const threads = 6

	type call struct {
		port uint16
		tid  int
		ret  int
	}
	calls := make([]call, threads)
	for i := range calls {
		calls[i].port = listenerPort(t, "tcp4", "127.0.0.1:0")
	}

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
			c.tid = syscall.Gettid()
			sa := sockaddrIn([4]byte{127, 0, 0, 1}, c.port)

			fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
			if err != nil {
				ready.Done()
				<-start
				return
			}
			defer syscall.Close(fd)

			ready.Done()
			<-start
			c.ret = rawConnect(fd, sa, len(sa))
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()

	// One drain for all six. Every one of these connects happened before the
	// stream was read, so a drain per thread would have the first thread's
	// drain consume the other five.
	byTID := make(map[int]decoded, threads)
	collectUntil(t, records, 5*time.Second, func(rec decoded) bool {
		if rec.event.Network == nil {
			return false
		}
		tid := int(rec.event.Process.TID)
		if _, seen := byTID[tid]; seen {
			return false
		}
		for _, c := range calls {
			if c.tid == tid {
				byTID[tid] = rec
				break
			}
		}
		return len(byTID) == threads
	})

	m := connectScratchMap(t, l)
	for i, c := range calls {
		rec, ok := byTID[c.tid]
		if !ok {
			t.Errorf("thread %d (tid %d): no connect event for port %d", i, c.tid, c.port)
			continue
		}
		if got := rec.event.Network.DestPort; got != int(c.port) {
			t.Errorf("tid %d: dest port = %d, want %d -- this record carries another thread's destination",
				c.tid, got, c.port)
		}
		if got := rec.event.Result.ReturnCode; got != int64(c.ret) {
			t.Errorf("tid %d: return code = %d, want %d -- this record carries another call's return",
				c.tid, got, c.ret)
		}
		if got := int(rec.event.Process.PID); got != os.Getpid() {
			t.Errorf("tid %d: pid = %d, want %d", c.tid, got, os.Getpid())
		}
		requireNoScratchEntry(t, m, scratchKey(os.Getpid(), c.tid), "a concurrent connect that completed")
	}
}

// --- loss ---------------------------------------------------------------------

// The connect pair carries the drop-counting obligation, and deletes its scratch
// entry on that path too.
//
// Only the two connect programs are attached and nothing drains the one-page
// ring, so every counted drop is a record connect_exit wanted to emit. The
// second assertion is the one this test exists for: the reservation failing is
// the terminal path most likely to be written as a bare `return`, and an entry
// left behind there accumulates precisely when the host is already losing
// records.
func TestRuntimeConnectProbeCountsDropsAndStillDeletesScratch(t *testing.T) {
	requireRoot(t)
	obj := objectOrSkip(t)
	ctx := context.Background()

	closed := refusedPort(t)

	l := NewLoader(Config{ObjectPath: obj, RingBufferSize: os.Getpagesize()}, nil)
	t.Cleanup(func() {
		if err := l.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	if err := l.Load(ctx, obj); err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, prog := range []string{ProgConnectEnter, ProgConnectExit} {
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
	sa := sockaddrIn([4]byte{127, 0, 0, 1}, closed)

	burstConnect := func(n int) {
		thread.do(func() {
			for range n {
				fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
				if err != nil {
					return
				}
				rawConnect(fd, sa, len(sa))
				syscall.Close(fd)
			}
		})
	}

	// Filtered: nothing tracked, so nothing is reserved and nothing is lost.
	burstConnect(64)
	if n, err := l.ReadCounter(ctx, MapRingbufDrops); err != nil {
		t.Fatalf("ReadCounter: %v", err)
	} else if n != 0 {
		t.Fatalf("64 connects the cgroup filter rejected were counted as %d drop(s); "+
			"a filtered event is not a lost one", n)
	}

	trackThisCgroup(t, l)

	const burst = 256
	burstConnect(burst)

	dropped, err := l.ReadCounter(ctx, MapRingbufDrops)
	if err != nil {
		t.Fatalf("ReadCounter: %v", err)
	}
	if dropped == 0 {
		t.Fatalf("%d connects into a %d-byte ring buffer nobody is draining produced 0 counted drops; "+
			"connect_exit is losing records without calling count_ringbuf_drop()", burst, os.Getpagesize())
	}
	t.Logf("burst of %d connects into a %d-byte ring, connect probes only: %d records counted as lost",
		burst, os.Getpagesize(), dropped)

	requireNoScratchEntry(t, connectScratchMap(t, l), scratchKey(os.Getpid(), thread.tid),
		"a connect whose record could not be reserved")
}

// --- coexistence and lifecycle ------------------------------------------------

// Both syscall pairs on one ring buffer, reporting an open and a connect from
// the same thread.
//
// The object has one ring buffer and one filter map by design, and now two
// scratch maps that must stay apart. The failure this rules out is a payload
// union written by one probe and read for another type: the open record's path
// and the connect record's addresses occupy the same bytes.
func TestRuntimeConnectAndOpenShareOneRingBuffer(t *testing.T) {
	l, records := loadAndAttachPrograms(t,
		ProgOpenatEnter, ProgOpenatExit, ProgConnectEnter, ProgConnectExit)

	port := listenerPort(t, "tcp4", "127.0.0.1:0")
	trackThisCgroup(t, l)
	thread := newLockedThread(t)

	openPath := openMarkerPath(t, "allseer-coexist-connect")
	thread.open(openPath, syscall.O_RDONLY, 0)

	sa := sockaddrIn([4]byte{127, 0, 0, 1}, port)
	if ret := thread.connectFrom(t, syscall.AF_INET, sa, len(sa)); ret != 0 {
		t.Fatalf("connect returned %v", syscall.Errno(-ret))
	}

	// One drain, two record shapes. Both were emitted before either was read.
	var opens, connects []decoded
	collectUntil(t, records, 5*time.Second, func(rec decoded) bool {
		if rec.event.File != nil && rec.event.File.Path == openPath {
			opens = append(opens, rec)
		}
		if rec.event.Network != nil && int(rec.event.Process.TID) == thread.tid {
			connects = append(connects, rec)
		}
		return len(opens) > 0 && len(connects) > 0
	})

	if len(opens) == 0 {
		t.Errorf("no open event for %s with both pairs attached", openPath)
	} else {
		if got := opens[0].event.Capability; got != capability.KindFileRead {
			t.Errorf("open capability = %s, want %s", got, capability.KindFileRead)
		}
		if opens[0].event.Network != nil {
			t.Error("an open event carries a network payload; the union was read for the wrong type")
		}
	}

	if len(connects) == 0 {
		t.Errorf("no connect event with both pairs attached")
	} else {
		if got := connects[0].event.Capability; got != capability.KindNetConnect {
			t.Errorf("connect capability = %s, want %s", got, capability.KindNetConnect)
		}
		if connects[0].event.File != nil || connects[0].event.Exec != nil {
			t.Error("a connect event carries a file or exec payload; the union was read for the wrong type")
		}
		if connects[0].event.Network.DestPort != int(port) {
			t.Errorf("connect dest port = %d, want %d", connects[0].event.Network.DestPort, port)
		}
	}

	// Each pair's state lives in its own map, and neither leaked.
	key := scratchKey(os.Getpid(), thread.tid)
	requireNoScratchEntry(t, scratchMap(t, l), key, "an open alongside a connect")
	requireNoScratchEntry(t, connectScratchMap(t, l), key, "a connect alongside an open")
}

// Both connect programs attach, refuse a second attach by name, and are released
// together by DetachAll.
func TestRuntimeConnectProbesAttachAndDetachTogether(t *testing.T) {
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

	pair := []string{ProgConnectEnter, ProgConnectExit}
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

	// Both are really running: one connect yields one event, which needs both.
	port := listenerPort(t, "tcp4", "127.0.0.1:0")
	trackThisCgroup(t, l)
	thread := newLockedThread(t)
	sa := sockaddrIn([4]byte{127, 0, 0, 1}, port)
	thread.connectFrom(t, syscall.AF_INET, sa, len(sa))
	if found := collectConnects(t, records, thread.tid, 1, 3*time.Second); len(found) == 0 {
		t.Error("no connect event with both connect programs attached")
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
