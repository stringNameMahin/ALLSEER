package e2e

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

// The e2e binary doubles as an agent helper for what bash cannot do. TestMain
// runs helperMain instead of the tests when the variable is set.
const helperEnv = "ALLSEER_E2E_HELPER"

// exitNoUring tells the test that io_uring is unavailable to the agent, which
// is a host property rather than a failure.
const exitNoUring = 77

func helperMain(name string, args []string) int {
	switch name {
	case "uring-connect":
		if len(args) != 1 {
			fmt.Fprintln(os.Stderr, "usage: uring-connect ADDR:PORT")
			return 2
		}
		res, err := uringConnect(args[0])
		if err == errNoUring {
			fmt.Fprintln(os.Stderr, err)
			return exitNoUring
		}
		if err != nil || res != 0 {
			fmt.Fprintf(os.Stderr, "uring-connect %s: res %d err %v\n", args[0], res, err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(os.Stderr, "unknown helper %q\n", name)
	return 2
}

var errNoUring = fmt.Errorf("io_uring is unavailable")

// uringConnect makes one IORING_OP_CONNECT to an IPv4 address and returns the
// completion's result. No connect syscall is made.
func uringConnect(addr string) (int32, error) {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil || !ap.Addr().Is4() {
		return 0, fmt.Errorf("want an IPv4 ADDR:PORT, got %q", addr)
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return 0, err
	}
	defer syscall.Close(fd)
	sa := make([]byte, 16)
	binary.NativeEndian.PutUint16(sa[0:], syscall.AF_INET)
	binary.BigEndian.PutUint16(sa[2:], ap.Port())
	ip := ap.Addr().As4()
	copy(sa[4:], ip[:])

	const (
		sysSetup, sysEnter = 425, 426
		opConnect          = 16
		getEvents          = 1
		featSingleMM       = 1
		offCQRing          = 0x8000000
		offSQEs            = 0x10000000
	)
	params := make([]byte, 120)
	ring, _, errno := syscall.Syscall(sysSetup, 1, uintptr(unsafe.Pointer(&params[0])), 0)
	if errno == syscall.ENOSYS || errno == syscall.EPERM {
		return 0, errNoUring
	}
	if errno != 0 {
		return 0, errno
	}
	defer syscall.Close(int(ring))
	u32 := func(b []byte, off uint32) *uint32 { return (*uint32)(unsafe.Pointer(&b[off])) }

	sqEntries, cqEntries, features := *u32(params, 0), *u32(params, 4), *u32(params, 20)
	sqTail, sqArray := *u32(params, 44), *u32(params, 64)
	cqHead, cqTail, cqMask, cqCQEs := *u32(params, 80), *u32(params, 84), *u32(params, 88), *u32(params, 100)

	mmap := func(off int64, n int) ([]byte, error) {
		return syscall.Mmap(int(ring), off, n, syscall.PROT_READ|syscall.PROT_WRITE,
			syscall.MAP_SHARED|syscall.MAP_POPULATE)
	}
	sqBytes, cqBytes := int(sqArray+sqEntries*4), int(cqCQEs+cqEntries*16)
	var sq, cq []byte
	if features&featSingleMM != 0 {
		sq, err = mmap(0, max(sqBytes, cqBytes))
		cq = sq
	} else if sq, err = mmap(0, sqBytes); err == nil {
		cq, err = mmap(offCQRing, cqBytes)
	}
	if err != nil {
		return 0, err
	}
	sqes, err := mmap(offSQEs, int(sqEntries)*64)
	if err != nil {
		return 0, err
	}

	sqe := sqes[:64]
	sqe[0] = opConnect
	*(*int32)(unsafe.Pointer(&sqe[4])) = int32(fd)
	*(*uint64)(unsafe.Pointer(&sqe[8])) = uint64(len(sa))
	*(*uint64)(unsafe.Pointer(&sqe[16])) = uint64(uintptr(unsafe.Pointer(&sa[0])))
	*u32(sq, sqArray) = 0
	*u32(sq, sqTail)++

	if _, _, errno := syscall.Syscall6(sysEnter, ring, 1, 0, 0, 0, 0); errno != 0 {
		return 0, errno
	}
	runtime.KeepAlive(sa)
	mask := *u32(cq, cqMask)
	for *u32(cq, cqHead) == *u32(cq, cqTail) {
		if _, _, errno := syscall.Syscall6(sysEnter, ring, 0, 1, getEvents, 0, 0); errno != 0 && errno != syscall.EINTR {
			return 0, errno
		}
	}
	cqe := cqCQEs + (*u32(cq, cqHead)&mask)*16
	return *(*int32)(unsafe.Pointer(&cq[cqe+8])), nil
}
