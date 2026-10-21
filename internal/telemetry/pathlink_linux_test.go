//go:build linux && ebpf

package telemetry

// Runtime tests for the security_path_link hook: a hard link reported by the
// file it points at and the name it creates, whichever entry point made it.

import (
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/stringNameMahin/ALLSEER/internal/telemetry/abi"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

const ioringOpLinkat = 39

// linkat calls linkat(2) on the pinned thread and returns 0 or -errno.
func (lt *lockedThread) linkat(olddfd int, oldpath string, newdfd int, newpath string) int {
	var ret int
	lt.do(func() {
		o, err1 := syscall.BytePtrFromString(oldpath)
		n, err2 := syscall.BytePtrFromString(newpath)
		if err1 != nil || err2 != nil {
			ret = -int(syscall.EINVAL)
			return
		}
		_, _, errno := syscall.Syscall6(syscall.SYS_LINKAT, uintptr(olddfd), uintptr(unsafe.Pointer(o)),
			uintptr(newdfd), uintptr(unsafe.Pointer(n)), 0, 0)
		runtime.KeepAlive(o)
		runtime.KeepAlive(n)
		if errno != 0 {
			ret = -int(errno)
		}
	})
	return ret
}

// linkat submits one IORING_OP_LINKAT. No link syscall is made.
func (r *uring) linkat(t *testing.T, oldpath, newpath string) int {
	t.Helper()
	o, err1 := syscall.BytePtrFromString(oldpath)
	n, err2 := syscall.BytePtrFromString(newpath)
	if err1 != nil || err2 != nil {
		t.Fatal("bad path")
	}
	sqe := r.sqes[:sqeSize]
	for i := range sqe {
		sqe[i] = 0
	}
	sqe[0] = ioringOpLinkat
	*(*int32)(unsafe.Pointer(&sqe[4])) = int32(fdcwd())
	*(*uint64)(unsafe.Pointer(&sqe[8])) = uint64(uintptr(unsafe.Pointer(n)))
	*(*uint64)(unsafe.Pointer(&sqe[16])) = uint64(uintptr(unsafe.Pointer(o)))
	*(*int32)(unsafe.Pointer(&sqe[24])) = int32(fdcwd())
	*(*uint64)(unsafe.Pointer(&sqe[32])) = 3
	res := r.submitOne(t)
	runtime.KeepAlive(o)
	runtime.KeepAlive(n)
	return int(res)
}

// oneLink returns the single link record whose destination is dst.
func oneLink(t *testing.T, records <-chan []byte, dst string) decoded {
	t.Helper()
	var found []decoded
	collectUntil(t, records, 2*time.Second, func(d decoded) bool {
		if d.event.Capability == capability.KindFileLink && d.event.File != nil && d.event.File.NewPath == dst {
			found = append(found, d)
		}
		return len(found) > 1
	})
	if len(found) != 1 {
		t.Fatalf("got %d link records for %s, want 1", len(found), dst)
	}
	return found[0]
}

// assertLink checks what every record from this hook carries: the source by
// the kernel's own absolute name with its inode, the name created, and no
// claim about the outcome.
func assertLink(t *testing.T, got decoded, src, dst string) {
	t.Helper()
	f := got.event.File
	if abi.EventType(got.raw.Type) != abi.EvtFileLink {
		t.Errorf("type = %s", abi.EventType(got.raw.Type))
	}
	if f.Path != src || f.NewPath != dst || f.Truncated || !f.KernelPath {
		t.Errorf("link %q -> %q truncated %v kernel %v, want %q -> %q from the kernel",
			f.Path, f.NewPath, f.Truncated, f.KernelPath, src, dst)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(src, &st); err != nil {
		t.Fatal(err)
	}
	if f.Inode != st.Ino {
		t.Errorf("inode = %d, want the source's %d", f.Inode, st.Ino)
	}
	if !got.event.Result.OutcomeUnobserved {
		t.Errorf("result = %+v, want the outcome unobserved", got.event.Result)
	}
	if err := (&PathEnricher{}).Enrich(t.Context(), got.event); err != nil || f.ResolvedPath != src {
		t.Errorf("ResolvedPath = %q, %v; want the kernel's source path %q", f.ResolvedPath, err, src)
	}
}

func newLinkSource(t *testing.T) (dir, src string) {
	t.Helper()
	dir = realDir(t)
	src = filepath.Join(dir, "secret")
	if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, src
}

// linkat with a relative source against a directory descriptor: the record
// names the file by its absolute path anyway, because the kernel resolved it.
func TestRuntimeLinkatIsReportedByTheKernelsNames(t *testing.T) {
	dir, src := newLinkSource(t)
	l, records := loadAndAttachPrograms(t, ProgPathLink)
	trackThisCgroup(t, l)
	thread := newLockedThread(t)

	dfd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(dfd)
	if ret := thread.linkat(dfd, "secret", dfd, "alias"); ret != 0 {
		t.Fatalf("linkat: %v", syscall.Errno(-ret))
	}
	assertLink(t, oneLink(t, records, filepath.Join(dir, "alias")), src, filepath.Join(dir, "alias"))
}

// The legacy link syscall, where the architecture has one.
func TestRuntimeLegacyLinkIsReported(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skipf("%s has no link syscall", runtime.GOARCH)
	}
	dir, src := newLinkSource(t)
	l, records := loadAndAttachPrograms(t, ProgPathLink)
	trackThisCgroup(t, l)
	thread := newLockedThread(t)
	dst := filepath.Join(dir, "legacy")
	var errno syscall.Errno
	thread.do(func() { errno, _ = syscall.Link(src, dst).(syscall.Errno) })
	if errno != 0 {
		t.Fatalf("link: %v", errno)
	}
	assertLink(t, oneLink(t, records, dst), src, dst)
}

// The entry point no syscall tracepoint could see.
func TestRuntimeIoUringLinkIsReported(t *testing.T) {
	dir, src := newLinkSource(t)
	l, records := loadAndAttachPrograms(t, ProgPathLink)
	trackThisCgroup(t, l)
	r := newUring(t)
	dst := filepath.Join(dir, "by-uring")
	if res := r.linkat(t, src, dst); res != 0 {
		t.Fatalf("io_uring linkat: %v", syscall.Errno(-res))
	}
	assertLink(t, oneLink(t, records, dst), src, dst)
}

// The hook filters on the cgroup like every other program.
func TestRuntimeLinkFromAnUntrackedCgroupIsNotReported(t *testing.T) {
	dir, src := newLinkSource(t)
	l, records := loadAndAttachPrograms(t, ProgPathLink)
	key, value := trackedKV(currentCgroupID(t) ^ 0xDEADBEEF)
	if err := l.UpdateMap(t.Context(), MapTrackedCgroups, key, value); err != nil {
		t.Fatal(err)
	}
	thread := newLockedThread(t)
	if ret := thread.linkat(fdcwd(), src, fdcwd(), filepath.Join(dir, "unseen")); ret != 0 {
		t.Fatalf("linkat: %v", syscall.Errno(-ret))
	}
	var seen []*event.Event
	collectUntil(t, records, 2*time.Second, func(d decoded) bool {
		if d.event.Capability == capability.KindFileLink {
			seen = append(seen, d.event)
		}
		return false
	})
	if len(seen) != 0 {
		t.Fatalf("an untracked cgroup produced %d link records", len(seen))
	}
}
