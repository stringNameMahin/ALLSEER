//go:build linux && ebpf

package telemetry

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// The kernel-side open hook on a live kernel. What the syscall probes cannot
// reach is the whole reason it exists, so these tests open files the ways a
// tracepoint on openat does not see: openat2, an io_uring request, and the
// legacy open syscall where the architecture still has one.

const (
	sysIoUringSetup = 425
	sysIoUringEnter = 426
	sysOpenat2      = 437

	ioringOpOpenat      = 18
	ioringEnterGetEvent = 1
	ioringOffSQRing     = 0
	ioringOffCQRing     = 0x8000000
	ioringOffSQEs       = 0x10000000
	ioringFeatSingleMM  = 1

	sqeSize = 64
	cqeSize = 16
)

// openHow is struct open_how, openat2's third argument.
type openHow struct {
	Flags   uint64
	Mode    uint64
	Resolve uint64
}

func (lt *lockedThread) openat2(path string, flags uint64) int {
	return lt.openat2At(fdcwd(), path, flags, 0)
}

func (lt *lockedThread) openat2At(dirfd int, path string, flags, resolve uint64) int {
	var ret int
	lt.do(func() {
		p, err := syscall.BytePtrFromString(path)
		if err != nil {
			ret = -int(syscall.EINVAL)
			return
		}
		how := openHow{Flags: flags, Resolve: resolve}
		fd, _, errno := syscall.Syscall6(sysOpenat2, uintptr(dirfd),
			uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&how)),
			unsafe.Sizeof(how), 0, 0)
		runtime.KeepAlive(p)
		runtime.KeepAlive(&how)
		if errno != 0 {
			ret = -int(errno)
			return
		}
		ret = int(fd)
		syscall.Close(ret)
	})
	return ret
}

func fdcwd() int { return -100 }

// u32 and u64 read a field out of a kernel-filled byte buffer.
func u32(b []byte, off uintptr) uint32 { return *(*uint32)(unsafe.Pointer(&b[off])) }

// uring is the smallest io_uring that can submit one request: no library, so
// what the kernel sees is exactly what this test wrote.
type uring struct {
	fd       int
	sqRing   []byte
	cqRing   []byte
	sqes     []byte
	sqTail   uintptr
	sqArray  uintptr
	cqHead   uintptr
	cqTail   uintptr
	cqCQEs   uintptr
	cqMask   uint32
	mappings [][]byte
}

func newUring(t *testing.T) *uring {
	t.Helper()
	// struct io_uring_params: 120 bytes, sq_off at 40 and cq_off at 80.
	params := make([]byte, 120)
	fd, _, errno := syscall.Syscall(sysIoUringSetup, 1, uintptr(unsafe.Pointer(&params[0])), 0)
	if errno == syscall.ENOSYS || errno == syscall.EPERM {
		t.Skipf("io_uring is unavailable on this host: %v", errno)
	}
	if errno != 0 {
		t.Fatalf("io_uring_setup: %v", errno)
	}
	r := &uring{fd: int(fd)}
	t.Cleanup(func() {
		for _, m := range r.mappings {
			_ = syscall.Munmap(m)
		}
		_ = syscall.Close(r.fd)
	})

	sqEntries := u32(params, 0)
	cqEntries := u32(params, 4)
	features := u32(params, 20)
	sqArray := u32(params, 40+24)
	r.sqTail = uintptr(u32(params, 40+4))
	cqHead := u32(params, 80)
	cqTail := u32(params, 80+4)
	r.cqMask = 0
	cqMaskOff := u32(params, 80+8)
	cqCQEs := u32(params, 80+20)

	mmapAt := func(off int64, length int) []byte {
		m, err := syscall.Mmap(r.fd, off, length,
			syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED|syscall.MAP_POPULATE)
		if err != nil {
			t.Fatalf("mmap io_uring at %#x: %v", off, err)
		}
		r.mappings = append(r.mappings, m)
		return m
	}

	sqBytes := int(sqArray) + int(sqEntries)*4
	cqBytes := int(cqCQEs) + int(cqEntries)*cqeSize
	if features&ioringFeatSingleMM != 0 {
		size := sqBytes
		if cqBytes > size {
			size = cqBytes
		}
		r.sqRing = mmapAt(ioringOffSQRing, size)
		r.cqRing = r.sqRing
	} else {
		r.sqRing = mmapAt(ioringOffSQRing, sqBytes)
		r.cqRing = mmapAt(ioringOffCQRing, cqBytes)
	}
	r.sqes = mmapAt(ioringOffSQEs, int(sqEntries)*sqeSize)

	r.sqArray = uintptr(sqArray)
	r.cqHead = uintptr(cqHead)
	r.cqTail = uintptr(cqTail)
	r.cqCQEs = uintptr(cqCQEs)
	r.cqMask = u32(r.cqRing, uintptr(cqMaskOff))
	return r
}

// openat submits one IORING_OP_OPENAT and returns its result. The open runs
// inside the kernel with no openat syscall anywhere, which is the case no
// syscall tracepoint can observe.
func (r *uring) openat(t *testing.T, path string) int {
	t.Helper()
	p, err := syscall.BytePtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}

	sqe := r.sqes[:sqeSize]
	for i := range sqe {
		sqe[i] = 0
	}
	sqe[0] = ioringOpOpenat
	*(*int32)(unsafe.Pointer(&sqe[4])) = int32(fdcwd())
	*(*uint64)(unsafe.Pointer(&sqe[16])) = uint64(uintptr(unsafe.Pointer(p)))
	*(*uint32)(unsafe.Pointer(&sqe[28])) = uint32(syscall.O_RDONLY)
	*(*uint64)(unsafe.Pointer(&sqe[32])) = 1 // user_data

	res := r.submitOne(t)
	runtime.KeepAlive(p)
	if res >= 0 {
		syscall.Close(int(res))
	}
	return int(res)
}

// submitOne submits the entry already written at slot 0 and waits for its
// completion. The wait is retried on EINTR: a request that does not complete
// inline, such as a connect, can be interrupted by the Go runtime's own
// preemption signal.
func (r *uring) submitOne(t *testing.T) int32 {
	t.Helper()
	*(*uint32)(unsafe.Pointer(&r.sqRing[r.sqArray])) = 0
	tail := *(*uint32)(unsafe.Pointer(&r.sqRing[r.sqTail]))
	*(*uint32)(unsafe.Pointer(&r.sqRing[r.sqTail])) = tail + 1

	if _, _, errno := syscall.Syscall6(sysIoUringEnter, uintptr(r.fd), 1, 0, 0, 0, 0); errno != 0 {
		t.Fatalf("io_uring_enter submit: %v", errno)
	}
	for {
		head := *(*uint32)(unsafe.Pointer(&r.cqRing[r.cqHead]))
		cqTail := *(*uint32)(unsafe.Pointer(&r.cqRing[r.cqTail]))
		if head != cqTail {
			cqe := r.cqCQEs + uintptr(head&r.cqMask)*cqeSize
			res := *(*int32)(unsafe.Pointer(&r.cqRing[cqe+8]))
			*(*uint32)(unsafe.Pointer(&r.cqRing[r.cqHead])) = head + 1
			return res
		}
		_, _, errno := syscall.Syscall6(sysIoUringEnter, uintptr(r.fd), 0, 1, ioringEnterGetEvent, 0, 0)
		if errno != 0 && errno != syscall.EINTR {
			t.Fatalf("io_uring_enter wait: %v", errno)
		}
	}
}

// existingFile creates a file and returns its path with symlinks resolved.
// Called before the probes attach, because this process's own cgroup is the
// tracked one and the open that creates the file would be reported too.
func existingFile(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join(realDir(t), name)
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// kernelOpen returns the single file event the hook produced for path, matched
// on the kernel's own name for it rather than on what the caller passed.
func kernelOpen(t *testing.T, records <-chan []byte, want string) *event.Event {
	t.Helper()
	var found []*event.Event
	collectUntil(t, records, 3*time.Second, func(d decoded) bool {
		if d.event.File != nil && d.event.File.Path == want {
			found = append(found, d.event)
		}
		return len(found) > 1
	})
	if len(found) != 1 {
		t.Fatalf("got %d file events for %q, want 1", len(found), want)
	}
	return found[0]
}

// assertKernelOpen checks the properties every record from this hook carries:
// the kernel's own absolute path, used as the resolved path without a walk, an
// inode, and an outcome it does not claim to know.
func assertKernelOpen(t *testing.T, e *event.Event, want string) {
	t.Helper()
	f := e.File
	switch {
	case !f.KernelPath:
		t.Errorf("record for %q is not marked as a kernel path: %+v", want, f)
	case f.Truncated || f.PathLate || f.Dir != "" || f.DirStatus != "":
		t.Errorf("kernel path carries user-space path state: %+v", f)
	case f.Inode == 0 || f.Device == 0:
		t.Errorf("kernel path has inode %d device %d, want both set", f.Inode, f.Device)
	}
	if !e.Result.OutcomeUnobserved || !e.Result.Succeeded || e.Result.Errno != "" {
		t.Errorf("result = %+v, want succeeded with the outcome unobserved", e.Result)
	}
	if err := (&PathEnricher{}).Enrich(context.Background(), e); err != nil || f.ResolvedPath != want {
		t.Errorf("ResolvedPath = %q, %v; want %q taken as it stands", f.ResolvedPath, err, want)
	}
	if e.Capability != capability.KindFileRead {
		t.Errorf("capability = %s, want fs.read", e.Capability)
	}
}

// The hook alone still sees an openat2 that succeeded. With the openat pair
// attached the pair owns it instead; see TestRuntimeOpenPairReportsEveryOpenSyscall.
func TestRuntimeOpenat2IsObservedByTheKernelHook(t *testing.T) {
	target := existingFile(t, "by-openat2.txt")
	l, records := loadAndAttachPrograms(t, ProgFileOpen)
	trackThisCgroup(t, l)
	thread := newLockedThread(t)
	if ret := thread.openat2(target, syscall.O_RDONLY); ret < 0 {
		if ret == -int(syscall.ENOSYS) {
			t.Skip("openat2 is not available on this kernel")
		}
		t.Fatalf("openat2: %d", ret)
	}
	assertKernelOpen(t, kernelOpen(t, records, target), target)
}

// The kernel's own name for a deep file fits too. bpf_d_path writes into the
// same field as the openat pair, and at 256 bytes it failed for any path past
// it, which ordinary layouts such as node_modules/.pnpm reach.
func TestRuntimeKernelHookReportsALongPathWhole(t *testing.T) {
	dir := realDir(t)
	for len(dir) < 600 {
		dir = filepath.Join(dir, strings.Repeat("d", 190))
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "deep.txt")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	l, records := loadAndAttachPrograms(t, ProgFileOpen)
	trackThisCgroup(t, l)
	thread := newLockedThread(t)
	if ret := thread.openat2(target, syscall.O_RDONLY); ret < 0 {
		if ret == -int(syscall.ENOSYS) {
			t.Skip("openat2 is not available on this kernel")
		}
		t.Fatalf("openat2: %d", ret)
	}
	assertKernelOpen(t, kernelOpen(t, records, target), target)
}

// The case no tracepoint can reach. An IORING_OP_OPENAT is a ring entry the
// kernel executes, so there is no openat syscall to attach to at all.
func TestRuntimeIoUringOpenIsObserved(t *testing.T) {
	target := existingFile(t, "by-io-uring.txt")
	l, records := loadAndAttachPrograms(t, ProgFileOpen)
	trackThisCgroup(t, l)
	r := newUring(t)
	if res := r.openat(t, target); res < 0 {
		t.Fatalf("io_uring openat: %d", res)
	}
	assertKernelOpen(t, kernelOpen(t, records, target), target)
}

// The legacy open syscall, where the architecture has one. arm64 has no open
// and no creat, so there is nothing to miss there.
func TestRuntimeLegacyOpenIsObserved(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skipf("%s has no open syscall; glibc calls openat", runtime.GOARCH)
	}
	target := existingFile(t, "by-open.txt")
	l, records := loadAndAttachPrograms(t, ProgFileOpen)
	trackThisCgroup(t, l)
	thread := newLockedThread(t)
	var ret int
	thread.do(func() {
		p, err := syscall.BytePtrFromString(target)
		if err != nil {
			t.Error(err)
			return
		}
		const sysOpen = 2
		fd, _, errno := syscall.Syscall(sysOpen, uintptr(unsafe.Pointer(p)), uintptr(syscall.O_RDONLY), 0)
		runtime.KeepAlive(p)
		if errno != 0 {
			ret = -int(errno)
			return
		}
		ret = int(fd)
		syscall.Close(ret)
	})
	if ret < 0 {
		t.Fatalf("open: %d", ret)
	}
	assertKernelOpen(t, kernelOpen(t, records, target), target)
}

// One open, one record. With the openat pair attached the pair owns every
// openat, because it alone can report the return value, so the hook must not
// add a second record for the same call.
func TestRuntimeOpenatIsReportedOnceWithBothAttached(t *testing.T) {
	target := existingFile(t, "once.txt")
	l, records := loadAndAttachPrograms(t, ProgOpenatEnter, ProgOpenatExit, ProgFileOpen)
	trackThisCgroup(t, l)
	thread := newLockedThread(t)
	if ret := thread.openAt(fdcwd(), target, syscall.O_RDONLY, 0); ret < 0 {
		t.Fatalf("openat: %d", ret)
	}

	var found []*event.Event
	collectUntil(t, records, 3*time.Second, func(d decoded) bool {
		if d.event.File != nil && d.event.File.Path == target {
			found = append(found, d.event)
		}
		return false
	})
	if len(found) != 1 {
		t.Fatalf("got %d records for one openat, want 1", len(found))
	}
	e := found[0]
	// The pair's record, not the hook's: it carries the return value.
	if e.File.KernelPath || e.Result.OutcomeUnobserved || !e.Result.Succeeded {
		t.Errorf("the surviving record is not the openat pair's: file %+v result %+v", e.File, e.Result)
	}
}

// Without the pair, the hook reports openat too. A host that could not attach
// the pair still sees the opens, by the kernel's own name and with no outcome,
// which is the degradation the family boundary is drawn for.
func TestRuntimeHookCoversOpenatWithoutThePair(t *testing.T) {
	target := existingFile(t, "hook-only.txt")
	l, records := loadAndAttachPrograms(t, ProgFileOpen)
	trackThisCgroup(t, l)
	thread := newLockedThread(t)
	if ret := thread.openAt(fdcwd(), target, syscall.O_RDONLY, 0); ret < 0 {
		t.Fatalf("openat: %d", ret)
	}
	assertKernelOpen(t, kernelOpen(t, records, target), target)
}

// An open that fails during path resolution never reaches the hook, because no
// file was opened. That gap is the other half of why the openat pair stays.
func TestRuntimeHookDoesNotSeeAFailedLookup(t *testing.T) {
	l, records := loadAndAttachPrograms(t, ProgFileOpen)
	trackThisCgroup(t, l)
	thread := newLockedThread(t)

	absent := filepath.Join(realDir(t), "absent.txt")
	if ret := thread.openAt(fdcwd(), absent, syscall.O_RDONLY, 0); ret != -int(syscall.ENOENT) {
		t.Fatalf("openat = %d, want ENOENT", ret)
	}
	var seen int
	collectUntil(t, records, time.Second, func(d decoded) bool {
		if d.event.File != nil && d.event.File.Path == absent {
			seen++
		}
		return false
	})
	if seen != 0 {
		t.Errorf("the hook reported %d records for an open that never opened a file", seen)
	}
}

// A program the loader left out of the kernel must refuse to attach and say
// why. GetProgram still finds it in the object, so without the disabled set
// the attach would fail with something about a descriptor and the operator
// would go looking for the wrong fault.
func TestRuntimeDisabledProgramRefusesToAttachWithItsReason(t *testing.T) {
	requireRoot(t)
	obj := objectOrSkip(t)

	l := NewLoader(Config{ObjectPath: obj, RingBufferSize: 1 << 22}, nil)
	if err := l.Load(context.Background(), obj); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })

	// What Load records when a kernel cannot load the hook.
	const reason = "not loaded: no BTF for security_file_open"
	l.mu.Lock()
	l.disabled[ProgFileOpen] = reason
	delete(l.loaded, ProgFileOpen)
	l.mu.Unlock()

	err := l.Attach(context.Background(), ProgFileOpen)
	if err == nil {
		t.Fatal("attaching a program that was not loaded succeeded")
	}
	if !strings.Contains(err.Error(), reason) {
		t.Errorf("attach error = %v, want the reason it was not loaded", err)
	}

	var info ProbeInfo
	for _, p := range l.Probes() {
		if p.Name == ProgFileOpen {
			info = p
		}
	}
	if info.Loaded || info.Attached || !strings.Contains(info.Error, reason) {
		t.Errorf("probe = %+v, want not loaded, not attached, and the reason reported", info)
	}

	// The rest of the object is unaffected: the point of dropping one program
	// is that the others still run.
	if err := l.Attach(context.Background(), ProgOpenatEnter); err != nil {
		t.Errorf("openat_enter did not attach alongside a disabled program: %v", err)
	}
}

// An exec is not a read. The kernel opens the program it runs through this same
// hook, and a record for it would be validated as fs.read against an envelope
// that granted process.exec - so a binary a session may run but not read would
// depart from its envelope for running. sched_process_exec is what reports the
// act, with the image and its arguments.
func TestRuntimeHookIgnoresTheOpenThatExecsAProgram(t *testing.T) {
	l, records := loadAndAttachPrograms(t, ProgFileOpen, ProgProcExec)
	trackThisCgroup(t, l)

	if out, err := exec.Command("/bin/true").CombinedOutput(); err != nil {
		t.Fatalf("/bin/true: %v: %s", err, out)
	}
	truePath, err := filepath.EvalSymlinks("/bin/true")
	if err != nil {
		t.Fatal(err)
	}

	var opens, execs int
	collectUntil(t, records, 2*time.Second, func(d decoded) bool {
		switch {
		case d.event.File != nil && d.event.File.Path == truePath:
			opens++
		case d.event.Capability == capability.KindProcessExec &&
			d.event.Exec != nil && strings.HasSuffix(d.event.Exec.Filename, "/true"):
			execs++
		}
		return false
	})
	if opens != 0 {
		t.Errorf("the hook reported %d file opens for an exec of %s", opens, truePath)
	}
	if execs == 0 {
		t.Error("the exec probe did not report the exec, so this test proves nothing")
	}
}

// legacyOpen calls the open syscall where the architecture has one.
func (lt *lockedThread) legacyOpen(path string) int {
	var ret int
	lt.do(func() {
		p, err := syscall.BytePtrFromString(path)
		if err != nil {
			ret = -int(syscall.EINVAL)
			return
		}
		const sysOpen = 2
		fd, _, errno := syscall.Syscall(sysOpen, uintptr(unsafe.Pointer(p)), uintptr(syscall.O_RDONLY), 0)
		runtime.KeepAlive(p)
		if errno != 0 {
			ret = -int(errno)
			return
		}
		ret = int(fd)
		syscall.Close(ret)
	})
	return ret
}

// The pair on do_sys_openat2 reports every open syscall, and reports a failed
// one with its errno - the case the kernel-side hook never sees, and the one a
// denied credential read depends on. Each open here names a file that does not
// exist, so a record can only have come from the pair.
func TestRuntimeOpenPairReportsEveryOpenSyscallWithItsOutcome(t *testing.T) {
	l, records := loadAndAttachPrograms(t, ProgOpenatEnter, ProgOpenatExit)
	trackThisCgroup(t, l)
	thread := newLockedThread(t)
	dir := realDir(t)

	opens := map[string]func(path string) int{
		"openat":  func(p string) int { return thread.openAt(fdcwd(), p, syscall.O_RDONLY, 0) },
		"openat2": func(p string) int { return thread.openat2(p, syscall.O_RDONLY) },
	}
	if runtime.GOARCH == "amd64" {
		opens["open"] = thread.legacyOpen
	}
	for name, open := range opens {
		path := filepath.Join(dir, "absent-via-"+name)
		if ret := open(path); ret != -int(syscall.ENOENT) {
			if ret == -int(syscall.ENOSYS) {
				t.Logf("%s is not available on this kernel", name)
				continue
			}
			t.Fatalf("%s = %d, want ENOENT", name, ret)
		}
		e := one(t, records, path)
		if e.File.KernelPath || e.Result.OutcomeUnobserved {
			t.Errorf("%s: the record is the hook's, not the pair's: %+v %+v", name, e.File, e.Result)
		}
		if e.Result.Succeeded || e.Result.Errno != "ENOENT" {
			t.Errorf("%s: result %+v, want ENOENT", name, e.Result)
		}
	}
}

// openat2 with RESOLVE_IN_ROOT resolves the name with the dirfd as its root, so
// "/etc/marker" names <dir>/etc/marker. The pair leaves such an open to the
// hook, which reports the file the kernel actually opened; the pair would have
// reported a host path that names a different file.
func TestRuntimeResolveInRootIsReportedByTheKernelsName(t *testing.T) {
	dir := realDir(t)
	if err := os.MkdirAll(filepath.Join(dir, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(dir, "etc", "marker")
	if err := os.WriteFile(inside, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	fd := dirFD(t, dir)

	l, records := loadAndAttachPrograms(t, ProgOpenatEnter, ProgOpenatExit, ProgFileOpen)
	trackThisCgroup(t, l)
	thread := newLockedThread(t)

	const resolveInRoot = 0x10
	if ret := thread.openat2At(fd, "/etc/marker", syscall.O_RDONLY, resolveInRoot); ret < 0 {
		if ret == -int(syscall.ENOSYS) {
			t.Skip("openat2 is not available on this kernel")
		}
		t.Fatalf("openat2 RESOLVE_IN_ROOT: %d", ret)
	}

	var byName, byKernel int
	collectUntil(t, records, 3*time.Second, func(d decoded) bool {
		if d.event.File == nil || int(d.event.Process.TID) != thread.tid {
			return false
		}
		switch d.event.File.Path {
		case "/etc/marker":
			byName++
		case inside:
			if d.event.File.KernelPath {
				byKernel++
			}
		}
		return false
	})
	if byName != 0 {
		t.Errorf("%d records name /etc/marker, which on the host is a different file", byName)
	}
	if byKernel != 1 {
		t.Errorf("got %d kernel-named records for %s, want 1", byKernel, inside)
	}
}
