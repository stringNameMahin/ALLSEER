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

	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// ABI v3 on a live kernel: the directory a relative openat is resolved against
// is captured by the probe, joined in user space, and anything the kernel could
// not establish stays unresolved.

func rawOpenatAt(dirfd int, path string, flags int, mode uint32) int {
	p, err := syscall.BytePtrFromString(path)
	if err != nil {
		return -int(syscall.EINVAL)
	}
	fd, _, errno := syscall.Syscall6(syscall.SYS_OPENAT,
		uintptr(dirfd), uintptr(unsafe.Pointer(p)), uintptr(flags), uintptr(mode), 0, 0)
	runtime.KeepAlive(p)
	if errno != 0 {
		return -int(errno)
	}
	return int(fd)
}

func (lt *lockedThread) openAt(dirfd int, path string, flags int, mode uint32) int {
	var ret int
	lt.do(func() {
		ret = rawOpenatAt(dirfd, path, flags, mode)
		if ret >= 0 {
			syscall.Close(ret)
		}
	})
	return ret
}

// realDir is a temporary directory with symlinks in its own path resolved, so
// it can be compared with what the kernel walk reports.
func realDir(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func dirFD(t *testing.T, dir string) int {
	t.Helper()
	fd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { syscall.Close(fd) })
	return fd
}

// one returns the single open event for path, enriched.
func one(t *testing.T, records <-chan []byte, path string) *event.Event {
	t.Helper()
	found := collectOpens(t, records, path, 3*time.Second)
	if len(found) != 1 {
		t.Fatalf("got %d open events for %q, want 1", len(found), path)
	}
	e := found[0].event
	_ = (&PathEnricher{}).Enrich(context.Background(), e)
	return e
}

func TestRuntimeDirfdRelativeOpenIsResolved(t *testing.T) {
	l, records := loadAndAttachPrograms(t, ProgOpenatEnter, ProgOpenatExit)
	trackThisCgroup(t, l)
	thread := newLockedThread(t)

	dir := realDir(t)
	if err := os.WriteFile(filepath.Join(dir, "rel-dirfd.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	fd := dirFD(t, dir)
	if ret := thread.openAt(fd, "rel-dirfd.txt", syscall.O_RDONLY, 0); ret < 0 {
		t.Fatalf("openat: %d", ret)
	}
	e := one(t, records, "rel-dirfd.txt")
	f := e.File
	if f.DirStatus != "complete" || f.Dir != dir || !strings.HasPrefix(f.DirSource, "fd:") {
		t.Fatalf("dir %q source %q status %q, want %q from a dirfd", f.Dir, f.DirSource, f.DirStatus, dir)
	}
	if f.ResolvedPath != filepath.Join(dir, "rel-dirfd.txt") || f.Inode == 0 {
		t.Fatalf("ResolvedPath %q inode %d", f.ResolvedPath, f.Inode)
	}
}

// A failed relative open still carries the directory and still resolves.
func TestRuntimeFailedRelativeOpenIsResolved(t *testing.T) {
	l, records := loadAndAttachPrograms(t, ProgOpenatEnter, ProgOpenatExit)
	trackThisCgroup(t, l)
	thread := newLockedThread(t)

	dir := realDir(t)
	if ret := thread.openAt(dirFD(t, dir), "absent.txt", syscall.O_RDONLY, 0); ret != -int(syscall.ENOENT) {
		t.Fatalf("openat = %d, want ENOENT", ret)
	}
	e := one(t, records, "absent.txt")
	if e.Result.Succeeded || e.File.ResolvedPath != filepath.Join(dir, "absent.txt") {
		t.Fatalf("succeeded %v ResolvedPath %q", e.Result.Succeeded, e.File.ResolvedPath)
	}
}

// ".." is resolved against the real directory tree.
func TestRuntimeDotDotFromDirfd(t *testing.T) {
	l, records := loadAndAttachPrograms(t, ProgOpenatEnter, ProgOpenatExit)
	trackThisCgroup(t, l)
	thread := newLockedThread(t)

	dir := realDir(t)
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "up.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if ret := thread.openAt(dirFD(t, sub), "../up.txt", syscall.O_RDONLY, 0); ret < 0 {
		t.Fatalf("openat: %d", ret)
	}
	if e := one(t, records, "../up.txt"); e.File.ResolvedPath != filepath.Join(dir, "up.txt") {
		t.Fatalf("ResolvedPath = %q", e.File.ResolvedPath)
	}
}

// An absolute path carries no directory, even with a dirfd present.
func TestRuntimeAbsolutePathCarriesNoDir(t *testing.T) {
	// Created before the probes attach: this process is in the tracked cgroup,
	// and its own write of the same path would be a second event.
	dir := realDir(t)
	target := filepath.Join(dir, "abs.txt")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	other := realDir(t)

	l, records := loadAndAttachPrograms(t, ProgOpenatEnter, ProgOpenatExit)
	trackThisCgroup(t, l)
	thread := newLockedThread(t)

	if ret := thread.openAt(dirFD(t, other), target, syscall.O_RDONLY, 0); ret < 0 {
		t.Fatalf("openat: %d", ret)
	}
	e := one(t, records, target)
	if e.File.Dir != "" || e.File.DirStatus != "" || e.File.ResolvedPath != target {
		t.Fatalf("dir %q status %q resolved %q", e.File.Dir, e.File.DirStatus, e.File.ResolvedPath)
	}
}

// A directory deeper than ALLSEER_DIR_MAX is reported truncated, never as a
// shorter path.
func TestRuntimeDeepDirectoryIsTruncatedNotShortened(t *testing.T) {
	l, records := loadAndAttachPrograms(t, ProgOpenatEnter, ProgOpenatExit)
	trackThisCgroup(t, l)
	thread := newLockedThread(t)

	deep := realDir(t)
	for i := 0; i < 4; i++ {
		deep = filepath.Join(deep, strings.Repeat(string(rune('a'+i)), 200))
	}
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	thread.openAt(dirFD(t, deep), "deep.txt", syscall.O_RDONLY, 0)
	e := one(t, records, "deep.txt")
	if e.File.DirStatus != "truncated" || e.File.Dir != "" || e.File.ResolvedPath != "" {
		t.Fatalf("status %q dir %q resolved %q", e.File.DirStatus, e.File.Dir, e.File.ResolvedPath)
	}
}

// A removed directory is reported deleted and its old name is not trusted.
func TestRuntimeDeletedDirectoryIsReported(t *testing.T) {
	l, records := loadAndAttachPrograms(t, ProgOpenatEnter, ProgOpenatExit)
	trackThisCgroup(t, l)
	thread := newLockedThread(t)

	gone := filepath.Join(realDir(t), "gone")
	if err := os.Mkdir(gone, 0o755); err != nil {
		t.Fatal(err)
	}
	fd := dirFD(t, gone)
	if err := os.Remove(gone); err != nil {
		t.Fatal(err)
	}
	thread.openAt(fd, "orphan.txt", syscall.O_RDONLY, 0)
	e := one(t, records, "orphan.txt")
	if e.File.DirStatus != "deleted" || e.File.ResolvedPath != "" {
		t.Fatalf("status %q resolved %q", e.File.DirStatus, e.File.ResolvedPath)
	}
}

// A bad dirfd is unavailable, not a guess.
func TestRuntimeBadDirfdIsUnavailable(t *testing.T) {
	l, records := loadAndAttachPrograms(t, ProgOpenatEnter, ProgOpenatExit)
	trackThisCgroup(t, l)
	thread := newLockedThread(t)

	thread.openAt(987654, "nofd.txt", syscall.O_RDONLY, 0)
	e := one(t, records, "nofd.txt")
	if e.File.DirStatus != "unavailable" || e.File.ResolvedPath != "" {
		t.Fatalf("status %q resolved %q", e.File.DirStatus, e.File.ResolvedPath)
	}
}

// The case that motivated ABI v3: "cd dir && cat file" from a short-lived
// child. The descriptor is closed long before user space could look at it.
func TestRuntimeRelativeOpenAfterCdInShortLivedChild(t *testing.T) {
	l, records := loadAndAttachPrograms(t, ProgOpenatEnter, ProgOpenatExit)
	trackThisCgroup(t, l)

	dir := realDir(t)
	if err := os.WriteFile(filepath.Join(dir, "secret-rel"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/bin/sh", "-c", "cd "+dir+" && /bin/cat secret-rel >/dev/null").CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	e := one(t, records, "secret-rel")
	if e.File.DirSource != "cwd" || e.File.ResolvedPath != filepath.Join(dir, "secret-rel") {
		t.Fatalf("source %q resolved %q", e.File.DirSource, e.File.ResolvedPath)
	}
}
