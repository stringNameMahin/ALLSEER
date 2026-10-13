//go:build linux

package telemetry

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// tree builds a host root with a symlinked directory and a symlink escape.
func tree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(root, "work/src"), 0o755))
	must(os.MkdirAll(filepath.Join(root, "home/u/.ssh"), 0o755))
	must(os.WriteFile(filepath.Join(root, "home/u/.ssh/id_rsa"), []byte("k"), 0o600))
	must(os.WriteFile(filepath.Join(root, "work/src/main.go"), []byte("x"), 0o644))
	must(os.Symlink("/home/u/.ssh", filepath.Join(root, "work/keys")))
	must(os.Symlink("src", filepath.Join(root, "work/code")))
	must(os.Symlink("loop2", filepath.Join(root, "work/loop1")))
	must(os.Symlink("loop1", filepath.Join(root, "work/loop2")))
	return root
}

func TestResolveAbsolutePaths(t *testing.T) {
	p := &PathEnricher{HostRoot: tree(t)}
	cases := []struct{ in, want string }{
		{"/work/src/main.go", "/work/src/main.go"},
		// A symlink inside a granted directory is matched on where it lands.
		{"/work/keys/id_rsa", "/home/u/.ssh/id_rsa"},
		{"/work/code/main.go", "/work/src/main.go"},
		{"/work/src/../keys/id_rsa", "/home/u/.ssh/id_rsa"},
		// A missing name cannot be a symlink, so the rest is lexical.
		{"/work/src/new/file.go", "/work/src/new/file.go"},
		{"/work/keys/missing", "/home/u/.ssh/missing"},
		{"//work/./src//main.go", "/work/src/main.go"},
	}
	for _, c := range cases {
		got, err := p.Resolve(c.in, 1, 1)
		if err != nil || got != c.want {
			t.Errorf("Resolve(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
	if _, err := p.Resolve("/work/loop1/x", 1, 1); !errors.Is(err, ErrUnresolvable) {
		t.Errorf("symlink loop: err = %v, want ErrUnresolvable", err)
	}
}

// /proc/self in the agent's record means the agent, not the daemon.
func TestResolveRewritesProcSelf(t *testing.T) {
	p := &PathEnricher{}
	got, err := p.Resolve("/proc/self/status", 4242, 4243)
	if err != nil {
		t.Fatal(err)
	}
	if got != "/proc/4242/status" {
		t.Fatalf("Resolve(/proc/self/status) = %q, want /proc/4242/status", got)
	}
	got, _ = p.Resolve("/proc/thread-self/comm", 4242, 4243)
	if got != "/proc/4242/task/4243/comm" {
		t.Fatalf("thread-self = %q", got)
	}
}

func openEvent(path string, pid int32, ret int64, ok bool) *event.Event {
	return &event.Event{
		Capability: capability.KindFileRead,
		Result:     event.Result{ReturnCode: ret, Succeeded: ok},
		Process:    event.Process{PID: pid, TID: pid},
		File:       &event.FilePayload{Path: path},
	}
}

func inodeAt(t *testing.T, p string) uint64 {
	t.Helper()
	ino, err := inodeOf(p)
	if err != nil {
		t.Fatal(err)
	}
	return ino
}

// relative builds the record the kernel produces for a relative open whose
// directory walk completed.
func relative(path, dir string, ok bool) *event.Event {
	ret := int64(3)
	if !ok {
		ret = -2
	}
	e := openEvent(path, 1, ret, ok)
	e.File.Dir, e.File.DirSource, e.File.DirStatus = dir, "cwd", "complete"
	return e
}

// The /etc/shadow scenario: "cd /etc && cat shadow" is the same file as
// "cat /etc/shadow", and a failed open (EACCES) is still resolved.
func TestRelativeOpenAfterCdResolvesThroughKernelDir(t *testing.T) {
	root := tree(t)
	p := &PathEnricher{HostRoot: root}
	for _, ok := range []bool{true, false} {
		e := relative("id_rsa", "/home/u/.ssh", ok)
		if ok {
			e.File.Inode = inodeAt(t, filepath.Join(root, "home/u/.ssh/id_rsa"))
		}
		if err := p.Enrich(context.Background(), e); err != nil {
			t.Fatalf("ok=%v: %v", ok, err)
		}
		if e.File.ResolvedPath != "/home/u/.ssh/id_rsa" {
			t.Fatalf("ok=%v: ResolvedPath = %q", ok, e.File.ResolvedPath)
		}
	}
}

func TestDirfdSourceResolvesLikeCwd(t *testing.T) {
	root := tree(t)
	e := relative("src/main.go", "/work", true)
	e.File.DirSource = "fd:7"
	e.File.Inode = inodeAt(t, filepath.Join(root, "work/src/main.go"))
	if err := (&PathEnricher{HostRoot: root}).Enrich(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if e.File.ResolvedPath != "/work/src/main.go" {
		t.Fatalf("ResolvedPath = %q", e.File.ResolvedPath)
	}
}

// An absolute path never consults the directory, whatever the record holds.
func TestAbsolutePathIgnoresDir(t *testing.T) {
	root := tree(t)
	e := relative("/work/src/main.go", "/home/u/.ssh", false)
	if err := (&PathEnricher{HostRoot: root}).Enrich(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if e.File.ResolvedPath != "/work/src/main.go" {
		t.Fatalf("ResolvedPath = %q", e.File.ResolvedPath)
	}
}

// ".." is applied to the directory a symlink led to, as the kernel does, not
// lexically to the name.
func TestDotDotFollowsTheSymlinkTarget(t *testing.T) {
	root := tree(t)
	if err := os.WriteFile(filepath.Join(root, "home/u/notes"), []byte("n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e := relative("keys/../notes", "/work", true)
	e.File.Inode = inodeAt(t, filepath.Join(root, "home/u/notes"))
	if err := (&PathEnricher{HostRoot: root}).Enrich(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if e.File.ResolvedPath != "/home/u/notes" {
		t.Fatalf("ResolvedPath = %q, want /home/u/notes (lexical would say /work/notes)", e.File.ResolvedPath)
	}
}

// Anything the kernel could not vouch for stays unresolved.
func TestUnverifiableInputsStayUnresolved(t *testing.T) {
	root := tree(t)
	p := &PathEnricher{HostRoot: root}
	cases := map[string]*event.Event{}

	for _, status := range []string{"truncated", "unavailable", "deleted", ""} {
		e := relative("src/main.go", "", false)
		e.File.DirStatus = status
		cases["dir "+status] = e
	}
	e := relative("/work/src/main.go", "", false)
	e.File.Truncated = true
	cases["truncated absolute path"] = e

	e = relative("src/main.go", "/work", false)
	e.File.Truncated = true
	cases["truncated relative path"] = e

	for name, e := range cases {
		if err := p.Enrich(context.Background(), e); !errors.Is(err, ErrUnresolvable) || e.File.ResolvedPath != "" {
			t.Errorf("%s: err = %v, ResolvedPath = %q", name, err, e.File.ResolvedPath)
		}
	}
}

// A successful open names one inode. A path that no longer names it, because
// a symlink was swapped after the open, is not reported as the opened file.
func TestSymlinkSwapAfterOpenIsDetected(t *testing.T) {
	root := tree(t)
	p := &PathEnricher{HostRoot: root}
	secret := inodeAt(t, filepath.Join(root, "home/u/.ssh/id_rsa"))

	// The agent opened the key through "work/x", then pointed "x" at a
	// harmless file before enrichment.
	if err := os.Symlink("/work/src/main.go", filepath.Join(root, "work/x")); err != nil {
		t.Fatal(err)
	}
	e := relative("x", "/work", true)
	e.File.Inode = secret
	if err := p.Enrich(context.Background(), e); !errors.Is(err, ErrUnresolvable) || e.File.ResolvedPath != "" {
		t.Fatalf("swapped symlink: err = %v, ResolvedPath = %q", err, e.File.ResolvedPath)
	}

	// The same, with the symlink deleted instead.
	e = relative("gone", "/work", true)
	e.File.Inode = secret
	if err := p.Enrich(context.Background(), e); !errors.Is(err, ErrUnresolvable) {
		t.Fatalf("deleted name after a successful open: err = %v", err)
	}
}

// O_CREAT|O_EXCL refuses a symlink, so a file it created and then removed was
// a regular file at that name.
func TestExclusiveCreateMayBeGoneAlready(t *testing.T) {
	root := tree(t)
	e := relative("tmp123", "/work", true)
	e.Capability = capability.KindFileCreate
	e.File.Flags = oCreat | oExcl | 1
	e.File.Inode = 99
	if err := (&PathEnricher{HostRoot: root}).Enrich(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if e.File.ResolvedPath != "/work/tmp123" {
		t.Fatalf("ResolvedPath = %q", e.File.ResolvedPath)
	}
}

// A failed open opened nothing: a missing tail is appended, unless ".."
// follows the missing part, which the walk cannot interpret.
func TestFailedOpenMissingTail(t *testing.T) {
	root := tree(t)
	p := &PathEnricher{HostRoot: root}

	e := relative("nope/deeper.txt", "/work/src", false)
	if err := p.Enrich(context.Background(), e); err != nil || e.File.ResolvedPath != "/work/src/nope/deeper.txt" {
		t.Fatalf("missing tail: %q, %v", e.File.ResolvedPath, err)
	}
	e = relative("nope/../../../home/u/.ssh/id_rsa", "/work/src", false)
	if err := p.Enrich(context.Background(), e); !errors.Is(err, ErrUnresolvable) {
		t.Fatalf("\"..\" after a missing component: %q, %v", e.File.ResolvedPath, err)
	}
}

func TestEnrichNeverOverwrites(t *testing.T) {
	e := openEvent("/x", 1, 3, true)
	e.File.ResolvedPath = "/already"
	if err := (&PathEnricher{}).Enrich(context.Background(), e); err != nil || e.File.ResolvedPath != "/already" {
		t.Fatalf("enricher overwrote a filled field: %q, %v", e.File.ResolvedPath, err)
	}
}

func TestExecEnricherReadsProcExe(t *testing.T) {
	want, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	want, _ = filepath.EvalSymlinks(want)
	e := &event.Event{
		Capability: capability.KindProcessExec,
		Process:    event.Process{PID: int32(os.Getpid())},
		Exec:       &event.ExecPayload{Filename: "./relative"},
	}
	if err := (&ExecEnricher{}).Enrich(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if e.Process.Executable != want {
		t.Fatalf("Executable = %q, want %q", e.Process.Executable, want)
	}
}

// O_NOFOLLOW means the kernel refused a symlink as the last component, so a
// directory opened that way and then removed is still exactly that name.
func TestNofollowOpenOfARemovedName(t *testing.T) {
	root := tree(t)
	e := relative("b001", "/work", true)
	e.File.Flags = int32(oNofollow) | syscall.O_DIRECTORY
	e.File.Inode = 7
	if err := (&PathEnricher{HostRoot: root}).Enrich(context.Background(), e); err != nil || e.File.ResolvedPath != "/work/b001" {
		t.Fatalf("%q, %v", e.File.ResolvedPath, err)
	}
	// Without it, the removed name may have been a symlink.
	e = relative("b002", "/work", true)
	e.File.Inode = 7
	if err := (&PathEnricher{HostRoot: root}).Enrich(context.Background(), e); !errors.Is(err, ErrUnresolvable) {
		t.Fatalf("plain open of a removed name: %v", err)
	}
}

// /proc/self of an actor that has exited names its own procfs entry, except
// for magic links, which point elsewhere and must not be read lexically.
func TestProcSelfOfAnExitedActor(t *testing.T) {
	const gone = 999999999 // no such pid
	p := &PathEnricher{}
	ok := openEvent("/proc/self/cgroup", gone, 3, true)
	ok.File.Inode = 1
	if err := p.Enrich(context.Background(), ok); err != nil || ok.File.ResolvedPath != "/proc/999999999/cgroup" {
		t.Fatalf("/proc/self/cgroup: %q, %v", ok.File.ResolvedPath, err)
	}
	for _, path := range []string{"/proc/self/root/etc/shadow", "/proc/self/cwd", "/proc/self/fd/3", "/proc/self/task/1/root/x"} {
		e := openEvent(path, gone, 3, true)
		e.File.Inode = 1
		if err := p.Enrich(context.Background(), e); !errors.Is(err, ErrUnresolvable) {
			t.Errorf("%s resolved to %q", path, e.File.ResolvedPath)
		}
	}
}

// Go's cleanup opens each build directory O_NOFOLLOW by name relative to its
// parent, then removes the whole tree. The kernel's directory plus one name
// that cannot be a symlink is exact even when neither exists any more.
func TestSingleNameInARemovedKernelDirectory(t *testing.T) {
	root := tree(t)
	e := relative("b013", "/tmp/go-build123", true)
	e.File.Flags = int32(oNofollow)
	e.File.Inode = 5
	if err := (&PathEnricher{HostRoot: root}).Enrich(context.Background(), e); err != nil || e.File.ResolvedPath != "/tmp/go-build123/b013" {
		t.Fatalf("%q, %v", e.File.ResolvedPath, err)
	}
	// Two components: the first may have been a symlink, so no shortcut.
	e = relative("gone/b013", "/tmp/go-build123", true)
	e.File.Flags = int32(oNofollow)
	e.File.Inode = 5
	if err := (&PathEnricher{HostRoot: root}).Enrich(context.Background(), e); !errors.Is(err, ErrUnresolvable) {
		t.Fatalf("multi-component name: %q, %v", e.File.ResolvedPath, err)
	}
}
