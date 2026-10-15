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

// A path read at syscall exit may have been rewritten after the kernel read
// it. For a successful open only the inode the open returned can confirm it,
// so every shortcut that trusts the name alone is closed to it. A failed open
// opened nothing, so its late name is treated like an entry-time one.
func TestLatePathIsTrustedOnlyWhenTheOpenedInodeConfirmsIt(t *testing.T) {
	root := tree(t)
	p := &PathEnricher{HostRoot: root}
	mainIno := inodeAt(t, filepath.Join(root, "work/src/main.go"))
	keyIno := inodeAt(t, filepath.Join(root, "home/u/.ssh/id_rsa"))
	late := func(e *event.Event) *event.Event { e.File.PathLate = true; return e }

	ok := late(openEvent("/work/code/main.go", 1, 3, true))
	ok.File.Inode = mainIno
	if err := p.Enrich(context.Background(), ok); err != nil || ok.File.ResolvedPath != "/work/src/main.go" {
		t.Fatalf("confirmed late path: %q, %v", ok.File.ResolvedPath, err)
	}

	refused := map[string]*event.Event{
		// The name was swapped to a harmless file after the kernel opened the key.
		"different inode":    late(openEvent("/work/src/main.go", 1, 3, true)),
		"no inode":           late(openEvent("/work/src/main.go", 1, 3, true)),
		"missing on success": late(openEvent("/work/src/gone.go", 1, 3, true)),
		// One name in the kernel directory with O_NOFOLLOW skips the lookup for
		// an entry-time path; a late one must still be confirmed.
		"single name nofollow": late(relative("main.go", "/work/src", true)),
		// Ambiguous for an entry-time name too.
		"failed dotdot after missing": late(openEvent("/work/gone/../src/x", 1, -2, false)),
	}
	refused["different inode"].File.Inode = keyIno
	refused["missing on success"].File.Inode = mainIno
	refused["single name nofollow"].File.Flags = int32(oNofollow)
	refused["single name nofollow"].File.Inode = keyIno
	for name, e := range refused {
		if err := p.Enrich(context.Background(), e); !errors.Is(err, ErrUnresolvable) || e.File.ResolvedPath != "" {
			t.Errorf("%s: resolved to %q, err %v; want unresolved", name, e.File.ResolvedPath, err)
		}
	}

	nf := late(relative("main.go", "/work/src", true))
	nf.File.Flags = int32(oNofollow)
	nf.File.Inode = mainIno
	if err := p.Enrich(context.Background(), nf); err != nil || nf.File.ResolvedPath != "/work/src/main.go" {
		t.Fatalf("confirmed late single name: %q, %v", nf.File.ResolvedPath, err)
	}

	// bash probing /dev/tty without a terminal on a kernel whose tracepoints
	// cannot fault: the open fails, and the name resolves as it would have
	// at entry.
	failed := map[string]struct {
		e    *event.Event
		want string
	}{
		"absolute":       {late(openEvent("/work/src/absent.go", 1, -6, false)), "/work/src/absent.go"},
		"through a link": {late(openEvent("/work/keys/id_rsa", 1, -13, false)), "/home/u/.ssh/id_rsa"},
		"relative":       {late(relative("id_rsa", "/home/u/.ssh", false)), "/home/u/.ssh/id_rsa"},
	}
	for name, c := range failed {
		if err := p.Enrich(context.Background(), c.e); err != nil || c.e.File.ResolvedPath != c.want {
			t.Errorf("failed open, %s: %q, %v; want %q", name, c.e.File.ResolvedPath, err, c.want)
		}
	}
}

// The kernel's own name for an opened file is the resolved path. It is already
// absolute and fully resolved, so enrichment neither walks it nor needs a host
// root to walk it in - and the two things that name is not are refused.
func TestKernelPathIsTakenAsResolved(t *testing.T) {
	p := &PathEnricher{HostRoot: tree(t)}

	// A path that does not exist under HostRoot still resolves: the kernel
	// named the file it opened, and no lookup can improve on that.
	e := openEvent("/work/keys/id_rsa", 1, 3, true)
	e.File.KernelPath = true
	e.File.Inode = 7
	if err := p.Enrich(context.Background(), e); err != nil || e.File.ResolvedPath != "/work/keys/id_rsa" {
		t.Fatalf("kernel path: %q, %v", e.File.ResolvedPath, err)
	}

	// No inode and no outcome, as the hook submits it.
	e = openEvent("/etc/shadow", 1, 0, true)
	e.File.KernelPath = true
	e.Result.OutcomeUnobserved = true
	if err := p.Enrich(context.Background(), e); err != nil || e.File.ResolvedPath != "/etc/shadow" {
		t.Fatalf("outcome unobserved: %q, %v", e.File.ResolvedPath, err)
	}

	refused := map[string]*event.Event{
		"unreadable": openEvent("", 1, 3, true),
		"relative":   openEvent("pipe:[12345]", 1, 3, true),
		"unlinked":   openEvent("/work/src/main.go (deleted)", 1, 3, true),
	}
	for name, e := range refused {
		e.File.KernelPath = true
		if err := p.Enrich(context.Background(), e); !errors.Is(err, ErrUnresolvable) || e.File.ResolvedPath != "" {
			t.Errorf("%s: resolved to %q, err %v; want unresolved", name, e.File.ResolvedPath, err)
		}
	}
}
