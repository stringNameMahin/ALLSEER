//go:build linux

package telemetry

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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

// A relative open is resolved from the descriptor it returned, and only when
// the descriptor agrees with the name.
func TestRelativeOpenResolvesFromDescriptor(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(dir, "a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	pid := int32(os.Getpid())
	want, _ := filepath.EvalSymlinks(filepath.Join(dir, "a.txt"))

	p := &PathEnricher{}
	e := openEvent("a.txt", pid, int64(f.Fd()), true)
	if err := p.Enrich(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if e.File.ResolvedPath != want {
		t.Fatalf("ResolvedPath = %q, want %q", e.File.ResolvedPath, want)
	}

	// The same descriptor named differently is not trusted.
	e = openEvent("other.txt", pid, int64(f.Fd()), true)
	if err := p.Enrich(context.Background(), e); !errors.Is(err, ErrUnresolvable) || e.File.ResolvedPath != "" {
		t.Fatalf("mismatched name: err = %v, ResolvedPath = %q", err, e.File.ResolvedPath)
	}

	// A failed relative open has no descriptor and is never guessed.
	e = openEvent("a.txt", pid, -2, false)
	if err := p.Enrich(context.Background(), e); !errors.Is(err, ErrUnresolvable) || e.File.ResolvedPath != "" {
		t.Fatalf("failed relative open: err = %v, ResolvedPath = %q", err, e.File.ResolvedPath)
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
