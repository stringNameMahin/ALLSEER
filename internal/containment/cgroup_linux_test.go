//go:build linux

package containment

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func requireRoot(t *testing.T) *Manager {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skipf("cgroup management needs root; running as uid %d", os.Geteuid())
	}
	m, err := NewManager("")
	if err != nil {
		t.Skipf("no cgroup v2: %v", err)
	}
	return m
}

func TestValidSessionName(t *testing.T) {
	for _, ok := range []string{"s-1", "abc.DEF_9", "a"} {
		if !ValidSessionName(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "../x", "a/b", ".hidden", "-x", strings.Repeat("a", 129), "a b"} {
		if ValidSessionName(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

// startHeld starts a shell that appends to a file in a loop, then moves it
// into g before it does anything else.
func startHeld(t *testing.T, g *Group, script string, cred *syscall.Credential) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("/bin/sh", "-c", "read _; "+script)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if cred != nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := g.Adopt(cmd.Process.Pid); err != nil {
		_ = cmd.Process.Kill()
		t.Fatal(err)
	}
	_, _ = stdin.Write([]byte("go\n"))
	_ = stdin.Close()
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return cmd
}

func size(p string) int64 {
	fi, err := os.Stat(p)
	if err != nil {
		return -1
	}
	return fi.Size()
}

func TestRuntimeFreezeThawKill(t *testing.T) {
	m := requireRoot(t)
	ctx := context.Background()
	sid := fmt.Sprintf("test-%d", time.Now().UnixNano())
	g, err := m.Create(sid)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Remove()
	if _, err := m.Create(sid); err == nil {
		t.Fatal("a second Create for one session succeeded")
	}

	out := filepath.Join(t.TempDir(), "ticks")
	// A child and a grandchild both write, so the whole tree is exercised.
	startHeld(t, g, fmt.Sprintf("(while :; do echo b >> %s; sleep 0.01; done) & while :; do echo a >> %s; sleep 0.01; done", out, out), nil)

	deadline := time.Now().Add(2 * time.Second)
	for size(out) < 10 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if pids, _ := g.Pids(); len(pids) < 2 {
		t.Fatalf("expected the shell and its child in the group, got %v", pids)
	}

	if err := g.Freeze(ctx); err != nil {
		t.Fatal(err)
	}
	before := size(out)
	time.Sleep(200 * time.Millisecond)
	if after := size(out); after != before {
		t.Fatalf("frozen tree kept writing: %d -> %d bytes", before, after)
	}
	if fz, _ := g.Frozen(); !fz {
		t.Fatal("Frozen() = false after Freeze")
	}

	if err := g.Thaw(ctx); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if size(out) == before {
		t.Fatal("thawed tree did not resume")
	}

	if err := g.Kill(ctx); err != nil {
		t.Fatal(err)
	}
	if pop, _ := g.Populated(); pop {
		t.Fatal("group still populated after Kill")
	}
	if err := g.Remove(); err != nil {
		t.Fatal(err)
	}
}

// A daemon that died without ending its sessions leaves their cgroups behind.
// The empty ones are garbage and are cleared; a populated one is a tree
// nothing governs any more, and has to be reported rather than killed.
func TestRuntimeSweepClearsEmptyLeftoversAndReportsLive(t *testing.T) {
	requireRoot(t)
	mnt, err := cgroup2Mount()
	if err != nil {
		t.Skipf("no cgroup v2: %v", err)
	}
	base := filepath.Join(mnt, fmt.Sprintf("allseer-sweep-%d", time.Now().UnixNano()))
	m, err := NewManager(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(base) })

	empty, err := m.Create("gone-1")
	if err != nil {
		t.Fatal(err)
	}
	live, err := m.Create("live-1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = live.Kill(context.Background()); _ = live.Remove() })
	startHeld(t, live, "while :; do sleep 0.05; done", nil)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if pop, _ := live.Populated(); pop {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	res, err := m.Sweep()
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Removed) != 1 || res.Removed[0] != "gone-1" {
		t.Fatalf("Removed = %v, want [gone-1]", res.Removed)
	}
	if len(res.Populated) != 1 || res.Populated[0] != "live-1" {
		t.Fatalf("Populated = %v, want [live-1]", res.Populated)
	}
	if _, err := os.Stat(empty.Path); !os.IsNotExist(err) {
		t.Fatalf("the empty leftover survived the sweep: %v", err)
	}
	if _, err := os.Stat(live.Path); err != nil {
		t.Fatalf("the populated group was removed: %v", err)
	}
	if pop, _ := live.Populated(); !pop {
		t.Fatal("the sweep killed the processes in a live group")
	}
}

// An unprivileged agent cannot move itself out of its session cgroup.
func TestRuntimeUnprivilegedProcessCannotEscape(t *testing.T) {
	m := requireRoot(t)
	ctx := context.Background()
	g, err := m.Create(fmt.Sprintf("esc-%d", time.Now().UnixNano()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Kill(ctx); _ = g.Remove() }()

	mnt, _ := cgroup2Mount()
	// The agent runs as nobody, so the result must be reachable without
	// traversing t.TempDir's 0700 parent.
	dir, err := os.MkdirTemp("", "allseer-esc-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	result := filepath.Join(dir, "result")
	script := fmt.Sprintf("if echo $$ > %s/cgroup.procs 2>/dev/null; then echo escaped > %s; else echo refused > %s; fi; sleep 5",
		mnt, result, result)
	cmd := startHeld(t, g, script, &syscall.Credential{Uid: 65534, Gid: 65534})

	deadline := time.Now().Add(3 * time.Second)
	var got string
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(result); err == nil && len(b) > 0 {
			got = strings.TrimSpace(string(b))
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got != "refused" {
		t.Fatalf("escape attempt result = %q, want refused", got)
	}
	pids, _ := g.Pids()
	var inside bool
	for _, p := range pids {
		if p == cmd.Process.Pid {
			inside = true
		}
	}
	if !inside {
		t.Fatalf("the process left its session cgroup; group holds %v", pids)
	}
}
