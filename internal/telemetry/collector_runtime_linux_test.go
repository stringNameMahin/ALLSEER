//go:build linux && ebpf

package telemetry

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stringNameMahin/ALLSEER/internal/containment"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// The whole M6 path on a live kernel: a dedicated session cgroup, the real BPF
// object, attribution, ancestry, path and exec enrichment, and resolved
// observations, for a process tree doing absolute, relative and symlinked
// opens.
func TestRuntimeCollectorEndToEnd(t *testing.T) {
	requireRoot(t)
	obj := objectOrSkip(t)
	ctx := context.Background()

	mgr, err := containment.NewManager("")
	if err != nil {
		t.Skipf("no cgroup v2 containment: %v", err)
	}
	sid := fmt.Sprintf("coll-%d", time.Now().UnixNano())
	g, err := mgr.Create(sid)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Kill(ctx); _ = g.Remove() }()

	c, err := NewBPFCollector(Config{ObjectPath: obj, RingBufferSize: 1 << 22})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if cov := c.Coverage(); !cov.FloorIntact || cov.Degraded {
		t.Fatalf("coverage on the build host: floor %v degraded %v\n%s", cov.FloorIntact, cov.Degraded, cov.BugReport())
	}

	dir, err := os.MkdirTemp("", "allseer-coll-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	dir, _ = filepath.EvalSymlinks(dir)
	rel := filepath.Join(dir, "rel.txt")
	target := filepath.Join(dir, "target.txt")
	for _, p := range []string{rel, target} {
		if err := os.WriteFile(p, []byte("x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(target, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}

	script := fmt.Sprintf("read _; cd %s && /bin/cat /etc/hostname rel.txt link >/dev/null; /bin/sh -c '/bin/cat %s >/dev/null'", dir, rel)
	cmd := exec.Command("/bin/sh", "-c", script)
	stdin, _ := cmd.StdinPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := g.Adopt(cmd.Process.Pid); err != nil {
		t.Fatal(err)
	}
	if err := c.AttachCgroup(ctx, sid, g.ID, int32(cmd.Process.Pid)); err != nil {
		t.Fatal(err)
	}

	// A process outside the session doing the same reads must not appear.
	_ = exec.Command("/bin/cat", "/etc/hostname").Run()

	_, _ = stdin.Write([]byte("go\n"))
	_ = stdin.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("agent script: %v", err)
	}

	var evs []event.Event
	deadline := time.After(3 * time.Second)
collect:
	for {
		select {
		case e := <-c.Events():
			evs = append(evs, e)
		case <-deadline:
			break collect
		}
	}

	var (
		seq        uint64
		catExec    int
		deepCat    bool
		resolved   = map[string]bool{}
		catExe     string
		exits      int
		relMissed  int
		relCorrect int
	)
	for _, e := range evs {
		if e.SessionID != sid {
			t.Fatalf("event attributed to %q: %+v", e.SessionID, e)
		}
		if e.Sequence != seq+1 {
			t.Fatalf("sequence gap: %d after %d", e.Sequence, seq)
		}
		seq = e.Sequence
		if e.Dropped != 0 {
			t.Fatalf("event reports %d dropped records", e.Dropped)
		}
		switch e.Capability {
		case capability.KindProcessExec:
			if e.Exec != nil && e.Exec.Filename == "/bin/cat" {
				catExec++
				catExe = e.Process.Executable
				if e.Process.AncestryDepth >= 2 {
					deepCat = true
				}
			}
		case capability.KindProcessExit:
			exits++
		case capability.KindFileRead:
			if filepath.IsAbs(e.File.Path) && e.File.ResolvedPath == "" {
				t.Errorf("absolute open of %q left unresolved: %s", e.File.Path, describeOpen(e))
			}
			if !filepath.IsAbs(e.File.Path) {
				// Resolved from the descriptor or not at all; never wrong.
				want := map[string]string{"rel.txt": rel, "link": target}[e.File.Path]
				switch e.File.ResolvedPath {
				case "":
					relMissed++
					t.Logf("unresolved open: %s", describeOpen(e))
				case want:
					relCorrect++
				default:
					t.Errorf("relative open of %q resolved to %q, want %q or nothing", e.File.Path, e.File.ResolvedPath, want)
				}
			}
			if e.File.ResolvedPath != "" {
				resolved[e.File.ResolvedPath] = true
				if e.Observation.Target != e.File.ResolvedPath {
					t.Errorf("observation target %q != resolved path %q", e.Observation.Target, e.File.ResolvedPath)
				}
			} else if e.Observation.Target != "" {
				t.Errorf("unresolved open has observation target %q", e.Observation.Target)
			}
		}
	}
	t.Logf("%d events for the session; relative opens resolved %d, unresolved %d", len(evs), relCorrect, relMissed)
	// ABI v3 captures the directory in the kernel, so a short-lived process's
	// relative opens resolve.
	if relMissed != 0 || relCorrect != 2 {
		t.Errorf("relative opens: %d resolved, %d unresolved; want 2 and 0", relCorrect, relMissed)
	}

	if catExec != 2 {
		t.Errorf("saw %d execs of /bin/cat, want 2", catExec)
	}
	if !deepCat {
		t.Error("the cat run through a nested shell was not seen at depth >= 2")
	}
	if want, _ := filepath.EvalSymlinks("/bin/cat"); catExe != want {
		t.Errorf("cat Executable = %q, want %q", catExe, want)
	}
	if exits < 3 {
		t.Errorf("saw %d exits, want at least 3", exits)
	}
	hostname, _ := filepath.EvalSymlinks("/etc/hostname")
	for _, want := range []string{hostname, rel, target} {
		if !resolved[want] {
			t.Errorf("no resolved read of %s; resolved set: %v", want, resolved)
		}
	}
	if st := c.CollectorStats(); st.Unattributed != 0 || st.DroppedEvents != 0 {
		t.Errorf("stats: %+v", st)
	}

	if err := c.DetachSession(ctx, sid); err != nil {
		t.Fatal(err)
	}
}

// describeOpen renders everything the record carried about an open, so a
// failure on a host that cannot be reproduced locally explains itself.
func describeOpen(e event.Event) string {
	f := e.File
	return fmt.Sprintf("pid %d tid %d comm %q exe %q path %q truncated %v dir %q dir_source %q dir_status %q flags %#x ret %d errno %q inode %d",
		e.Process.PID, e.Process.TID, e.Process.Comm, e.Process.Executable, f.Path, f.Truncated,
		f.Dir, f.DirSource, f.DirStatus, f.Flags, e.Result.ReturnCode, e.Result.Errno, f.Inode)
}
