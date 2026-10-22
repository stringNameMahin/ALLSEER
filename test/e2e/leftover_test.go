package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stringNameMahin/ALLSEER/internal/ipc"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
)

// ctl runs allseerctl as root against a daemon and returns its output.
func ctl(t *testing.T, d *daemon, args ...string) string {
	t.Helper()
	cmd := exec.Command(filepath.Join(e.bin, "allseerctl"), append([]string{args[0], "-socket", d.socket}, args[1:]...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("allseerctl %v: %v\n%s", args, err, out)
	}
	return string(out)
}

// ticking reports whether the agent's loop is still writing its counter.
func ticking(t *testing.T, counter string) bool {
	t.Helper()
	before, _ := os.ReadFile(counter)
	time.Sleep(600 * time.Millisecond)
	after, _ := os.ReadFile(counter)
	return !bytes.Equal(before, after)
}

// A daemon killed without cleanup leaves its session's processes running in
// their cgroup. The next daemon on the same base freezes them at startup, and
// root can list, thaw and kill them. A second daemon on a base that is in use
// refuses to start, which is what makes acting on leftovers safe.
func TestLeftoversAreFrozenAfterADaemonCrash(t *testing.T) {
	first := startDaemon(t, "monitor")
	ws := workspace(t)
	counter := filepath.Join(ws, "counter")
	r := shim(t, first.socket, ws, "", script(t, fmt.Sprintf(
		"(while :; do date +%%s%%N > %s; sleep 0.1; done) </dev/null >/dev/null 2>&1 &\nsleep 60", counter)))
	sid := r.sessionID(t)
	group := filepath.Join(e.cgroups, sid)
	t.Cleanup(func() { killGroup(group) })
	deadline := time.Now().Add(10 * time.Second)
	for !exists(counter) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if !ticking(t, counter) {
		t.Fatal("the agent's loop never started")
	}

	if err := first.cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	<-first.done
	first.done <- nil
	if !ticking(t, counter) {
		t.Fatal("the loop stopped with the daemon; there is no leftover to test")
	}

	second := startDaemon(t, "monitor")
	if ticking(t, counter) {
		t.Fatalf("the leftover still runs after the next daemon started\n%s", filterLibbpf(second.log.String()))
	}
	if b, _ := os.ReadFile(filepath.Join(group, "cgroup.events")); !strings.Contains(string(b), "frozen 1") {
		t.Fatalf("the leftover cgroup is not frozen:\n%s", b)
	}

	var list []ipc.LeftoverInfo
	if err := json.Unmarshal([]byte(ctl(t, second, "leftovers", "-json")), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Name != sid || !list[0].Frozen || len(list[0].PIDs) == 0 {
		t.Fatalf("leftovers = %+v, want %s frozen with its processes", list, sid)
	}
	if st, err := second.client().Status(t.Context()); err != nil || st.Leftovers != 1 {
		t.Fatalf("status leftovers = %v, %v", st, err)
	}

	// A third daemon on the same base would treat the second one's sessions
	// as leftovers. It must not start.
	third := exec.Command(filepath.Join(e.bin, "allseerd"), "--socket", filepath.Join(e.dir, "third.sock"),
		"--object", e.object, "--cgroup-base", e.cgroups, "--audit", filepath.Join(e.dir, "third.jsonl"),
		"--rules", filepath.Join(e.repo, "configs/rules.default.yaml"),
		"--sensitivity", filepath.Join(e.repo, "configs/sensitivity.default.yaml"))
	out, err := third.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "another daemon is governing this cgroup base") {
		t.Fatalf("a second daemon on a base in use = %v:\n%s", err, filterLibbpf(string(out)))
	}
	if exists(filepath.Join(e.dir, "third.jsonl")) {
		t.Fatal("the refused daemon created its audit log")
	}

	ctl(t, second, "leftovers", "thaw", sid)
	if !ticking(t, counter) {
		t.Fatal("the leftover did not resume after thaw")
	}
	ctl(t, second, "leftovers", "kill", sid)
	if exists(group) {
		t.Fatal("the leftover cgroup survived kill")
	}
	if ticking(t, counter) {
		t.Fatal("the leftover's processes survived kill")
	}

	var actions []decision.LeftoverAction
	for _, l := range records[decision.Leftover](t, second, decision.RecordLeftover, sid) {
		actions = append(actions, l.Action)
	}
	if fmt.Sprint(actions) != "[frozen thawed killed]" {
		t.Fatalf("leftover records = %v, want [frozen thawed killed]", actions)
	}
}

// A daemon restarted inside the shim's grace period comes back without the
// session and freezes its agent as a leftover. The shim used to wait on the
// frozen agent and say nothing; it now says why and stops it.
func TestShimNoticesItsSessionWasLostToARestart(t *testing.T) {
	first := startDaemon(t, "monitor")
	ws := workspace(t)
	r := shim(t, first.socket, ws, "", script(t, "sleep 120"))
	sid := r.sessionID(t)
	group := filepath.Join(e.cgroups, sid)
	t.Cleanup(func() { killGroup(group) })
	deadline := time.Now().Add(10 * time.Second)
	for {
		if b, _ := os.ReadFile(filepath.Join(group, "cgroup.procs")); len(strings.TrimSpace(string(b))) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the agent never ran in its cgroup:\n%s", r.stderr.String())
		}
		time.Sleep(50 * time.Millisecond)
	}

	if err := first.cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	<-first.done
	first.done <- nil
	startDaemonAt(t, "monitor", "", first.socket)

	// The shim's stderr is a pipe here and the frozen leftover holds it open,
	// so Wait cannot return before the leftover is gone. The shim process
	// itself has to have exited, which /proc shows.
	pid := r.cmd.Process.Pid
	deadline = time.Now().Add(30 * time.Second)
	for !strings.Contains(r.stderr.String(), "restarted without it") || running(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("the shim did not report the lost session and exit (running %v):\n%s", running(pid), r.stderr.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !strings.Contains(r.stderr.String(), "no longer knows session "+sid) {
		t.Fatalf("shim output after a restart:\n%s", r.stderr.String())
	}
	killGroup(group)
	if code := r.wait(t, 10*time.Second); code == 0 {
		t.Fatal("the shim exited 0 for an agent it stopped")
	}
}

// running reports whether pid is a live process, not gone or a zombie.
func running(pid int) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	return i >= 0 && i+2 < len(s) && s[i+2] != 'Z'
}
