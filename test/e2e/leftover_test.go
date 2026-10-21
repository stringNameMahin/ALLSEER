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
