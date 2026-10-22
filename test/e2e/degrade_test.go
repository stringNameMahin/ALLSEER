package e2e

import (
	"bytes"
	"context"
	"debug/elf"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A kernel whose verifier refuses one probe family used to stop the daemon
// governing at all. It now governs without that family, and says so to the
// person launching the agent, in status and in the session's audit record.
// It does not run enforce sessions on it.
func TestDaemonGovernsWithoutAFamilyTheKernelRefuses(t *testing.T) {
	need(t)
	obj := refuseSections(t, e.object, "tracepoint/syscalls/sys_exit_connect")
	d := startDaemonFrom(t, "monitor", "", filepath.Join(e.dir, fmt.Sprintf("refused-%d.sock", time.Now().UnixNano())), obj)

	r := shim(t, d.socket, workspace(t), "", script(t, "exit 0"))
	sid := r.sessionID(t)
	if code := r.wait(t, 30*time.Second); code != 0 {
		t.Fatalf("agent exit = %d\n%s", code, r.stderr.String())
	}
	if !strings.Contains(r.stderr.String(), "WARNING: telemetry is degraded on this host") {
		t.Errorf("the shim did not warn that telemetry is degraded:\n%s", r.stderr.String())
	}
	st, err := d.client().Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !st.Coverage.Degraded {
		t.Errorf("status coverage = %+v, want degraded", st.Coverage)
	}
	if start, _ := d.framed(t, sid); !start.Coverage.Degraded {
		t.Errorf("session_start coverage = %+v, want degraded", start.Coverage)
	}
	if log := filterLibbpf(d.log.String()); !strings.Contains(log, "refused the connect family") {
		t.Errorf("the daemon log does not name the refused family:\n%s", log)
	}

	// Nobody reads the warning in an unattended run, so enforce is refused
	// and the agent never starts.
	r = shim(t, d.socket, workspace(t), "enforce", script(t, "exit 0"))
	if code := r.wait(t, 30*time.Second); code != 125 {
		t.Errorf("enforce on degraded telemetry: shim exit = %d, want 125 (not launched)\n%s", code, r.stderr.String())
	}
	if !strings.Contains(r.stderr.String(), "refusing an enforce session") || !strings.Contains(r.stderr.String(), "connect") {
		t.Errorf("the refusal does not say why:\n%s", r.stderr.String())
	}
}

// A kernel that refuses every family behind a core kind leaves the lead
// guarantees without evidence. The daemon refuses to govern rather than run
// sessions whose file opens or connects go unrecorded. Without the openat pair
// the self-test is what refuses; without both connect families, the core check.
func TestDaemonRefusesWhenTheKernelRefusesACoreKind(t *testing.T) {
	need(t)
	for _, c := range []struct {
		name     string
		sections []string
		why      []string
	}{
		{"openat", []string{"fexit/do_sys_openat2"},
			[]string{"refused the openat family", "telemetry self-test failed; refusing to govern"}},
		{"connect", []string{"tracepoint/syscalls/sys_exit_connect", "fentry/security_socket_connect"},
			[]string{"core kinds are unobservable on this host; refusing to govern: [net.connect]"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			log := daemonRefuses(t, refuseSections(t, e.object, c.sections...))
			for _, w := range c.why {
				if !strings.Contains(log, w) {
					t.Errorf("the refusal does not say %q:\n%s", w, log)
				}
			}
		})
	}
}

// daemonRefuses runs allseerd in enforce mode on obj, wants it to exit
// without becoming ready, and returns its log.
func daemonRefuses(t *testing.T, obj string) string {
	t.Helper()
	socket := filepath.Join(e.dir, fmt.Sprintf("refuse-%d.sock", time.Now().UnixNano()))
	cmd := exec.Command(filepath.Join(e.bin, "allseerd"),
		"--socket", socket, "--object", obj, "--mode", "enforce", "--cgroup-base", e.cgroups,
		"--audit", filepath.Join(e.dir, fmt.Sprintf("refuse-%d.jsonl", time.Now().UnixNano())),
		"--rules", filepath.Join(e.repo, "configs/rules.default.yaml"),
		"--sensitivity", filepath.Join(e.repo, "configs/sensitivity.default.yaml"))
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("allseerd exited 0:\n%s", filterLibbpf(out.String()))
		}
	case <-time.After(60 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("allseerd kept running:\n%s", filterLibbpf(out.String()))
	}
	log := filterLibbpf(out.String())
	if strings.Contains(log, "allseerd ready") {
		t.Errorf("allseerd reported ready before refusing:\n%s", log)
	}
	if _, err := os.Stat(socket); err == nil {
		t.Error("the control socket was created although the daemon refused to govern")
	}
	return log
}

// refuseSections copies obj with the first instruction of each program
// section made an exit, which the verifier refuses: R0 is read before it is
// set.
func refuseSections(t *testing.T, obj string, sections ...string) string {
	t.Helper()
	b, err := os.ReadFile(obj)
	if err != nil {
		t.Fatal(err)
	}
	f, err := elf.NewFile(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	for _, section := range sections {
		sec := f.Section(section)
		if sec == nil {
			t.Fatalf("no section %s in %s", section, obj)
		}
		copy(b[sec.Offset:], []byte{0x95, 0, 0, 0, 0, 0, 0, 0})
	}
	out := filepath.Join(e.dir, fmt.Sprintf("refused-%d.bpf.o", time.Now().UnixNano()))
	if err := os.WriteFile(out, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return out
}
