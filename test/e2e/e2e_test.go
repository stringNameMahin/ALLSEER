// Package e2e runs the shipped binaries end to end on a live kernel: allseerd
// as root with the real BPF object, allseer-shim launching an agent as an
// unprivileged user, and allseerctl and the control socket as the observer.
//
// It needs root, kernel BTF, cgroup v2 and prebuilt binaries:
//
//	ALLSEER_E2E_BIN=<dir with allseerd (ebpf), allseer-shim, allseerctl>
//	ALLSEER_E2E_OBJECT=<path to allseer.bpf.o>
//
// make test-e2e builds them and runs this as root. Without them every test
// skips and says why.
package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stringNameMahin/ALLSEER/internal/ipc"
	"github.com/stringNameMahin/ALLSEER/internal/session"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

const agentUID = 65534 // nobody

type env struct {
	dir    string // 0755 scratch reachable by the agent user
	bin    string
	object string
	repo   string
	skip   string
	// cgroups is this run's own cgroup base, so the suite neither takes nor
	// trips over the lock of a daemon installed on the host.
	cgroups string
}

var e env

func TestMain(m *testing.M) {
	if name := os.Getenv(helperEnv); name != "" {
		os.Exit(helperMain(name, os.Args[1:]))
	}
	e = setup()
	code := m.Run()
	clearCgroups()
	os.Exit(code)
}

// clearCgroups kills whatever this run left under its cgroup base and
// removes it.
func clearCgroups() {
	if e.cgroups == "" {
		return
	}
	entries, _ := os.ReadDir(e.cgroups)
	for _, ent := range entries {
		if ent.IsDir() {
			killGroup(filepath.Join(e.cgroups, ent.Name()))
		}
	}
	_ = os.Remove(e.cgroups)
}

// killGroup kills every process in a session cgroup and removes it.
func killGroup(g string) {
	_ = os.WriteFile(filepath.Join(g, "cgroup.kill"), []byte("1"), 0)
	for i := 0; i < 100 && os.Remove(g) != nil; i++ {
		time.Sleep(20 * time.Millisecond)
	}
}

func setup() env {
	var out env
	switch {
	case os.Geteuid() != 0:
		out.skip = "needs root"
	case os.Getenv("ALLSEER_E2E_BIN") == "" || os.Getenv("ALLSEER_E2E_OBJECT") == "":
		out.skip = "ALLSEER_E2E_BIN and ALLSEER_E2E_OBJECT are not set (use make test-e2e)"
	}
	if out.skip != "" {
		return out
	}
	out.repo, _ = filepath.Abs("../..")
	dir, err := os.MkdirTemp("", "allseer-e2e-")
	if err != nil {
		out.skip = err.Error()
		return out
	}
	_ = os.Chmod(dir, 0o755)
	out.dir = dir
	out.cgroups = fmt.Sprintf("/sys/fs/cgroup/allseer-e2e-%d", os.Getpid())
	out.object = os.Getenv("ALLSEER_E2E_OBJECT")
	// Copy the binaries somewhere the agent user can execute them.
	out.bin = filepath.Join(dir, "bin")
	_ = os.Mkdir(out.bin, 0o755)
	for _, name := range []string{"allseerd", "allseer-shim", "allseerctl"} {
		b, err := os.ReadFile(filepath.Join(os.Getenv("ALLSEER_E2E_BIN"), name))
		if err != nil {
			out.skip = err.Error()
			return out
		}
		if err := os.WriteFile(filepath.Join(out.bin, name), b, 0o755); err != nil {
			out.skip = err.Error()
			return out
		}
	}
	// And this binary, for the agent helpers bash cannot stand in for.
	self, err := os.ReadFile("/proc/self/exe")
	if err == nil {
		err = os.WriteFile(filepath.Join(out.bin, "e2e-helper"), self, 0o755)
	}
	if err != nil {
		out.skip = err.Error()
	}
	return out
}

func need(t *testing.T) {
	t.Helper()
	if e.skip != "" {
		t.Skip(e.skip)
	}
}

// daemon is one running allseerd.
type daemon struct {
	cmd    *exec.Cmd
	socket string
	audit  string
	log    *bytes.Buffer
	done   chan error
}

func startDaemon(t *testing.T, mode string) *daemon {
	return startDaemonWithConfig(t, mode, "")
}

// startDaemonWithConfig starts a daemon with extra configuration, written to a
// file and passed with --config. An empty body uses the built-in defaults.
func startDaemonWithConfig(t *testing.T, mode, body string) *daemon {
	t.Helper()
	need(t)
	var cfg string
	if body != "" {
		cfg = filepath.Join(e.dir, fmt.Sprintf("cfg-%d.yaml", time.Now().UnixNano()))
		if err := os.WriteFile(cfg, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return startDaemonWith(t, mode, cfg)
}

func startDaemonWith(t *testing.T, mode, cfg string) *daemon {
	t.Helper()
	need(t)
	d := &daemon{
		socket: filepath.Join(e.dir, fmt.Sprintf("d-%d.sock", time.Now().UnixNano())),
		audit:  filepath.Join(e.dir, fmt.Sprintf("audit-%d.jsonl", time.Now().UnixNano())),
		log:    &bytes.Buffer{},
		done:   make(chan error, 1),
	}
	args := []string{
		"--socket", d.socket, "--object", e.object, "--audit", d.audit, "--cgroup-base", e.cgroups,
		"--rules", filepath.Join(e.repo, "configs/rules.default.yaml"),
		"--sensitivity", filepath.Join(e.repo, "configs/sensitivity.default.yaml"),
	}
	// An empty mode runs the daemon on its built-in default.
	if mode != "" {
		args = append(args, "--mode", mode)
	}
	if cfg != "" {
		args = append([]string{"--config", cfg}, args...)
	}
	d.cmd = exec.Command(filepath.Join(e.bin, "allseerd"), args...)
	d.cmd.Stdout, d.cmd.Stderr = d.log, d.log
	if err := d.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { d.done <- d.cmd.Wait() }()
	t.Cleanup(func() {
		var pending []decision.ApprovalRequest
		if t.Failed() {
			pending, _ = d.client().PendingApprovals(context.Background())
		}
		_ = d.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-d.done:
		case <-time.After(15 * time.Second):
			_ = d.cmd.Process.Kill()
		}
		if t.Failed() {
			t.Logf("daemon log:\n%s", filterLibbpf(d.log.String()))
			for _, r := range pending {
				t.Logf("pending approval %s: %s", r.ID, describeEvent(r.Event))
			}
			t.Logf("decisions other than allow:\n%s", d.explain())
		}
	})
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := ipc.Dial(context.Background(), d.socket); err == nil {
			return d
		}
		select {
		case err := <-d.done:
			t.Fatalf("allseerd exited during startup: %v\n%s", err, filterLibbpf(d.log.String()))
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("allseerd did not come up\n%s", filterLibbpf(d.log.String()))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func filterLibbpf(s string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if !strings.HasPrefix(l, "libbpf:") {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

func (d *daemon) client() *ipc.SocketClient { return &ipc.SocketClient{Path: d.socket} }

// auditLine is one line of the audit log with its kind.
type auditLine struct {
	kind decision.RecordKind
	sid  string
	raw  []byte
}

// lines reads the whole audit log. Every line must name its kind.
func (d *daemon) lines(t *testing.T) []auditLine {
	t.Helper()
	f, err := os.Open(d.audit)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []auditLine
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<22)
	for sc.Scan() {
		kind, err := decision.KindOf(sc.Bytes())
		if err != nil {
			t.Fatalf("malformed audit record: %v\n%s", err, sc.Bytes())
		}
		var head struct {
			SessionID string `json:"session_id"`
		}
		_ = json.Unmarshal(sc.Bytes(), &head)
		out = append(out, auditLine{kind: kind, sid: head.SessionID, raw: append([]byte(nil), sc.Bytes()...)})
	}
	return out
}

// records decodes the audit lines of one kind that belong to session sid.
func records[T any](t *testing.T, d *daemon, kind decision.RecordKind, sid string) []T {
	t.Helper()
	var out []T
	for _, l := range d.lines(t) {
		if l.kind != kind || l.sid != sid {
			continue
		}
		var v T
		if err := json.Unmarshal(l.raw, &v); err != nil {
			t.Fatalf("malformed %s record: %v", kind, err)
		}
		out = append(out, v)
	}
	return out
}

// decisions returns the decisions of one session.
func (d *daemon) decisions(t *testing.T, sid string) []decision.Decision {
	t.Helper()
	return records[decision.Decision](t, d, decision.RecordDecision, sid)
}

// framed checks that a session's part of the log opens with its start record
// and closes with its end record, and returns both.
func (d *daemon) framed(t *testing.T, sid string) (decision.SessionStart, decision.SessionEnd) {
	t.Helper()
	var kinds []decision.RecordKind
	for _, l := range d.lines(t) {
		if l.sid == sid {
			kinds = append(kinds, l.kind)
		}
	}
	if len(kinds) < 2 || kinds[0] != decision.RecordSessionStart || kinds[len(kinds)-1] != decision.RecordSessionEnd {
		t.Fatalf("session %s is not framed by its start and end records: %v", sid, kinds)
	}
	starts := records[decision.SessionStart](t, d, decision.RecordSessionStart, sid)
	ends := records[decision.SessionEnd](t, d, decision.RecordSessionEnd, sid)
	if len(starts) != 1 || len(ends) != 1 {
		t.Fatalf("session %s has %d start and %d end records, want one of each", sid, len(starts), len(ends))
	}
	return starts[0], ends[0]
}

// explain renders every decision that was not a plain allow, with the factors
// and evidence behind it, so a failure on a CI host explains itself.
func (d *daemon) explain() string {
	f, err := os.Open(d.audit)
	if err != nil {
		return err.Error()
	}
	defer f.Close()
	var b strings.Builder
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<22)
	for n := 0; sc.Scan() && n < 60; {
		var dec decision.Decision
		if k, _ := decision.KindOf(sc.Bytes()); k != decision.RecordDecision {
			continue
		}
		if json.Unmarshal(sc.Bytes(), &dec) != nil || dec.Action == ece.ActionAllow {
			continue
		}
		n++
		fmt.Fprintf(&b, "  %s %s %s rule=%s target=%q risk=%.0f enforced=%v\n",
			dec.SessionID, dec.Verdict, dec.Action, dec.MatchedRule, target(dec), dec.Risk.Score, dec.Enforced)
		for _, fac := range dec.Risk.Factors {
			if fac.Weight != 0 {
				fmt.Fprintf(&b, "    %s=%.0f %v\n", fac.Name, fac.Weight, fac.Evidence)
			}
		}
	}
	return b.String()
}

func describeEvent(e event.Event) string {
	s := fmt.Sprintf("%s pid %d comm %q exe %q", e.Capability, e.Process.PID, e.Process.Comm, e.Process.Executable)
	if f := e.File; f != nil {
		s += fmt.Sprintf(" path %q resolved %q truncated %v dir %q dir_source %q dir_status %q flags %#x ret %d",
			f.Path, f.ResolvedPath, f.Truncated, f.Dir, f.DirSource, f.DirStatus, f.Flags, e.Result.ReturnCode)
	}
	return s
}

// target is the observation the validator resolved for a decision.
func target(d decision.Decision) string {
	for _, r := range d.Reasoning {
		if r.Stage == "validator" && r.Conclusion == "resolved observation" {
			return r.Detail
		}
	}
	return ""
}

func find(ds []decision.Decision, verdict decision.Verdict, contains string) *decision.Decision {
	for i := range ds {
		if ds[i].Verdict == verdict && strings.Contains(target(ds[i]), contains) {
			return &ds[i]
		}
	}
	return nil
}

// workspace is a directory the agent user owns.
func workspace(t *testing.T) string {
	t.Helper()
	ws, err := os.MkdirTemp(e.dir, "ws-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(ws, agentUID, agentUID); err != nil {
		t.Fatal(err)
	}
	return ws
}

// script writes an agent script the agent user can run.
func script(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(e.dir, fmt.Sprintf("agent-%d.sh", time.Now().UnixNano()))
	if err := os.WriteFile(p, []byte("#!/bin/bash\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

type shimRun struct {
	cmd    *exec.Cmd
	stderr *bytes.Buffer
	done   chan struct{}
	code   int
}

var sessionLine = regexp.MustCompile(`\[allseer\] session (s-[a-z0-9-]+)`)

func (r *shimRun) sessionID(t *testing.T) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if m := sessionLine.FindStringSubmatch(r.stderr.String()); m != nil {
			return m[1]
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no session id in shim output:\n%s", r.stderr.String())
	return ""
}

func (r *shimRun) wait(t *testing.T, d time.Duration) int {
	t.Helper()
	select {
	case <-r.done:
		return r.code
	case <-time.After(d):
		_ = r.cmd.Process.Kill()
		t.Fatalf("shim did not exit within %s:\n%s", d, r.stderr.String())
	}
	return -1
}

func shim(t *testing.T, socket, ws, mode, agent string, extra ...string) *shimRun {
	t.Helper()
	args := []string{"-socket", socket, "-yes", "-quiet", "-no-tty-approvals",
		"-prompt", "build the project and run the tests", "-workspace", ws}
	if mode != "" {
		args = append(args, "-mode", mode)
	}
	args = append(args, extra...)
	args = append(args, "--", agent)
	cmd := exec.Command(filepath.Join(e.bin, "allseer-shim"), args...)
	cmd.Dir = ws
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + ws}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: agentUID, Gid: agentUID}}
	r := &shimRun{cmd: cmd, stderr: &bytes.Buffer{}, done: make(chan struct{})}
	cmd.Stderr = r.stderr
	cmd.Stdout = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		err := cmd.Wait()
		var ee *exec.ExitError
		switch {
		case err == nil:
		case errors.As(err, &ee):
			if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
				r.code = 128 + int(ws.Signal())
			} else {
				r.code = ee.ExitCode()
			}
		default:
			r.code = -1
		}
		close(r.done)
	}()
	return r
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// --- tests -----------------------------------------------------------------

func TestShimRefusesToLaunchWithoutDaemon(t *testing.T) {
	need(t)
	ws := workspace(t)
	marker := filepath.Join(ws, "ran")
	r := shim(t, filepath.Join(e.dir, "no-such.sock"), ws, "", script(t, "echo x > "+marker))
	if code := r.wait(t, 20*time.Second); code != 125 {
		t.Fatalf("shim exit = %d, want 125\n%s", code, r.stderr.String())
	}
	if exists(marker) {
		t.Fatal("the agent ran without a daemon")
	}
	if !strings.Contains(r.stderr.String(), "refusing to launch") {
		t.Fatalf("no refusal message:\n%s", r.stderr.String())
	}
}

func TestMonitorRecordsDeparturesAndPropagatesExitCode(t *testing.T) {
	d := startDaemon(t, "monitor")
	ws := workspace(t)
	agent := script(t, fmt.Sprintf(`echo hi > %[1]s/out.txt
cat %[1]s/out.txt >/dev/null
cat /etc/shadow 2>/dev/null
(exec 3<>/dev/tcp/127.0.0.1/9) 2>/dev/null
exit 3`, ws))
	r := shim(t, d.socket, ws, "", agent)
	sid := r.sessionID(t)
	if code := r.wait(t, 30*time.Second); code != 3 {
		t.Fatalf("shim exit = %d, want the agent's 3\n%s", code, r.stderr.String())
	}

	s, err := d.client().GetSession(context.Background(), sid)
	if err != nil {
		t.Fatal(err)
	}
	if s.State != session.StateCompleted || !s.Outcome.TelemetryComplete {
		t.Fatalf("session %s, telemetry complete %v: %s", s.State, s.Outcome.TelemetryComplete, s.Outcome.Reason)
	}
	ds := d.decisions(t, sid)
	if uint64(len(ds)) != s.Summary.EventsObserved || len(ds) == 0 {
		t.Fatalf("%d audit records for %d events", len(ds), s.Summary.EventsObserved)
	}
	if find(ds, decision.VerdictWithinEnvelope, ws+"/out.txt") == nil {
		t.Error("the workspace write was not within the envelope")
	}
	shadow := find(ds, decision.VerdictExplicitlyDenied, "/etc/shadow")
	if shadow == nil {
		t.Error("the /etc/shadow read was not an explicit denial")
	} else if shadow.Enforced {
		t.Error("monitor mode reported containment as applied")
	}
	if find(ds, decision.VerdictOutsideEnvelope, "127.0.0.1:9") == nil {
		t.Error("the unexpected connection was not outside the envelope")
	}

	// The log carries what the session was judged against and how it ended.
	start, end := d.framed(t, sid)
	if start.Envelope == nil || start.Envelope.Digest != s.Envelope.Digest || start.Mode != "monitor" || start.RootPID == 0 {
		t.Errorf("session start = mode %s root %d envelope %v", start.Mode, start.RootPID, start.Envelope != nil)
	}
	// connect(2) is the only egress entry point watched, and the record says so.
	unwatched := false
	for _, g := range start.Coverage.EntryPoints {
		unwatched = unwatched || (g.Kind == "net.connect" && len(g.Missing) > 0)
	}
	if !unwatched {
		t.Errorf("the start record does not name the unwatched egress entry points: %+v", start.Coverage.EntryPoints)
	}
	if end.Result != string(session.StateCompleted) || !end.TelemetryComplete ||
		end.EventsObserved != s.Summary.EventsObserved || end.ViolationCount != s.Outcome.ViolationCount {
		t.Errorf("session end = %+v, want it to match the session %+v", end, s.Outcome)
	}
}

// The agent's own exec is observed: it happens after the launcher was moved
// into the session cgroup, so the first instruction is governed.
func TestNoUnobservedLaunchWindow(t *testing.T) {
	d := startDaemon(t, "monitor")
	ws := workspace(t)
	agent := script(t, "true")
	r := shim(t, d.socket, ws, "", agent)
	sid := r.sessionID(t)
	if code := r.wait(t, 30*time.Second); code != 0 {
		t.Fatalf("shim exit %d\n%s", code, r.stderr.String())
	}
	ds := d.decisions(t, sid)
	if len(ds) == 0 || !strings.HasPrefix(target(ds[0]), "process.exec") || !strings.Contains(target(ds[0]), agent) {
		got := ""
		if len(ds) > 0 {
			got = target(ds[0])
		}
		t.Fatalf("first observed event = %q, want the exec of %s", got, agent)
	}
}

func TestEnforceKillsAfterCredentialRead(t *testing.T) {
	d := startDaemon(t, "monitor")
	ws := workspace(t)
	marker := filepath.Join(ws, "survived")
	r := shim(t, d.socket, ws, "enforce", script(t, "cat /etc/shadow 2>/dev/null\nsleep 3\necho x > "+marker))
	sid := r.sessionID(t)
	if code := r.wait(t, 30*time.Second); code != 137 {
		t.Fatalf("shim exit = %d, want 137 (killed)\n%s", code, r.stderr.String())
	}
	if exists(marker) {
		t.Fatal("the agent kept running after the kill")
	}
	s, _ := d.client().GetSession(context.Background(), sid)
	if s.State != session.StateTerminated || s.Outcome.BlockedCount != 1 {
		t.Fatalf("session %s blocked %d: %s", s.State, s.Outcome.BlockedCount, s.Outcome.Reason)
	}
	if dec := find(d.decisions(t, sid), decision.VerdictExplicitlyDenied, "/etc/shadow"); dec == nil || !dec.Enforced {
		t.Fatal("the denial is not recorded as enforced")
	}
}

// The enforce contract decided on 2026-10-21: warn is recorded and the agent
// keeps running. A read outside the workspace of a file nothing grades as
// sensitive is the commonest warn under the shipped rules.
func TestEnforceLetsWarnThrough(t *testing.T) {
	d := startDaemon(t, "monitor")
	ws := workspace(t)
	marker := filepath.Join(ws, "survived")
	r := shim(t, d.socket, ws, "enforce", script(t, "cat /etc/hostname >/dev/null\nsleep 1\necho x > "+marker))
	sid := r.sessionID(t)
	if code := r.wait(t, 30*time.Second); code != 0 {
		t.Fatalf("shim exit = %d, want 0\n%s", code, r.stderr.String())
	}
	if !exists(marker) {
		t.Fatal("the agent was stopped after a warning")
	}
	var warned *decision.Decision
	ds := d.decisions(t, sid)
	for i := range ds {
		if strings.Contains(target(ds[i]), "/etc/hostname") {
			warned = &ds[i]
		}
	}
	if warned == nil || warned.Action != ece.ActionWarn || warned.Enforced {
		t.Fatalf("the /etc/hostname read = %+v, want an unenforced warn", warned)
	}
	if s, _ := d.client().GetSession(context.Background(), sid); s.State != session.StateCompleted || s.Outcome.BlockedCount != 0 {
		t.Fatalf("session %s blocked %d, want completed with nothing blocked", s.State, s.Outcome.BlockedCount)
	}
}

func TestInteractiveApproveResumesAndDenyKills(t *testing.T) {
	d := startDaemon(t, "monitor")
	ctx := context.Background()
	for _, approve := range []bool{true, false} {
		ws := workspace(t)
		marker := filepath.Join(ws, "finished")
		r := shim(t, d.socket, ws, "interactive", script(t,
			"(exec 3<>/dev/tcp/127.0.0.1/9) 2>/dev/null\nsleep 1\necho x > "+marker))
		sid := r.sessionID(t)

		// The connect is the only thing this agent does that needs approval;
		// any other request is a false positive and fails the test.
		var req decision.ApprovalRequest
		deadline := time.Now().Add(15 * time.Second)
	wait:
		for {
			list, _ := d.client().PendingApprovals(ctx)
			for _, p := range list {
				if p.SessionID != sid {
					continue
				}
				if !strings.Contains(target(p.Decision), "127.0.0.1:9") {
					t.Fatalf("unexpected approval request: %s", p.Summary)
				}
				req = p
				break wait
			}
			if time.Now().After(deadline) {
				t.Fatalf("no approval request\n%s", r.stderr.String())
			}
			time.Sleep(50 * time.Millisecond)
		}
		s, _ := d.client().GetSession(ctx, sid)
		if s.State != session.StateSuspended {
			t.Fatalf("state while awaiting approval = %s", s.State)
		}
		time.Sleep(1500 * time.Millisecond)
		if exists(marker) {
			t.Fatal("a frozen agent made progress")
		}
		if err := d.client().RespondApproval(ctx, decision.ApprovalResponse{RequestID: req.ID, Approved: approve}); err != nil {
			t.Fatal(err)
		}
		code := r.wait(t, 30*time.Second)
		if approve && (code != 0 || !exists(marker)) {
			t.Fatalf("approved: exit %d, finished %v\n%s", code, exists(marker), r.stderr.String())
		}
		if !approve && (code != 137 || exists(marker)) {
			t.Fatalf("denied: exit %d, finished %v\n%s", code, exists(marker), r.stderr.String())
		}

		answers := records[decision.Approval](t, d, decision.RecordApproval, sid)
		want := decision.EffectResume
		if !approve {
			want = decision.EffectTerminate
		}
		if len(answers) != 1 || answers[0].RequestID != req.ID || answers[0].DecisionID != req.Decision.ID ||
			answers[0].Approved != approve || answers[0].Effect != want || answers[0].RespondedBy != "root" {
			t.Fatalf("approval records = %+v, want one %s answer to %s by root", answers, want, req.ID)
		}
		d.framed(t, sid)
	}
}

// Stopping the daemon must not leave an agent running ungoverned or frozen.
func TestDaemonShutdownKillsLiveSessions(t *testing.T) {
	d := startDaemon(t, "monitor")
	ws := workspace(t)
	r := shim(t, d.socket, ws, "", script(t, "sleep 60"))
	sid := r.sessionID(t)
	time.Sleep(500 * time.Millisecond)
	if err := d.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if code := r.wait(t, 20*time.Second); code != 137 {
		t.Fatalf("shim exit = %d after daemon shutdown, want 137\n%s", code, r.stderr.String())
	}
	select {
	case err := <-d.done:
		d.done <- err
		if err != nil {
			t.Fatalf("allseerd exited with %v on SIGTERM", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("allseerd did not exit after SIGTERM")
	}
	if exists(filepath.Join(e.cgroups, sid)) {
		t.Fatal("the session cgroup outlived the daemon")
	}
	// The end is written before the daemon exits, not lost with it.
	if _, end := d.framed(t, sid); end.Result != string(session.StateFailed) || !strings.Contains(end.Reason, "shut down") {
		t.Fatalf("session end after shutdown = %+v", end)
	}
}

// An agent cannot leave its cgroup to escape attribution.
func TestAgentCannotEscapeItsCgroup(t *testing.T) {
	d := startDaemon(t, "monitor")
	ws := workspace(t)
	result := filepath.Join(ws, "result")
	r := shim(t, d.socket, ws, "", script(t, fmt.Sprintf(
		"if echo $$ > /sys/fs/cgroup/cgroup.procs 2>/dev/null; then echo escaped > %[1]s; else echo refused > %[1]s; fi\ncat /etc/hostname >/dev/null",
		result)))
	sid := r.sessionID(t)
	if code := r.wait(t, 30*time.Second); code != 0 {
		t.Fatalf("shim exit %d\n%s", code, r.stderr.String())
	}
	b, _ := os.ReadFile(result)
	if strings.TrimSpace(string(b)) != "refused" {
		t.Fatalf("escape attempt: %q", b)
	}
	if find(d.decisions(t, sid), decision.VerdictWithinEnvelope, "/etc/hostname") == nil &&
		find(d.decisions(t, sid), decision.VerdictGrantExceeded, "/etc/hostname") == nil {
		t.Fatal("the read after the escape attempt was not attributed to the session")
	}
}

// The ABI v3 regression: the same denied read through a relative name, after
// cd, is denied and contained exactly like the absolute one.
// The benign case, which is the one that decides whether anybody can leave
// this running. A build-shaped workload that stays inside what the envelope
// grants must finish with nothing asked of the user: no approval, no block,
// and a session that completes with its telemetry intact. A system that
// interrupts ordinary work trains people to approve without reading.
func TestBenignBuildWorkloadRaisesNothing(t *testing.T) {
	d := startDaemon(t, "enforce")
	ws := workspace(t)
	// Reads its own sources, compiles nothing it was not given, writes its
	// output into the workspace, and uses the system tools the envelope grants.
	agent := script(t, fmt.Sprintf(`set -e
mkdir -p %[1]s/src %[1]s/out
for i in 1 2 3 4 5 6 7 8; do
  printf 'package main\nfunc f%%d() int { return %%d }\n' "$i" "$i" > %[1]s/src/f$i.go
done
cat %[1]s/src/*.go > %[1]s/out/all.txt
wc -l %[1]s/out/all.txt > %[1]s/out/count.txt
grep -c func %[1]s/out/all.txt >> %[1]s/out/count.txt
sort %[1]s/out/all.txt | uniq | tail -5 > %[1]s/out/sample.txt
cp %[1]s/out/all.txt %[1]s/out/all.bak
rm %[1]s/out/all.bak
test -s %[1]s/out/count.txt`, ws))

	r := shim(t, d.socket, ws, "enforce", agent)
	sid := r.sessionID(t)
	if code := r.wait(t, 60*time.Second); code != 0 {
		t.Fatalf("the benign workload exited %d under enforce mode\n%s", code, r.stderr.String())
	}

	s, err := d.client().GetSession(context.Background(), sid)
	if err != nil {
		t.Fatal(err)
	}
	if s.State != session.StateCompleted {
		t.Fatalf("session state = %s, want completed: %s", s.State, s.Outcome.Reason)
	}
	if !s.Outcome.TelemetryComplete {
		t.Errorf("telemetry incomplete on a benign run: %s", s.Outcome.Reason)
	}

	ds := d.decisions(t, sid)
	if len(ds) == 0 {
		t.Fatal("no decisions recorded; the workload was not observed at all")
	}
	for _, dec := range ds {
		switch dec.Action {
		case ece.ActionBlock, ece.ActionRequestApproval:
			t.Errorf("benign workload triggered %s on %s (verdict %s, risk %.0f): %s",
				dec.Action, target(dec), dec.Verdict, dec.Risk.Score, dec.MatchedRule)
		}
	}
	// Its own writes must read as expected behaviour, not as departures.
	if find(ds, decision.VerdictWithinEnvelope, ws+"/out/count.txt") == nil {
		t.Error("the workspace write was not within the envelope")
	}
	t.Logf("benign run: %d decisions, %d events observed", len(ds), s.Summary.EventsObserved)
}

// Telemetry that drops records cannot support the claim that nothing bad
// happened, so a drop ends the session rather than letting it run on. The ring
// and the decode channel are made small enough that a burst of opens overruns
// them, which is the only way to provoke a real drop from outside the kernel.
func TestDroppedTelemetryFailsTheSessionClosed(t *testing.T) {
	d := startDaemonWithConfig(t, "monitor", `telemetry:
  ring_buffer_size: 4096
  event_channel_size: 1
  fail_closed_on_drop: true
`)
	ws := workspace(t)
	marker := filepath.Join(ws, "finished")
	// A burst of opens, far more than a 4 KiB ring and a 1-deep channel can
	// carry while user space enriches each one.
	agent := script(t, fmt.Sprintf(`for i in $(seq 1 4000); do
  cat %[1]s/src.txt >/dev/null 2>&1 || true
done
echo done > %[2]s`, ws, marker))
	if err := os.WriteFile(filepath.Join(ws, "src.txt"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(filepath.Join(ws, "src.txt"), agentUID, agentUID); err != nil {
		t.Fatal(err)
	}

	r := shim(t, d.socket, ws, "", agent)
	sid := r.sessionID(t)
	r.wait(t, 90*time.Second)

	s, err := d.client().GetSession(context.Background(), sid)
	if err != nil {
		t.Fatal(err)
	}
	st, err := d.client().Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("session %s: %s (telemetry complete %v); daemon dropped %d",
		s.State, s.Outcome.Reason, s.Outcome.TelemetryComplete, st.DroppedEvents)

	if st.DroppedEvents == 0 && s.Outcome.TelemetryComplete {
		t.Skip("the burst did not overrun the ring on this host, so there is no drop to fail closed on")
	}
	// Something was lost. The session must not read as a clean completion.
	if s.Outcome.TelemetryComplete {
		t.Errorf("records were dropped but the session reports complete telemetry")
	}
	if s.State == session.StateCompleted && !strings.Contains(s.Outcome.Reason, "telemetry") {
		t.Errorf("session completed without mentioning the telemetry gap: %s", s.Outcome.Reason)
	}
	// The durable record carries the gap too, not only the live session.
	if _, end := d.framed(t, sid); end.TelemetryComplete {
		t.Errorf("the session end record reports complete telemetry after a drop: %+v", end)
	}
}

// A daemon killed outright never gets to end its sessions, so nothing on the
// host stops the agent. The shim notices that governance has gone and stops
// the launcher it holds, which is the one thing an unprivileged shim can do.
func TestAgentStopsWhenTheDaemonDiesWithoutCleanup(t *testing.T) {
	d := startDaemon(t, "monitor")
	ws := workspace(t)
	marker := filepath.Join(ws, "survived")
	// stdio detached so the orphaned sleep does not hold the shim's output
	// pipe open after its shell is killed, which would only slow the test.
	// That it survives at all is the point below.
	r := shim(t, d.socket, ws, "", script(t,
		"sleep 25 </dev/null >/dev/null 2>&1\necho x > "+marker))
	sid := r.sessionID(t)
	time.Sleep(500 * time.Millisecond)

	// SIGKILL, so no shutdown path runs and the session cgroup is left behind.
	if err := d.cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	<-d.done

	if code := r.wait(t, 30*time.Second); code == 0 {
		t.Fatalf("shim exit = 0 after the daemon was killed; the agent ran to completion\n%s", r.stderr.String())
	}
	if exists(marker) {
		t.Fatal("the agent completed its work after governance disappeared")
	}
	if !strings.Contains(r.stderr.String(), "has not answered") {
		t.Fatalf("the shim did not report the daemon loss:\n%s", r.stderr.String())
	}
	// The cgroup outlives the daemon here, which is what the next daemon's
	// startup sweep is for.
	// The orphaned sleep is killed here so the next daemon's sweep does not
	// find it and freeze it.
	left := filepath.Join(e.cgroups, sid)
	if exists(left) {
		t.Cleanup(func() { killGroup(left) })
	}
}

// The agent runs as its owner, so it can reach the control socket and the
// shipped shim. What it must not be able to do is ask the daemon for a second,
// weaker session and have one of its own processes moved into it: that process
// would leave the envelope its owner approved and the cgroup enforce mode
// kills. The nested shim runs inside the session cgroup, which is what the
// daemon refuses on.
func TestAgentCannotObtainAWeakerNestedSession(t *testing.T) {
	d := startDaemon(t, "monitor")
	ws := workspace(t)
	out := filepath.Join(ws, "nested.out")
	agent := script(t, fmt.Sprintf(
		"%s/allseer-shim -socket %s -yes -quiet -no-tty-approvals "+
			"-prompt 'anything the agent wants' -workspace %s -- /bin/true > %s 2>&1\n"+
			"echo exit=$? >> %s\nsleep 2",
		e.bin, d.socket, ws, out, out))
	r := shim(t, d.socket, ws, "enforce", agent)
	sid := r.sessionID(t)
	r.wait(t, 30*time.Second)

	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("the agent produced no result: %v\n%s", err, r.stderr.String())
	}
	got := string(b)
	if !strings.Contains(got, "a governed process cannot govern") {
		t.Fatalf("the nested shim was not refused by the daemon:\n%s", got)
	}
	if strings.Contains(got, "exit=0") {
		t.Fatalf("the nested shim reported success:\n%s", got)
	}
	// The original session is the only one that ever existed.
	sessions, err := d.client().ListSessions(context.Background(), session.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].ID != sid {
		var ids []string
		for _, s := range sessions {
			ids = append(ids, s.ID)
		}
		t.Fatalf("sessions = %v, want only %s", ids, sid)
	}
	if st, err := d.client().Status(context.Background()); err != nil {
		t.Fatal(err)
	} else if st.RefusedRequests == 0 {
		t.Fatal("the refusal was not counted in the daemon status")
	}
	// The attempt is in the audit log, attributed to the session it came from.
	refused := records[decision.ControlRefused](t, d, decision.RecordControlRefused, sid)
	if len(refused) == 0 || refused[0].Method != ipc.MethodCreateSession || refused[0].UID != agentUID {
		t.Fatalf("control_refused records for %s = %+v", sid, refused)
	}
}

func TestEnforceKillsRelativeCredentialRead(t *testing.T) {
	d := startDaemon(t, "monitor")
	ws := workspace(t)
	marker := filepath.Join(ws, "survived")
	r := shim(t, d.socket, ws, "enforce", script(t, "cd /etc && cat shadow 2>/dev/null\nsleep 3\necho x > "+marker))
	sid := r.sessionID(t)
	if code := r.wait(t, 30*time.Second); code != 137 {
		t.Fatalf("shim exit = %d, want 137 (killed)\n%s", code, r.stderr.String())
	}
	if exists(marker) {
		t.Fatal("the agent kept running after a relative credential read")
	}
	if dec := find(d.decisions(t, sid), decision.VerdictExplicitlyDenied, "/etc/shadow"); dec == nil || !dec.Enforced {
		t.Fatal("the relative read of shadow was not an enforced explicit denial on /etc/shadow")
	}
}

// Padding a path past the kernel's buffer hides its tail. The probe flags the
// truncation, the path is never resolved, and unverifiable_path carries it to
// indeterminate-high-risk, which enforce mode contains.
func TestEnforceContainsATruncatedPath(t *testing.T) {
	d := startDaemon(t, "monitor")
	ws := workspace(t)
	marker := filepath.Join(ws, "survived")
	padded := "/etc/" + strings.Repeat("./", 140) + "shadow"
	r := shim(t, d.socket, ws, "enforce", script(t, "cat "+padded+" 2>/dev/null\nsleep 3\necho x > "+marker))
	sid := r.sessionID(t)
	if code := r.wait(t, 30*time.Second); code != 137 {
		t.Fatalf("shim exit = %d, want 137 (killed)\n%s", code, r.stderr.String())
	}
	if exists(marker) {
		t.Fatal("the agent kept running after a truncated-path read")
	}
	// The charge must be for the padded read itself, not for some other
	// unverifiable open that happened to come first.
	var charged bool
	for _, dec := range d.decisions(t, sid) {
		for _, f := range dec.Risk.Factors {
			if f.Name == "unverifiable_path" && dec.Verdict == decision.VerdictIndeterminate && dec.Enforced &&
				strings.HasPrefix(f.Evidence["raw_path"], "/etc/./") {
				charged = true
			}
		}
	}
	if !charged {
		t.Fatal("no enforced indeterminate decision charged unverifiable_path on the padded path")
	}
}

// The startup self-test on the real kernel: the daemon performs a failed open
// before it serves, and status reports that the openat probe recorded it.
func TestDaemonSelfTestProvesTheOpenProbe(t *testing.T) {
	d := startDaemon(t, "monitor")
	st, err := d.client().Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !st.SelfTest.Passed || st.SelfTest.Probe != "openat" || !st.TelemetryHealthy {
		t.Fatalf("self-test %+v, telemetry healthy %v", st.SelfTest, st.TelemetryHealthy)
	}
	if !strings.Contains(d.log.String(), "telemetry self-test passed") {
		t.Errorf("the daemon did not log the self-test:\n%s", filterLibbpf(d.log.String()))
	}
	if left, _ := filepath.Glob(filepath.Join(e.cgroups, "selftest-*")); len(left) != 0 {
		t.Errorf("the self-test left cgroups behind: %v", left)
	}
}

// The failure the self-test exists for. With the openat pair not attached and
// the kernel-side hook attached, every probe the daemon loaded reports as
// attached and successful opens are still recorded - and a refused credential
// read would not be. The daemon must refuse to govern rather than start.
func TestDaemonRefusesToGovernWhenTheOpenProbeIsMissing(t *testing.T) {
	need(t)
	cfg := filepath.Join(e.dir, fmt.Sprintf("no-openat-%d.yaml", time.Now().UnixNano()))
	if err := os.WriteFile(cfg, []byte("telemetry:\n  enabled_probes: [connect, file_open]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(e.dir, fmt.Sprintf("refuse-%d.sock", time.Now().UnixNano()))
	cmd := exec.Command(filepath.Join(e.bin, "allseerd"),
		"--config", cfg, "--socket", socket, "--object", e.object, "--mode", "enforce",
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
			t.Fatalf("allseerd exited 0 without the openat probe:\n%s", filterLibbpf(out.String()))
		}
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("allseerd kept running without the openat probe:\n%s", filterLibbpf(out.String()))
	}
	log := filterLibbpf(out.String())
	if !strings.Contains(log, "telemetry self-test failed; refusing to govern") || !strings.Contains(log, "no record") {
		t.Errorf("the refusal does not say why:\n%s", log)
	}
	if strings.Contains(log, "allseerd ready") {
		t.Errorf("allseerd reported ready before refusing:\n%s", log)
	}
	if _, err := os.Stat(socket); err == nil {
		t.Error("the control socket was created although the daemon refused to govern")
	}
	if left, _ := filepath.Glob(filepath.Join(e.cgroups, "selftest-*")); len(left) != 0 {
		t.Errorf("the failed self-test left cgroups behind: %v", left)
	}
}

// Plan D's lead scenario: an agent reads a credential and then opens a
// connection. The sequence detector must mark the egress, whichever entry point
// it used. connect(2) was the only one observed before the security_socket_connect
// hook; io_uring is the one that hook added.
//
// Monitor mode, because under enforce the credential read is itself a denial
// and the agent is killed before it can connect (TestEnforceKillsAfterCredentialRead).
func TestCredentialReadThenEgressIsFlagged(t *testing.T) {
	d := startDaemon(t, "monitor")
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	dest := ln.Addr().String()
	port := dest[strings.LastIndex(dest, ":")+1:]

	cases := []struct{ name, egress string }{
		{"connect", fmt.Sprintf("exec 3<>/dev/tcp/127.0.0.1/%s || exit 1", port)},
		{"io_uring", fmt.Sprintf("%s=uring-connect %s %s", helperEnv, filepath.Join(e.bin, "e2e-helper"), dest)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ws := workspace(t)
			key := filepath.Join(ws, ".ssh", "id_rsa")
			if err := os.MkdirAll(filepath.Dir(key), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(key, []byte("test fixture, not a key\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, p := range []string{filepath.Dir(key), key} {
				if err := os.Chown(p, agentUID, agentUID); err != nil {
					t.Fatal(err)
				}
			}

			r := shim(t, d.socket, ws, "", script(t, "cat "+key+" >/dev/null || exit 1\n"+tc.egress))
			sid := r.sessionID(t)
			code := r.wait(t, 30*time.Second)
			if code == exitNoUring {
				t.Skipf("io_uring is unavailable to the agent on this host:\n%s", r.stderr.String())
			}
			if code != 0 {
				t.Fatalf("agent exit = %d, want 0\n%s", code, r.stderr.String())
			}

			ds := d.decisions(t, sid)
			var egress *decision.Decision
			for i := range ds {
				if strings.HasPrefix(target(ds[i]), "net.connect") && strings.Contains(target(ds[i]), dest) {
					egress = &ds[i]
				}
			}
			// For io_uring this is the hook's own proof: without it the
			// connect produces no record and so no decision.
			if egress == nil {
				t.Fatalf("no decision for the connect to %s", dest)
			}
			flagged := false
			for _, f := range egress.Risk.Factors {
				flagged = flagged || (f.Name == "credential_access_egress" && f.Weight > 0)
			}
			if !flagged {
				t.Errorf("the connect after reading %s does not carry credential_access_egress: risk %.0f %+v",
					key, egress.Risk.Score, egress.Risk.Factors)
			}
		})
	}
}
