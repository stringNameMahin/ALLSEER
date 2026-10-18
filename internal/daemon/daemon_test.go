package daemon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stringNameMahin/ALLSEER/internal/config"
	"github.com/stringNameMahin/ALLSEER/internal/containment"
	"github.com/stringNameMahin/ALLSEER/internal/ipc"
	"github.com/stringNameMahin/ALLSEER/internal/policy"
	"github.com/stringNameMahin/ALLSEER/internal/risk"
	"github.com/stringNameMahin/ALLSEER/internal/session"
	"github.com/stringNameMahin/ALLSEER/internal/telemetry"
	"github.com/stringNameMahin/ALLSEER/internal/telemetry/abi"
	"github.com/stringNameMahin/ALLSEER/internal/telemetry/synth"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// --- fakes -------------------------------------------------------------------

type fakeTel struct {
	mu       sync.Mutex
	ch       chan event.Event
	attached map[string]uint64
	observe  []capability.Kind
}

func newFakeTel() *fakeTel {
	return &fakeTel{ch: make(chan event.Event, 256), attached: map[string]uint64{}, observe: []capability.Kind{
		capability.KindFileRead, capability.KindFileWrite, capability.KindFileCreate,
		capability.KindProcessExec, capability.KindProcessExit, capability.KindNetConnect,
	}}
}

func (f *fakeTel) Events() <-chan event.Event               { return f.ch }
func (f *fakeTel) Start(context.Context) error              { return nil }
func (f *fakeTel) Close() error                             { return nil }
func (f *fakeTel) Stats() event.SourceStats                 { return event.SourceStats{} }
func (f *fakeTel) CollectorStats() telemetry.CollectorStats { return telemetry.CollectorStats{} }
func (f *fakeTel) Coverage() telemetry.Coverage {
	return telemetry.Coverage{FloorIntact: true, Observable: f.observe}
}
func (f *fakeTel) AttachCgroup(_ context.Context, sid string, id uint64, _ int32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attached[sid] = id
	return nil
}
func (f *fakeTel) DetachSession(_ context.Context, sid string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.attached, sid)
	return nil
}

// How the fake probe answers the self-test's open.
type probeBehaviour int

const (
	probeReports    probeBehaviour = iota // the openat pair reports ENOENT
	probeSilent                           // nothing reports it
	probeHookOnly                         // only the kernel-side hook reports
	probeWrongError                       // reported, with the wrong outcome
)

// fakeProber stands in for the self-test process. Released, it writes onto the
// fake telemetry stream whatever record the behaviour calls for, attributed to
// the cgroup the daemon attached for it.
func fakeProber(tel *fakeTel, b probeBehaviour) Prober {
	return func(_ context.Context, path string) (int, func() error, func() error, error) {
		release := func() error {
			tel.mu.Lock()
			var sid string
			for id := range tel.attached {
				if strings.HasPrefix(id, "selftest-") {
					sid = id
				}
			}
			tel.mu.Unlock()
			e := event.Event{SessionID: sid, Capability: capability.KindFileRead,
				File: &event.FilePayload{Path: path}}
			switch b {
			case probeSilent:
				return nil
			case probeReports:
				e.Result = event.Result{ReturnCode: -2, Errno: "ENOENT"}
			case probeHookOnly:
				e.File.KernelPath = true
				e.Result = event.Result{Succeeded: true, OutcomeUnobserved: true}
			case probeWrongError:
				e.Result = event.Result{ReturnCode: -13, Errno: "EACCES"}
			}
			tel.ch <- e
			return nil
		}
		return os.Getpid(), release, func() error { return nil }, nil
	}
}

type fakeGroup struct {
	mu                      sync.Mutex
	id                      uint64
	adopted                 []int
	frozen, killed, removed bool
	populated               bool
	// killErr and freezeErr make containment fail, which is how the
	// fail-closed paths are exercised.
	killErr   error
	freezeErr error
}

// failKill makes every Kill on this group fail.
func (g *fakeGroup) failKill(err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.killErr = err
}

// failFreeze makes every Freeze on this group fail.
func (g *fakeGroup) failFreeze(err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.freezeErr = err
}

func (g *fakeGroup) CgroupID() uint64 { return g.id }
func (g *fakeGroup) Adopt(pid int) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.adopted = append(g.adopted, pid)
	g.populated = true
	return nil
}
func (g *fakeGroup) Freeze(context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.freezeErr != nil {
		return g.freezeErr
	}
	g.frozen = true
	return nil
}
func (g *fakeGroup) Thaw(context.Context) error {
	g.mu.Lock()
	g.frozen = false
	g.mu.Unlock()
	return nil
}
func (g *fakeGroup) Kill(context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.killErr != nil {
		return g.killErr
	}
	g.killed, g.populated = true, false
	return nil
}
func (g *fakeGroup) Populated() (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.populated, nil
}
func (g *fakeGroup) Remove() error { g.mu.Lock(); g.removed = true; g.mu.Unlock(); return nil }
func (g *fakeGroup) state() (frozen, killed bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.frozen, g.killed
}

type fakeGroups struct {
	mu     sync.Mutex
	groups map[string]*fakeGroup
	// governed records which pids sit inside a session cgroup. govErr makes
	// the lookup fail, which is how the fail-closed path is exercised.
	governed map[int32]bool
	govErr   error
}

func (f *fakeGroups) Create(sid string) (SessionGroup, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.groups[sid]; ok {
		return nil, containment.ErrExists
	}
	g := &fakeGroup{id: uint64(1000 + len(f.groups))}
	f.groups[sid] = g
	return g, nil
}
func (f *fakeGroups) Capabilities() containment.Capabilities {
	return containment.Capabilities{Freeze: true, Kill: true}
}
func (f *fakeGroups) Governed(pid int32) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.govErr != nil {
		return false, f.govErr
	}
	return f.governed[pid], nil
}

// govern marks pid as being inside a session cgroup.
func (f *fakeGroups) govern(pid int32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.governed == nil {
		f.governed = map[int32]bool{}
	}
	f.governed[pid] = true
}
func (f *fakeGroups) get(sid string) *fakeGroup {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.groups[sid]
}

type fakeHost struct{ ppid int32 }

func (h fakeHost) Process(int32) (int32, uint32, error) { return h.ppid, uint32(os.Getuid()), nil }
func (fakeHost) Home(uint32) string                     { return "/home/dev" }
func (fakeHost) UserName(uint32) string                 { return "dev" }

type memSink struct {
	mu  sync.Mutex
	got []decision.Decision
}

func (s *memSink) Emit(_ context.Context, d decision.Decision) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got = append(s.got, d)
	return nil
}
func (s *memSink) Flush(context.Context) error { return nil }
func (s *memSink) all() []decision.Decision {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]decision.Decision(nil), s.got...)
}

// --- harness -----------------------------------------------------------------

type rig struct {
	d      *Daemon
	tel    *fakeTel
	groups *fakeGroups
	audit  *memSink
	client *ipc.SocketClient
	ws     string
}

func newRig(t *testing.T, mode policy.Mode, timeout time.Duration) *rig {
	t.Helper()
	rs, err := policy.NewLoader().Load(context.Background(), "../../configs/rules.default.yaml")
	if err != nil {
		t.Fatal(err)
	}
	pe, err := policy.NewEngine(rs)
	if err != nil {
		t.Fatal(err)
	}
	oracle, err := risk.LoadResourceOracle("../../configs/sensitivity.default.yaml")
	if err != nil {
		t.Fatal(err)
	}
	re, err := risk.NewEngineWithOracle(oracle)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Policy.DefaultMode = mode
	cfg.Policy.ApprovalTimeout = timeout

	r := &rig{tel: newFakeTel(), groups: &fakeGroups{groups: map[string]*fakeGroup{}}, audit: &memSink{}}
	r.d, err = New(Options{
		Config: cfg, Telemetry: r.tel, Groups: r.groups, Host: fakeHost{ppid: int32(os.Getpid())},
		Policy: pe, Risk: re, Audit: r.audit, Resolvers: []string{"127.0.0.53"},
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		EndSettle: 20 * time.Millisecond, OrphanGrace: 50 * time.Millisecond,
		Prober: fakeProber(r.tel, probeReports), SelfTestTimeout: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.d.SelfTest(context.Background()); err != nil {
		t.Fatalf("self-test against a working fake probe: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = r.d.Run(ctx) }()
	srv := &ipc.SocketServer{Path: filepath.Join(t.TempDir(), "d.sock"), Mode: 0o600, Handler: r.d}
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ctx) }()
	t.Cleanup(func() { cancel(); _ = srv.Shutdown(context.Background()) })
	r.client = &ipc.SocketClient{Path: srv.Path}
	r.ws = t.TempDir()
	return r
}

func (r *rig) start(t *testing.T, prompt string) string {
	t.Helper()
	ctx := context.Background()
	resp, err := r.client.CreateSession(ctx, ipc.CreateSessionRequest{Prompt: prompt, WorkspaceRoot: r.ws})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.RequiresApproval || !resp.Envelope.Sealed || resp.Envelope.Digest == "" {
		t.Fatalf("new session: approval %v sealed %v digest %q", resp.RequiresApproval, resp.Envelope.Sealed, resp.Envelope.Digest)
	}
	if err := r.client.StartSession(ctx, resp.SessionID, 4242); err == nil {
		t.Fatal("an unapproved session started")
	}
	if err := r.client.ApproveEnvelope(ctx, ipc.ApproveEnvelopeRequest{SessionID: resp.SessionID, Approved: true}); err != nil {
		t.Fatal(err)
	}
	if err := r.client.StartSession(ctx, resp.SessionID, 4242); err != nil {
		t.Fatal(err)
	}
	return resp.SessionID
}

func (r *rig) feed(t *testing.T, sid string, specs ...synth.Spec) {
	t.Helper()
	g, err := synth.New(synth.Config{SessionID: sid, Process: synth.Proc{PID: 4242, TID: 4242, Comm: "agent", CgroupID: 1000}})
	if err != nil {
		t.Fatal(err)
	}
	evs, err := g.Generate(specs...)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range evs {
		r.tel.ch <- e
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func read(path string) synth.Spec {
	return synth.Spec{Type: abi.EvtFileOpen, Ret: 3, File: &synth.File{Path: path, ResolvedPath: path}}
}

// kernelRead is the record the security_file_open hook submits: the kernel's
// own path, no return value, and an outcome nothing observed. This is what an
// open reached through io_uring or openat2 looks like by the time it reaches
// the pipeline.
func kernelRead(path string) synth.Spec {
	return synth.Spec{
		Type:  abi.EvtFileOpen,
		Flags: uint32(abi.AllseerEvtFOutcomeUnknown),
		File: &synth.File{
			Path:         path,
			ResolvedPath: path,
			Inode:        4242,
			PathFlags:    uint32(abi.AllseerPathKernel),
		},
	}
}

// --- tests -------------------------------------------------------------------

// newUntested builds a daemon whose startup self-test has not passed, with the
// fake probe behaving as b.
func newUntested(t *testing.T, b probeBehaviour, prober bool) (*Daemon, *fakeTel) {
	t.Helper()
	tel := newFakeTel()
	rs, err := policy.NewLoader().Load(context.Background(), "../../configs/rules.default.yaml")
	if err != nil {
		t.Fatal(err)
	}
	pe, err := policy.NewEngine(rs)
	if err != nil {
		t.Fatal(err)
	}
	re := risk.NewEngine()
	o := Options{
		Config: config.Defaults(), Telemetry: tel, Groups: &fakeGroups{groups: map[string]*fakeGroup{}},
		Host: fakeHost{ppid: int32(os.Getpid())}, Policy: pe, Risk: re, Audit: &memSink{},
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		SelfTestTimeout: 150 * time.Millisecond,
	}
	if prober {
		o.Prober = fakeProber(tel, b)
	}
	d, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return d, tel
}

// The self-test has to be satisfied by the critical probe and nothing else. A
// record from the kernel-side hook, a record with the wrong outcome, silence,
// and having no way to run the check at all are each a failure - and after a
// failure the daemon must neither report healthy telemetry nor govern.
func TestSelfTestAcceptsOnlyTheOpenProbesRecord(t *testing.T) {
	cases := []struct {
		name   string
		b      probeBehaviour
		prober bool
		pass   bool
		why    string
	}{
		{"probe reports ENOENT", probeReports, true, true, ""},
		{"nothing reports", probeSilent, true, false, "no record"},
		{"only the kernel hook reports", probeHookOnly, true, false, "kernel-hook record"},
		{"wrong outcome", probeWrongError, true, false, "not ENOENT"},
		{"no prober", probeReports, false, false, "no self-test prober"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, _ := newUntested(t, c.b, c.prober)
			res, err := d.SelfTest(context.Background())
			if c.pass {
				if err != nil || !res.Passed || res.Probe != "openat" {
					t.Fatalf("result %+v, err %v; want a pass naming the openat probe", res, err)
				}
				if !d.status().TelemetryHealthy {
					t.Error("telemetry is not reported healthy after the self-test passed")
				}
				return
			}
			if err == nil || !errors.Is(err, ErrSelfTestFailed) || res.Passed {
				t.Fatalf("result %+v, err %v; want a failure", res, err)
			}
			if !strings.Contains(res.Detail, c.why) {
				t.Errorf("detail %q does not say %q", res.Detail, c.why)
			}
			st := d.status()
			if st.TelemetryHealthy || st.SelfTest.Passed {
				t.Errorf("status reports healthy telemetry after a failed self-test: %+v", st.SelfTest)
			}
			if _, err := d.createSession(context.Background(), ipc.Peer{UID: uint32(os.Getuid())},
				ipc.CreateSessionRequest{Prompt: "run the go tests", WorkspaceRoot: t.TempDir()}); err == nil {
				t.Error("a session was created after the self-test failed")
			}
		})
	}
}

// Before the self-test has run at all, nothing is governed either: the check is
// a precondition, not a report produced after the fact.
func TestSessionsAreRefusedBeforeTheSelfTestRuns(t *testing.T) {
	d, _ := newUntested(t, probeReports, true)
	_, err := d.createSession(context.Background(), ipc.Peer{UID: uint32(os.Getuid())},
		ipc.CreateSessionRequest{Prompt: "run the go tests", WorkspaceRoot: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "self-test has not passed") {
		t.Fatalf("createSession before the self-test: %v", err)
	}
	if d.status().TelemetryHealthy {
		t.Error("telemetry is reported healthy before the self-test ran")
	}
}

func TestSessionLifecycleOverTheSocket(t *testing.T) {
	r := newRig(t, policy.ModeMonitor, time.Minute)
	ctx := context.Background()
	sid := r.start(t, "run the go tests")

	if r.tel.attached[sid] == 0 || len(r.groups.get(sid).adopted) != 1 {
		t.Fatal("start did not adopt the root into a cgroup and attach telemetry")
	}

	stream, err := r.client.StreamDecisions(ctx, sid)
	if err != nil {
		t.Fatal(err)
	}
	r.feed(t, sid, read(filepath.Join(r.ws, "main.go")), read("/home/dev/.ssh/id_rsa"))

	var got []decision.Decision
	for len(got) < 2 {
		select {
		case d := <-stream:
			got = append(got, d)
		case <-time.After(3 * time.Second):
			t.Fatalf("stream delivered %d decisions", len(got))
		}
	}
	if got[0].Verdict != decision.VerdictWithinEnvelope || got[1].Verdict != decision.VerdictExplicitlyDenied {
		t.Fatalf("verdicts = %s, %s", got[0].Verdict, got[1].Verdict)
	}
	if got[1].Action != ece.ActionBlock || got[1].Enforced {
		t.Fatalf("monitor mode: action %s enforced %v, want block recorded and not applied", got[1].Action, got[1].Enforced)
	}
	if frozen, killed := r.groups.get(sid).state(); frozen || killed {
		t.Fatal("monitor mode applied containment")
	}

	s, err := r.client.EndSession(ctx, sid, 0)
	if err != nil {
		t.Fatal(err)
	}
	if s.State != session.StateCompleted || s.Summary.EventsObserved != 2 || s.Outcome.ViolationCount == 0 {
		t.Fatalf("ended session: state %s summary %+v outcome %+v", s.State, s.Summary, s.Outcome)
	}
	if !r.groups.get(sid).removed {
		t.Fatal("the session cgroup was not removed")
	}
	if len(r.audit.all()) != 2 {
		t.Fatalf("audit has %d records, want 2", len(r.audit.all()))
	}
	if again, err := r.client.EndSession(ctx, sid, 0); err != nil || again.State != session.StateCompleted {
		t.Fatalf("EndSession is not idempotent: %v %v", again, err)
	}
}

// The entry points no syscall tracepoint reaches have to arrive at the same
// decision as the ones that do. A credential read through io_uring carries no
// syscall return, so the only thing separating it from an openat read is the
// record shape - and a shape that policy treated as unevaluable would be a
// bypass with a probe behind it.
func TestKernelPathReadIsBlockedLikeAnyOther(t *testing.T) {
	r := newRig(t, policy.ModeEnforce, time.Minute)
	sid := r.start(t, "run the go tests")
	r.feed(t, sid, kernelRead("/home/dev/.aws/credentials"))

	waitFor(t, "the kill", func() bool { _, k := r.groups.get(sid).state(); return k })
	recs := r.audit.all()
	if len(recs) != 1 || !recs[0].Enforced || recs[0].Action != ece.ActionBlock {
		t.Fatalf("audit = %+v", recs)
	}
	if recs[0].Verdict != decision.VerdictExplicitlyDenied {
		t.Errorf("verdict = %s, want the denial the path is covered by", recs[0].Verdict)
	}
	// Not charged as an unverifiable path: the kernel vouched for this name.
	for _, f := range recs[0].Risk.Factors {
		if f.Name == risk.FactorUnverifiablePath {
			t.Errorf("a kernel path was charged as unverifiable: %+v", f)
		}
	}
}

func TestEnforceModeKillsOnBlock(t *testing.T) {
	r := newRig(t, policy.ModeEnforce, time.Minute)
	sid := r.start(t, "run the go tests")
	r.feed(t, sid, read("/home/dev/.aws/credentials"))

	waitFor(t, "the kill", func() bool { _, k := r.groups.get(sid).state(); return k })
	waitFor(t, "termination", func() bool {
		s, _ := r.client.GetSession(context.Background(), sid)
		return s != nil && s.State == session.StateTerminated
	})
	recs := r.audit.all()
	if len(recs) != 1 || !recs[0].Enforced || recs[0].Action != ece.ActionBlock {
		t.Fatalf("audit = %+v", recs)
	}
	if s, _ := r.client.GetSession(context.Background(), sid); s.Outcome.BlockedCount != 1 {
		t.Fatalf("BlockedCount = %d, want 1", s.Outcome.BlockedCount)
	}
}

func TestInteractiveFreezeThenApproveOrDeny(t *testing.T) {
	r := newRig(t, policy.ModeInteractive, time.Minute)
	ctx := context.Background()

	// Unexpected egress asks for approval; approving thaws.
	sid := r.start(t, "run the go tests")
	r.feed(t, sid, synth.Spec{Type: abi.EvtNetConnect, Ret: 0, Net: &synth.Net{Family: 2, DestAddr: netip.MustParseAddr("203.0.113.9"), DestPort: 443}})
	waitFor(t, "freeze", func() bool { f, _ := r.groups.get(sid).state(); return f })
	pend, err := r.client.PendingApprovals(ctx)
	if err != nil || len(pend) != 1 || pend[0].SessionID != sid || !pend[0].Decision.Enforced {
		t.Fatalf("pending = %+v, %v", pend, err)
	}
	if s, _ := r.client.GetSession(ctx, sid); s.State != session.StateSuspended {
		t.Fatalf("state while frozen = %s", s.State)
	}
	if err := r.client.RespondApproval(ctx, decision.ApprovalResponse{RequestID: pend[0].ID, Approved: true}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "thaw", func() bool { f, _ := r.groups.get(sid).state(); return !f })
	if s, _ := r.client.GetSession(ctx, sid); s.State != session.StateActive {
		t.Fatalf("state after approval = %s", s.State)
	}

	// Denying kills.
	r.feed(t, sid, synth.Spec{Type: abi.EvtNetConnect, Ret: 0, Net: &synth.Net{Family: 2, DestAddr: netip.MustParseAddr("198.51.100.7"), DestPort: 443}})
	waitFor(t, "second request", func() bool { p, _ := r.client.PendingApprovals(ctx); return len(p) == 1 })
	pend, _ = r.client.PendingApprovals(ctx)
	if err := r.client.RespondApproval(ctx, decision.ApprovalResponse{RequestID: pend[0].ID, Approved: false}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "kill after denial", func() bool { _, k := r.groups.get(sid).state(); return k })
	waitFor(t, "termination", func() bool {
		s, _ := r.client.GetSession(ctx, sid)
		return s.State == session.StateTerminated
	})
}

func TestApprovalTimeoutDenies(t *testing.T) {
	r := newRig(t, policy.ModeInteractive, 100*time.Millisecond)
	sid := r.start(t, "run the go tests")
	r.feed(t, sid, synth.Spec{Type: abi.EvtNetConnect, Ret: 0, Net: &synth.Net{Family: 2, DestAddr: netip.MustParseAddr("203.0.113.9"), DestPort: 443}})
	waitFor(t, "kill on timeout", func() bool { _, k := r.groups.get(sid).state(); return k })
}

func TestStartRefusesAProcessThatIsNotTheCallersChild(t *testing.T) {
	r := newRig(t, policy.ModeMonitor, time.Minute)
	r.d.host = fakeHost{ppid: 1}
	ctx := context.Background()
	resp, err := r.client.CreateSession(ctx, ipc.CreateSessionRequest{Prompt: "run the go tests", WorkspaceRoot: r.ws})
	if err != nil {
		t.Fatal(err)
	}
	_ = r.client.ApproveEnvelope(ctx, ipc.ApproveEnvelopeRequest{SessionID: resp.SessionID, Approved: true})
	err = r.client.StartSession(ctx, resp.SessionID, 1)
	var e *ipc.Error
	if !errors.As(err, &e) || e.Code != ipc.ErrCodePermissionDenied {
		t.Fatalf("StartSession with a foreign pid = %v", err)
	}
}

// A kill that fails must not leave the session running as though containment
// had worked. Freeze is the weaker containment left, and the session ends as
// failed because our own containment is what broke.
func TestFailedKillFreezesAndFailsTheSession(t *testing.T) {
	r := newRig(t, policy.ModeEnforce, time.Minute)
	ctx := context.Background()
	sid := r.start(t, "run the go tests")
	r.groups.get(sid).failKill(errors.New("injected kill failure"))

	r.feed(t, sid, read("/home/dev/.aws/credentials"))
	waitFor(t, "the freeze fallback", func() bool { f, _ := r.groups.get(sid).state(); return f })
	waitFor(t, "the session to fail", func() bool {
		s, _ := r.client.GetSession(ctx, sid)
		return s != nil && s.State == session.StateFailed
	})

	recs := r.audit.all()
	if len(recs) == 0 {
		t.Fatal("no decision was recorded")
	}
	d := recs[len(recs)-1]
	if d.Action != ece.ActionBlock {
		t.Fatalf("action = %s, want block", d.Action)
	}
	// Freeze worked, so containment was applied and Enforced must say so.
	if !d.Enforced {
		t.Fatalf("enforced = false although the session was frozen: %+v", d.Reasoning)
	}
	last := d.Reasoning[len(d.Reasoning)-1]
	if !strings.Contains(last.Conclusion, "kill failed") || !strings.Contains(last.Conclusion, "frozen instead") {
		t.Fatalf("reasoning does not record the failure: %q", last.Conclusion)
	}
}

// When neither kill nor freeze works there is no containment at all, and the
// record has to say so rather than claim a block was applied.
func TestContainmentFailureIsReportedHonestly(t *testing.T) {
	r := newRig(t, policy.ModeEnforce, time.Minute)
	ctx := context.Background()
	sid := r.start(t, "run the go tests")
	g := r.groups.get(sid)
	g.failKill(errors.New("injected kill failure"))
	g.failFreeze(errors.New("injected freeze failure"))

	r.feed(t, sid, read("/home/dev/.aws/credentials"))
	waitFor(t, "the session to fail", func() bool {
		s, _ := r.client.GetSession(ctx, sid)
		return s != nil && s.State == session.StateFailed
	})
	recs := r.audit.all()
	d := recs[len(recs)-1]
	if d.Enforced {
		t.Fatal("enforced = true although no containment was applied")
	}
	if f, k := g.state(); f || k {
		t.Fatalf("group reports frozen=%v killed=%v after both failed", f, k)
	}
}

// A denied approval takes the session down. A second request answered after
// the denial must not thaw it before the kill runs.
func TestDeniedSessionIsNotThawedByALaterApproval(t *testing.T) {
	r := newRig(t, policy.ModeInteractive, time.Minute)
	ctx := context.Background()
	sid := r.start(t, "run the go tests")

	egress := func(ip string) synth.Spec {
		return synth.Spec{Type: abi.EvtNetConnect, Ret: 0,
			Net: &synth.Net{Family: 2, DestAddr: netip.MustParseAddr(ip), DestPort: 443}}
	}
	r.feed(t, sid, egress("203.0.113.9"), egress("203.0.113.10"))
	waitFor(t, "two pending approvals", func() bool {
		p, _ := r.client.PendingApprovals(ctx)
		return len(p) >= 2
	})
	pending, err := r.client.PendingApprovals(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Answered directly rather than over the socket. The denial's kill runs on
	// the dispatch loop, and going through the socket lets it land first, which
	// hides the reversal behind timing. Called back to back, the second answer
	// is the one that used to resume the session.
	if !r.d.approvals.resolve(ctx, decision.ApprovalResponse{
		RequestID: pending[0].ID, Approved: false, RespondedBy: "operator"}) {
		t.Fatal("the denial was not accepted")
	}
	if r.d.approvals.resolve(ctx, decision.ApprovalResponse{
		RequestID: pending[1].ID, Approved: true, RespondedBy: "operator"}) {
		t.Fatal("an approval was accepted for a session that had already been denied")
	}

	waitFor(t, "the kill after the denial", func() bool { _, k := r.groups.get(sid).state(); return k })
	s, _ := r.client.GetSession(ctx, sid)
	if s == nil || s.State != session.StateTerminated {
		t.Fatalf("session state = %v, want terminated", s)
	}
	// Still frozen, never resumed: a thaw here is the reversal this guards.
	if f, _ := r.groups.get(sid).state(); !f {
		t.Fatal("the denied session was thawed by the later approval")
	}
	if p, _ := r.client.PendingApprovals(ctx); len(p) != 0 {
		t.Fatalf("pending approvals after the denial = %d, want 0", len(p))
	}
}

// A governed agent runs as its owner's UID, so UID authorization alone would
// let it drive the daemon. Every call that changes state has to refuse it.
func TestGovernedCallerCannotChangeState(t *testing.T) {
	r := newRig(t, policy.ModeMonitor, time.Minute)
	ctx := context.Background()
	sid := r.start(t, "run the go tests")
	r.feed(t, sid, synth.Spec{Type: abi.EvtNetConnect, Ret: 0,
		Net: &synth.Net{Family: 2, DestAddr: netip.MustParseAddr("203.0.113.9"), DestPort: 443}})

	// Every later call arrives from a process inside a session cgroup.
	r.groups.govern(int32(os.Getpid()))

	denied := func(what string, err error) {
		t.Helper()
		var e *ipc.Error
		if !errors.As(err, &e) || e.Code != ipc.ErrCodePermissionDenied {
			t.Fatalf("%s from a governed caller = %v, want permission_denied", what, err)
		}
	}
	_, err := r.client.CreateSession(ctx, ipc.CreateSessionRequest{Prompt: "anything", WorkspaceRoot: r.ws})
	denied("CreateSession", err)
	denied("ApproveEnvelope", r.client.ApproveEnvelope(ctx,
		ipc.ApproveEnvelopeRequest{SessionID: sid, Approved: true}))
	denied("StartSession", r.client.StartSession(ctx, sid, 4242))
	denied("EndSession", func() error { _, err := r.client.EndSession(ctx, sid, 0); return err }())

	if n := r.d.refusalCount(); n < 4 {
		t.Fatalf("refusals = %d, want at least 4", n)
	}
	if s, _ := r.client.GetSession(ctx, sid); s == nil || session.IsTerminal(s.State) {
		t.Fatal("the refused calls ended the session anyway")
	}
}

// A frozen agent must not be able to answer the approval it is waiting on,
// directly or through a helper it placed in a session cgroup.
func TestGovernedCallerCannotAnswerApprovals(t *testing.T) {
	r := newRig(t, policy.ModeInteractive, time.Minute)
	ctx := context.Background()
	sid := r.start(t, "run the go tests")
	r.feed(t, sid, synth.Spec{Type: abi.EvtNetConnect, Ret: 0,
		Net: &synth.Net{Family: 2, DestAddr: netip.MustParseAddr("203.0.113.9"), DestPort: 443}})
	waitFor(t, "the freeze", func() bool { f, _ := r.groups.get(sid).state(); return f })

	pending, err := r.client.PendingApprovals(ctx)
	if err != nil || len(pending) == 0 {
		t.Fatalf("PendingApprovals = %v, %v", pending, err)
	}
	r.groups.govern(int32(os.Getpid()))

	err = r.client.RespondApproval(ctx, decision.ApprovalResponse{RequestID: pending[0].ID, Approved: true})
	var e *ipc.Error
	if !errors.As(err, &e) || e.Code != ipc.ErrCodePermissionDenied {
		t.Fatalf("self-approval = %v, want permission_denied", err)
	}
	if f, _ := r.groups.get(sid).state(); !f {
		t.Fatal("the session was thawed by a governed caller")
	}
}

// A caller the daemon cannot place is refused. Otherwise the check is optional
// for anyone able to make the lookup fail.
func TestUnlocatableCallerIsRefused(t *testing.T) {
	r := newRig(t, policy.ModeMonitor, time.Minute)
	r.groups.govErr = errors.New("no such process")
	_, err := r.client.CreateSession(context.Background(),
		ipc.CreateSessionRequest{Prompt: "run the go tests", WorkspaceRoot: r.ws})
	var e *ipc.Error
	if !errors.As(err, &e) || e.Code != ipc.ErrCodePermissionDenied {
		t.Fatalf("CreateSession with an unlocatable caller = %v, want permission_denied", err)
	}
}

// An already-governed process cannot be moved into a second session, which is
// what would take it out of the scope its owner approved.
func TestAlreadyGovernedProcessIsNotAdopted(t *testing.T) {
	r := newRig(t, policy.ModeMonitor, time.Minute)
	ctx := context.Background()
	resp, err := r.client.CreateSession(ctx, ipc.CreateSessionRequest{Prompt: "run the go tests", WorkspaceRoot: r.ws})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.client.ApproveEnvelope(ctx, ipc.ApproveEnvelopeRequest{SessionID: resp.SessionID, Approved: true}); err != nil {
		t.Fatal(err)
	}
	r.groups.govern(4242)
	err = r.client.StartSession(ctx, resp.SessionID, 4242)
	var e *ipc.Error
	if !errors.As(err, &e) || e.Code != ipc.ErrCodePermissionDenied {
		t.Fatalf("adopting a governed pid = %v, want permission_denied", err)
	}
	if g := r.groups.get(resp.SessionID); g != nil {
		if _, k := g.state(); !k {
			t.Log("note: the refused session kept its cgroup; it is cleaned up by session failure")
		}
	}
}

func TestTamperedEnvelopeIsNotEnforced(t *testing.T) {
	r := newRig(t, policy.ModeMonitor, time.Minute)
	ctx := context.Background()
	resp, _ := r.client.CreateSession(ctx, ipc.CreateSessionRequest{Prompt: "run the go tests", WorkspaceRoot: r.ws})
	_ = r.client.ApproveEnvelope(ctx, ipc.ApproveEnvelopeRequest{SessionID: resp.SessionID, Approved: true})
	s, _ := r.d.manager.Get(ctx, resp.SessionID)
	s.Envelope.Grants[0].Selector.PathPatterns = append(s.Envelope.Grants[0].Selector.PathPatterns, "/**")
	if err := r.client.StartSession(ctx, resp.SessionID, 4242); err == nil {
		t.Fatal("a widened envelope was started")
	}
}

func TestRejectedEnvelopeEndsTheSession(t *testing.T) {
	r := newRig(t, policy.ModeMonitor, time.Minute)
	ctx := context.Background()
	resp, _ := r.client.CreateSession(ctx, ipc.CreateSessionRequest{Prompt: "run the go tests", WorkspaceRoot: r.ws})
	if err := r.client.ApproveEnvelope(ctx, ipc.ApproveEnvelopeRequest{SessionID: resp.SessionID, Approved: false}); err != nil {
		t.Fatal(err)
	}
	s, _ := r.client.GetSession(ctx, resp.SessionID)
	if s.State != session.StateTerminated {
		t.Fatalf("rejected session state = %s", s.State)
	}
}

func TestModeRequestCannotWeaken(t *testing.T) {
	r := newRig(t, policy.ModeEnforce, time.Minute)
	resp, err := r.client.CreateSession(context.Background(), ipc.CreateSessionRequest{
		Prompt: "run the go tests", WorkspaceRoot: r.ws, Mode: policy.ModeMonitor,
	})
	if err != nil {
		t.Fatal(err)
	}
	s, _ := r.client.GetSession(context.Background(), resp.SessionID)
	if s.Mode != policy.ModeEnforce {
		t.Fatalf("mode = %s, want enforce", s.Mode)
	}
}

func TestDropsFailTheSessionClosed(t *testing.T) {
	r := newRig(t, policy.ModeMonitor, time.Minute)
	sid := r.start(t, "run the go tests")
	g, _ := synth.New(synth.Config{SessionID: sid, Process: synth.Proc{PID: 4242, TID: 4242}})
	evs, _ := g.Generate(synth.Spec{Type: abi.EvtFileOpen, Ret: 3, Dropped: 5, File: &synth.File{Path: "/x", ResolvedPath: "/x"}})
	r.tel.ch <- evs[0]
	waitFor(t, "fail-closed", func() bool {
		s, _ := r.client.GetSession(context.Background(), sid)
		return s.State == session.StateFailed && !s.Outcome.TelemetryComplete
	})
	if _, k := r.groups.get(sid).state(); !k {
		t.Fatal("a session with a telemetry gap kept running")
	}
}

func TestOrphanedSessionIsReaped(t *testing.T) {
	r := newRig(t, policy.ModeMonitor, time.Minute)
	sid := r.start(t, "run the go tests")
	g := r.groups.get(sid)
	g.mu.Lock()
	g.populated = false
	g.mu.Unlock()
	waitFor(t, "reaping", func() bool {
		s, _ := r.client.GetSession(context.Background(), sid)
		return session.IsTerminal(s.State)
	})
}

func TestOtherUsersCannotTouchASession(t *testing.T) {
	r := newRig(t, policy.ModeMonitor, time.Minute)
	sid := r.start(t, "run the go tests")
	stranger := ipc.Peer{UID: uint32(os.Getuid()) + 1, PID: 1}
	if _, err := r.d.Call(context.Background(), stranger, ipc.MethodGetSession, []byte(`{"session_id":"`+sid+`"}`)); err == nil {
		t.Fatal("another user read the session")
	}
	list, _ := r.d.Call(context.Background(), stranger, ipc.MethodListSessions, nil)
	if l := list.([]*session.Session); len(l) != 0 {
		t.Fatalf("another user listed %d sessions", len(l))
	}
}
