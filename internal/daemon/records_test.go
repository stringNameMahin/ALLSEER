package daemon

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stringNameMahin/ALLSEER/internal/ipc"
	"github.com/stringNameMahin/ALLSEER/internal/policy"
	"github.com/stringNameMahin/ALLSEER/internal/session"
	"github.com/stringNameMahin/ALLSEER/internal/telemetry"
	"github.com/stringNameMahin/ALLSEER/internal/telemetry/abi"
	"github.com/stringNameMahin/ALLSEER/internal/telemetry/synth"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
)

// recordsOf returns the session records of one kind, in write order.
func recordsOf[T decision.Record](s *memSink) []T {
	var out []T
	for _, r := range s.records() {
		if v, ok := r.(T); ok {
			out = append(out, v)
		}
	}
	return out
}

func egress(ip string) synth.Spec {
	return synth.Spec{Type: abi.EvtNetConnect, Ret: 0,
		Net: &synth.Net{Family: 2, DestAddr: netip.MustParseAddr(ip), DestPort: 443}}
}

// A session's part of the log opens with what it is judged against and closes
// with how it ended, with its decisions in between.
func TestAuditFramesASessionWithItsStartAndEnd(t *testing.T) {
	r := newRig(t, policy.ModeMonitor, time.Minute)
	ctx := context.Background()
	sid := r.start(t, "run the go tests")
	r.feed(t, sid, read(filepath.Join(r.ws, "main.go")), read("/home/dev/.ssh/id_rsa"))
	waitFor(t, "two decisions", func() bool { return len(r.audit.all()) == 2 })
	if _, err := r.client.EndSession(ctx, sid, 0); err != nil {
		t.Fatal(err)
	}

	want := []decision.RecordKind{decision.RecordSessionStart, decision.RecordDecision,
		decision.RecordDecision, decision.RecordSessionEnd}
	if got := r.audit.order(); !reflect.DeepEqual(got, want) {
		t.Fatalf("audit order = %v, want %v", got, want)
	}

	starts := recordsOf[decision.SessionStart](r.audit)
	st := starts[0]
	s, _ := r.client.GetSession(ctx, sid)
	switch {
	case st.SessionID != sid || st.Mode != string(policy.ModeMonitor) || st.RootPID != 4242:
		t.Errorf("start = %+v", st)
	case st.Owner != "dev" || st.OwnerUID != uint32(os.Getuid()):
		t.Errorf("owner = %q (%d)", st.Owner, st.OwnerUID)
	case st.CgroupID != r.groups.get(sid).CgroupID():
		t.Errorf("cgroup id = %d, want %d", st.CgroupID, r.groups.get(sid).CgroupID())
	case st.Envelope == nil || st.Envelope.Digest != s.Envelope.Digest || st.Envelope.Approval == nil:
		t.Errorf("the start record does not carry the sealed, approved envelope: %+v", st.Envelope)
	case !reflect.DeepEqual(st.Coverage.Observable, r.tel.observe):
		t.Errorf("coverage observable = %v, want %v", st.Coverage.Observable, r.tel.observe)
	case !st.Timestamp.Equal(s.StartedAt):
		t.Errorf("start timestamp = %v, want the session's start %v", st.Timestamp, s.StartedAt)
	}

	end := recordsOf[decision.SessionEnd](r.audit)[0]
	switch {
	case end.SessionID != sid || end.Result != string(session.StateCompleted):
		t.Errorf("end = %+v", end)
	case !end.TelemetryComplete || end.ViolationCount == 0:
		t.Errorf("end outcome = %+v", end)
	case end.EventsObserved != 2 || end.DecisionsIssued != 2:
		t.Errorf("end counts events %d decisions %d, want 2 and 2", end.EventsObserved, end.DecisionsIssued)
	case !strings.Contains(end.Reason, "exited with code 0"):
		t.Errorf("end reason = %q", end.Reason)
	}
}

// Coverage gaps travel with the session, so a quiet log cannot be read as a
// clean one when the probes were not watching.
func TestStartRecordCarriesCoverageGaps(t *testing.T) {
	r := newRig(t, policy.ModeMonitor, time.Minute)
	r.tel.mu.Lock()
	r.tel.gaps = []telemetry.EntryPointGap{
		{Kind: capability.KindNetConnect, Observed: []string{"connect"}, Missing: []string{"io_uring", "sendto"}},
		{Kind: capability.KindFileRead, Observed: []string{"openat"}},
	}
	r.tel.mu.Unlock()
	r.start(t, "run the go tests")

	cov := recordsOf[decision.SessionStart](r.audit)[0].Coverage
	want := []decision.EntryPointGap{{Kind: capability.KindNetConnect, Missing: []string{"io_uring", "sendto"}}}
	if !reflect.DeepEqual(cov.EntryPoints, want) {
		t.Fatalf("entry points = %+v, want only the kind with unwatched entry points", cov.EntryPoints)
	}
}

// Every answer reaches the log with what it did: the approval that resumed
// the session, and the denial that terminated it.
func TestApprovalAnswersReachTheAuditTrail(t *testing.T) {
	r := newRig(t, policy.ModeInteractive, time.Minute)
	ctx := context.Background()
	sid := r.start(t, "run the go tests")

	answer := func(ip string, approve bool) decision.ApprovalRequest {
		t.Helper()
		r.feed(t, sid, egress(ip))
		var req decision.ApprovalRequest
		waitFor(t, "the request for "+ip, func() bool {
			p, _ := r.client.PendingApprovals(ctx)
			if len(p) == 1 {
				req = p[0]
			}
			return len(p) == 1
		})
		if err := r.client.RespondApproval(ctx, decision.ApprovalResponse{
			RequestID: req.ID, Approved: approve, Reason: "checked"}); err != nil {
			t.Fatal(err)
		}
		return req
	}
	first := answer("203.0.113.9", true)
	waitFor(t, "thaw", func() bool { f, _ := r.groups.get(sid).state(); return !f })
	second := answer("198.51.100.7", false)
	waitFor(t, "termination", func() bool {
		s, _ := r.client.GetSession(ctx, sid)
		return s.State == session.StateTerminated
	})

	got := recordsOf[decision.Approval](r.audit)
	if len(got) != 2 {
		t.Fatalf("approval records = %+v, want 2", got)
	}
	for i, c := range []struct {
		req      decision.ApprovalRequest
		approved bool
		effect   decision.ApprovalEffect
	}{{first, true, decision.EffectResume}, {second, false, decision.EffectTerminate}} {
		a := got[i]
		if a.SessionID != sid || a.RequestID != c.req.ID || a.DecisionID != c.req.Decision.ID {
			t.Errorf("answer %d does not name its request and decision: %+v", i, a)
		}
		if a.Approved != c.approved || a.Effect != c.effect || a.TimedOut {
			t.Errorf("answer %d = approved %v effect %s timed out %v, want %v %s", i, a.Approved, a.Effect, a.TimedOut, c.approved, c.effect)
		}
		if a.RespondedBy != "dev" || a.Reason != "checked" || a.Timestamp.IsZero() {
			t.Errorf("answer %d = by %q reason %q at %v", i, a.RespondedBy, a.Reason, a.Timestamp)
		}
	}

	// The answer precedes its consequence: the denial before the end it causes.
	order := r.audit.order()
	if order[len(order)-2] != decision.RecordApproval || order[len(order)-1] != decision.RecordSessionEnd {
		t.Errorf("the log does not end with the denial and then the session end: %v", order)
	}
	if end := recordsOf[decision.SessionEnd](r.audit); len(end) != 1 || end[0].Result != string(session.StateTerminated) {
		t.Errorf("session end = %+v", end)
	}
}

// Nobody answering is an answer too, and the log says it was the timeout.
func TestApprovalTimeoutReachesTheAuditTrail(t *testing.T) {
	r := newRig(t, policy.ModeInteractive, 100*time.Millisecond)
	sid := r.start(t, "run the go tests")
	r.feed(t, sid, egress("203.0.113.9"))
	waitFor(t, "the timeout's answer", func() bool { return len(recordsOf[decision.Approval](r.audit)) == 1 })

	a := recordsOf[decision.Approval](r.audit)[0]
	if !a.TimedOut || a.Approved || a.RespondedBy != "timeout" || a.Effect != decision.EffectTerminate {
		t.Fatalf("timeout record = %+v", a)
	}
}

// A refused control request is a governed process trying to govern. The log
// names the session that process belongs to.
func TestRefusedControlRequestsReachTheAuditTrail(t *testing.T) {
	r := newRig(t, policy.ModeMonitor, time.Minute)
	ctx := context.Background()
	sid := r.start(t, "run the go tests")

	r.groups.govern(int32(os.Getpid()), sid)
	if _, err := r.client.CreateSession(ctx, ipc.CreateSessionRequest{Prompt: "anything", WorkspaceRoot: r.ws}); err == nil {
		t.Fatal("a governed caller created a session")
	}
	got := recordsOf[decision.ControlRefused](r.audit)
	if len(got) != 1 {
		t.Fatalf("refusal records = %+v, want 1", got)
	}
	c := got[0]
	if c.Method != ipc.MethodCreateSession || c.SessionID != sid || c.PID != int32(os.Getpid()) || c.UID != uint32(os.Getuid()) {
		t.Errorf("refusal = %+v", c)
	}
	if !strings.Contains(c.Reason, "inside a governed session") || c.Timestamp.IsZero() {
		t.Errorf("refusal reason %q at %v", c.Reason, c.Timestamp)
	}

	// A caller that cannot be placed is refused and recorded with no session.
	r.groups.mu.Lock()
	r.groups.govErr = errors.New("no such process")
	r.groups.mu.Unlock()
	_, _ = r.client.CreateSession(ctx, ipc.CreateSessionRequest{Prompt: "anything", WorkspaceRoot: r.ws})
	got = recordsOf[decision.ControlRefused](r.audit)
	if len(got) != 2 || got[1].SessionID != "" || !strings.Contains(got[1].Reason, "could not be located") {
		t.Fatalf("unlocatable refusal = %+v", got)
	}
}

// A session that never ran still ends in the log, and has no start record to
// suggest that it ran.
func TestRejectedEnvelopeEndsWithoutAStartRecord(t *testing.T) {
	r := newRig(t, policy.ModeMonitor, time.Minute)
	ctx := context.Background()
	resp, err := r.client.CreateSession(ctx, ipc.CreateSessionRequest{Prompt: "run the go tests", WorkspaceRoot: r.ws})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.client.ApproveEnvelope(ctx, ipc.ApproveEnvelopeRequest{
		SessionID: resp.SessionID, Approved: false, Reason: "too broad"}); err != nil {
		t.Fatal(err)
	}
	if got := r.audit.order(); !reflect.DeepEqual(got, []decision.RecordKind{decision.RecordSessionEnd}) {
		t.Fatalf("audit order = %v, want a lone session end", got)
	}
	end := recordsOf[decision.SessionEnd](r.audit)[0]
	if end.SessionID != resp.SessionID || end.Result != string(session.StateTerminated) ||
		!strings.Contains(end.Reason, "too broad") {
		t.Fatalf("session end = %+v", end)
	}
}

// A dropped record fails the session, and the end record says the telemetry
// was incomplete.
func TestEndRecordReportsIncompleteTelemetry(t *testing.T) {
	r := newRig(t, policy.ModeMonitor, time.Minute)
	sid := r.start(t, "run the go tests")
	g, _ := synth.New(synth.Config{SessionID: sid, Process: synth.Proc{PID: 4242, TID: 4242}})
	evs, _ := g.Generate(synth.Spec{Type: abi.EvtFileOpen, Ret: 3, Dropped: 5, File: &synth.File{Path: "/x", ResolvedPath: "/x"}})
	r.tel.ch <- evs[0]
	waitFor(t, "the end record", func() bool { return len(recordsOf[decision.SessionEnd](r.audit)) == 1 })

	end := recordsOf[decision.SessionEnd](r.audit)[0]
	if end.TelemetryComplete || end.Result != string(session.StateFailed) {
		t.Fatalf("end = %+v, want failed with incomplete telemetry", end)
	}
}

// A record the log could not take is counted where an operator looks.
func TestFailedRecordWritesAreReportedInStatus(t *testing.T) {
	r := newRig(t, policy.ModeMonitor, time.Minute)
	r.audit.mu.Lock()
	r.audit.recErr = errors.New("disk full")
	r.audit.mu.Unlock()
	r.start(t, "run the go tests")

	st, err := r.client.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.AuditErrors == 0 {
		t.Fatal("a failed session record write is not reported in status")
	}
}
