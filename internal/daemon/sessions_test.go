package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/stringNameMahin/ALLSEER/internal/intent"
	"github.com/stringNameMahin/ALLSEER/internal/ipc"
	"github.com/stringNameMahin/ALLSEER/internal/policy"
	"github.com/stringNameMahin/ALLSEER/internal/session"
)

// allseerctl sessions and allseerctl session read GetSession and ListSessions.
// A running session reports what it has seen so far, not the zeros it used to
// carry until it ended.
func TestRunningSessionReportsItsCountsSoFar(t *testing.T) {
	r := newRig(t, policy.ModeMonitor, time.Minute)
	ctx := context.Background()
	resp, err := r.client.CreateSession(ctx, ipc.CreateSessionRequest{
		Prompt: "run the go tests", WorkspaceRoot: r.ws,
		Workspace: intent.WorkspaceContext{Languages: []string{"go"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	sid := resp.SessionID
	if err := r.client.ApproveEnvelope(ctx, ipc.ApproveEnvelopeRequest{SessionID: sid, Approved: true}); err != nil {
		t.Fatal(err)
	}
	if err := r.client.StartSession(ctx, sid, 4242); err != nil {
		t.Fatal(err)
	}

	// One read the envelope grants and one it does not.
	r.feed(t, sid, read(r.ws+"/main_test.go"), read("/etc/hostname"))
	waitFor(t, "two decisions in the live counters", func() bool {
		s, err := r.client.GetSession(ctx, sid)
		return err == nil && s.Summary.DecisionsIssued == 2
	})

	got, err := r.client.GetSession(ctx, sid)
	if err != nil {
		t.Fatal(err)
	}
	list, err := r.client.ListSessions(ctx, session.Filter{})
	if err != nil || len(list) != 1 {
		t.Fatalf("ListSessions = %d sessions, %v", len(list), err)
	}
	for name, s := range map[string]*session.Session{"GetSession": got, "ListSessions": list[0]} {
		if s.State != session.StateActive || s.Summary.EventsObserved != 2 || s.Summary.DecisionsIssued != 2 ||
			s.Outcome.ViolationCount != 1 {
			t.Errorf("%s: state %s, %d events, %d decisions, %d violations; want active, 2, 2 and 1",
				name, s.State, s.Summary.EventsObserved, s.Summary.DecisionsIssued, s.Outcome.ViolationCount)
		}
	}
}

// A daemon that ran session after session kept every one, in the manager and
// in its own table. Past KeepEnded the one that ended first is forgotten by
// both, and the running one stays.
func TestEndedSessionsPastKeepEndedAreForgotten(t *testing.T) {
	r := newRigWith(t, policy.ModeMonitor, time.Minute, func(_ *rig, o *Options) { o.KeepEnded = 1 })
	ctx := context.Background()
	start := func() string {
		resp, err := r.client.CreateSession(ctx, ipc.CreateSessionRequest{Prompt: "run the go tests", WorkspaceRoot: r.ws})
		if err != nil {
			t.Fatal(err)
		}
		if err := r.client.ApproveEnvelope(ctx, ipc.ApproveEnvelopeRequest{SessionID: resp.SessionID, Approved: true}); err != nil {
			t.Fatal(err)
		}
		if err := r.client.StartSession(ctx, resp.SessionID, 4242); err != nil {
			t.Fatal(err)
		}
		return resp.SessionID
	}
	first, second, running := start(), start(), start()
	for _, sid := range []string{first, second} {
		if _, err := r.client.EndSession(ctx, sid, 0); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := r.client.GetSession(ctx, first); err == nil {
		t.Error("the session that ended first is still queryable")
	}
	r.d.mu.Lock()
	_, kept := r.d.sessions[first]
	r.d.mu.Unlock()
	if kept {
		t.Error("the daemon still holds the forgotten session")
	}
	for _, sid := range []string{second, running} {
		if _, err := r.client.GetSession(ctx, sid); err != nil {
			t.Errorf("GetSession(%s) = %v, want it kept", sid, err)
		}
	}
}
