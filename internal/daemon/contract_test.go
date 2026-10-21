package daemon

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stringNameMahin/ALLSEER/internal/intent"
	"github.com/stringNameMahin/ALLSEER/internal/ipc"
	"github.com/stringNameMahin/ALLSEER/internal/policy"
	"github.com/stringNameMahin/ALLSEER/internal/session"
	"github.com/stringNameMahin/ALLSEER/internal/telemetry/abi"
	"github.com/stringNameMahin/ALLSEER/internal/telemetry/synth"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
)

// The enforce-mode contract decided on 2026-10-21: enforce contains block and
// request_approval, and lets warn through. Under the shipped rules warn is a
// moderate-risk departure, an indeterminate verdict with low risk, and
// whatever no rule matches. Each is recorded and the agent keeps running.
func TestEnforceContainsBlockAndApprovalButNotWarn(t *testing.T) {
	r := newRig(t, policy.ModeEnforce, time.Minute)
	ctx := context.Background()

	// A Go workspace, so the envelope grants the module proxy by name and a
	// connection to one of its addresses cannot be compared without DNS.
	resp, err := r.client.CreateSession(ctx, ipc.CreateSessionRequest{
		Prompt: "install the dependencies and run the go tests", WorkspaceRoot: r.ws,
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

	warns := []struct {
		rule string
		spec synth.Spec
	}{
		{"medium-risk-departure", synth.Spec{Type: abi.EvtProcExec, Exec: &synth.Exec{Filename: "/home/dev/tools/fmt"}}},
		{"indeterminate-low-risk", synth.Spec{Type: abi.EvtNetConnect, Ret: 0,
			Net: &synth.Net{Family: 2, DestAddr: netip.MustParseAddr("142.250.80.17"), DestPort: 443}}},
		{"workspace-escape-read", read("/etc/hostname")},
	}
	for i, w := range warns {
		r.feed(t, sid, w.spec)
		waitFor(t, w.rule, func() bool { return len(r.audit.all()) == i+1 })
		d := r.audit.all()[i]
		if d.Action != ece.ActionWarn || d.MatchedRule != w.rule || d.Enforced {
			t.Fatalf("event %d: action %s rule %s enforced %v, want an unenforced warn from %s",
				i, d.Action, d.MatchedRule, d.Enforced, w.rule)
		}
		if frozen, killed := r.groups.get(sid).state(); frozen || killed {
			t.Fatalf("a warn contained the session: frozen %v killed %v", frozen, killed)
		}
	}
	if s, _ := r.client.GetSession(ctx, sid); s.State != session.StateActive {
		t.Fatalf("state after three warnings = %s, want active", s.State)
	}

	// The rule set's own fallback is warn, so an event no rule matches is
	// treated the same way.
	rs, err := policy.NewLoader().Load(ctx, "../../configs/rules.default.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if rs.DefaultAction != ece.ActionWarn {
		t.Fatalf("the shipped rule set falls back to %s, want warn", rs.DefaultAction)
	}

	// And request_approval, with no human to ask, is a kill.
	r.feed(t, sid, synth.Spec{Type: abi.EvtNetConnect, Ret: 0,
		Net: &synth.Net{Family: 2, DestAddr: netip.MustParseAddr("127.0.0.1"), DestPort: 9}})
	waitFor(t, "the kill", func() bool { _, k := r.groups.get(sid).state(); return k })
	d := r.audit.all()[len(warns)]
	if d.Action != ece.ActionRequestApproval || !d.Enforced {
		t.Fatalf("unexpected egress: action %s enforced %v, want an enforced request_approval", d.Action, d.Enforced)
	}
}
