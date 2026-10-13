package daemon

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/stringNameMahin/ALLSEER/internal/policy"
	"github.com/stringNameMahin/ALLSEER/internal/session"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// MechanismCgroup names the containment this build applies.
const MechanismCgroup = "cgroup-v2 freeze/kill after detection"

// Enforcer turns decisions into containment.
//
// What it can and cannot do, stated once: tracepoints report a syscall after
// it completed, and BPF LSM is not in the default LSM stack, so nothing here
// prevents the operation a decision is about. It suspends (freezes) or
// terminates (kills) the session's whole cgroup after detection. CanBlock is
// therefore false, and Decision.Enforced is true only when a freeze or kill
// was actually applied.
//
//	monitor, warn   record only
//	interactive     request_approval: freeze and ask the owner; block: kill
//	enforce         request_approval and block: kill (no human to ask)
type Enforcer struct {
	d *Daemon
}

func newEnforcer(d *Daemon) *Enforcer { return &Enforcer{d: d} }

var _ decision.Enforcer = (*Enforcer)(nil)

// Capabilities reports what the enforcer can do on this host.
func (e *Enforcer) Capabilities() decision.EnforcerCapabilities {
	c := e.d.groups.Capabilities()
	return decision.EnforcerCapabilities{
		CanBlock:     false,
		CanSuspend:   c.Freeze,
		CanTerminate: c.Kill || c.Freeze,
		Mechanism:    MechanismCgroup,
	}
}

// Enforce applies d's action to the session and reports whether containment
// was applied.
func (e *Enforcer) Enforce(ctx context.Context, d decision.Decision, _ *event.Event) (bool, error) {
	out := e.react(ctx, d)
	return out.Enforced, nil
}

// react applies containment for a decision and returns it annotated. Runs on
// the dispatch goroutine.
func (e *Enforcer) react(ctx context.Context, d decision.Decision) decision.Decision {
	if d.Action != ece.ActionRequestApproval && d.Action != ece.ActionBlock {
		return d
	}
	b, ok := e.d.manager.Binding(d.SessionID)
	if !ok || !session.AcceptsEvents(b.Lifecycle) {
		return d
	}

	switch b.Mode {
	case policy.ModeMonitor, policy.ModeWarn:
		return note(d, false, fmt.Sprintf("%s mode: recorded, not applied", b.Mode))

	case policy.ModeInteractive:
		if d.Action == ece.ActionBlock {
			return e.terminate(ctx, d, "blocked by policy")
		}
		if err := e.suspend(ctx, d.SessionID); err != nil {
			e.d.log.Error("freezing session for approval failed; terminating instead",
				"session", d.SessionID, "err", err)
			return e.terminate(ctx, d, "approval required but the session could not be suspended")
		}
		d = note(d, true, "session frozen pending approval by its owner")
		e.d.approvals.open(d)
		return d

	case policy.ModeEnforce:
		return e.terminate(ctx, d, fmt.Sprintf("%s in enforce mode, with no human to ask", d.Action))
	}
	return d
}

func (e *Enforcer) suspend(ctx context.Context, sid string) error {
	s, err := e.d.manager.Get(ctx, sid)
	if err != nil {
		return err
	}
	if s.State == session.StateSuspended {
		return nil
	}
	return e.d.manager.Suspend(ctx, sid, "approval required")
}

func (e *Enforcer) terminate(ctx context.Context, d decision.Decision, why string) decision.Decision {
	g := e.d.groupOf(d.SessionID)
	if g == nil {
		return note(d, false, "no session cgroup to contain")
	}
	if err := g.Kill(ctx); err != nil {
		e.d.log.Error("killing session tree failed", "session", d.SessionID, "err", err)
		return note(d, false, "kill failed: "+err.Error())
	}
	sid := d.SessionID
	d = note(d, true, "session process tree killed: "+why)
	if st, ok := e.d.manager.State(sid); ok {
		if ms, ok := st.(*session.MemoryState); ok {
			ms.MarkEnforced(&d)
		}
	}
	e.d.later(func() {
		e.d.failSessionAs(context.Background(), sid, session.StateTerminated, "terminated: "+why)
	})
	return d
}

func note(d decision.Decision, applied bool, what string) decision.Decision {
	d.Enforced = applied
	detail := "the triggering operation had already completed; containment acts on the session afterwards"
	if !applied {
		detail = "no containment applied"
	}
	d.Reasoning = append(d.Reasoning, decision.ReasoningStep{Stage: "enforce", Conclusion: what, Detail: detail})
	return d
}

// supervisor adapts session cgroups to session.Supervisor.
type supervisor struct{ d *Daemon }

var _ session.Supervisor = supervisor{}

var errLaunchByShim = errors.New("daemon: agents are launched by allseer-shim, not by the daemon")

func (supervisor) Launch(context.Context, string, session.Command) (int32, error) {
	return 0, errLaunchByShim
}

func (s supervisor) Suspend(ctx context.Context, sid string) error {
	g := s.d.groupOf(sid)
	if g == nil {
		return fmt.Errorf("daemon: session %s has no cgroup", sid)
	}
	return g.Freeze(ctx)
}

func (s supervisor) Resume(ctx context.Context, sid string) error {
	g := s.d.groupOf(sid)
	if g == nil {
		return fmt.Errorf("daemon: session %s has no cgroup", sid)
	}
	return g.Thaw(ctx)
}

func (s supervisor) Terminate(ctx context.Context, sid string, _ time.Duration) error {
	g := s.d.groupOf(sid)
	if g == nil {
		return fmt.Errorf("daemon: session %s has no cgroup", sid)
	}
	return g.Kill(ctx)
}

func (supervisor) Wait(context.Context, string) (int, error) { return 0, errLaunchByShim }

func (d *Daemon) groupOf(sid string) SessionGroup {
	d.mu.Lock()
	defer d.mu.Unlock()
	if info := d.sessions[sid]; info != nil {
		return info.group
	}
	return nil
}

// later queues fn to run on the dispatch goroutine after the current step.
func (d *Daemon) later(fn func()) {
	select {
	case d.control <- fn:
	default:
		go func() { d.control <- fn }()
	}
}

func (d *Daemon) failSessionAs(ctx context.Context, sid string, result session.State, reason string) {
	s, err := d.manager.Get(ctx, sid)
	if err != nil || session.IsTerminal(s.State) {
		return
	}
	d.finish(ctx, sid, result, reason)
}
