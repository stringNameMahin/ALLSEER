package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/stringNameMahin/ALLSEER/internal/config"
	"github.com/stringNameMahin/ALLSEER/internal/envelope"
	"github.com/stringNameMahin/ALLSEER/internal/intent"
	"github.com/stringNameMahin/ALLSEER/internal/ipc"
	"github.com/stringNameMahin/ALLSEER/internal/session"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
)

var _ ipc.Handler = (*Daemon)(nil)

// Call implements ipc.Handler.
func (d *Daemon) Call(ctx context.Context, peer ipc.Peer, method string, params json.RawMessage) (any, error) {
	switch method {
	case ipc.MethodStatus:
		return d.status(), nil
	case ipc.MethodCreateSession:
		var req ipc.CreateSessionRequest
		if err := decode(params, &req); err != nil {
			return nil, err
		}
		if err := d.ungoverned(peer, method); err != nil {
			return nil, err
		}
		return d.createSession(ctx, peer, req)
	case ipc.MethodApproveEnvelope:
		var req ipc.ApproveEnvelopeRequest
		if err := decode(params, &req); err != nil {
			return nil, err
		}
		if err := d.ungoverned(peer, method); err != nil {
			return nil, err
		}
		return struct{}{}, d.approveEnvelope(ctx, peer, req)
	case ipc.MethodStartSession:
		var req ipc.StartSessionRequest
		if err := decode(params, &req); err != nil {
			return nil, err
		}
		if err := d.ungoverned(peer, method); err != nil {
			return nil, err
		}
		return struct{}{}, d.startSession(ctx, peer, req)
	case ipc.MethodEndSession:
		var req ipc.EndSessionRequest
		if err := decode(params, &req); err != nil {
			return nil, err
		}
		if err := d.ungoverned(peer, method); err != nil {
			return nil, err
		}
		return d.endSession(ctx, peer, req)
	case ipc.MethodGetSession:
		var req ipc.SessionRequest
		if err := decode(params, &req); err != nil {
			return nil, err
		}
		if err := d.authorize(peer, req.SessionID); err != nil {
			return nil, err
		}
		return d.manager.Get(ctx, req.SessionID)
	case ipc.MethodGetEnvelope:
		var req ipc.SessionRequest
		if err := decode(params, &req); err != nil {
			return nil, err
		}
		if err := d.authorize(peer, req.SessionID); err != nil {
			return nil, err
		}
		s, err := d.manager.Get(ctx, req.SessionID)
		if err != nil {
			return nil, ipc.Errorf(ipc.ErrCodeEnvelopeNotFound, "%v", err)
		}
		return s.Envelope, nil
	case ipc.MethodListSessions:
		var f session.Filter
		if len(params) > 0 {
			if err := decode(params, &f); err != nil {
				return nil, err
			}
		}
		all, err := d.manager.List(ctx, f)
		if err != nil {
			return nil, err
		}
		out := make([]*session.Session, 0, len(all))
		for _, s := range all {
			if d.authorize(peer, s.ID) == nil {
				out = append(out, s)
			}
		}
		return out, nil
	case ipc.MethodPendingApprovals:
		return d.approvals.list(func(sid string) bool { return d.authorize(peer, sid) == nil }), nil
	case ipc.MethodRespondApproval:
		var resp decision.ApprovalResponse
		if err := decode(params, &resp); err != nil {
			return nil, err
		}
		sid, ok := d.approvals.sessionOf(resp.RequestID)
		if !ok {
			return nil, ipc.Errorf(ipc.ErrCodeInvalidRequest, "no pending approval %q", resp.RequestID)
		}
		if err := d.ungoverned(peer, method); err != nil {
			return nil, err
		}
		if err := d.authorize(peer, sid); err != nil {
			return nil, err
		}
		resp.RespondedBy = d.host.UserName(peer.UID)
		resp.RespondedAt = d.now()
		resp.TimedOut = false
		d.approvals.resolve(ctx, resp)
		return struct{}{}, nil
	case ipc.MethodReloadPolicy:
		return nil, ipc.Errorf(ipc.ErrCodeInvalidRequest, "policy reload is not supported by this build; restart the daemon")
	case ipc.MethodListLeftovers:
		return d.listLeftovers(peer)
	case ipc.MethodThawLeftover, ipc.MethodKillLeftover:
		var req ipc.LeftoverRequest
		if err := decode(params, &req); err != nil {
			return nil, err
		}
		if method == ipc.MethodThawLeftover {
			return struct{}{}, d.thawLeftover(ctx, peer, req.Name)
		}
		return struct{}{}, d.killLeftover(ctx, peer, req.Name)
	}
	return nil, ipc.Errorf(ipc.ErrCodeInvalidRequest, "unknown method %q", method)
}

// Stream implements ipc.Handler.
func (d *Daemon) Stream(ctx context.Context, peer ipc.Peer, method string, params json.RawMessage, send func(any) error) error {
	switch method {
	case ipc.MethodStreamDecisions:
		var req ipc.SessionRequest
		if len(params) > 0 {
			if err := decode(params, &req); err != nil {
				return err
			}
		}
		if req.SessionID != "" {
			if err := d.authorize(peer, req.SessionID); err != nil {
				return err
			}
		}
		id, ch := d.hub.subscribe(func(dec decision.Decision) bool {
			if req.SessionID != "" {
				return dec.SessionID == req.SessionID
			}
			return d.authorize(peer, dec.SessionID) == nil
		})
		defer d.hub.unsubscribe(id)
		for {
			select {
			case <-ctx.Done():
				return nil
			case dec, ok := <-ch:
				if !ok {
					return nil
				}
				if err := send(dec); err != nil {
					return nil
				}
			}
		}
	case ipc.MethodStreamApprovals:
		id, ch := d.approvals.subscribe()
		defer d.approvals.unsubscribe(id)
		for _, req := range d.approvals.list(func(sid string) bool { return d.authorize(peer, sid) == nil }) {
			if err := send(req); err != nil {
				return nil
			}
		}
		for {
			select {
			case <-ctx.Done():
				return nil
			case req := <-ch:
				if d.authorize(peer, req.SessionID) != nil {
					continue
				}
				if err := send(req); err != nil {
					return nil
				}
			}
		}
	}
	return ipc.Errorf(ipc.ErrCodeInvalidRequest, "unknown stream %q", method)
}

func decode(params json.RawMessage, v any) error {
	if len(params) == 0 {
		return ipc.Errorf(ipc.ErrCodeInvalidRequest, "missing params")
	}
	if err := json.Unmarshal(params, v); err != nil {
		return ipc.Errorf(ipc.ErrCodeInvalidRequest, "malformed params: %v", err)
	}
	return nil
}

// ungoverned refuses a state-changing call made from inside a session cgroup.
//
// The daemon acts for the human who launched an agent, not for the agent. The
// owner's UID is also the agent's UID, so UID alone cannot tell them apart: a
// governed process that could create, approve, start or end sessions would be
// able to hand its own descendants an envelope its owner never approved, or
// answer its own approval request.
//
// Root is exempt. A kernel-privileged caller is out of the threat model, and
// the operator's own root tooling must keep working.
//
// A caller the daemon cannot place is refused as well. Treating an unreadable
// peer as ungoverned would make the check optional for anyone who can race it.
func (d *Daemon) ungoverned(peer ipc.Peer, method string) error {
	if peer.Root() {
		return nil
	}
	sid, governed, err := d.groups.Governed(peer.PID)
	if err != nil {
		d.refuse(method, peer, "", "the caller could not be located: "+err.Error())
		return ipc.Errorf(ipc.ErrCodePermissionDenied,
			"refusing %s: the calling process could not be located (%v)", method, err)
	}
	if governed {
		d.refuse(method, peer, sid, "the caller is inside a governed session")
		return ipc.Errorf(ipc.ErrCodePermissionDenied,
			"refusing %s: a governed process cannot govern", method)
	}
	return nil
}

// refusalCount returns how many control requests have been refused.
func (d *Daemon) refusalCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.refusals
}

// auditErrors returns how many audit writes have failed.
func (d *Daemon) auditErrors() uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.sinkErrors
}

// refuse records a rejected control request. sid is the session holding the
// process the refusal was about, when known.
func (d *Daemon) refuse(method string, peer ipc.Peer, sid, why string) {
	d.mu.Lock()
	d.refusals++
	d.mu.Unlock()
	d.log.Warn("control request refused", "method", method, "pid", peer.PID, "uid", peer.UID,
		"session", sid, "reason", why)
	d.record(context.Background(), decision.ControlRefused{
		Timestamp: d.now().UTC(), Method: method, PID: peer.PID, UID: peer.UID, SessionID: sid, Reason: why,
	})
}

// authorize allows a session's owner and root.
func (d *Daemon) authorize(peer ipc.Peer, sid string) error {
	d.mu.Lock()
	info := d.sessions[sid]
	d.mu.Unlock()
	if info == nil {
		return ipc.Errorf(ipc.ErrCodeSessionNotFound, "no session %q", sid)
	}
	if peer.Root() || peer.UID == info.owner.UID {
		return nil
	}
	return ipc.Errorf(ipc.ErrCodePermissionDenied, "session %q belongs to another user", sid)
}

func (d *Daemon) activeCount() int {
	n := 0
	list, _ := d.manager.List(context.Background(), session.Filter{})
	for _, s := range list {
		if !session.IsTerminal(s.State) {
			n++
		}
	}
	return n
}

func (d *Daemon) createSession(ctx context.Context, peer ipc.Peer, req ipc.CreateSessionRequest) (*ipc.CreateSessionResponse, error) {
	// Nothing is governed on telemetry that has not been shown to report. A
	// session started now would read as governed while the probe it depends on
	// most could be silent.
	if st, ok := d.selfTestPassed(); !ok {
		return nil, ipc.Errorf(ipc.ErrCodeTelemetryFailed,
			"refusing to govern: the telemetry self-test has not passed (%s)", st.Detail)
	}
	if req.Prompt == "" {
		return nil, ipc.Errorf(ipc.ErrCodeInvalidRequest, "a prompt is required: the envelope is derived from it")
	}
	ws := filepath.Clean(req.WorkspaceRoot)
	if !filepath.IsAbs(ws) {
		return nil, ipc.Errorf(ipc.ErrCodeInvalidRequest, "workspace_root must be absolute, got %q", req.WorkspaceRoot)
	}
	if real, err := filepath.EvalSymlinks(ws); err == nil {
		ws = real
	}
	if fi, err := os.Stat(ws); err != nil || !fi.IsDir() {
		return nil, ipc.Errorf(ipc.ErrCodeInvalidRequest, "workspace_root %q is not a directory", ws)
	}
	if req.Mode != "" && !config.ValidMode(req.Mode) {
		return nil, ipc.Errorf(ipc.ErrCodeInvalidRequest, "unknown mode %q", req.Mode)
	}
	if d.activeCount() >= d.cfg.Daemon.MaxConcurrentSessions {
		return nil, ipc.Errorf(ipc.ErrCodeInvalidRequest, "the daemon is at its limit of %d live sessions", d.cfg.Daemon.MaxConcurrentSessions)
	}

	// The analyzer reads the sanitized prompt. Any indicator is carried as an
	// ambiguity so the person approving the envelope sees it.
	prompt, indicators := req.Prompt, []string(nil)
	if d.sanitizer != nil {
		clean, found, err := d.sanitizer.Sanitize(ctx, req.Prompt)
		if err != nil {
			return nil, ipc.Errorf(ipc.ErrCodeAnalysisFailed, "sanitizing the prompt: %v", err)
		}
		prompt, indicators = clean, found
	}
	an, err := d.analyzer.Analyze(ctx, intent.Request{
		Prompt: prompt, WorkspaceRoot: ws, WorkspaceContext: req.Workspace, AgentIdentity: req.AgentIdentity,
	})
	if err != nil {
		return nil, ipc.Errorf(ipc.ErrCodeAnalysisFailed, "%v", err)
	}
	// The prompt is kept only when the operator asked for it. Nothing after
	// generation reads it: the grants, not the text, govern the session.
	an.Record.RawPrompt = ""
	if d.cfg.Intent.RetainPrompt {
		an.Record.RawPrompt = req.Prompt
	}
	for _, i := range indicators {
		an.Record.Ambiguities = append(an.Record.Ambiguities, "possible prompt injection: "+i)
	}
	if len(indicators) > 0 {
		d.log.Warn("possible prompt injection", "owner", peer.UID, "indicators", indicators)
	}
	sid := envelope.NewSessionID(d.now())
	res, err := d.generator.Generate(ctx, an, d.observableCatalog(), envelope.Params{
		SessionID: sid, WorkspaceRoot: ws, Home: d.host.Home(peer.UID), Resolvers: d.resolvers,
		TTL: d.cfg.Envelope.DefaultTTL, Now: d.now().UTC(),
	})
	if err != nil {
		return nil, ipc.Errorf(ipc.ErrCodeAnalysisFailed, "generating the envelope: %v", err)
	}
	if err := d.sealer.Seal(res.Envelope); err != nil {
		return nil, err
	}

	mode := config.Restrict(d.cfg.Policy.DefaultMode, req.Mode)
	if _, err := d.manager.Create(ctx, session.CreateRequest{
		Envelope: res.Envelope, Prompt: an.Record.RawPrompt, WorkspaceRoot: ws, Mode: mode, AgentIdentity: req.AgentIdentity,
	}); err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.sessions[sid] = &sessionInfo{owner: peer}
	d.mu.Unlock()
	if err := d.manager.Seal(ctx, sid); err != nil {
		return nil, err
	}
	s, _ := d.manager.Get(ctx, sid)

	warnings := res.Warnings
	if req.Mode != "" && mode != req.Mode {
		warnings = append(warnings, fmt.Sprintf("requested mode %s is weaker than the configured %s; running in %s", req.Mode, mode, mode))
	}
	if cov := d.tel.Coverage(); cov.Degraded {
		warnings = append(warnings, fmt.Sprintf("telemetry is degraded on this host; unobservable: %v", cov.Unobservable))
		// A kind can stay observable and still lose entry points: with the
		// kernel-side open hook missing, an open through io_uring or openat2
		// produces no record while fs.read still reads as observable. Naming
		// the entry points is what keeps that from passing as full coverage.
		for _, g := range cov.DegradedEntryPoints() {
			if len(g.Missing) > 0 {
				warnings = append(warnings, fmt.Sprintf(
					"%s is not observed through %s on this host; those operations produce no records",
					g.Kind, strings.Join(g.Missing, ", ")))
			}
			if len(g.SuccessOnly) > 0 {
				warnings = append(warnings, fmt.Sprintf(
					"%s through %s is observed only when the kernel permits it on this host; refused attempts produce no records",
					g.Kind, strings.Join(g.SuccessOnly, ", ")))
			}
		}
	}
	d.log.Info("session created", "session", sid, "owner", peer.UID, "task", an.Record.TaskType, "mode", mode)
	return &ipc.CreateSessionResponse{
		SessionID:        sid,
		Envelope:         s.Envelope,
		RequiresApproval: s.State == session.StateAwaitingApproval,
		Warnings:         warnings,
	}, nil
}

func (d *Daemon) approveEnvelope(ctx context.Context, peer ipc.Peer, req ipc.ApproveEnvelopeRequest) error {
	if err := d.authorize(peer, req.SessionID); err != nil {
		return err
	}
	if !req.Approved {
		reason := "envelope rejected by " + d.host.UserName(peer.UID)
		if req.Reason != "" {
			reason += ": " + req.Reason
		}
		return d.onLoop(ctx, func() { d.failSessionAs(ctx, req.SessionID, session.StateTerminated, reason) })
	}
	return d.manager.Approve(ctx, req.SessionID, ece.ApprovalRecord{
		ApprovedBy: d.host.UserName(peer.UID), ApprovedAt: d.now().UTC(), Method: "allseer-shim", Modifications: req.Modifications,
	})
}

// startSession binds the shim's held child to the session. The child has not
// run any agent code yet: it waits on a pipe until this returns, so the agent's
// first instruction executes inside an observed cgroup.
func (d *Daemon) startSession(ctx context.Context, peer ipc.Peer, req ipc.StartSessionRequest) error {
	if err := d.authorize(peer, req.SessionID); err != nil {
		return err
	}
	s, err := d.manager.Get(ctx, req.SessionID)
	if err != nil {
		return err
	}
	if s.State != session.StateReady {
		if s.State == session.StateAwaitingApproval {
			return ipc.Errorf(ipc.ErrCodeNotApproved, "session %q is awaiting approval", req.SessionID)
		}
		return ipc.Errorf(ipc.ErrCodeAlreadyStarted, "session %q is %s", req.SessionID, s.State)
	}
	if err := d.sealer.Verify(s.Envelope); err != nil {
		return ipc.Errorf(ipc.ErrCodePermissionDenied, "refusing to enforce: %v", err)
	}
	ppid, uid, err := d.host.Process(req.RootPID)
	if err != nil {
		return ipc.Errorf(ipc.ErrCodeInvalidRequest, "root pid %d: %v", req.RootPID, err)
	}
	if ppid != peer.PID {
		return ipc.Errorf(ipc.ErrCodePermissionDenied, "pid %d is not a child of the caller", req.RootPID)
	}
	if !peer.Root() && uid != peer.UID {
		return ipc.Errorf(ipc.ErrCodePermissionDenied, "pid %d belongs to another user", req.RootPID)
	}
	// A process already inside a session cgroup must not be moved into a
	// second one. Adopting it would take it out of the scope its owner
	// approved, and out of reach of that session's containment.
	if holder, governed, err := d.groups.Governed(req.RootPID); err != nil {
		d.refuse(ipc.MethodStartSession, peer, "", fmt.Sprintf("root pid %d could not be located: %v", req.RootPID, err))
		return ipc.Errorf(ipc.ErrCodePermissionDenied,
			"refusing to adopt pid %d: it could not be located (%v)", req.RootPID, err)
	} else if governed {
		d.refuse(ipc.MethodStartSession, peer, holder, fmt.Sprintf("root pid %d is already governed", req.RootPID))
		return ipc.Errorf(ipc.ErrCodePermissionDenied,
			"refusing to adopt pid %d: it is already governed by another session", req.RootPID)
	}

	g, err := d.groups.Create(req.SessionID)
	if err != nil {
		return ipc.Errorf(ipc.ErrCodeTelemetryFailed, "creating the session cgroup: %v", err)
	}
	fail := func(stage string, err error) error {
		_ = d.tel.DetachSession(ctx, req.SessionID)
		_ = g.Kill(ctx)
		_ = g.Remove()
		_ = d.onLoop(ctx, func() {
			d.failSessionAs(ctx, req.SessionID, session.StateFailed, stage+": "+err.Error())
		})
		return ipc.Errorf(ipc.ErrCodeTelemetryFailed, "%s: %v", stage, err)
	}
	if err := g.Adopt(int(req.RootPID)); err != nil {
		return fail("moving the agent into its cgroup", err)
	}
	d.mu.Lock()
	d.sessions[req.SessionID].group = g
	d.mu.Unlock()
	if err := d.tel.AttachCgroup(ctx, req.SessionID, g.CgroupID(), req.RootPID); err != nil {
		return fail("attaching telemetry", err)
	}
	if err := d.manager.Start(ctx, req.SessionID, req.RootPID); err != nil {
		return fail("starting the session", err)
	}
	// Written before the agent is released, so it precedes every decision
	// the session produces.
	if s, err := d.manager.Get(ctx, req.SessionID); err == nil {
		d.mu.Lock()
		owner := d.sessions[req.SessionID].owner.UID
		d.mu.Unlock()
		d.record(ctx, d.sessionStart(s, owner, g.CgroupID()))
	}
	d.log.Info("session started", "session", req.SessionID, "root_pid", req.RootPID, "cgroup", g.CgroupID())
	return nil
}

func (d *Daemon) endSession(ctx context.Context, peer ipc.Peer, req ipc.EndSessionRequest) (*session.Session, error) {
	if err := d.authorize(peer, req.SessionID); err != nil {
		return nil, err
	}
	s, err := d.manager.Get(ctx, req.SessionID)
	if err != nil {
		return nil, err
	}
	if !session.IsTerminal(s.State) {
		d.mu.Lock()
		if info := d.sessions[req.SessionID]; info != nil {
			info.ending = true
		}
		d.mu.Unlock()
		// Let events already in the ring reach the pipeline first.
		select {
		case <-time.After(d.settle):
		case <-ctx.Done():
		}
		reason := fmt.Sprintf("agent exited with code %d", req.ExitCode)
		if err := d.onLoop(ctx, func() {
			d.failSessionAs(ctx, req.SessionID, session.StateCompleted, reason)
		}); err != nil {
			return nil, err
		}
	}
	return d.manager.Get(ctx, req.SessionID)
}

func (d *Daemon) status() *ipc.StatusResponse {
	cov := d.tel.Coverage()
	cs := d.tel.CollectorStats()
	attached := 0
	for _, p := range cov.Probes {
		if p.Attached {
			attached++
		}
	}
	selfTest, passed := d.selfTestPassed()
	return &ipc.StatusResponse{
		SelfTest:          selfTest,
		Version:           d.version,
		ProtocolVersion:   ipc.ProtocolVersion,
		Uptime:            d.now().Sub(d.started).Seconds(),
		ActiveSessions:    d.activeCount(),
		Mode:              d.cfg.Policy.DefaultMode,
		TelemetryHealthy:  cov.FloorIntact && passed,
		ProbesAttached:    attached,
		EnforcerMechanism: MechanismCgroup,
		DroppedEvents:     cs.DroppedEvents,
		Coverage:          cov,
		Collector:         cs,
		RefusedRequests:   d.refusalCount(),
		AuditErrors:       d.auditErrors(),
		Leftovers:         d.leftoverCount(),
		Dispatch:          d.dispatch.Stats(),
		Containment:       d.groups.Capabilities(),
		Enforcer:          d.enforcer.Capabilities(),
	}
}

// IsNotFound reports whether err is a session-not-found protocol error.
func IsNotFound(err error) bool {
	var e *ipc.Error
	return errors.As(err, &e) && e.Code == ipc.ErrCodeSessionNotFound
}
