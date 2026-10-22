// Package daemon composes the governance runtime: live telemetry, per-session
// pipelines, the audit trail, session cgroups, and the control socket.
//
// One goroutine owns every session's tracking state. Events are dispatched on
// it, and any lifecycle step that reads that state (ending a session) is run on
// it too, through the control channel, so the single-writer rule MemoryState
// relies on holds without a lock.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/stringNameMahin/ALLSEER/internal/config"
	"github.com/stringNameMahin/ALLSEER/internal/containment"
	"github.com/stringNameMahin/ALLSEER/internal/envelope"
	"github.com/stringNameMahin/ALLSEER/internal/intent"
	"github.com/stringNameMahin/ALLSEER/internal/ipc"
	"github.com/stringNameMahin/ALLSEER/internal/pipeline"
	"github.com/stringNameMahin/ALLSEER/internal/session"
	"github.com/stringNameMahin/ALLSEER/internal/telemetry"
	"github.com/stringNameMahin/ALLSEER/internal/validator"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// ErrTelemetryLost means the event stream ended while the daemon was running.
var ErrTelemetryLost = errors.New("daemon: the telemetry stream ended; governance cannot continue")

// Telemetry is the live event source plus session attachment.
type Telemetry interface {
	event.Source
	AttachCgroup(ctx context.Context, sessionID string, cgroupID uint64, rootPID int32) error
	DetachSession(ctx context.Context, sessionID string) error
	Coverage() telemetry.Coverage
	CollectorStats() telemetry.CollectorStats
}

// SessionGroup is one session's cgroup.
type SessionGroup interface {
	CgroupID() uint64
	Adopt(pid int) error
	Freeze(ctx context.Context) error
	Thaw(ctx context.Context) error
	Kill(ctx context.Context) error
	Populated() (bool, error)
	Remove() error
}

// Groups creates session cgroups.
type Groups interface {
	Create(sessionID string) (SessionGroup, error)
	Capabilities() containment.Capabilities
	// Governed reports whether pid is inside a session cgroup this daemon
	// owns, and which session holds it when that is known.
	Governed(pid int32) (sid string, governed bool, err error)
	// Leftover opens a session cgroup an earlier daemon left behind.
	Leftover(name string) (LeftoverGroup, error)
}

// AuditTrail is the durable record: every decision, and the session-level
// records that frame them, in one stream.
type AuditTrail interface {
	decision.Sink
	decision.RecordSink
}

// Host answers questions about local processes and users.
type Host interface {
	// Process returns the parent PID and real UID of pid.
	Process(pid int32) (ppid int32, uid uint32, err error)
	// Home returns a user's home directory, or "" when unknown.
	Home(uid uint32) string
	// UserName returns a user's login name.
	UserName(uid uint32) string
}

// Options assembles a daemon.
type Options struct {
	Config    *config.Config
	Telemetry Telemetry
	Groups    Groups
	Host      Host
	Policy    pipeline.PolicyEngine
	Risk      pipeline.RiskEngine
	// Audit receives every decision and session record. Required: a daemon
	// does not govern without an audit trail.
	Audit AuditTrail
	// Resolvers are the DNS servers granted to sessions that need the network.
	Resolvers []string
	Logger    *slog.Logger
	Now       func() time.Time
	// EndSettle is how long EndSession waits for in-flight events.
	EndSettle time.Duration
	// OrphanGrace is how long an emptied session waits for its shim.
	OrphanGrace time.Duration
	Version     string

	// Prober starts the process the startup self-test opens a file from. Nil
	// makes SelfTest fail, and sessions are refused until it passes.
	Prober Prober

	// SelfTestTimeout bounds the self-test's wait for its record. Zero uses
	// DefaultSelfTestTimeout.
	SelfTestTimeout time.Duration

	// Leftovers is what the startup sweep found: the session cgroups an
	// earlier daemon left with processes in them, and which it froze.
	Leftovers containment.SweepResult

	// KeepEnded is how many ended sessions stay queryable. Zero means
	// session.DefaultKeepEnded.
	KeepEnded int
}

type sessionInfo struct {
	owner      ipc.Peer
	group      SessionGroup
	emptySince time.Time
	ending     bool
}

// Daemon is the governance runtime.
type Daemon struct {
	cfg       *config.Config
	tel       Telemetry
	groups    Groups
	host      Host
	audit     AuditTrail
	log       *slog.Logger
	now       func() time.Time
	settle    time.Duration
	orphan    time.Duration
	version   string
	resolvers []string

	analyzer  intent.Analyzer
	sanitizer intent.Sanitizer
	generator envelope.RuleGenerator
	sealer    envelope.DigestSealer
	manager   *session.MemoryManager
	dispatch  *session.Dispatcher
	hub       *hub
	enforcer  *Enforcer
	approvals *approvals

	control chan func()
	started time.Time

	// refusals counts control requests rejected because the caller was itself
	// governed, or could not be located.
	refusals int

	prober          Prober
	selfTestTimeout time.Duration

	mu       sync.Mutex
	sessions map[string]*sessionInfo

	// leftovers names the session cgroups an earlier daemon left behind that
	// still exist. Guarded by mu.
	leftovers map[string]bool

	sinkErrors uint64

	// selfTestResult is the startup self-test's outcome. Sessions are refused
	// until it records a pass. Guarded by mu.
	selfTestResult ipc.SelfTestResult
}

// New validates options and builds a daemon. Telemetry must already be
// started: a daemon is never constructed around probes that did not attach.
func New(o Options) (*Daemon, error) {
	switch {
	case o.Config == nil:
		return nil, errors.New("daemon: config is required")
	case o.Telemetry == nil:
		return nil, errors.New("daemon: telemetry is required")
	case o.Groups == nil:
		return nil, errors.New("daemon: session cgroups are required")
	case o.Host == nil:
		return nil, errors.New("daemon: host access is required")
	case o.Policy == nil || o.Risk == nil:
		return nil, errors.New("daemon: policy and risk engines are required")
	case o.Audit == nil:
		return nil, errors.New("daemon: an audit sink is required")
	}
	if !o.Telemetry.Coverage().FloorIntact {
		return nil, telemetry.ErrTelemetryFloor
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	logger := o.Logger
	if logger == nil {
		logger = slog.Default()
	}
	settle := o.EndSettle
	if settle <= 0 {
		settle = 300 * time.Millisecond
	}
	orphan := o.OrphanGrace
	if orphan <= 0 {
		orphan = 5 * time.Second
	}
	selfTestTimeout := o.SelfTestTimeout
	if selfTestTimeout <= 0 {
		selfTestTimeout = DefaultSelfTestTimeout
	}

	d := &Daemon{
		cfg:       o.Config,
		tel:       o.Telemetry,
		groups:    o.Groups,
		host:      o.Host,
		audit:     o.Audit,
		log:       logger,
		now:       now,
		settle:    settle,
		orphan:    orphan,
		version:   o.Version,
		resolvers: o.Resolvers,

		prober:          o.Prober,
		selfTestTimeout: selfTestTimeout,
		selfTestResult: ipc.SelfTestResult{
			Probe:  SelfTestProbe,
			Detail: "the startup self-test has not run",
		},
		analyzer:  intent.NewRuleAnalyzer(),
		generator: envelope.RuleGenerator{Limits: envelope.Limits{MaxGrants: o.Config.Envelope.MaxGrants}},
		hub:       newHub(),
		control:   make(chan func(), 64),
		started:   now(),
		sessions:  make(map[string]*sessionInfo),
		leftovers: make(map[string]bool),
	}
	d.manager = session.NewManager(session.ManagerConfig{
		RequireApproval: o.Config.Envelope.RequireApproval,
		DefaultMode:     o.Config.Policy.DefaultMode,
		Supervisor:      supervisor{d: d},
		Now:             now,
		KeepEnded:       o.KeepEnded,
		OnEvict:         d.forget,
	})
	d.enforcer = newEnforcer(d)
	d.approvals = newApprovals(d)
	if o.Config.Intent.EnableSanitizer {
		d.sanitizer = intent.RuleSanitizer{}
	}

	disp, err := session.NewDispatcher(session.DispatchConfig{
		Registry: d.manager,
		Factory: func(b session.Binding) (session.EventProcessor, error) {
			return pipeline.NewWithRisk(pipeline.Config{
				Session: pipeline.Session{ID: b.SessionID, Envelope: b.Envelope, Mode: b.Mode, State: b.State},
				Now:     now,
			}, validator.NewValidator(), o.Risk, o.Policy)
		},
		Sink: sinkFunc(d.emit),
	})
	if err != nil {
		return nil, err
	}
	d.dispatch = disp
	d.noteLeftovers(o.Leftovers)
	return d, nil
}

// Manager exposes the session manager for inspection.
func (d *Daemon) Manager() *session.MemoryManager { return d.manager }

type sinkFunc func(context.Context, decision.Decision) error

func (f sinkFunc) Emit(ctx context.Context, dec decision.Decision) error { return f(ctx, dec) }
func (f sinkFunc) Flush(context.Context) error                           { return nil }

// emit records a decision, acts on it, and publishes it. Runs on the dispatch
// goroutine.
func (d *Daemon) emit(ctx context.Context, dec decision.Decision) error {
	dec = d.enforcer.react(ctx, dec)
	err := d.audit.Emit(ctx, dec)
	if err != nil {
		d.mu.Lock()
		d.sinkErrors++
		d.mu.Unlock()
		d.log.Error("audit write failed", "session", dec.SessionID, "decision", dec.ID, "err", err)
	}
	d.hub.publish(dec)
	return err
}

// record writes a session-level record. A failed write is counted and logged
// like a failed decision write; it does not stop governance.
func (d *Daemon) record(ctx context.Context, r decision.Record) {
	if err := d.audit.EmitRecord(ctx, r); err != nil {
		d.mu.Lock()
		d.sinkErrors++
		d.mu.Unlock()
		d.log.Error("audit write failed", "record", r.RecordKind(), "err", err)
	}
}

// Run dispatches events until ctx ends or the telemetry stream ends. The
// second is a failure: every active session is ended as failed and its
// process tree killed, because it can no longer be observed.
func (d *Daemon) Run(ctx context.Context) error {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	events := d.tel.Events()
	for {
		select {
		case <-ctx.Done():
			return nil
		case fn := <-d.control:
			fn()
		case <-tick.C:
			d.reapOrphans(ctx)
		case e, ok := <-events:
			if !ok {
				d.failAll(context.Background(), "telemetry stream ended")
				return ErrTelemetryLost
			}
			d.handleEvent(ctx, &e)
		}
	}
}

func (d *Daemon) handleEvent(ctx context.Context, e *event.Event) {
	if e.Dropped > 0 && d.cfg.Telemetry.FailClosedOnDrop {
		d.log.Warn("telemetry gap in session", "session", e.SessionID, "dropped", e.Dropped)
	}
	_, _ = d.dispatch.Dispatch(ctx, e)
	if e.Dropped > 0 && d.cfg.Telemetry.FailClosedOnDrop && e.SessionID != "" {
		d.failSession(ctx, e.SessionID, fmt.Sprintf("telemetry lost %d records and fail_closed_on_drop is set", e.Dropped))
	}
}

// onLoop runs fn on the dispatch goroutine and waits for it.
func (d *Daemon) onLoop(ctx context.Context, fn func()) error {
	done := make(chan struct{})
	select {
	case d.control <- func() { fn(); close(done) }:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// finish ends a session: detaches telemetry, kills whatever is left of its
// tree, removes its cgroup, and records the outcome. Must run on the loop.
func (d *Daemon) finish(ctx context.Context, sid string, result session.State, reason string) {
	d.mu.Lock()
	info := d.sessions[sid]
	d.mu.Unlock()

	_ = d.tel.DetachSession(ctx, sid)
	if info != nil && info.group != nil {
		if err := info.group.Kill(ctx); err != nil {
			d.log.Error("killing session tree", "session", sid, "err", err)
		}
		if err := info.group.Remove(); err != nil {
			d.log.Warn("removing session cgroup", "session", sid, "err", err)
		}
	}
	d.approvals.cancelSession(sid)

	out := session.Outcome{Result: result, Reason: reason}
	if st, ok := d.manager.State(sid); ok {
		if ms, ok := st.(*session.MemoryState); ok {
			out = ms.Outcome(reason)
			out.Result = result
			if !out.TelemetryComplete && result == session.StateCompleted {
				out.Reason += "; telemetry was incomplete"
			}
		}
	}
	if err := d.manager.End(ctx, sid, out); err != nil {
		d.log.Warn("ending session", "session", sid, "err", err)
	}
	d.record(ctx, d.sessionEnd(ctx, sid, out))
	d.dispatch.Release(sid)
	d.log.Info("session ended", "session", sid, "result", result, "reason", reason)
}

// forget drops what the daemon kept for a session the manager evicted.
func (d *Daemon) forget(sid string) {
	d.mu.Lock()
	delete(d.sessions, sid)
	d.mu.Unlock()
}

func (d *Daemon) failSession(ctx context.Context, sid, reason string) {
	s, err := d.manager.Get(ctx, sid)
	if err != nil || session.IsTerminal(s.State) {
		return
	}
	d.finish(ctx, sid, session.StateFailed, reason)
}

func (d *Daemon) failAll(ctx context.Context, reason string) {
	list, _ := d.manager.List(ctx, session.Filter{})
	for _, s := range list {
		if !session.IsTerminal(s.State) {
			d.finish(ctx, s.ID, session.StateFailed, reason)
		}
	}
}

// Shutdown ends every live session as failed and kills its tree. An agent is
// never left running ungoverned or frozen when the daemon goes away.
func (d *Daemon) Shutdown(ctx context.Context) {
	d.failAll(ctx, "daemon shut down")
	_ = d.audit.Flush(ctx)
	d.hub.closeAll()
}

// reapOrphans ends active sessions whose process tree has been empty for
// longer than the shim's grace, for a shim that died without ending them.
func (d *Daemon) reapOrphans(ctx context.Context) {
	now := d.now()
	d.mu.Lock()
	var due []string
	for sid, info := range d.sessions {
		if info.group == nil || info.ending {
			continue
		}
		pop, err := info.group.Populated()
		if err != nil || pop {
			info.emptySince = time.Time{}
			continue
		}
		if info.emptySince.IsZero() {
			info.emptySince = now
			continue
		}
		if now.Sub(info.emptySince) >= d.orphan {
			info.ending = true
			due = append(due, sid)
		}
	}
	d.mu.Unlock()
	for _, sid := range due {
		if s, err := d.manager.Get(ctx, sid); err == nil && !session.IsTerminal(s.State) {
			d.finish(ctx, sid, session.StateCompleted, "process tree exited and no shim ended the session")
		}
	}
}

// observableCatalog is the catalog an envelope is generated against: the
// kinds the attached probes actually observe.
func (d *Daemon) observableCatalog() capability.Catalog {
	return capability.NewCatalog(d.tel.Coverage().Observable...)
}
