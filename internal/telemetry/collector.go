package telemetry

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/stringNameMahin/ALLSEER/internal/telemetry/resolve"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// Collector errors.
var (
	// ErrTelemetryFloor means proc_exec or proc_exit did not attach. Without
	// them nothing can be attributed, so the collector refuses to start rather
	// than report a quiet session.
	ErrTelemetryFloor = errors.New("telemetry: core probes (proc_exec, proc_exit) are not attached; refusing to govern")

	// ErrNotStarted means a session operation was called before Start.
	ErrNotStarted = errors.New("telemetry: collector is not started")

	// ErrSessionAttached means the session or its cgroup is already attached.
	ErrSessionAttached = errors.New("telemetry: session or cgroup is already attached")

	// ErrSessionUnknown means the session is not attached.
	ErrSessionUnknown = errors.New("telemetry: session is not attached")
)

const (
	defaultEventChannelSize = 4096
	defaultDropPoll         = 250 * time.Millisecond
	detachGrace             = 2 * time.Second
)

// CollectorOptions are the parts of a collector that are not configuration.
type CollectorOptions struct {
	// Loader drives the BPF object. Required.
	Loader Loader
	// Decoder turns records into events. Nil uses this build's decoder.
	Decoder Decoder
	// Enrichers run in order on every attributed event. Nil installs the path
	// and exec enrichers.
	Enrichers []Enricher
	// Tracker records process ancestry. Nil creates one.
	Tracker *ProcTracker
	// SkipLoad means the loader already holds a loaded object.
	SkipLoad bool
	// DropPoll is how often the kernel drop counter is read.
	DropPoll time.Duration
	// Now is the clock for uptime. Nil means time.Now.
	Now func() time.Time
}

// CollectorStats is SourceStats plus the losses specific to a live collector.
type CollectorStats struct {
	event.SourceStats
	// KernelDrops are records the probes could not reserve ring space for.
	KernelDrops uint64 `json:"kernel_drops"`
	// Overflow are decoded events dropped because the consumer was behind.
	Overflow uint64 `json:"overflow"`
	// Unattributed are records from a cgroup no session holds.
	Unattributed uint64 `json:"unattributed"`
	// EnrichErrors counts enricher failures. Those events are still delivered,
	// unresolved, so they reach validation as indeterminate.
	EnrichErrors uint64 `json:"enrich_errors"`
	// Sessions is the number of attached sessions.
	Sessions int `json:"sessions"`
}

type collSession struct {
	id       string
	cgroupID uint64
	seq      uint64
	pending  uint64 // records lost since the last delivered event
	detached bool
}

// LiveCollector implements Collector over a Loader.
//
// One goroutine drains the ring buffer, decodes, attributes by cgroup,
// tracks ancestry, enriches, resolves the observation, and delivers. It never
// blocks on the consumer: a full output channel drops the event and charges
// the loss to its session, and the next delivered event of that session
// carries the count in Event.Dropped.
type LiveCollector struct {
	cfg       Config
	loader    Loader
	decoder   Decoder
	enrichers []Enricher
	tracker   *ProcTracker
	skipLoad  bool
	dropPoll  time.Duration
	now       func() time.Time

	out chan event.Event

	mu        sync.Mutex
	sessions  map[string]*collSession
	byCgroup  map[uint64]*collSession
	probes    []ProbeInfo
	started   bool
	closed    bool
	startedAt time.Time
	cancel    context.CancelFunc
	done      chan struct{}
	closeOnce sync.Once

	received     atomic.Uint64
	decodeErrs   atomic.Uint64
	kernelDrops  atomic.Uint64
	overflow     atomic.Uint64
	unattributed atomic.Uint64
	enrichErrs   atomic.Uint64
}

var _ Collector = (*LiveCollector)(nil)

// NewLiveCollector returns a collector over opts.Loader.
func NewLiveCollector(cfg Config, opts CollectorOptions) (*LiveCollector, error) {
	if opts.Loader == nil {
		return nil, errors.New("telemetry: a loader is required")
	}
	dec := opts.Decoder
	if dec == nil {
		dec = NewDecoder()
	}
	enr := opts.Enrichers
	if enr == nil {
		paths := &PathEnricher{}
		enr = []Enricher{paths, &ExecEnricher{Paths: paths}}
	}
	tr := opts.Tracker
	if tr == nil {
		tr = NewProcTracker()
	}
	size := cfg.EventChannelSize
	if size <= 0 {
		size = defaultEventChannelSize
	}
	poll := opts.DropPoll
	if poll <= 0 {
		poll = defaultDropPoll
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &LiveCollector{
		cfg:       cfg,
		loader:    opts.Loader,
		decoder:   dec,
		enrichers: enr,
		tracker:   tr,
		skipLoad:  opts.SkipLoad,
		dropPoll:  poll,
		now:       now,
		out:       make(chan event.Event, size),
		sessions:  make(map[string]*collSession),
		byCgroup:  make(map[uint64]*collSession),
		done:      make(chan struct{}),
	}, nil
}

// Events returns the stream. It closes after Close.
func (c *LiveCollector) Events() <-chan event.Event { return c.out }

// Tracker exposes the process tracker.
func (c *LiveCollector) Tracker() *ProcTracker { return c.tracker }

// Start loads the object, attaches probes, enforces the attribution floor, and
// begins draining the ring buffer.
func (c *LiveCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.closed:
		return ErrClosed
	case c.started:
		return nil
	}

	if !c.skipLoad {
		if err := c.loader.Load(ctx, c.cfg.ObjectPath); err != nil {
			return err
		}
	}

	c.probes = c.attachLocked(ctx)
	if !floorAttached(c.probes) {
		_ = c.loader.Close()
		return fmt.Errorf("%w\n%s", ErrTelemetryFloor, ComputeCoverage(c.probes).BugReport())
	}

	raw, err := c.loader.RingBuffer(ctx, MapEvents)
	if err != nil {
		_ = c.loader.Close()
		return err
	}

	runCtx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	c.started = true
	c.startedAt = c.now()
	go c.run(runCtx, raw)
	return nil
}

// attachLocked attaches every enabled program and returns per-probe status.
func (c *LiveCollector) attachLocked(ctx context.Context) []ProbeInfo {
	enabled := map[string]bool{}
	for _, n := range c.cfg.EnabledProbes {
		enabled[n] = true
	}
	errs := map[string]string{}
	attached := map[string]bool{}
	for _, d := range AllProbes() {
		if len(enabled) > 0 && !enabled[d.Name] && !enabled[d.Family] && !isFloor(d.Name) {
			errs[d.Name] = "not enabled by configuration"
			continue
		}
		if err := c.loader.Attach(ctx, d.Name); err != nil {
			errs[d.Name] = err.Error()
			continue
		}
		attached[d.Name] = true
	}

	if p, ok := c.loader.(interface{ Probes() []ProbeInfo }); ok {
		probes := p.Probes()
		for i := range probes {
			if probes[i].Error == "" {
				probes[i].Error = errs[probes[i].Name]
			}
		}
		return probes
	}
	descs := AllProbes()
	out := make([]ProbeInfo, 0, len(descs))
	for _, d := range descs {
		out = append(out, ProbeInfo{
			Name:         d.Name,
			Family:       d.Family,
			Type:         d.Type,
			AttachPoint:  d.AttachPoint,
			Capabilities: capabilitiesFor([]ProbeDescriptor{d}),
			Loaded:       true,
			Attached:     attached[d.Name],
			Error:        errs[d.Name],
		})
	}
	return out
}

func isFloor(name string) bool { return name == ProgProcExec || name == ProgProcExit }

func floorAttached(probes []ProbeInfo) bool {
	var exec, exit bool
	for _, p := range probes {
		switch p.Name {
		case ProgProcExec:
			exec = p.Attached
		case ProgProcExit:
			exit = p.Attached
		}
	}
	return exec && exit
}

// Probes reports per-probe status as of Start.
func (c *LiveCollector) Probes() []ProbeInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]ProbeInfo(nil), c.probes...)
}

// Coverage reports what the attached probes can observe.
func (c *LiveCollector) Coverage() Coverage { return ComputeCoverage(c.Probes()) }

// AttachSession begins collecting for the cgroup rootPID is in. The cgroup
// must be dedicated to the session: every process in it is attributed to it.
func (c *LiveCollector) AttachSession(ctx context.Context, sessionID string, rootPID int32) error {
	id, err := CgroupIDOfPID(rootPID)
	if err != nil {
		return err
	}
	return c.AttachCgroup(ctx, sessionID, id, rootPID)
}

// AttachCgroup begins collecting for a session's dedicated cgroup. rootPID,
// when positive, is registered as the session's depth-0 process.
func (c *LiveCollector) AttachCgroup(ctx context.Context, sessionID string, cgroupID uint64, rootPID int32) error {
	if sessionID == "" || cgroupID == 0 {
		return errors.New("telemetry: session ID and cgroup ID are required")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.started || c.closed {
		return ErrNotStarted
	}
	if s, ok := c.sessions[sessionID]; ok && !s.detached {
		return fmt.Errorf("%w: %s", ErrSessionAttached, sessionID)
	}
	if s, ok := c.byCgroup[cgroupID]; ok && !s.detached {
		return fmt.Errorf("%w: cgroup %d", ErrSessionAttached, cgroupID)
	}

	s := &collSession{id: sessionID, cgroupID: cgroupID}
	c.sessions[sessionID] = s
	c.byCgroup[cgroupID] = s
	if rootPID > 0 {
		c.tracker.TrackRoot(sessionID, rootPID)
	}

	key := binary.NativeEndian.AppendUint64(nil, cgroupID)
	if err := c.loader.UpdateMap(ctx, MapTrackedCgroups, key, []byte{1}); err != nil {
		delete(c.sessions, sessionID)
		delete(c.byCgroup, cgroupID)
		c.tracker.ForgetSession(sessionID)
		return err
	}
	return nil
}

// DetachSession stops collecting for a session. Records already in the ring
// are still attributed for a short grace period.
func (c *LiveCollector) DetachSession(ctx context.Context, sessionID string) error {
	c.mu.Lock()
	s, ok := c.sessions[sessionID]
	if !ok || s.detached {
		c.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrSessionUnknown, sessionID)
	}
	s.detached = true
	c.mu.Unlock()

	key := binary.NativeEndian.AppendUint64(nil, s.cgroupID)
	err := c.loader.DeleteMap(ctx, MapTrackedCgroups, key)
	if errors.Is(err, ErrMapKeyNotFound) {
		err = nil
	}

	time.AfterFunc(detachGrace, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if cur, ok := c.sessions[sessionID]; ok && cur == s {
			delete(c.sessions, sessionID)
		}
		if cur, ok := c.byCgroup[s.cgroupID]; ok && cur == s {
			delete(c.byCgroup, s.cgroupID)
		}
		c.tracker.ForgetSession(sessionID)
	})
	return err
}

// Close detaches probes, stops the drain, and closes Events. Idempotent.
func (c *LiveCollector) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		started := c.started
		cancel := c.cancel
		c.mu.Unlock()

		if cancel != nil {
			cancel()
		}
		err = c.loader.Close()
		if started {
			<-c.done
		} else {
			close(c.out)
		}
	})
	return err
}

// Stats reports collection health.
func (c *LiveCollector) Stats() event.SourceStats { return c.CollectorStats().SourceStats }

// CollectorStats reports collection health in full.
func (c *LiveCollector) CollectorStats() CollectorStats {
	c.mu.Lock()
	n := 0
	for _, s := range c.sessions {
		if !s.detached {
			n++
		}
	}
	var up time.Duration
	if c.started {
		up = c.now().Sub(c.startedAt)
	}
	c.mu.Unlock()

	kd, ov := c.kernelDrops.Load(), c.overflow.Load()
	usage := 0.0
	if cap(c.out) > 0 {
		usage = float64(len(c.out)) / float64(cap(c.out))
	}
	return CollectorStats{
		SourceStats: event.SourceStats{
			EventsReceived:  c.received.Load(),
			DroppedEvents:   kd + ov,
			DecodeErrors:    c.decodeErrs.Load(),
			RingBufferUsage: usage,
			Uptime:          up,
		},
		KernelDrops:  kd,
		Overflow:     ov,
		Unattributed: c.unattributed.Load(),
		EnrichErrors: c.enrichErrs.Load(),
		Sessions:     n,
	}
}

// run is the single drain goroutine.
func (c *LiveCollector) run(ctx context.Context, raw <-chan []byte) {
	defer close(c.done)
	defer close(c.out)

	tick := time.NewTicker(c.dropPoll)
	defer tick.Stop()
	var lastKernel uint64

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			lastKernel = c.pollKernelDrops(ctx, lastKernel)
		case rec, ok := <-raw:
			if !ok {
				return
			}
			c.handle(ctx, rec)
		}
	}
}

// pollKernelDrops charges new kernel ring losses to every attached session.
// The kernel counter is global, so any session may have lost a record.
func (c *LiveCollector) pollKernelDrops(ctx context.Context, last uint64) uint64 {
	n, err := c.loader.ReadCounter(ctx, MapRingbufDrops)
	if err != nil || n <= last {
		return last
	}
	delta := n - last
	c.kernelDrops.Add(delta)
	c.mu.Lock()
	for _, s := range c.sessions {
		if !s.detached {
			s.pending += delta
		}
	}
	c.mu.Unlock()
	return n
}

func (c *LiveCollector) handle(ctx context.Context, rec []byte) {
	ev, err := c.decoder.Decode(rec)
	if err != nil {
		c.decodeErrs.Add(1)
		return
	}
	c.received.Add(1)

	c.mu.Lock()
	s := c.byCgroup[ev.Process.CgroupID]
	if s == nil {
		c.mu.Unlock()
		c.unattributed.Add(1)
		return
	}
	s.seq++
	ev.SessionID = s.id
	ev.Sequence = s.seq
	c.mu.Unlock()
	ev.ID = fmt.Sprintf("%s/%d", s.id, ev.Sequence)

	p := &ev.Process
	depth := c.tracker.Observe(s.id, p.PID, p.StartTime, p.PPID)
	if depth > 0 {
		p.AncestryDepth = depth
	}
	if p.Executable == "" && ev.Capability != capability.KindProcessExec {
		p.Executable = c.tracker.Executable(p.PID, p.StartTime)
	}

	for _, en := range c.enrichers {
		if err := en.Enrich(ctx, ev); err != nil {
			c.enrichErrs.Add(1)
		}
	}
	if ev.Capability == capability.KindProcessExec && p.Executable != "" {
		c.tracker.SetExecutable(p.PID, p.StartTime, p.Executable)
	}
	if obs, err := resolve.Observe(ev); err == nil {
		ev.Observation = obs
	}
	if ev.Capability == capability.KindProcessExit {
		_ = c.tracker.Untrack(p.PID, p.StartTime)
	}

	c.mu.Lock()
	ev.Dropped = s.pending
	select {
	case c.out <- *ev:
		s.pending = 0
	default:
		s.pending++
		c.overflow.Add(1)
	}
	c.mu.Unlock()
}
