package synth_test

import (
	"context"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/stringNameMahin/ALLSEER/internal/pipeline"
	"github.com/stringNameMahin/ALLSEER/internal/policy"
	"github.com/stringNameMahin/ALLSEER/internal/risk"
	"github.com/stringNameMahin/ALLSEER/internal/session"
	"github.com/stringNameMahin/ALLSEER/internal/telemetry/abi"
	"github.com/stringNameMahin/ALLSEER/internal/telemetry/synth"
	"github.com/stringNameMahin/ALLSEER/internal/validator"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// These tests are the reason the generator exists in the shape it does: a
// generated stream has to reach the same conclusions a recorded one would,
// through the same stages, with nothing downstream configured differently
// because the events were synthetic.
//
// They are an external test package so the imports below are honest. Nothing in
// internal/telemetry/synth depends on the pipeline, the policy engine, the risk
// engine or the session manager, and it must stay that way: a generator that
// the governance stages depended on, or that depended on them, could not be
// used to test them.

const (
	sessionID    = "s-synth"
	defaultRules = "../../../configs/rules.default.yaml"
	sensitivity  = "../../../configs/sensitivity.default.yaml"
)

// The envelope a `go build` session would be governed by: the workspace and the
// toolchain granted, the user's SSH directory denied outright.
const buildEnvelope = `{
  "schema_version": "allseer.dev/ece/v1alpha1",
  "id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "session_id": "s-synth",
  "created_at": "2026-03-02T10:00:00Z",
  "intent": {
    "raw_prompt": "build the project",
    "summary": "Run go build in the workspace.",
    "task_type": "go-build",
    "analyzer": "rules:v1",
    "confidence": 0.9
  },
  "grants": [
    {"kind": "fs.read", "domain": "filesystem", "selector": {"path_patterns": ["/home/dev/project/**"]}},
    {"kind": "process.exec", "domain": "process", "selector": {"executables": ["/usr/local/go/bin/go"]}},
    {"kind": "process.exit", "domain": "process", "selector": {"executables": ["/usr/local/go/bin/go"]}}
  ],
  "denials": [
    {"kind": "fs.read", "domain": "filesystem", "selector": {"path_patterns": ["/home/dev/.ssh/**"]}}
  ],
  "constraints": {"workspace_root": "/home/dev/project"},
  "default_action": "request_approval",
  "sealed": true
}`

func envelope(t *testing.T) *ece.Envelope {
	t.Helper()
	var env ece.Envelope
	if err := json.Unmarshal([]byte(buildEnvelope), &env); err != nil {
		t.Fatalf("parsing the envelope: %v", err)
	}
	return &env
}

// collector is a decision.Sink that keeps what it was given, in order.
type collector struct {
	mu        sync.Mutex
	decisions []decision.Decision
}

func (c *collector) Emit(_ context.Context, d decision.Decision) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.decisions = append(c.decisions, d)
	return nil
}

func (c *collector) Flush(context.Context) error { return nil }
func (c *collector) Close() error                { return nil }

func (c *collector) all() []decision.Decision {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]decision.Decision(nil), c.decisions...)
}

func generator(t *testing.T) *synth.Generator {
	t.Helper()
	g, err := synth.New(synth.Config{
		SessionID: sessionID,
		Process: synth.Proc{
			PID: 4101, TID: 4101, PPID: 4100, UID: 1000, GID: 1000,
			Comm: "go", CgroupID: 9001, StartTime: 88_120_000,
			Executable: "/usr/local/go/bin/go",
		},
	})
	if err != nil {
		t.Fatalf("synth.New: %v", err)
	}
	return g
}

// buildSession is the stream every test below runs: an exec the envelope
// grants, a workspace read it grants, an SSH key read it denies, and a
// connection to an address no grant covers.
func buildSession() []synth.Spec {
	return []synth.Spec{
		{Type: abi.EvtProcExec, Exec: &synth.Exec{
			Filename: "/usr/local/go/bin/go",
			Argv:     []string{"go", "build", "./..."},
		}},
		{Type: abi.EvtFileOpen, Ret: 3, File: &synth.File{
			Path: "go.mod", ResolvedPath: "/home/dev/project/go.mod", Inode: 525301, Device: 2049,
		}},
		{Type: abi.EvtFileOpen, Ret: 4, File: &synth.File{
			Path: ".ssh/id_rsa", ResolvedPath: "/home/dev/.ssh/id_rsa", Inode: 700123, Device: 2049,
		}},
		{Type: abi.EvtNetConnect, Net: &synth.Net{
			Family: synth.AFInet, Protocol: synth.IPProtoTCP, SockType: synth.SockStream,
			DestAddr: netip.MustParseAddr("198.51.100.7"), DestPort: 443,
		}},
	}
}

// The whole path, end to end: specs, records, the decoder, the resolver, the
// replay format, an event.Source, and then validate, score and decide over the
// shipped rule set. What is asserted is the verdicts, because a verdict is what
// the rest of the system acts on and it is the only way to show that a
// synthetic event was understood rather than merely accepted.
func TestGeneratedStreamReachesTheExpectedVerdicts(t *testing.T) {
	env := envelope(t)
	sink := &collector{}

	rs, err := policy.NewLoader().Load(context.Background(), filepath.FromSlash(defaultRules))
	if err != nil {
		t.Fatalf("loading %s: %v", defaultRules, err)
	}
	engine, err := policy.NewEngine(rs)
	if err != nil {
		t.Fatalf("building the policy engine: %v", err)
	}
	oracle, err := risk.LoadResourceOracle(filepath.FromSlash(sensitivity))
	if err != nil {
		t.Fatalf("loading %s: %v", sensitivity, err)
	}
	riskEngine, err := risk.NewEngineWithOracle(oracle)
	if err != nil {
		t.Fatalf("building the risk engine: %v", err)
	}

	p, err := pipeline.NewWithRisk(pipeline.Config{
		Session: pipeline.Session{
			Envelope: env,
			Mode:     policy.ModeMonitor,
			State:    session.NewState(env.SessionID, env),
		},
		Sink: sink,
	}, validator.NewValidator(), riskEngine, engine)
	if err != nil {
		t.Fatalf("building the pipeline: %v", err)
	}

	specs := buildSession()
	src, err := generator(t).Source(specs...)
	if err != nil {
		t.Fatalf("Source: %v", err)
	}
	if err := src.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = src.Close() }()

	if err := p.Run(context.Background(), src); err != nil {
		t.Fatalf("Run: %v", err)
	}

	got := sink.all()
	if len(got) != len(specs) {
		t.Fatalf("the pipeline produced %d decisions for %d events", len(got), len(specs))
	}

	want := []decision.Verdict{
		decision.VerdictWithinEnvelope,   // the granted exec
		decision.VerdictWithinEnvelope,   // the granted workspace read
		decision.VerdictExplicitlyDenied, // the denied SSH key read
		decision.VerdictOutsideEnvelope,  // a connection no grant covers
	}
	for i, w := range want {
		if got[i].Verdict != w {
			t.Errorf("decision %d: Verdict = %q, want %q", i, got[i].Verdict, w)
		}
		if got[i].SessionID != sessionID {
			t.Errorf("decision %d: SessionID = %q, want %q", i, got[i].SessionID, sessionID)
		}
		// The decision is tied back to the event by the generator's own ID,
		// which is what makes an audit record from a synthetic stream traceable
		// to the spec that produced it.
		if want := "d-" + sessionID + "/" + strconv.Itoa(i+1); got[i].ID != want {
			t.Errorf("decision %d: ID = %q, want %q", i, got[i].ID, want)
		}
	}
}

// Rerunning the same specs through the same pipeline must reach the same
// decisions. This is the property a benchmark and a regression test both need,
// and the one a generator that read a clock or a random source would not have.
func TestTheSameSpecsDecideTheSameWay(t *testing.T) {
	run := func() []decision.Verdict {
		env := envelope(t)
		sink := &collector{}

		rs, err := policy.NewLoader().Load(context.Background(), filepath.FromSlash(defaultRules))
		if err != nil {
			t.Fatalf("loading %s: %v", defaultRules, err)
		}
		engine, err := policy.NewEngine(rs)
		if err != nil {
			t.Fatalf("building the policy engine: %v", err)
		}
		p, err := pipeline.New(pipeline.Config{
			Session: pipeline.Session{
				Envelope: env,
				Mode:     policy.ModeMonitor,
				State:    session.NewState(env.SessionID, env),
			},
			Sink: sink,
		}, validator.NewValidator(), engine)
		if err != nil {
			t.Fatalf("building the pipeline: %v", err)
		}

		src, err := generator(t).Source(buildSession()...)
		if err != nil {
			t.Fatalf("Source: %v", err)
		}
		if err := src.Start(context.Background()); err != nil {
			t.Fatalf("Start: %v", err)
		}
		defer func() { _ = src.Close() }()

		if err := p.Run(context.Background(), src); err != nil {
			t.Fatalf("Run: %v", err)
		}

		out := make([]decision.Verdict, 0, 4)
		for _, d := range sink.all() {
			out = append(out, d.Verdict)
		}
		return out
	}

	first, second := run(), run()
	if len(first) != len(second) {
		t.Fatalf("two runs produced %d and %d decisions", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Errorf("decision %d: %q on the first run, %q on the second", i, first[i], second[i])
		}
	}
}

// --- dispatch --------------------------------------------------------------------

// registry is the narrow view of a session manager that routing needs.
type registry struct {
	binding session.Binding
	held    string
}

func (r registry) Binding(id string) (session.Binding, bool) {
	if id != r.held {
		return session.Binding{}, false
	}
	return r.binding, true
}

// counter is an EventProcessor that reaches no conclusion and only records what
// it was handed. Routing is what is under test here, not the stages.
type counter struct {
	events []string
}

func (c *counter) Process(_ context.Context, e *event.Event) (*decision.Decision, error) {
	c.events = append(c.events, e.ID)
	return &decision.Decision{ID: "d-" + e.ID, SessionID: e.SessionID, EventID: e.ID}, nil
}

// Dispatch routes on the session ID the generator stamps, so a generated stream
// has to be routable. The negative half matters as much: a stream naming a
// session nobody registered must be counted as unattributed rather than
// silently processed, and a generator is the easiest way to produce one.
func TestGeneratedStreamRoutesByItsSessionID(t *testing.T) {
	env := envelope(t)
	proc := &counter{}

	reg := registry{
		held: sessionID,
		binding: session.Binding{
			SessionID: sessionID,
			Envelope:  env,
			Mode:      policy.ModeMonitor,
			State:     session.NewState(sessionID, env),
			Lifecycle: session.StateActive,
		},
	}

	d, err := session.NewDispatcher(session.DispatchConfig{
		Registry: reg,
		Factory:  func(session.Binding) (session.EventProcessor, error) { return proc, nil },
	})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	specs := buildSession()
	src, err := generator(t).Source(specs...)
	if err != nil {
		t.Fatalf("Source: %v", err)
	}
	if err := src.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = src.Close() }()

	if err := d.Run(context.Background(), src); err != nil {
		t.Fatalf("Run: %v", err)
	}

	stats := d.Stats()
	if stats.EventsRouted != uint64(len(specs)) {
		t.Errorf("EventsRouted = %d, want %d", stats.EventsRouted, len(specs))
	}
	if stats.Unidentified != 0 || stats.Unattributed != 0 || stats.NotAccepting != 0 {
		t.Errorf("routing findings on a well-formed stream: %+v", stats)
	}
	if len(proc.events) != len(specs) {
		t.Fatalf("the processor saw %d events, want %d", len(proc.events), len(specs))
	}
	for i, id := range proc.events {
		if want := sessionID + "/" + strconv.Itoa(i+1); id != want {
			t.Errorf("event %d reached the processor as %q, want %q", i, id, want)
		}
	}
}

func TestAStreamForAnUnknownSessionIsUnattributed(t *testing.T) {
	env := envelope(t)

	reg := registry{
		held: sessionID,
		binding: session.Binding{
			SessionID: sessionID,
			Envelope:  env,
			Mode:      policy.ModeMonitor,
			State:     session.NewState(sessionID, env),
			Lifecycle: session.StateActive,
		},
	}
	d, err := session.NewDispatcher(session.DispatchConfig{
		Registry: reg,
		Factory: func(session.Binding) (session.EventProcessor, error) {
			return &counter{}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	stranger, err := synth.New(synth.Config{SessionID: "s-unregistered"})
	if err != nil {
		t.Fatalf("synth.New: %v", err)
	}
	src, err := stranger.Source(buildSession()...)
	if err != nil {
		t.Fatalf("Source: %v", err)
	}
	if err := src.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = src.Close() }()

	if err := d.Run(context.Background(), src); err != nil {
		t.Fatalf("Run: %v", err)
	}

	stats := d.Stats()
	if stats.Unattributed != uint64(len(buildSession())) {
		t.Errorf("Unattributed = %d, want %d", stats.Unattributed, len(buildSession()))
	}
	if stats.EventsRouted != 0 {
		t.Errorf("EventsRouted = %d; events for a session nobody holds must not be processed",
			stats.EventsRouted)
	}
}
