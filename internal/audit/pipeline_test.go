package audit

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/stringNameMahin/ALLSEER/internal/config"
	"github.com/stringNameMahin/ALLSEER/internal/pipeline"
	"github.com/stringNameMahin/ALLSEER/internal/policy"
	"github.com/stringNameMahin/ALLSEER/internal/risk"
	"github.com/stringNameMahin/ALLSEER/internal/session"
	"github.com/stringNameMahin/ALLSEER/internal/telemetry/replay"
	"github.com/stringNameMahin/ALLSEER/internal/validator"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// The integration this feature exists for: a committed recording, the shipped
// rule set, the real stages, and the concrete sink, producing an audit file.
//
// It is deliberately not the M4 golden test. There is no committed expected
// output here and nothing is asserted byte for byte against a checked-in file;
// what is asserted is that the records on disk are the decisions the pipeline
// produced, and that attaching the sink changed none of them. The golden test
// is the next feature and needs committed envelope fixtures, which do not exist
// yet — every envelope in the tree, including the one below, is written inside
// a test.

const (
	gitFixture   = "../../test/testdata/replay/git-operation.jsonl"
	defaultRules = "../../configs/rules.default.yaml"
	sensitivity  = "../../configs/sensitivity.default.yaml"
)

// gitEnvelope is the envelope a `git commit` session would have been governed
// by: workspace-wide filesystem grants with CI configuration carved out by a
// denial. The same shape cmd/allseerctl's dry-run test uses, so the decisions
// this test audits are the decisions that command reports.
const gitEnvelope = `{
  "schema_version": "allseer.dev/ece/v1alpha1",
  "id": "11111111-2222-3333-4444-555555555555",
  "session_id": "s-git",
  "created_at": "2026-03-02T12:00:00Z",
  "intent": {
    "raw_prompt": "commit the staged changes",
    "summary": "Run git commit in the project.",
    "task_type": "git-operation",
    "analyzer": "rules:v1",
    "confidence": 0.9
  },
  "grants": [
    {"kind": "fs.read", "domain": "filesystem", "selector": {"path_patterns": ["/home/dev/project/**"]}},
    {"kind": "fs.write", "domain": "filesystem", "selector": {"path_patterns": ["/home/dev/project/**"]}},
    {"kind": "fs.create", "domain": "filesystem", "selector": {"path_patterns": ["/home/dev/project/**"]}},
    {"kind": "fs.rename", "domain": "filesystem", "selector": {"path_patterns": ["/home/dev/project/**"]}},
    {"kind": "process.exec", "domain": "process", "selector": {"executables": ["/usr/bin/git"]}},
    {"kind": "process.exit", "domain": "process", "selector": {"executables": ["/usr/bin/git"]}}
  ],
  "denials": [
    {"kind": "fs.write", "domain": "filesystem", "selector": {"path_patterns": ["/home/dev/project/.github/**"]}}
  ],
  "constraints": {"workspace_root": "/home/dev/project"},
  "default_action": "request_approval",
  "sealed": true
}`

// frozen is a clock that does not advance, so Decision.Latency is a
// deterministic zero. Decision timestamps come from each event's own wall clock
// and are unaffected.
func frozen() func() time.Time {
	return func() time.Time { return stamp }
}

func loadEnvelope(t *testing.T) *ece.Envelope {
	t.Helper()
	var env ece.Envelope
	if err := json.Unmarshal([]byte(gitEnvelope), &env); err != nil {
		t.Fatalf("parsing the envelope: %v", err)
	}
	return &env
}

// buildPipeline assembles the composition a daemon runs: validate, score,
// decide, over the shipped rule set and sensitivity list.
func buildPipeline(t *testing.T, sink decision.Sink) *pipeline.EventPipeline {
	t.Helper()

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

	env := loadEnvelope(t)
	p, err := pipeline.NewWithRisk(pipeline.Config{
		Session: pipeline.Session{
			Envelope: env,
			Mode:     policy.ModeMonitor,
			State:    session.NewState(env.SessionID, env),
		},
		Sink: sink,
		Now:  frozen(),
	}, validator.NewValidator(), riskEngine, engine)
	if err != nil {
		t.Fatalf("building the pipeline: %v", err)
	}
	return p
}

// replayEvents reads the fixture into a slice, in file order.
//
// Read up front rather than streamed, because the reference run and the audited
// run must see the identical stream and a replay.Source is single-use.
func replayEvents(t *testing.T) []event.Event {
	t.Helper()

	src := replay.Open(filepath.FromSlash(gitFixture))
	if err := src.Start(context.Background()); err != nil {
		t.Fatalf("starting the replay source: %v", err)
	}
	defer func() { _ = src.Close() }()

	var out []event.Event
	for e := range src.Events() {
		out = append(out, e)
	}
	if err := src.Err(); err != nil {
		t.Fatalf("replaying %s: %v", gitFixture, err)
	}
	if len(out) == 0 {
		t.Fatalf("%s replayed no events", gitFixture)
	}
	return out
}

// sliceSource replays an already-read slice through event.Source, so Run — the
// only path that reaches the sink — can be driven over the same events the
// reference run saw.
type sliceSource struct{ ch chan event.Event }

func newSliceSource(events []event.Event) *sliceSource {
	ch := make(chan event.Event, len(events))
	for _, e := range events {
		ch <- e
	}
	close(ch)
	return &sliceSource{ch: ch}
}

func (s *sliceSource) Events() <-chan event.Event  { return s.ch }
func (s *sliceSource) Start(context.Context) error { return nil }
func (s *sliceSource) Close() error                { return nil }
func (s *sliceSource) Stats() event.SourceStats    { return event.SourceStats{} }

// TestReplayThroughTheSinkWritesEveryDecision is the end-to-end path: replay a
// fixture, run the pipeline with the concrete sink attached, flush, and read the
// JSONL back.
func TestReplayThroughTheSinkWritesEveryDecision(t *testing.T) {
	events := replayEvents(t)

	// The reference run: the same stages over the same events with no sink, so
	// the decisions the pipeline produces are known independently of anything
	// the sink did.
	reference := buildPipeline(t, nil)
	want := make([]decision.Decision, 0, len(events))
	for i := range events {
		d, err := reference.Process(context.Background(), &events[i])
		if err != nil {
			t.Fatalf("processing %s: %v", events[i].ID, err)
		}
		if d == nil {
			t.Fatalf("processing %s produced no decision", events[i].ID)
		}
		want = append(want, *d)
	}

	path := filepath.Join(t.TempDir(), "audit.jsonl")
	sink, err := Open(auditConfig(path, true))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	audited := buildPipeline(t, sink)
	if err := audited.Run(context.Background(), newSliceSource(events)); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if err := sink.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	got := lines(t, path)
	if len(got) != len(events) {
		t.Fatalf("audit file has %d records, want one per event (%d)", len(got), len(events))
	}
	if st := sink.Stats(); st.Written != uint64(len(events)) || st.Errors != 0 {
		t.Errorf("Stats = %+v, want Written %d and no errors", st, len(events))
	}

	for i, line := range got {
		var back decision.Decision
		if err := json.Unmarshal([]byte(line), &back); err != nil {
			t.Fatalf("record %d is not valid JSON: %v\nline: %s", i, err, line)
		}
		if !reflect.DeepEqual(back, want[i]) {
			t.Errorf("record %d is not the decision the pipeline produced\n got: %+v\nwant: %+v", i, back, want[i])
		}
		if back.EventID != events[i].ID {
			t.Errorf("record %d has event_id %q, want %q; audit order must be event order",
				i, back.EventID, events[i].ID)
		}
	}
}

// A sink is an output mechanism, not a stage. Attaching one must not change
// what the system decided — otherwise the audit log would be a record of a
// session that only happens when auditing is on.
func TestSinkChangesNoDecision(t *testing.T) {
	events := replayEvents(t)

	unaudited := buildPipeline(t, nil)
	var without []decision.Decision
	for i := range events {
		d, err := unaudited.Process(context.Background(), &events[i])
		if err != nil {
			t.Fatalf("processing %s: %v", events[i].ID, err)
		}
		without = append(without, *d)
	}

	path := filepath.Join(t.TempDir(), "audit.jsonl")
	sink, err := Open(auditConfig(path, true))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = sink.Close() }()

	audited := buildPipeline(t, sink)
	var with []decision.Decision
	for i := range events {
		d, err := audited.Process(context.Background(), &events[i])
		if err != nil {
			t.Fatalf("processing %s: %v", events[i].ID, err)
		}
		with = append(with, *d)
	}

	for i := range without {
		a, b := without[i], with[i]
		switch {
		case a.Verdict != b.Verdict:
			t.Errorf("%s: verdict changed with the sink attached: %q -> %q", a.EventID, a.Verdict, b.Verdict)
		case a.Risk.Score != b.Risk.Score || a.Risk.Level != b.Risk.Level:
			t.Errorf("%s: risk changed with the sink attached: %v/%s -> %v/%s",
				a.EventID, a.Risk.Score, a.Risk.Level, b.Risk.Score, b.Risk.Level)
		case a.MatchedRule != b.MatchedRule:
			t.Errorf("%s: matched rule changed with the sink attached: %q -> %q", a.EventID, a.MatchedRule, b.MatchedRule)
		case a.Action != b.Action:
			t.Errorf("%s: action changed with the sink attached: %q -> %q", a.EventID, a.Action, b.Action)
		case !reflect.DeepEqual(a, b):
			t.Errorf("%s: the decision differs with the sink attached\nwithout: %+v\n   with: %+v", a.EventID, a, b)
		}
	}
}

// The record on disk is deterministic across runs, which is the property the
// golden test that follows this feature will depend on. Anything that made the
// bytes vary between two identical replays — an emission timestamp, a random
// identifier, a map iterated in place — would surface here rather than as a
// flaky golden file later.
func TestTwoIdenticalReplaysProduceIdenticalBytes(t *testing.T) {
	events := replayEvents(t)

	run := func() []byte {
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		sink, err := Open(auditConfig(path, true))
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		p := buildPipeline(t, sink)
		if err := p.Run(context.Background(), newSliceSource(events)); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if err := sink.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		return data
	}

	first, second := run(), run()
	if string(first) != string(second) {
		t.Errorf("two identical replays produced different audit files\nfirst:\n%s\nsecond:\n%s", first, second)
	}
}

// With the shipped default — record_all_events false — an audit of this
// recording is shorter than the recording, and every record it keeps is a
// finding rather than a routine allow.
func TestRecordAllEventsFalseKeepsOnlyFindings(t *testing.T) {
	events := replayEvents(t)

	path := filepath.Join(t.TempDir(), "audit.jsonl")
	sink, err := Open(auditConfig(path, false))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	p := buildPipeline(t, sink)
	if err := p.Run(context.Background(), newSliceSource(events)); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	got := lines(t, path)
	if len(got) == 0 {
		t.Fatal("nothing was recorded; the fixture contains a denial and it is a finding")
	}
	if len(got) >= len(events) {
		t.Errorf("recorded %d of %d decisions; with record_all_events off the routine allows must be suppressed",
			len(got), len(events))
	}
	for i, line := range got {
		var d decision.Decision
		if err := json.Unmarshal([]byte(line), &d); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
		if d.Verdict == decision.VerdictWithinEnvelope && d.Action == ece.ActionAllow {
			t.Errorf("record %d (%s) is a routine allow and should have been filtered", i, d.EventID)
		}
	}
	if st := sink.Stats(); st.Written+st.Filtered != uint64(len(events)) {
		t.Errorf("Stats = %+v; written plus filtered must account for every decision (%d)", st, len(events))
	}
}

// auditConfig is the sink configuration these tests run against: JSONL, no
// per-record fsync, with RecordAllEvents chosen per test.
func auditConfig(path string, recordAll bool) config.AuditConfig {
	return config.AuditConfig{
		Path:            path,
		Format:          FormatJSONL,
		RecordAllEvents: recordAll,
	}
}
