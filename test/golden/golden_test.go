// Package golden holds ALLSEER's end-to-end regression guard: a committed
// recording and a committed envelope go in, a committed decision stream comes
// out, and the bytes have to match.
//
// # Why this exists
//
// Every other test in the tree checks one component against its own
// expectations. A validator test knows what the validator should say, a scorer
// test knows what that scorer should contribute, and a pipeline test knows the
// plumbing. None of them knows what the *system* concludes about a session, and
// that is the thing this project's research question is actually about. This
// test is the only place where the composition is pinned: if a scorer's weight
// moves, a rule's priority changes, a verdict is reclassified, or a serialized
// field is renamed, a golden file changes and a human has to look at the diff
// and say whether that was intended.
//
// # It runs the production path, not a copy of it
//
//	replay.Source ──▶ EventPipeline.Run ──▶ validate ──▶ score ──▶ decide
//	                                             │
//	                                             └──▶ emit ──▶ audit.JSONLSink ──▶ file
//
// Every component is the one a daemon would run: the shipped rule set from
// configs/rules.default.yaml, the shipped sensitivity list from
// configs/sensitivity.default.yaml, the real validator, the real
// session.MemoryState, and the real JSONL sink. Nothing here re-implements a
// stage, and nothing here reaches inside one. A golden test built on a
// parallel harness would pin the harness.
//
// # Determinism, and where it comes from
//
// Nothing is normalized away to make the comparison work. Each field is
// deterministic because the production semantics already made it so, and this
// test would rather fail than paper over one that is not:
//
//   - Decision.ID derives from the event ID (pipeline.decisionID), not from a
//     random source.
//   - Decision.Timestamp is the event's own recorded wall clock
//     (pipeline.timestampOf), so a session replayed a year later dates its
//     decisions the way the live run did.
//   - Risk scores and factors are pure functions of the observation and the
//     session history, and the history is rebuilt from the same recording.
//   - Map-valued Factor.Evidence is serialized by encoding/json, which sorts
//     keys.
//   - Decision.Latency is the one field that measures the host rather than the
//     session. It is pinned by injecting a stopped clock through
//     pipeline.Config.Now — the seam the pipeline already documents as being
//     there "so a replayed session produces a reproducible record" — which
//     makes every latency exactly zero. That is an honest zero for a replay:
//     the number the field exists to report is the delay charged to a live
//     agent's syscall, and a replay charges none.
//
// # Regenerating
//
//	make golden
//
// which is `go test ./test/golden/ -run TestGolden$ -update`. Regeneration is
// deliberately a separate, named action: an ordinary `go test ./...` compares
// and fails, and never writes. A golden file that quietly rewrote itself would
// assert nothing at all.
package golden

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stringNameMahin/ALLSEER/internal/audit"
	"github.com/stringNameMahin/ALLSEER/internal/config"
	"github.com/stringNameMahin/ALLSEER/internal/pipeline"
	"github.com/stringNameMahin/ALLSEER/internal/policy"
	"github.com/stringNameMahin/ALLSEER/internal/session"
	"github.com/stringNameMahin/ALLSEER/internal/telemetry/replay"
	"github.com/stringNameMahin/ALLSEER/internal/validator"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
)

// update rewrites the committed golden files instead of comparing against them.
//
// Registered on the test binary's own flag set rather than read from an
// environment variable so that `go test -update` is discoverable from
// `go test -h` and cannot be set by accident in a CI environment block.
var update = flag.Bool("update", false,
	"rewrite the committed golden decision streams instead of comparing against them")

const (
	repoRoot     = "../.."
	rulesPath    = repoRoot + "/configs/rules.default.yaml"
	sensPath     = repoRoot + "/configs/sensitivity.default.yaml"
	envelopeDir  = repoRoot + "/test/testdata/envelopes"
	recordingDir = repoRoot + "/test/testdata/replay"
	goldenDir    = repoRoot + "/test/testdata/golden"
)

// goldenClock is the stopped clock injected through pipeline.Config.Now.
//
// Its value never reaches a golden file: Decision.Timestamp comes from the
// event's own wall clock, and the only field this clock decides is Latency,
// which it makes zero. It is dated inside the recordings' own window anyway, so
// that a stage which ever did consult the pipeline clock would not silently
// produce a decision dated years from the session it describes.
var goldenClock = time.Date(2026, 3, 2, 12, 40, 0, 0, time.UTC)

// A case is one recording governed by one envelope, producing one decision
// stream.
//
// Two of them, chosen to cover different halves of the deterministic core
// rather than to raise a coverage number. Adding a third is a deliberate act:
// a golden file is a maintenance obligation, and one that exercises nothing new
// is a file that will be regenerated without being read.
type goldenCase struct {
	// Name is the fixture stem, shared by all three files.
	Name string

	// Why records what this case exists to pin, so a future reader can tell
	// whether a diff matters.
	Why string

	// Mode is the enforcement posture. Monitor throughout: no enforcer exists
	// (M12), so any other mode would only change which rules are eligible
	// without changing what is applied, and the golden would imply an
	// enforcement that did not happen.
	Mode policy.Mode
}

var cases = []goldenCase{
	{
		Name: "git-operation",
		Why: "denial-over-grant precedence, a workspace-wide grant with a carve-out, " +
			"and a failed read of credential material that is still a governance signal",
		Mode: policy.ModeMonitor,
	},
	{
		Name: "credential-egress",
		Why: "the credential-access to egress sequence, an uncorrelated destination " +
			"the validator cannot resolve, and every near-miss beside them",
		Mode: policy.ModeMonitor,
	},
}

// --- the run ------------------------------------------------------------------

// run replays one case through the production path and returns the audit file's
// bytes.
//
// The output goes to t.TempDir(), never to a path in the repository and never
// to a configured audit log. `go test` may run these cases in any order and a
// golden run must not depend on, or leave behind, state anywhere else.
func run(t *testing.T, tc goldenCase) []byte {
	t.Helper()

	env := loadEnvelope(t, filepath.Join(envelopeDir, tc.Name+".json"))
	if env.SessionID == "" {
		t.Fatalf("%s: the envelope fixture has no session_id; decisions would be stamped with an empty session", tc.Name)
	}

	out := filepath.Join(t.TempDir(), tc.Name+".decisions.jsonl")
	sink, err := audit.Open(config.AuditConfig{
		Path:   out,
		Format: audit.FormatJSONL,

		// Every decision, including routine allows. A golden stream that
		// dropped the common case would assert nothing about the path most
		// events take, and "one decision per event" is the property that makes
		// a missing record visible.
		RecordAllEvents: true,
	})
	if err != nil {
		t.Fatalf("%s: opening the sink: %v", tc.Name, err)
	}

	p, err := pipeline.NewWithRisk(
		pipeline.Config{
			Session: pipeline.Session{
				Envelope: env,
				Mode:     tc.Mode,
				State:    session.NewState(env.SessionID, env),
			},
			Sink: sink,
			Now:  func() time.Time { return goldenClock },
		},
		validator.NewValidator(),
		riskEngine(t),
		policyEngine(t),
	)
	if err != nil {
		t.Fatalf("%s: building the pipeline: %v", tc.Name, err)
	}

	src := replay.Open(filepath.FromSlash(filepath.Join(recordingDir, tc.Name+".jsonl")))
	if err := src.Start(context.Background()); err != nil {
		t.Fatalf("%s: starting the replay source: %v", tc.Name, err)
	}
	defer func() { _ = src.Close() }()

	if err := p.Run(context.Background(), src); err != nil {
		t.Fatalf("%s: Run: %v", tc.Name, err)
	}
	if err := src.Err(); err != nil {
		t.Fatalf("%s: the recording did not replay cleanly: %v", tc.Name, err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("%s: closing the sink: %v", tc.Name, err)
	}

	// A sink error is counted and never returned, by design — an audit failure
	// must not stop governance. That makes it invisible unless it is checked,
	// and a golden generated over a sink that dropped records would be a
	// silently short file.
	if st := sink.Stats(); st.Errors != 0 || st.Filtered != 0 {
		t.Fatalf("%s: sink stats = %+v, want no errors and nothing filtered", tc.Name, st)
	}
	stats := p.Stats()
	if stats.DecisionsIssued != stats.EventsProcessed {
		t.Fatalf("%s: %d decisions for %d events; every event must produce exactly one record",
			tc.Name, stats.DecisionsIssued, stats.EventsProcessed)
	}
	if stats.Errors != 0 {
		t.Fatalf("%s: pipeline reported %d errors; a golden stream must not contain "+
			"decisions produced by a failed stage", tc.Name, stats.Errors)
	}
	if got := sink.Stats().Written; got != stats.DecisionsIssued {
		t.Fatalf("%s: sink wrote %d records for %d decisions", tc.Name, got, stats.DecisionsIssued)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("%s: reading the generated stream: %v", tc.Name, err)
	}
	return data
}

// --- the tests ----------------------------------------------------------------

// TestGolden is the regression guard, and with -update it is the generator.
//
// One function for both so the committed file is produced by exactly the code
// path that checks it. A separate generator binary would be a second definition
// of "the output", and the two would drift the first time one of them was
// edited.
func TestGolden(t *testing.T) {
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			got := run(t, tc)
			path := filepath.Join(goldenDir, tc.Name+".decisions.jsonl")

			if *update {
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatalf("writing %s: %v", path, err)
				}
				t.Logf("wrote %s (%d bytes, %d decisions)", path, len(got), bytes.Count(got, []byte("\n")))
				return
			}

			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("reading %s: %v\nrun `make golden` to create it", path, err)
			}

			// Compared as bytes, because the claim is that the audit log is
			// byte-reproducible. Reported line by line, because a whole-file
			// diff of ten JSON objects is unreadable and the first differing
			// line is almost always the whole story.
			if !bytes.Equal(got, want) {
				reportDiff(t, tc.Name, want, got)
			}
		})
	}
}

// TestGoldenIsDeterministic replays each case twice in one process and requires
// identical bytes.
//
// Distinct from TestGolden, which would also catch this: that one compares
// against a file generated at some earlier moment, so it proves reproducibility
// across time but not that two runs agree *now*. Map iteration order is the
// failure this separates out — it varies per run, not per build, and a
// serializer that leaked it would pass a freshly regenerated golden and fail
// the next day.
func TestGoldenIsDeterministic(t *testing.T) {
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			first, second := run(t, tc), run(t, tc)
			if !bytes.Equal(first, second) {
				reportDiff(t, tc.Name, first, second)
			}
			if len(first) == 0 {
				t.Fatal("the run produced no output at all")
			}
		})
	}
}

// TestGoldenStreamIsWellFormed checks the committed files as JSONL, separately
// from what they contain.
//
// A byte comparison cannot tell a formatting change from a semantic one, and
// the audit format's promise to external tooling — one decision per line, no
// embedded newlines, a trailing newline on the last record — is a promise about
// the shape rather than the values.
func TestGoldenStreamIsWellFormed(t *testing.T) {
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			path := filepath.Join(goldenDir, tc.Name+".decisions.jsonl")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("reading %s: %v", path, err)
			}
			if len(data) == 0 {
				t.Fatal("the golden stream is empty")
			}
			if !bytes.HasSuffix(data, []byte("\n")) {
				t.Error("the stream does not end in a newline; a reader would see a truncated final record")
			}
			if bytes.Contains(data, []byte("\r")) {
				t.Error("the stream contains a carriage return; the audit writer emits LF only")
			}

			for i, line := range splitLines(t, data) {
				if strings.TrimSpace(line) == "" {
					t.Errorf("line %d is blank; a JSONL stream has no blank records", i)
					continue
				}
				var d decision.Decision
				dec := json.NewDecoder(strings.NewReader(line))
				dec.DisallowUnknownFields()
				if err := dec.Decode(&d); err != nil {
					// DisallowUnknownFields turns a field the writer emits and
					// decision.Decision does not declare into a failure here.
					// That is the drift worth catching: it means the record on
					// disk stopped being the type.
					t.Fatalf("line %d does not decode into decision.Decision: %v\nline: %s", i, err, line)
				}
				if err := dec.Decode(new(json.RawMessage)); err == nil {
					t.Errorf("line %d holds more than one JSON value", i)
				}
			}
		})
	}
}

// TestGoldenDecisionsAreTheExpectedFindings asserts what the stream says, in Go,
// beside what it says on disk.
//
// The byte comparison catches every change; this catches the ones that matter,
// and says so in words. Regenerating a golden is one command, and a reviewer
// looking at a diff of ten JSON objects can easily accept a verdict flip as
// noise. These expectations have to be edited deliberately, one line at a time,
// with a reason.
//
// Deliberately not a second copy of the risk and policy unit tests: no weight,
// threshold, or matcher semantics is restated here. What is pinned is the
// system's conclusion per event — verdict, score, level, rule, action — which
// is the thing no single-component test can see.
func TestGoldenDecisionsAreTheExpectedFindings(t *testing.T) {
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			want := expected[tc.Name]
			if len(want) == 0 {
				t.Fatalf("no expectations recorded for %s", tc.Name)
			}

			got := readGolden(t, tc.Name)
			if len(got) != len(want) {
				t.Fatalf("the stream holds %d decisions, want %d", len(got), len(want))
			}

			for i, w := range want {
				d := got[i]
				// Ordering first: everything below is meaningless if the
				// records are not the ones being compared. Per-session order is
				// a correctness guarantee, not a presentation detail — risk
				// scoring reads history, so a reordered stream silently changes
				// verdicts.
				if d.EventID != w.EventID {
					t.Fatalf("record %d is for event %q, want %q; decision order must be event order",
						i, d.EventID, w.EventID)
				}
				if d.ID != "d-"+w.EventID {
					t.Errorf("%s: decision ID = %q, want %q; the ID must derive from the event",
						w.EventID, d.ID, "d-"+w.EventID)
				}
				if d.SessionID != w.SessionID {
					t.Errorf("%s: session = %q, want %q", w.EventID, d.SessionID, w.SessionID)
				}
				if d.Verdict != w.Verdict {
					t.Errorf("%s: verdict = %q, want %q", w.EventID, d.Verdict, w.Verdict)
				}
				if d.Risk.Score != w.Score {
					t.Errorf("%s: risk score = %v, want %v", w.EventID, d.Risk.Score, w.Score)
				}
				if d.Risk.Level != w.Level {
					t.Errorf("%s: risk level = %q, want %q", w.EventID, d.Risk.Level, w.Level)
				}
				if d.MatchedRule != w.Rule {
					t.Errorf("%s: matched rule = %q, want %q", w.EventID, d.MatchedRule, w.Rule)
				}
				if d.Action != w.Action {
					t.Errorf("%s: action = %q, want %q", w.EventID, d.Action, w.Action)
				}
				if got := factorNames(d); !equalStrings(got, w.Factors) {
					t.Errorf("%s: factors = %v, want %v", w.EventID, got, w.Factors)
				}

				// Enforcement is M12. Until it exists, a record claiming an
				// action was applied would be the specific dishonesty
				// Decision.Enforced was added to prevent.
				if d.Enforced {
					t.Errorf("%s: enforced = true, but no enforcer exists", w.EventID)
				}
				// Latency is zero by construction under the stopped clock. If
				// it is not, something consulted a different clock and the
				// stream has stopped being reproducible.
				if d.Latency != 0 {
					t.Errorf("%s: latency = %v, want 0 under the injected clock", w.EventID, d.Latency)
				}
				// Every decision carries its reasoning. A record that cannot
				// explain itself is the one thing this project says an audit
				// record must never be.
				if len(d.Reasoning) == 0 {
					t.Errorf("%s: the decision carries no reasoning chain", w.EventID)
				}

				for key, val := range w.Evidence {
					if got := evidenceOf(d, key); got != val {
						t.Errorf("%s: evidence %q = %q, want %q", w.EventID, key, got, val)
					}
				}
			}
		})
	}
}

// TestNoGoldenDecisionIsUnscored guards the one shape the shipped decision
// schema cannot accept.
//
// api/schema/decision.v1alpha1.schema.json requires risk.level to be one of five
// named levels and risk.factors to be an array. Decision.Risk is a value, so a
// decision nothing scored publishes "" and null, and the schema admits neither
// — an open wire-format question recorded in docs/milestones.md and STATUS.md
// and deliberately not settled here.
//
// Both golden streams run the scored pipeline over recordings that reach policy
// on every event, so neither contains that shape. This test says so rather than
// leaving it to be assumed, and it is the thing that will fail if a future
// change routes a golden event through a stage failure — at which point the
// wire-format question has to be answered before the golden can be regenerated.
func TestNoGoldenDecisionIsUnscored(t *testing.T) {
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			raw := readGoldenRaw(t, tc.Name)
			for i, r := range raw {
				if r.Risk.Level == nil {
					t.Fatalf("record %d has no risk.level field at all", i)
				}
				if !decision.ValidLevel(decision.Level(*r.Risk.Level)) {
					t.Errorf("record %d (%s) has risk.level %q, which is not a member of decision.AllLevels; "+
						"this is the unscored shape the shipped schema rejects",
						i, r.EventID, *r.Risk.Level)
				}
				if r.Risk.Factors == nil {
					t.Errorf("record %d (%s) has risk.factors null rather than an array; "+
						"this is the unscored shape the shipped schema rejects", i, r.EventID)
				}
			}
		})
	}
}

// TestGoldenEnvelopesAreAdmissible runs the committed envelopes through the
// admission linter the daemon would run before sealing one.
//
// A golden generated against an envelope the system would refuse would be a
// regression guard for a session that could never happen.
func TestGoldenEnvelopesAreAdmissible(t *testing.T) {
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			env := loadEnvelope(t, filepath.Join(envelopeDir, tc.Name+".json"))
			issues := validator.LintEnvelope(env)

			// Only a blocking issue fails. The linter reports judgment calls
			// too — a broad pattern, an unanchored glob — and a fixture written
			// the way a real envelope would be written is expected to draw some
			// of those. They are logged so a reader can see what the shipped
			// linter thinks of a realistic envelope.
			for _, issue := range validator.BlockingIssues(issues) {
				t.Errorf("envelope is inadmissible: %s: %s: %s",
					issue.Field, issue.Severity, issue.Message)
			}
			for _, issue := range issues {
				t.Logf("lint: %s: %s: %s", issue.Field, issue.Severity, issue.Message)
			}
		})
	}
}

// TestGoldenRecordingsMatchTheirEnvelopes catches the fixture-level mismatch a
// byte comparison would happily bless: a recording replayed against an envelope
// sealed for a different session.
func TestGoldenRecordingsMatchTheirEnvelopes(t *testing.T) {
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			env := loadEnvelope(t, filepath.Join(envelopeDir, tc.Name+".json"))
			for i, d := range readGolden(t, tc.Name) {
				if d.SessionID != env.SessionID {
					t.Fatalf("record %d is stamped session %q; the envelope governs %q",
						i, d.SessionID, env.SessionID)
				}
			}
		})
	}
}

// --- expectations ---------------------------------------------------------------

// finding is what the system concluded about one event.
type finding struct {
	EventID   string
	SessionID string
	Verdict   decision.Verdict
	Score     float64
	Level     decision.Level
	Rule      string
	Action    ece.Action

	// Factors are the scorer names that contributed, in the order the engine
	// reports them. Names rather than weights: this test pins which heuristics
	// fired, and what each is worth is internal/risk's own business.
	Factors []string

	// Evidence is a spot check on individual factor evidence keys, for the
	// events where the *reason* is the finding rather than the score.
	Evidence map[string]string
}
