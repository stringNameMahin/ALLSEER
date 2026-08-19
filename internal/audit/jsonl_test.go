package audit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stringNameMahin/ALLSEER/internal/config"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
)

// --- fixtures ----------------------------------------------------------------

// stamp is a fixed wall clock. Constructed in UTC so a JSON round trip compares
// equal: a Time carrying a monotonic reading or a named location does not
// survive RFC 3339 unchanged, and a test that used time.Now() would be
// asserting the encoding of the clock rather than of the decision.
var stamp = time.Date(2026, 3, 2, 12, 40, 0, 1_000_000, time.UTC)

// scored is a fully populated decision: every optional field present, so the
// serializer is exercised over the whole type rather than over its common case.
func scored() decision.Decision {
	return decision.Decision{
		ID:        "d-gt-008",
		SessionID: "s-git",
		EventID:   "gt-008",
		Timestamp: stamp,
		Action:    ece.ActionBlock,
		Verdict:   decision.VerdictExplicitlyDenied,
		Risk: decision.RiskAssessment{
			Score: 73.5,
			Level: decision.LevelHigh,
			Factors: []decision.Factor{{
				Name:        "sensitive_path",
				Weight:      30,
				Description: "write to CI configuration",
				Evidence:    map[string]string{"path": "/home/dev/project/.github/workflows/release.yml"},
			}},
			Confidence: 0.8,
		},
		Reasoning: []decision.ReasoningStep{
			{Stage: "validate", Conclusion: "explicitly denied", Detail: "denial matched before any grant"},
			{Stage: "decide", Conclusion: "block"},
		},
		MatchedRule: "explicit-denial",
		Latency:     421 * time.Microsecond,
		Enforced:    false,
	}
}

// unscored is the shape both an unscored pipeline and every stage failure
// produce: Decision.Risk is a value, so a decision nothing scored still carries
// a zero RiskAssessment. See contradiction 1 in the package doc.
func unscored() decision.Decision {
	return decision.Decision{
		ID:        "d-gt-009",
		SessionID: "s-git",
		EventID:   "gt-009",
		Timestamp: stamp,
		Action:    ece.ActionRequestApproval,
		Verdict:   decision.VerdictIndeterminate,
		Reasoning: []decision.ReasoningStep{
			{Stage: "pipeline", Conclusion: `stage "score" failed`, Detail: "unreadable input"},
		},
	}
}

// allowed is the routine case RecordAllEvents=false suppresses.
func allowed(id string) decision.Decision {
	return decision.Decision{
		ID:        "d-" + id,
		SessionID: "s-git",
		EventID:   id,
		Timestamp: stamp,
		Action:    ece.ActionAllow,
		Verdict:   decision.VerdictWithinEnvelope,
		Risk:      decision.RiskAssessment{Level: decision.LevelNone, Factors: []decision.Factor{}},
		Reasoning: []decision.ReasoningStep{{Stage: "validate", Conclusion: "within envelope"}},
		MatchedGrant: &capability.Grant{
			Kind:     capability.KindFileWrite,
			Domain:   capability.DomainFilesystem,
			Selector: capability.Selector{PathPatterns: []string{"/home/dev/project/**"}},
		},
		MatchedRule: "default",
	}
}

// openSink opens a sink over a fresh temporary file and closes it on cleanup.
func openSink(t *testing.T, cfg config.AuditConfig) (*JSONLSink, string) {
	t.Helper()
	if cfg.Path == "" {
		cfg.Path = filepath.Join(t.TempDir(), "audit.jsonl")
	}
	s, err := Open(cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, cfg.Path
}

// lines reads the audit file back as its non-empty lines.
func lines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	if len(data) == 0 {
		return nil
	}
	if !bytes.HasSuffix(data, []byte("\n")) {
		t.Errorf("audit file does not end in a newline; a JSONL reader would see a truncated record")
	}
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) != "" {
			out = append(out, sc.Text())
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scanning %s: %v", path, err)
	}
	return out
}

// --- basic writing -----------------------------------------------------------

func TestOneDecisionIsOneLine(t *testing.T) {
	s, path := openSink(t, config.AuditConfig{RecordAllEvents: true})

	if err := s.Emit(context.Background(), scored()); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	got := lines(t, path)
	if len(got) != 1 {
		t.Fatalf("audit file has %d lines, want 1:\n%s", len(got), strings.Join(got, "\n"))
	}
	var back decision.Decision
	if err := json.Unmarshal([]byte(got[0]), &back); err != nil {
		t.Fatalf("the line is not valid JSON: %v\nline: %s", err, got[0])
	}
	if back.ID != "d-gt-008" {
		t.Errorf("decoded ID = %q, want %q", back.ID, "d-gt-008")
	}
	if st := s.Stats(); st.Written != 1 || st.Filtered != 0 || st.Errors != 0 {
		t.Errorf("Stats = %+v, want Written 1 and nothing else", st)
	}
}

func TestEachDecisionOccupiesItsOwnLine(t *testing.T) {
	s, path := openSink(t, config.AuditConfig{RecordAllEvents: true})

	want := []decision.Decision{scored(), unscored(), allowed("gt-001")}
	for _, d := range want {
		if err := s.Emit(context.Background(), d); err != nil {
			t.Fatalf("Emit %s: %v", d.ID, err)
		}
	}

	got := lines(t, path)
	if len(got) != len(want) {
		t.Fatalf("audit file has %d lines, want %d", len(got), len(want))
	}
	for i, line := range got {
		var back decision.Decision
		if err := json.Unmarshal([]byte(line), &back); err != nil {
			t.Fatalf("line %d is not valid JSON: %v", i, err)
		}
		if back.ID != want[i].ID {
			t.Errorf("line %d has ID %q, want %q; order must be emission order", i, back.ID, want[i].ID)
		}
		// One object per line means no embedded newline, whatever the payload
		// contains. Reasoning details are free text written by stages.
		if strings.ContainsAny(line, "\n\r") {
			t.Errorf("line %d contains an embedded newline", i)
		}
	}
}

// The audit log of the previous run is the least recoverable data the daemon
// holds, and destroying it on startup is what an attacker who can restart the
// daemon would want.
func TestOpenAppendsAndDoesNotTruncate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	const existing = `{"id":"d-from-a-previous-run"}` + "\n"
	if err := os.WriteFile(path, []byte(existing), FileMode); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	s, err := Open(config.AuditConfig{Path: path, Format: FormatJSONL, RecordAllEvents: true})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.Emit(context.Background(), scored()); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	got := lines(t, path)
	if len(got) != 2 {
		t.Fatalf("file has %d lines, want 2 (the seeded record plus the new one)", len(got))
	}
	if !strings.Contains(got[0], "d-from-a-previous-run") {
		t.Errorf("first line is %q; the pre-existing record must survive", got[0])
	}
	if !strings.Contains(got[1], "d-gt-008") {
		t.Errorf("second line is %q; the new record must be appended after it", got[1])
	}
}

// Reopening must append rather than start over, which is the property a daemon
// restart depends on.
func TestReopenAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	cfg := config.AuditConfig{Path: path, RecordAllEvents: true}

	for i := 0; i < 3; i++ {
		s, err := Open(cfg)
		if err != nil {
			t.Fatalf("Open %d: %v", i, err)
		}
		d := scored()
		d.ID = fmt.Sprintf("d-run-%d", i)
		if err := s.Emit(context.Background(), d); err != nil {
			t.Fatalf("Emit %d: %v", i, err)
		}
		if err := s.Close(); err != nil {
			t.Fatalf("Close %d: %v", i, err)
		}
	}

	if got := lines(t, path); len(got) != 3 {
		t.Fatalf("file has %d lines after three sessions, want 3", len(got))
	}
}

// A sink that recorded nothing must leave an empty file rather than a blank
// line, so a reader cannot mistake "nothing happened" for a malformed record.
func TestEmptySinkWritesNothing(t *testing.T) {
	s, path := openSink(t, config.AuditConfig{RecordAllEvents: true})

	if err := s.Flush(context.Background()); err != nil {
		t.Errorf("Flush on an empty sink = %v, want nil", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() != 0 {
		t.Errorf("empty sink wrote %d bytes, want 0", info.Size())
	}
	if st := s.Stats(); st != (Stats{}) {
		t.Errorf("Stats = %+v, want the zero value", st)
	}
}

// --- flush -------------------------------------------------------------------

func TestEmitThenFlushLeavesTheRecordPresent(t *testing.T) {
	s, path := openSink(t, config.AuditConfig{RecordAllEvents: true})

	if err := s.Emit(context.Background(), scored()); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := s.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got := lines(t, path); len(got) != 1 {
		t.Fatalf("file has %d lines after Emit+Flush, want 1", len(got))
	}
}

func TestManyEmitsThenFlushLeavesEveryRecord(t *testing.T) {
	s, path := openSink(t, config.AuditConfig{RecordAllEvents: true})

	const n = 50
	for i := 0; i < n; i++ {
		d := scored()
		d.ID = fmt.Sprintf("d-%03d", i)
		if err := s.Emit(context.Background(), d); err != nil {
			t.Fatalf("Emit %d: %v", i, err)
		}
	}
	if err := s.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	got := lines(t, path)
	if len(got) != n {
		t.Fatalf("file has %d lines, want %d", len(got), n)
	}
	for i, line := range got {
		want := fmt.Sprintf(`"id":"d-%03d"`, i)
		if !strings.Contains(line, want) {
			t.Fatalf("line %d does not contain %s", i, want)
		}
	}
}

// The settlement of contradiction 2: nothing in the pipeline calls Flush, so a
// record must already be readable without one. This is the test that would fail
// the moment somebody adds user-space buffering.
func TestRecordsSurviveWithoutAnyFlush(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s, err := Open(config.AuditConfig{Path: path, RecordAllEvents: true})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	for i := 0; i < 5; i++ {
		d := scored()
		d.ID = fmt.Sprintf("d-%d", i)
		if err := s.Emit(context.Background(), d); err != nil {
			t.Fatalf("Emit %d: %v", i, err)
		}
	}
	// No Flush, no Close: exactly what EventPipeline.Run does today.
	if got := lines(t, path); len(got) != 5 {
		t.Fatalf("file has %d lines with no Flush and no Close, want 5; the sink must not buffer across Emit", len(got))
	}
	_ = s.Close()
}

func TestCloseIsIdempotentAndSealsTheSink(t *testing.T) {
	s, path := openSink(t, config.AuditConfig{RecordAllEvents: true})

	if err := s.Emit(context.Background(), scored()); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("second Close = %v, want nil; Close is meant to be safe to defer", err)
	}
	if err := s.Emit(context.Background(), scored()); !errors.Is(err, ErrClosed) {
		t.Errorf("Emit after Close = %v, want ErrClosed", err)
	}
	if err := s.Flush(context.Background()); !errors.Is(err, ErrClosed) {
		t.Errorf("Flush after Close = %v, want ErrClosed", err)
	}
	if got := lines(t, path); len(got) != 1 {
		t.Errorf("file has %d lines, want 1; an Emit after Close must not reach the file", len(got))
	}
}

// A cancelled context is what shutdown looks like, and refusing to record then
// would drop exactly the decisions most worth having.
func TestCancelledContextStillRecords(t *testing.T) {
	s, path := openSink(t, config.AuditConfig{RecordAllEvents: true})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := s.Emit(ctx, scored()); err != nil {
		t.Fatalf("Emit with a cancelled context = %v, want nil", err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatalf("Flush with a cancelled context = %v, want nil", err)
	}
	if got := lines(t, path); len(got) != 1 {
		t.Errorf("file has %d lines, want 1", len(got))
	}
}

// --- serialization -----------------------------------------------------------

// The record on disk must be the decision, recoverable field for field. This is
// what makes the audit log the system's public product rather than a summary of
// it.
func TestSerializedRecordRoundTripsToTheDecision(t *testing.T) {
	s, path := openSink(t, config.AuditConfig{RecordAllEvents: true})

	for _, want := range []decision.Decision{scored(), unscored(), allowed("gt-001")} {
		if err := s.Emit(context.Background(), want); err != nil {
			t.Fatalf("Emit %s: %v", want.ID, err)
		}
	}

	got := lines(t, path)
	for i, want := range []decision.Decision{scored(), unscored(), allowed("gt-001")} {
		var back decision.Decision
		if err := json.Unmarshal([]byte(got[i]), &back); err != nil {
			t.Fatalf("decoding line %d: %v", i, err)
		}
		if !reflect.DeepEqual(back, want) {
			t.Errorf("line %d round trip mismatch\n got: %+v\nwant: %+v", i, back, want)
		}
	}
}

// The writer adds nothing of its own. A record with a field the type does not
// have is a second decision schema, and the point of using the type's own JSON
// encoding is that there is only one.
func TestNoFieldsAreFabricated(t *testing.T) {
	s, path := openSink(t, config.AuditConfig{RecordAllEvents: true})

	d := scored()
	if err := s.Emit(context.Background(), d); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	reference, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshalling the reference: %v", err)
	}
	line := lines(t, path)[0]
	if line != string(reference) {
		t.Errorf("the written line is not encoding/json's own encoding of the Decision\n got: %s\nwant: %s", line, reference)
	}

	var keys map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &keys); err != nil {
		t.Fatalf("decoding to a key map: %v", err)
	}
	want := map[string]bool{
		"id": true, "session_id": true, "event_id": true, "timestamp": true,
		"action": true, "verdict": true, "risk": true, "reasoning": true,
		"matched_rule": true, "latency": true, "enforced": true,
	}
	for k := range keys {
		if !want[k] {
			t.Errorf("unexpected top-level key %q in the audit record", k)
		}
	}
	for k := range want {
		if _, ok := keys[k]; !ok {
			t.Errorf("missing top-level key %q", k)
		}
	}
}

// A sink that normalized a record in place would silently change what the rest
// of the pipeline sees, including the state the pipeline is about to fold in.
func TestEmitDoesNotMutateTheDecision(t *testing.T) {
	s, _ := openSink(t, config.AuditConfig{RecordAllEvents: true})

	d := scored()
	d.MatchedGrant = &capability.Grant{
		Kind:     capability.KindFileWrite,
		Domain:   capability.DomainFilesystem,
		Selector: capability.Selector{PathPatterns: []string{"/home/dev/project/**"}},
	}
	before := deepCopy(t, d)

	if err := s.Emit(context.Background(), d); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if !reflect.DeepEqual(d, before) {
		t.Errorf("Emit mutated the caller's Decision\nafter: %+v\nbefore: %+v", d, before)
	}
	// The nested slices and maps are shared with the caller rather than copied,
	// so mutation of those has to be checked through the original pointers.
	if d.Risk.Factors[0].Evidence["path"] != before.Risk.Factors[0].Evidence["path"] {
		t.Error("Emit mutated a factor's evidence map")
	}
}

// Identical decisions must produce identical bytes, which is what makes the
// golden test that follows this feature possible at all. Map-valued Evidence is
// the field most likely to break it; encoding/json sorts map keys.
func TestIdenticalDecisionsSerializeIdentically(t *testing.T) {
	s, path := openSink(t, config.AuditConfig{RecordAllEvents: true})

	d := scored()
	d.Risk.Factors[0].Evidence = map[string]string{
		"path": "/home/dev/project/.github/workflows/release.yml",
		"rule": "explicit-denial",
		"kind": "fs.write",
	}
	for i := 0; i < 8; i++ {
		if err := s.Emit(context.Background(), d); err != nil {
			t.Fatalf("Emit %d: %v", i, err)
		}
	}

	got := lines(t, path)
	for i, line := range got[1:] {
		if line != got[0] {
			t.Fatalf("line %d differs from line 0; serialization is not deterministic\n got: %s\nwant: %s", i+1, line, got[0])
		}
	}
}

// Contradiction 1, pinned. An unscored decision reaches disk with an empty risk
// level and a null factor list, neither of which
// api/schema/decision.v1alpha1.schema.json admits. The writer does not repair
// it: "" is how a consumer tells unscored from scored-none, and a fabricated
// level would be an assessment nobody made.
//
// This test is deliberately a shape assertion rather than a schema check. When
// the wire-format decision is finally taken — an "unscored" level, a pointer
// Risk, or an anyOf in the schema — this fails and says so here.
func TestUnscoredDecisionIsWrittenFaithfully(t *testing.T) {
	s, path := openSink(t, config.AuditConfig{RecordAllEvents: true})

	if err := s.Emit(context.Background(), unscored()); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	line := lines(t, path)[0]

	var raw struct {
		Risk struct {
			Score      float64           `json:"score"`
			Level      *string           `json:"level"`
			Factors    []decision.Factor `json:"factors"`
			Confidence float64           `json:"confidence"`
		} `json:"risk"`
	}
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if raw.Risk.Level == nil {
		t.Fatal("risk.level is absent; it must be present and empty, not omitted")
	}
	if *raw.Risk.Level != "" {
		t.Errorf(`risk.level = %q, want ""; the sink must not invent a level for an unscored decision`, *raw.Risk.Level)
	}
	if decision.ValidLevel(decision.Level(*raw.Risk.Level)) {
		t.Error("the empty level is a member of decision.AllLevels; unscored is no longer distinguishable from scored")
	}
	if !strings.Contains(line, `"factors":null`) {
		t.Errorf(`the record does not carry "factors":null; the sink must not substitute an empty array`+"\nline: %s", line)
	}
	if raw.Risk.Score != 0 || raw.Risk.Confidence != 0 {
		t.Errorf("score/confidence = %v/%v, want 0/0", raw.Risk.Score, raw.Risk.Confidence)
	}
}

// --- configuration -----------------------------------------------------------

func TestFormatHandling(t *testing.T) {
	for _, tc := range []struct {
		name    string
		format  string
		wantErr error
	}{
		{"explicit jsonl", FormatJSONL, nil},
		{"empty means jsonl", "", nil},
		{"cbor is named by config and not implemented", "cbor", ErrUnsupportedFormat},
		{"unknown format", "parquet", ErrUnsupportedFormat},
		{"case is not normalized", "JSONL", ErrUnsupportedFormat},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.jsonl")
			s, err := Open(config.AuditConfig{Path: path, Format: tc.format})
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Open = %v, want %v", err, tc.wantErr)
				}
				if s != nil {
					t.Error("Open returned a sink alongside an error")
				}
				if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
					t.Error("a refused format still created the file; nothing should be opened before the format is checked")
				}
				return
			}
			if err != nil {
				t.Fatalf("Open = %v, want nil", err)
			}
			_ = s.Close()
		})
	}
}

func TestOpenWithoutAPathIsRefused(t *testing.T) {
	if _, err := Open(config.AuditConfig{}); !errors.Is(err, ErrNoPath) {
		t.Errorf("Open with no path = %v, want ErrNoPath", err)
	}
}

// RecordAllEvents answers the question config.AuditConfig poses and does not
// settle: whether an allow is recorded.
func TestRecordAllEventsSelectsWhatIsRecorded(t *testing.T) {
	for _, tc := range []struct {
		name        string
		recordAll   bool
		wantWritten int
		wantIDs     []string
	}{
		{"off records only the non-routine", false, 2, []string{"d-gt-008", "d-gt-009"}},
		{"on records everything", true, 3, []string{"d-gt-008", "d-gt-009", "d-gt-001"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, path := openSink(t, config.AuditConfig{RecordAllEvents: tc.recordAll})

			for _, d := range []decision.Decision{scored(), unscored(), allowed("gt-001")} {
				if err := s.Emit(context.Background(), d); err != nil {
					t.Fatalf("Emit %s: %v", d.ID, err)
				}
			}

			got := lines(t, path)
			if len(got) != tc.wantWritten {
				t.Fatalf("file has %d lines, want %d", len(got), tc.wantWritten)
			}
			for i, id := range tc.wantIDs {
				if !strings.Contains(got[i], `"id":"`+id+`"`) {
					t.Errorf("line %d does not carry %s", i, id)
				}
			}
			st := s.Stats()
			if st.Written != uint64(tc.wantWritten) {
				t.Errorf("Stats.Written = %d, want %d", st.Written, tc.wantWritten)
			}
			if want := uint64(3 - tc.wantWritten); st.Filtered != want {
				t.Errorf("Stats.Filtered = %d, want %d; a suppressed record must still be counted", st.Filtered, want)
			}
		})
	}
}

// A within-envelope event that policy did not simply allow is not routine. Both
// halves of the predicate matter, and a filter that looked only at the verdict
// would swallow every risk-conditioned warning on a granted operation.
func TestWithinEnvelopeButNotAllowedIsStillRecorded(t *testing.T) {
	s, path := openSink(t, config.AuditConfig{RecordAllEvents: false})

	d := allowed("gt-002")
	d.Action = ece.ActionWarn
	d.MatchedRule = "granted-but-high-risk"
	if err := s.Emit(context.Background(), d); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	if got := lines(t, path); len(got) != 1 {
		t.Fatalf("file has %d lines, want 1; a warn on a granted operation is the finding a rule exists to produce", len(got))
	}
}

// --- SyncWrites --------------------------------------------------------------

// countingFile records what the sink asked the file to do.
type countingFile struct {
	buf    bytes.Buffer
	writes int
	syncs  int
	closes int

	writeErr error
	syncErr  error
	closeErr error
}

func (f *countingFile) Write(p []byte) (int, error) {
	f.writes++
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	return f.buf.Write(p)
}

func (f *countingFile) Sync() error {
	f.syncs++
	return f.syncErr
}

func (f *countingFile) Close() error {
	f.closes++
	return f.closeErr
}

// Contradiction 3, both sides. SyncWrites is the operator's explicit choice to
// trade latency for durability, and it is the one setting under which the sink
// is allowed to block.
func TestSyncWrites(t *testing.T) {
	for _, tc := range []struct {
		name      string
		sync      bool
		wantSyncs int
	}{
		{"false does not fsync per record", false, 0},
		{"true fsyncs every record", true, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &countingFile{}
			s := newSink(f, config.AuditConfig{SyncWrites: tc.sync, RecordAllEvents: true})

			for i := 0; i < 3; i++ {
				if err := s.Emit(context.Background(), scored()); err != nil {
					t.Fatalf("Emit %d: %v", i, err)
				}
			}
			if f.writes != 3 {
				t.Errorf("writes = %d, want 3; one write per record either way", f.writes)
			}
			if f.syncs != tc.wantSyncs {
				t.Errorf("syncs = %d, want %d", f.syncs, tc.wantSyncs)
			}

			// Flush syncs regardless, so a caller never has to know the mode.
			if err := s.Flush(context.Background()); err != nil {
				t.Fatalf("Flush: %v", err)
			}
			if f.syncs != tc.wantSyncs+1 {
				t.Errorf("syncs after Flush = %d, want %d", f.syncs, tc.wantSyncs+1)
			}
		})
	}
}

// Whichever mode is in force, the bytes on disk are the same. Durability is not
// allowed to change the record.
func TestSyncWritesDoesNotChangeTheBytes(t *testing.T) {
	var written [2]string
	for i, sync := range []bool{false, true} {
		s, path := openSink(t, config.AuditConfig{SyncWrites: sync, RecordAllEvents: true})
		if err := s.Emit(context.Background(), scored()); err != nil {
			t.Fatalf("Emit (sync=%v): %v", sync, err)
		}
		written[i] = lines(t, path)[0]
	}
	if written[0] != written[1] {
		t.Errorf("SyncWrites changed the record\n false: %s\n  true: %s", written[0], written[1])
	}
}

// --- errors ------------------------------------------------------------------

func TestOpenFailure(t *testing.T) {
	dir := t.TempDir()

	for _, tc := range []struct{ name, path string }{
		{"the path is a directory", dir},
		{"the parent directory does not exist", filepath.Join(dir, "missing", "audit.jsonl")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := Open(config.AuditConfig{Path: tc.path, Format: FormatJSONL})
			if err == nil {
				_ = s.Close()
				t.Fatal("Open succeeded, want an error")
			}
			if !strings.Contains(err.Error(), "audit: opening") {
				t.Errorf("error = %q, want it to name the failed open", err)
			}
			if !strings.Contains(err.Error(), tc.path) {
				t.Errorf("error = %q, want it to name the path", err)
			}
		})
	}
}

func TestWriteFailureIsReportedAndCounted(t *testing.T) {
	f := &countingFile{writeErr: errors.New("disk full")}
	s := newSink(f, config.AuditConfig{RecordAllEvents: true})

	err := s.Emit(context.Background(), scored())
	if err == nil {
		t.Fatal("Emit succeeded over a failing writer")
	}
	if !strings.Contains(err.Error(), "disk full") {
		t.Errorf("error = %q, want the underlying cause preserved", err)
	}
	if !strings.Contains(err.Error(), "d-gt-008") {
		t.Errorf("error = %q, want it to name the decision that was lost", err)
	}
	if st := s.Stats(); st.Errors != 1 || st.Written != 0 {
		t.Errorf("Stats = %+v, want Errors 1 and Written 0", st)
	}

	// The sink stays usable. An audit failure must not be able to end
	// governance, and the pipeline keeps calling Emit after one.
	f.writeErr = nil
	if err := s.Emit(context.Background(), scored()); err != nil {
		t.Errorf("Emit after a failed write = %v, want nil", err)
	}
	if st := s.Stats(); st.Written != 1 {
		t.Errorf("Stats.Written = %d, want 1", st.Written)
	}
}

func TestSyncFailureIsReportedByEmitAndFlush(t *testing.T) {
	f := &countingFile{syncErr: errors.New("fsync failed")}
	s := newSink(f, config.AuditConfig{SyncWrites: true, RecordAllEvents: true})

	err := s.Emit(context.Background(), scored())
	if err == nil || !strings.Contains(err.Error(), "fsync failed") {
		t.Errorf("Emit under a failing fsync = %v, want the fsync error", err)
	}

	if err := s.Flush(context.Background()); err == nil || !strings.Contains(err.Error(), "fsync failed") {
		t.Errorf("Flush under a failing fsync = %v, want the fsync error", err)
	}
	if st := s.Stats(); st.Errors != 2 {
		t.Errorf("Stats.Errors = %d, want 2", st.Errors)
	}

	// Close reports the same failure rather than swallowing it, since a close
	// that could not sync has not made the log durable.
	if err := s.Close(); err == nil || !strings.Contains(err.Error(), "fsync failed") {
		t.Errorf("Close under a failing fsync = %v, want the fsync error", err)
	}
	if f.closes != 1 {
		t.Errorf("closes = %d, want 1; the descriptor must be released even when the sync failed", f.closes)
	}
}

// A record that failed to encode is reported rather than written, so a
// half-serialized line cannot reach the file.
func TestEncodeFailureIsReported(t *testing.T) {
	f := &countingFile{}
	s := newSink(f, config.AuditConfig{RecordAllEvents: true})

	d := scored()
	d.Risk.Score = math.Inf(1) // JSON has no infinity

	err := s.Emit(context.Background(), d)
	if err == nil {
		t.Fatal("Emit succeeded on an unencodable decision")
	}
	if f.writes != 0 {
		t.Errorf("writes = %d, want 0; nothing may reach the file when encoding failed", f.writes)
	}
	if st := s.Stats(); st.Errors != 1 || st.Written != 0 {
		t.Errorf("Stats = %+v, want Errors 1 and Written 0", st)
	}
}

// --- concurrency -------------------------------------------------------------

// The pipeline serializes one session on one goroutine, but a sink is a
// process-wide resource several session pipelines are expected to share, and
// Flush and Close arrive from shutdown. Interleaving inside a line would corrupt
// two records at once.
func TestConcurrentEmitProducesWholeLines(t *testing.T) {
	s, path := openSink(t, config.AuditConfig{RecordAllEvents: true})

	const writers, each = 8, 40
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				d := scored()
				d.ID = fmt.Sprintf("d-%d-%d", w, i)
				d.SessionID = fmt.Sprintf("s-%d", w)
				if err := s.Emit(context.Background(), d); err != nil {
					t.Errorf("Emit: %v", err)
					return
				}
			}
			// Flush and Stats from the same goroutines, since a shutdown path
			// really does call them while others are still emitting.
			if err := s.Flush(context.Background()); err != nil {
				t.Errorf("Flush: %v", err)
			}
			_ = s.Stats()
		}(w)
	}
	wg.Wait()

	got := lines(t, path)
	if len(got) != writers*each {
		t.Fatalf("file has %d lines, want %d", len(got), writers*each)
	}
	seen := make(map[string]bool, len(got))
	for i, line := range got {
		var d decision.Decision
		if err := json.Unmarshal([]byte(line), &d); err != nil {
			t.Fatalf("line %d is not a whole JSON object: %v\nline: %s", i, err, line)
		}
		if seen[d.ID] {
			t.Errorf("decision %s appears twice", d.ID)
		}
		seen[d.ID] = true
	}
	if st := s.Stats(); st.Written != uint64(writers*each) {
		t.Errorf("Stats.Written = %d, want %d", st.Written, writers*each)
	}
}

// --- security ----------------------------------------------------------------

// An audit log an agent can read tells it what is watched, and one it can write
// lets it rewrite the evidence.
func TestCreatedFileIsNotReadableByOthers(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Windows maps Go's mode bits onto ACLs approximately, so os.Stat
		// reports what the syscall layer synthesized rather than the real ACL.
		// Asserting 0600 here would be asserting a translation rather than a
		// permission, which is the kind of platform guarantee this project
		// declines to claim it can verify.
		t.Skip("file mode bits are not a meaningful assertion on Windows")
	}

	_, path := openSink(t, config.AuditConfig{RecordAllEvents: true})

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("audit file mode = %04o, want no group or world bits", perm)
	}
	if perm := info.Mode().Perm(); perm != FileMode.Perm() {
		t.Errorf("audit file mode = %04o, want %04o", perm, FileMode.Perm())
	}
}

// The mode of a file the operator placed is theirs, not this package's.
func TestExistingFileKeepsItsMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file mode bits are not a meaningful assertion on Windows")
	}

	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(path, nil, 0o640); err != nil {
		t.Fatalf("seeding: %v", err)
	}
	s, err := Open(config.AuditConfig{Path: path})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o640 {
		t.Errorf("mode = %04o, want 0640 unchanged; Open must not chmod a file it did not create", got)
	}
}

// --- helpers -----------------------------------------------------------------

// deepCopy round trips a decision through JSON to get an independent value,
// which is what lets a mutation test compare against the input as it was.
func deepCopy(t *testing.T, d decision.Decision) decision.Decision {
	t.Helper()
	data, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("copying: %v", err)
	}
	var out decision.Decision
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("copying: %v", err)
	}
	return out
}

// --- benchmarks ---------------------------------------------------------------

// The cost charged per governed syscall in enforce mode is the number that
// decides whether auditing can be left on. These measure the sink alone;
// BenchmarkProcess in internal/pipeline measures the decision path it follows.
func BenchmarkEmit(b *testing.B) {
	benchEmit(b, false)
}

// SyncWrites is the operator's explicit trade, and the size of it is worth
// knowing rather than guessing: this is an fsync per governed syscall.
func BenchmarkEmitSyncWrites(b *testing.B) {
	benchEmit(b, true)
}

func benchEmit(b *testing.B, sync bool) {
	b.Helper()
	path := filepath.Join(b.TempDir(), "audit.jsonl")
	s, err := Open(config.AuditConfig{Path: path, SyncWrites: sync, RecordAllEvents: true})
	if err != nil {
		b.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()

	d := scored()
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := s.Emit(ctx, d); err != nil {
			b.Fatalf("Emit: %v", err)
		}
	}
}

// Serialization on its own, with the file taken out of the measurement, so a
// regression in the encoder can be told apart from a slower disk.
func BenchmarkEmitToDiscard(b *testing.B) {
	s := newSink(discard{}, config.AuditConfig{RecordAllEvents: true})
	d := scored()
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := s.Emit(ctx, d); err != nil {
			b.Fatalf("Emit: %v", err)
		}
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
func (discard) Sync() error                 { return nil }
func (discard) Close() error                { return nil }

var _ io.Writer = discard{}
