package golden

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stringNameMahin/ALLSEER/internal/policy"
	"github.com/stringNameMahin/ALLSEER/internal/risk"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
)

// policyEngine builds the engine over the shipped rule set.
//
// The shipped file, not a rule set written for this test. A golden asserted
// against bespoke rules would pin the test's own rules and say nothing about
// what an operator installing ALLSEER would get, and configs/rules.default.yaml
// is one of the artifacts most likely to be edited without anyone noticing what
// it changes downstream.
func policyEngine(t *testing.T) *policy.RuleEngine {
	t.Helper()

	rs, err := policy.NewLoader().Load(context.Background(), filepath.FromSlash(rulesPath))
	if err != nil {
		t.Fatalf("loading %s: %v", rulesPath, err)
	}
	e, err := policy.NewEngine(rs)
	if err != nil {
		t.Fatalf("building the policy engine: %v", err)
	}
	return e
}

// riskEngine builds the baseline engine with the shipped sensitivity list
// behind it.
//
// With no oracle the engine rates no resource, and sensitive_path,
// sensitive_host, and the credential half of the sequence detector all go
// quiet -- which is a legitimate configuration and the wrong one to pin here.
// The golden exists to show what the system concludes when it is configured the
// way it ships.
func riskEngine(t *testing.T) *risk.BaselineEngine {
	t.Helper()

	oracle, err := risk.LoadResourceOracle(filepath.FromSlash(sensPath))
	if err != nil {
		t.Fatalf("loading %s: %v", sensPath, err)
	}
	e, err := risk.NewEngineWithOracle(oracle)
	if err != nil {
		t.Fatalf("building the risk engine: %v", err)
	}
	return e
}

// loadEnvelope reads a committed envelope fixture.
//
// Unknown fields are tolerated, matching cmd/allseerctl's loader: an envelope is
// a wire document that may have been written by a newer build, and the fixtures
// carry a "$comment" explaining what each one is for. What the document must
// have is checked by the linter in TestGoldenEnvelopesAreAdmissible rather than
// by strictness here.
func loadEnvelope(t *testing.T, path string) *ece.Envelope {
	t.Helper()

	data, err := os.ReadFile(filepath.FromSlash(path))
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var env ece.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	return &env
}

// readGolden decodes a committed stream into decisions.
func readGolden(t *testing.T, name string) []decision.Decision {
	t.Helper()

	path := filepath.Join(goldenDir, name+".decisions.jsonl")
	data, err := os.ReadFile(filepath.FromSlash(path))
	if err != nil {
		t.Fatalf("reading %s: %v\nrun `make golden` to create it", path, err)
	}

	var out []decision.Decision
	for i, line := range splitLines(t, data) {
		var d decision.Decision
		if err := json.Unmarshal([]byte(line), &d); err != nil {
			t.Fatalf("%s line %d: %v", path, i, err)
		}
		out = append(out, d)
	}
	return out
}

// rawRecord is the decision as it appears on the wire, with the two fields the
// schema question turns on kept distinguishable from their zero values.
//
// decision.Decision cannot answer it: Risk is a value and Level is a string, so
// an absent level, an empty level, and a level of "none" all decode the same
// way. This is the only place in the tree that has to tell them apart.
type rawRecord struct {
	EventID string `json:"event_id"`
	Risk    struct {
		Level   *string           `json:"level"`
		Factors []decision.Factor `json:"factors"`
	} `json:"risk"`
}

func readGoldenRaw(t *testing.T, name string) []rawRecord {
	t.Helper()

	path := filepath.Join(goldenDir, name+".decisions.jsonl")
	data, err := os.ReadFile(filepath.FromSlash(path))
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}

	var out []rawRecord
	for i, line := range splitLines(t, data) {
		var r rawRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("%s line %d: %v", path, i, err)
		}
		out = append(out, r)
	}
	return out
}

// splitLines returns the stream's lines without the trailing empty one.
func splitLines(t *testing.T, data []byte) []string {
	t.Helper()

	var out []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scanning the stream: %v", err)
	}
	return out
}

// factorNames lists the scorers that contributed, in engine order.
func factorNames(d decision.Decision) []string {
	out := make([]string, 0, len(d.Risk.Factors))
	for _, f := range d.Risk.Factors {
		out = append(out, f.Name)
	}
	return out
}

// evidenceOf finds one evidence value across every factor on a decision.
//
// Flattened across factors because the assertion is about what the record can
// tell a human -- "which path was rated", "which antecedent the sequence
// detector named" -- and which scorer happened to attach the key is the detail
// the caller should not have to track.
func evidenceOf(d decision.Decision, key string) string {
	for _, f := range d.Risk.Factors {
		if v, ok := f.Evidence[key]; ok {
			return v
		}
	}
	return ""
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// reportDiff prints the first differing line and the surrounding counts.
//
// A whole-file dump of two JSONL streams is unreadable, and the first
// divergence is almost always the entire story: the pipeline is serial and
// history-dependent, so one changed decision usually changes the ones after it.
func reportDiff(t *testing.T, name string, want, got []byte) {
	t.Helper()

	wl, gl := splitLines(t, want), splitLines(t, got)
	for i := 0; i < len(wl) && i < len(gl); i++ {
		if wl[i] != gl[i] {
			t.Fatalf("%s: stream differs at record %d (%d records before, %d after)\n"+
				"want: %s\n got: %s\n\n"+
				"If this change is intended, regenerate with `make golden` and review the diff.",
				name, i, len(wl), len(gl), wl[i], gl[i])
		}
	}
	t.Fatalf("%s: streams agree on their first %d records but hold %d and %d records\n\n"+
		"If this change is intended, regenerate with `make golden` and review the diff.",
		name, min(len(wl), len(gl)), len(wl), len(gl))
}
