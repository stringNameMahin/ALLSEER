package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stringNameMahin/ALLSEER/internal/policy"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
)

// The envelope a `git commit` session would have been governed by, matching
// test/testdata/replay/git-operation.jsonl: workspace-wide filesystem grants
// with CI configuration carved out by a denial. It is written as JSON rather
// than built in Go because the command's job includes reading one.
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

const gitEvents = "../../test/testdata/replay/git-operation.jsonl"

func defaultRules() string { return filepath.Join("..", "..", "configs", "rules.default.yaml") }

func writeFixture(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// captureStdout runs f with stdout redirected and returns what it wrote.
func captureStdout(t *testing.T, f func() int) (string, int) {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	saved := os.Stdout
	os.Stdout = w

	done := make(chan string, 1)
	go func() {
		var b strings.Builder
		_, _ = io.Copy(&b, r)
		done <- b.String()
	}()

	code := f()

	_ = w.Close()
	os.Stdout = saved
	return <-done, code
}

// dryRun runs the command with -json and decodes the per-event results, which
// is the shape a test can assert without depending on column widths.
func dryRun(t *testing.T, args ...string) ([]dryRunResult, int) {
	t.Helper()

	out, code := captureStdout(t, func() int {
		return run(append([]string{"policy", "dry-run", "-json", "-quiet"}, args...))
	})

	var results []dryRunResult
	dec := json.NewDecoder(strings.NewReader(out))
	for {
		var r dryRunResult
		if err := dec.Decode(&r); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("decoding output: %v\noutput was:\n%s", err, out)
		}
		results = append(results, r)
	}
	return results, code
}

// --- the happy path ---------------------------------------------------------

// TestDryRunOverRecordedSession is the command's reason to exist: a real
// recording, the shipped rule set, and a plausible envelope, producing the
// decisions the policy would have produced.
func TestDryRunOverRecordedSession(t *testing.T) {
	env := writeFixture(t, "envelope.json", gitEnvelope)
	results, code := dryRun(t, "-rules", defaultRules(), "-envelope", env, gitEvents)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if len(results) != 10 {
		t.Fatalf("got %d results, want 10 (one per recorded event)", len(results))
	}

	byEvent := map[string]dryRunResult{}
	for _, r := range results {
		byEvent[r.EventID] = r
	}

	want := []struct {
		id      string
		verdict decision.Verdict
		ruleID  string
		action  ece.Action
	}{
		{"gt-001", decision.VerdictWithinEnvelope, "within-envelope", ece.ActionAllow},
		{"gt-006", decision.VerdictWithinEnvelope, "within-envelope", ece.ActionAllow},
		// The carve-out: a write to CI configuration the envelope denied.
		{"gt-008", decision.VerdictExplicitlyDenied, "envelope-explicit-denial", ece.ActionBlock},
		// Reading an SSH key outside the workspace. The rule written for it,
		// workspace-escape-read, is risk-conditioned and cannot fire without a
		// risk engine, so this falls through to the posture — which is exactly
		// what the summary's caveat exists to explain.
		{"gt-009", decision.VerdictGrantExceeded, "default", ece.ActionWarn},
		{"gt-010", decision.VerdictWithinEnvelope, "within-envelope", ece.ActionAllow},
	}

	for _, w := range want {
		got, ok := byEvent[w.id]
		if !ok {
			t.Errorf("%s: no result", w.id)
			continue
		}
		if got.Verdict != w.verdict || got.RuleID != w.ruleID || got.Action != w.action {
			t.Errorf("%s: got %s/%s/%s, want %s/%s/%s",
				w.id, got.Verdict, got.RuleID, got.Action, w.verdict, w.ruleID, w.action)
		}
		if got.Reasoning == nil {
			t.Errorf("%s: no reasoning; the run would not explain itself", w.id)
		}
	}

	// The denial is reported with the violation that produced it, and the
	// escape is reported alongside the selector mismatch.
	if v := byEvent["gt-008"].Violations; len(v) != 1 || v[0] != "explicit_denial" {
		t.Errorf("gt-008 violations = %v, want [explicit_denial]", v)
	}
	if v := byEvent["gt-009"].Violations; len(v) != 2 || v[1] != "workspace_escape" {
		t.Errorf("gt-009 violations = %v, want the mismatch and the escape", v)
	}
}

// TestDryRunEnforcesNothing is the safety property. Nothing may be written,
// nothing may be applied, and the output must never claim otherwise.
func TestDryRunEnforcesNothing(t *testing.T) {
	env := writeFixture(t, "envelope.json", gitEnvelope)

	before := map[string][]byte{}
	for _, p := range []string{defaultRules(), env, gitEvents} {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		before[p] = data
	}

	// Enforce mode is the one that would act if anything could.
	results, code := dryRun(t, "-mode", "enforce", "-rules", defaultRules(), "-envelope", env, gitEvents)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	for p, want := range before {
		got, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("re-read %s: %v", p, err)
		}
		if string(got) != string(want) {
			t.Errorf("%s was modified by a dry run", p)
		}
	}

	var blocks int
	for _, r := range results {
		if r.Enforced {
			t.Errorf("%s reports enforced=true; nothing was applied", r.EventID)
		}
		if r.Action == ece.ActionBlock {
			blocks++
			if !r.WouldEnforce {
				t.Errorf("%s: a block in enforce mode should report would_enforce", r.EventID)
			}
		}
	}
	if blocks == 0 {
		t.Error("no event produced a block, so the property was not exercised")
	}
}

// TestDryRunModeChangesEnforcementNotAction pins the engine's rule at the CLI
// boundary: mode decides what enforcement would be asked to do, never what the
// policy decided.
func TestDryRunModeChangesEnforcementNotAction(t *testing.T) {
	env := writeFixture(t, "envelope.json", gitEnvelope)

	monitor, code := dryRun(t, "-mode", "monitor", "-rules", defaultRules(), "-envelope", env, gitEvents)
	if code != 0 {
		t.Fatalf("monitor exit code = %d", code)
	}
	enforce, code := dryRun(t, "-mode", "enforce", "-rules", defaultRules(), "-envelope", env, gitEvents)
	if code != 0 {
		t.Fatalf("enforce exit code = %d", code)
	}
	if len(monitor) != len(enforce) {
		t.Fatalf("event counts differ: %d and %d", len(monitor), len(enforce))
	}

	for i := range monitor {
		if monitor[i].Action != enforce[i].Action || monitor[i].RuleID != enforce[i].RuleID {
			t.Errorf("%s: mode changed the decision, %s/%s to %s/%s",
				monitor[i].EventID, monitor[i].RuleID, monitor[i].Action,
				enforce[i].RuleID, enforce[i].Action)
		}
		if monitor[i].WouldEnforce {
			t.Errorf("%s: monitor mode reports it would enforce", monitor[i].EventID)
		}
	}
}

// TestDryRunDefaultActionIsReported checks the fall-through path end to end,
// with a rule set that matches nothing in the recording.
func TestDryRunDefaultActionIsReported(t *testing.T) {
	rules := writeFixture(t, "rules.yaml", `
name: narrow
version: "1"
default_action: request_approval
rules:
  - id: kernel-only
    description: Nothing in a git session touches the kernel.
    priority: 100
    enabled: true
    match:
      domains: [kernel]
    action: block
`)
	env := writeFixture(t, "envelope.json", gitEnvelope)

	results, code := dryRun(t, "-rules", rules, "-envelope", env, gitEvents)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if len(results) == 0 {
		t.Fatal("no results")
	}
	for _, r := range results {
		if r.RuleID != "default" || r.Action != ece.ActionRequestApproval {
			t.Errorf("%s: got %s/%s, want default/request_approval", r.EventID, r.RuleID, r.Action)
		}
	}
}

// TestDryRunOverMultipleFixtures runs the other recorded sessions, including
// the lossy one, to check the command copes with what the corpus contains.
func TestDryRunOverMultipleFixtures(t *testing.T) {
	env := writeFixture(t, "envelope.json", gitEnvelope)

	for _, fixture := range []string{"go-build.jsonl", "npm-install.jsonl"} {
		t.Run(fixture, func(t *testing.T) {
			path := filepath.Join("..", "..", "test", "testdata", "replay", fixture)
			results, code := dryRun(t, "-rules", defaultRules(), "-envelope", env, path)
			if code != 0 {
				t.Fatalf("exit code = %d, want 0", code)
			}
			if len(results) == 0 {
				t.Fatal("no events evaluated")
			}
			for _, r := range results {
				if r.Verdict == "" || r.RuleID == "" || r.Action == "" {
					t.Errorf("%s: incomplete result %+v", r.EventID, r)
				}
			}
		})
	}
}

// --- refusals ---------------------------------------------------------------

func TestDryRunExitCodes(t *testing.T) {
	env := writeFixture(t, "envelope.json", gitEnvelope)
	missing := filepath.Join(t.TempDir(), "absent")

	// A rule set that loads and admits but cannot fire: the linter's job.
	deadRules := writeFixture(t, "dead.yaml", `
name: dead
version: "1"
default_action: warn
rules:
  - id: typo
    description: A verdict nothing produces.
    priority: 100
    enabled: true
    match:
      verdicts: [outside-envelope]
    action: block
`)

	// A denial whose pattern matches nothing, so verdicts under it would be
	// meaningless.
	brokenEnvelope := writeFixture(t, "broken.json", strings.Replace(gitEnvelope,
		`"path_patterns": ["/home/dev/project/.github/**"]`,
		`"path_patterns": ["/home/dev/project/**.github/**"]`, 1))

	corrupt := writeFixture(t, "corrupt.jsonl",
		"{\"id\":\"a\",\"session_id\":\"s\",\"sequence\":1,\"capability\":\"fs.read\",\"domain\":\"filesystem\"}\nnot json\n")

	tests := []struct {
		name string
		args []string
		want int
	}{
		{"no subcommand", []string{"policy"}, 2},
		{"unknown subcommand", []string{"policy", "bogus"}, 2},
		{"subcommand help", []string{"policy", "help"}, 0},
		{"no events file", []string{"policy", "dry-run", "-rules", defaultRules(), "-envelope", env}, 2},
		{"no rules flag", []string{"policy", "dry-run", "-envelope", env, gitEvents}, 2},
		{"no envelope flag", []string{"policy", "dry-run", "-rules", defaultRules(), gitEvents}, 2},
		{"unknown mode", []string{"policy", "dry-run", "-mode", "paranoid", "-rules", defaultRules(), "-envelope", env, gitEvents}, 2},
		{"missing rule set", []string{"policy", "dry-run", "-rules", missing, "-envelope", env, gitEvents}, 1},
		{"unlintable rule set", []string{"policy", "dry-run", "-rules", deadRules, "-envelope", env, gitEvents}, 1},
		{"missing envelope", []string{"policy", "dry-run", "-rules", defaultRules(), "-envelope", missing, gitEvents}, 1},
		{"envelope that denies nothing", []string{"policy", "dry-run", "-rules", defaultRules(), "-envelope", brokenEnvelope, gitEvents}, 1},
		{"missing events file", []string{"policy", "dry-run", "-rules", defaultRules(), "-envelope", env, missing}, 1},
		// A truncated recording is a partial session, and a dry run over one
		// must not exit 0: whatever consumed it would read a partial answer as
		// a complete one.
		{"corrupt stream", []string{"policy", "dry-run", "-quiet", "-rules", defaultRules(), "-envelope", env, corrupt}, 1},
		{"corrupt stream skipping", []string{"policy", "dry-run", "-quiet", "-skip-malformed", "-rules", defaultRules(), "-envelope", env, corrupt}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, code := captureStdout(t, func() int { return run(tt.args) })
			if code != tt.want {
				t.Errorf("run(%q) = %d, want %d\nstdout:\n%s", tt.args, code, tt.want, out)
			}
		})
	}
}

// TestDryRunRefusesABadEnvelopeSchema keeps the envelope's own rule at the
// boundary: a version this build cannot faithfully interpret is refused rather
// than partially understood.
func TestDryRunRefusesABadEnvelopeSchema(t *testing.T) {
	env := writeFixture(t, "future.json",
		strings.Replace(gitEnvelope, ece.SchemaVersion, "allseer.dev/ece/v9", 1))

	_, code := captureStdout(t, func() int {
		return run([]string{"policy", "dry-run", "-quiet", "-rules", defaultRules(), "-envelope", env, gitEvents})
	})
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
}

func TestDryRunRefusesMalformedEnvelopeJSON(t *testing.T) {
	env := writeFixture(t, "bad.json", "{not json")

	_, code := captureStdout(t, func() int {
		return run([]string{"policy", "dry-run", "-quiet", "-rules", defaultRules(), "-envelope", env, gitEvents})
	})
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
}

// --- table output -----------------------------------------------------------

func TestDryRunTableOutput(t *testing.T) {
	env := writeFixture(t, "envelope.json", gitEnvelope)

	out, code := captureStdout(t, func() int {
		return run([]string{"policy", "dry-run", "-quiet", "-rules", defaultRules(), "-envelope", env, gitEvents})
	})
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	if !strings.Contains(out, "SEQ") || !strings.Contains(out, "ENFORCED") {
		t.Errorf("no header in output:\n%s", out)
	}
	if !strings.Contains(out, "envelope-explicit-denial") {
		t.Errorf("the denial's rule is not named in the table:\n%s", out)
	}
	// In monitor mode nothing would be enforced, and the column must not say
	// anything that reads as though it had been.
	if strings.Contains(out, "would-block") {
		t.Errorf("monitor mode reported would-block:\n%s", out)
	}
	if !strings.Contains(out, "advisory") {
		t.Errorf("no advisory marker in output:\n%s", out)
	}
}

func TestWouldEnforce(t *testing.T) {
	cases := []struct {
		mode   string
		action ece.Action
		want   bool
	}{
		{"monitor", ece.ActionBlock, false},
		{"monitor", ece.ActionRequestApproval, false},
		{"warn", ece.ActionBlock, false},
		{"interactive", ece.ActionBlock, true},
		{"interactive", ece.ActionRequestApproval, true},
		{"interactive", ece.ActionWarn, false},
		{"enforce", ece.ActionBlock, true},
		// No human to prompt in enforce mode. A CI rule set is expected to
		// collapse this to block itself, visibly, rather than have the CLI do
		// it quietly.
		{"enforce", ece.ActionRequestApproval, false},
		{"enforce", ece.ActionAllow, false},
	}

	for _, tc := range cases {
		if got := wouldEnforce(policy.Mode(tc.mode), tc.action); got != tc.want {
			t.Errorf("wouldEnforce(%s, %s) = %v, want %v", tc.mode, tc.action, got, tc.want)
		}
	}
}
