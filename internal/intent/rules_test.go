package intent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"sort"
	"testing"
)

const corpusPath = "../../test/testdata/prompts/corpus.json"

// corpusCase is one hand-labeled prompt. The labels are what a careful reader
// says the prompt means; when the analyzer and the label disagree, one of the
// two is wrong and the disagreement is the point of the file.
type corpusCase struct {
	Name       string   `json:"name"`
	Prompt     string   `json:"prompt"`
	PriorTurns []string `json:"prior_turns"`

	Workspace struct {
		Languages      []string `json:"languages"`
		BuildSystems   []string `json:"build_systems"`
		HasVCS         bool     `json:"has_vcs"`
		TopLevelDirs   []string `json:"top_level_dirs"`
		SensitivePaths []string `json:"sensitive_paths"`
	} `json:"workspace"`

	Expect struct {
		TaskType        string   `json:"task_type"`
		Confidence      float64  `json:"confidence"`
		RequiresNetwork bool     `json:"requires_network"`
		Destructive     bool     `json:"destructive"`
		WorkspaceOnly   bool     `json:"workspace_only"`
		Verbs           []string `json:"verbs"`
		ToolHints       []string `json:"tool_hints"`
		PathHints       []string `json:"path_hints"`
		NetworkHints    []string `json:"network_hints"`
		Ambiguities     []string `json:"ambiguities"`
	} `json:"expect"`
}

func loadCorpus(t *testing.T) []corpusCase {
	t.Helper()

	data, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var doc struct {
		Cases []corpusCase `json:"cases"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	if len(doc.Cases) == 0 {
		t.Fatal("corpus is empty")
	}
	return doc.Cases
}

func (c corpusCase) request() Request {
	return Request{
		Prompt:     c.Prompt,
		PriorTurns: c.PriorTurns,
		WorkspaceContext: WorkspaceContext{
			Languages:      c.Workspace.Languages,
			BuildSystems:   c.Workspace.BuildSystems,
			HasVCS:         c.Workspace.HasVCS,
			TopLevelDirs:   c.Workspace.TopLevelDirs,
			SensitivePaths: c.Workspace.SensitivePaths,
		},
	}
}

// verbsOf returns the distinct verbs an analysis emitted, sorted so the corpus
// labels a set rather than an ordering.
func verbsOf(actions []Action) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, a := range actions {
		if _, ok := seen[a.Verb]; ok {
			continue
		}
		seen[a.Verb] = struct{}{}
		out = append(out, a.Verb)
	}
	sort.Strings(out)
	return out
}

func norm(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// TestRuleAnalyzerAgainstCorpus is the baseline measurement. Every field it
// checks is one the envelope generator or a human approver would read.
func TestRuleAnalyzerAgainstCorpus(t *testing.T) {
	a := NewRuleAnalyzer()

	for _, tc := range loadCorpus(t) {
		t.Run(tc.Name, func(t *testing.T) {
			got, err := a.Analyze(context.Background(), tc.request())
			if err != nil {
				t.Fatalf("Analyze: %v", err)
			}

			if got.Record.TaskType != tc.Expect.TaskType {
				t.Errorf("task type = %q, want %q", got.Record.TaskType, tc.Expect.TaskType)
			}
			if got.Record.Confidence != tc.Expect.Confidence {
				t.Errorf("confidence = %v, want %v", got.Record.Confidence, tc.Expect.Confidence)
			}
			if got.RequiresNetwork != tc.Expect.RequiresNetwork {
				t.Errorf("requires network = %v, want %v", got.RequiresNetwork, tc.Expect.RequiresNetwork)
			}
			if got.Destructive != tc.Expect.Destructive {
				t.Errorf("destructive = %v, want %v", got.Destructive, tc.Expect.Destructive)
			}
			if got.Scope.WorkspaceOnly != tc.Expect.WorkspaceOnly {
				t.Errorf("workspace only = %v, want %v", got.Scope.WorkspaceOnly, tc.Expect.WorkspaceOnly)
			}
			if v := verbsOf(got.Actions); !reflect.DeepEqual(v, norm(tc.Expect.Verbs)) {
				t.Errorf("verbs = %v, want %v", v, norm(tc.Expect.Verbs))
			}
			if v := norm(got.Scope.ToolHints); !reflect.DeepEqual(v, norm(tc.Expect.ToolHints)) {
				t.Errorf("tool hints = %v, want %v", v, norm(tc.Expect.ToolHints))
			}
			if v := norm(got.Scope.PathHints); !reflect.DeepEqual(v, norm(tc.Expect.PathHints)) {
				t.Errorf("path hints = %v, want %v", v, norm(tc.Expect.PathHints))
			}
			if v := norm(got.Scope.NetworkHints); !reflect.DeepEqual(v, norm(tc.Expect.NetworkHints)) {
				t.Errorf("network hints = %v, want %v", v, norm(tc.Expect.NetworkHints))
			}
			if v := norm(got.Record.Ambiguities); !reflect.DeepEqual(v, norm(tc.Expect.Ambiguities)) {
				t.Errorf("ambiguities = %v, want %v", v, norm(tc.Expect.Ambiguities))
			}
		})
	}
}

// TestAnalysisIsDeterministic is the property the whole module rests on. A
// benchmark the LLM analyzer is measured against is worthless if it moves
// between runs, and Go's map iteration order makes that a live risk.
func TestAnalysisIsDeterministic(t *testing.T) {
	a := NewRuleAnalyzer()

	for _, tc := range loadCorpus(t) {
		t.Run(tc.Name, func(t *testing.T) {
			first, err := a.Analyze(context.Background(), tc.request())
			if err != nil {
				t.Fatalf("Analyze: %v", err)
			}
			want, err := json.Marshal(first)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}

			for i := 0; i < 50; i++ {
				next, err := a.Analyze(context.Background(), tc.request())
				if err != nil {
					t.Fatalf("Analyze run %d: %v", i, err)
				}
				got, err := json.Marshal(next)
				if err != nil {
					t.Fatalf("marshal run %d: %v", i, err)
				}
				if string(got) != string(want) {
					t.Fatalf("run %d differs:\n got %s\nwant %s", i, got, want)
				}
			}
		})
	}
}

// TestAnalyzerGrantsNothing pins the module's central security property at the
// type level: an Analysis has no field through which a capability could reach
// the envelope generator.
func TestAnalyzerGrantsNothing(t *testing.T) {
	ty := reflect.TypeOf(Analysis{})
	for i := 0; i < ty.NumField(); i++ {
		if got := ty.Field(i).Type.String(); got == "capability.Grant" ||
			got == "[]capability.Grant" || got == "capability.Kind" {
			t.Errorf("Analysis.%s is %s; analysis must not carry capabilities",
				ty.Field(i).Name, got)
		}
	}
}

func TestEmptyPromptIsAnError(t *testing.T) {
	a := NewRuleAnalyzer()

	for _, prompt := range []string{"", "   ", "\t\n"} {
		got, err := a.Analyze(context.Background(), Request{Prompt: prompt})
		if !errors.Is(err, ErrEmptyPrompt) {
			t.Errorf("Analyze(%q) error = %v, want ErrEmptyPrompt", prompt, err)
		}
		if got != nil {
			t.Errorf("Analyze(%q) returned an analysis alongside an error", prompt)
		}
	}
}

func TestNameIsTheRecordedAnalyzer(t *testing.T) {
	a := NewRuleAnalyzer()
	if a.Name() != RuleAnalyzerName {
		t.Errorf("Name() = %q, want %q", a.Name(), RuleAnalyzerName)
	}

	got, err := a.Analyze(context.Background(), Request{Prompt: "run the go test suite"})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if got.Record.Analyzer != a.Name() {
		t.Errorf("record analyzer = %q, want %q", got.Record.Analyzer, a.Name())
	}
	if got.Record.RawPrompt != "run the go test suite" {
		t.Errorf("raw prompt = %q, want it verbatim", got.Record.RawPrompt)
	}
}

// TestClassifierAgreesWithAnalyzer keeps the cheap path honest. A classifier
// that drifts from the analyzer would select a profile for one task while the
// analysis described another.
func TestClassifierAgreesWithAnalyzer(t *testing.T) {
	a := NewRuleAnalyzer()
	c := RuleClassifier{}

	for _, tc := range loadCorpus(t) {
		t.Run(tc.Name, func(t *testing.T) {
			an, err := a.Analyze(context.Background(), tc.request())
			if err != nil {
				t.Fatalf("Analyze: %v", err)
			}
			gotType, gotConf, err := c.Classify(context.Background(), tc.Prompt)
			if err != nil {
				t.Fatalf("Classify: %v", err)
			}
			if gotType != an.Record.TaskType {
				t.Errorf("Classify task type = %q, analyzer said %q", gotType, an.Record.TaskType)
			}
			// The classifier reads the prompt alone, so it cannot apply the
			// penalties that need the request. It must never be lower.
			if gotConf < an.Record.Confidence {
				t.Errorf("Classify confidence %v below analyzer's %v", gotConf, an.Record.Confidence)
			}
		})
	}

	if _, _, err := c.Classify(context.Background(), " "); !errors.Is(err, ErrEmptyPrompt) {
		t.Errorf("Classify(empty) error = %v, want ErrEmptyPrompt", err)
	}
}
