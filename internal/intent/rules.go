package intent

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/stringNameMahin/ALLSEER/pkg/ece"
)

// The deterministic analyzer.
//
// It is the baseline the LLM analyzer has to beat, so it is written to be
// measurable rather than clever: every decision comes from an ordered table in
// this file, the same prompt always produces the same Analysis byte for byte,
// and anything it cannot resolve becomes an ambiguity instead of a guess.
//
// It interprets only. Nothing here issues a capability, so a prompt that talks
// the analyzer into a wrong reading still cannot widen an envelope; that is
// settled in internal/envelope, against the catalog and the operator's limits.

// RuleAnalyzerName identifies this implementation in ece.IntentRecord.Analyzer.
// The committed envelope fixtures already carry it.
const RuleAnalyzerName = "rules:v1"

// Task types. These are the vocabulary envelope profiles select on, so they are
// a wire contract in the same sense capability kinds are: add freely, never
// repurpose an existing value.
const (
	TaskTypeBuild             = "build"
	TaskTypeTest              = "test"
	TaskTypeDependencyInstall = "dependency-install"
	TaskTypeGitOperation      = "git-operation"
	TaskTypeRefactor          = "refactor"
	TaskTypeDocsEdit          = "docs-edit"

	// TaskTypeUnknown is what no match produces. It is a named answer rather
	// than an empty string because "nothing matched" has to survive into the
	// record a human reads.
	TaskTypeUnknown = "unknown"
)

// ErrEmptyPrompt reports a request with no prompt to analyze. It is an error
// rather than a zero-confidence analysis because there is nothing to be
// uncertain about.
var ErrEmptyPrompt = errors.New("intent: prompt is empty")

// Confidence bands. Stated as constants so the corpus can assert against the
// same numbers the analyzer uses.
const (
	confidenceSingleMatch = 0.90
	confidenceMultiMatch  = 0.60
	confidenceNoMatch     = 0.25

	penaltyUnresolvedRef = 0.15
	penaltyVeryShort     = 0.05
)

// RuleAnalyzer is the deterministic Analyzer. The zero value is usable and it
// holds no state, so it is safe for concurrent use.
type RuleAnalyzer struct{}

var (
	_ Analyzer   = RuleAnalyzer{}
	_ Classifier = RuleClassifier{}
)

// NewRuleAnalyzer returns the deterministic analyzer.
func NewRuleAnalyzer() RuleAnalyzer { return RuleAnalyzer{} }

// Name identifies the implementation for provenance.
func (RuleAnalyzer) Name() string { return RuleAnalyzerName }

// RuleClassifier assigns a task type without running a full analysis. It shares
// the analyzer's table, so the two can never disagree.
type RuleClassifier struct{}

// Classify returns the task type and the confidence in it.
func (RuleClassifier) Classify(_ context.Context, prompt string) (string, float64, error) {
	if strings.TrimSpace(prompt) == "" {
		return "", 0, ErrEmptyPrompt
	}
	c := classify(normalize(prompt))
	return c.taskType, round2(c.confidence), nil
}

// taskRule maps phrases to a task type. Ordered, and the order is precedence:
// the first matching entry wins when several match, and the losers become an
// ambiguity rather than being discarded silently.
type taskRule struct {
	taskType string
	signals  []string
}

var taskRules = []taskRule{
	{TaskTypeDependencyInstall, []string{
		"npm install", "npm ci", "yarn install", "pnpm install",
		"pip install", "go mod download", "go mod tidy", "cargo fetch",
		"bundle install", "install the dependencies", "install dependencies",
		"install the project dependencies", "add a dependency",
		"upgrade the dependencies", "upgrade all dependencies",
		"update the dependencies", "update dependencies",
	}},
	{TaskTypeTest, []string{
		"run the tests", "run tests", "test suite", "go test", "npm test",
		"pytest", "cargo test", "make test", "unit test", "failing test",
		"failing spec", "run the spec",
	}},
	{TaskTypeBuild, []string{
		"build the project", "go build", "npm run build", "make build",
		"cargo build", "compile the", "recompile",
	}},
	{TaskTypeGitOperation, []string{
		"git commit", "git push", "git pull", "git checkout", "git merge",
		"git rebase", "commit the", "push to", "create a branch",
		"stage the changes", "cherry-pick",
	}},
	{TaskTypeRefactor, []string{
		"refactor", "rename the", "extract the", "simplify the",
		"reorganize", "move the function", "clean up the code",
	}},
	{TaskTypeDocsEdit, []string{
		"readme", "changelog", "the documentation", "the docs",
		"docstring", "update the comment",
	}},
}

// summaries restate a task in the analyzer's words. IntentRecord.Summary is
// what a reviewer compares against the raw prompt, so these stay plain.
var summaries = map[string]string{
	TaskTypeBuild:             "Build the project.",
	TaskTypeTest:              "Run the project's test suite.",
	TaskTypeDependencyInstall: "Install or update project dependencies.",
	TaskTypeGitOperation:      "Run a git operation in the project.",
	TaskTypeRefactor:          "Modify source files in the project.",
	TaskTypeDocsEdit:          "Edit project documentation.",
	TaskTypeUnknown:           "No recognized task type; the request needs a human reading.",
}

// baseActions is what a task type requires before the prompt's specifics are
// read. Ordered so the emitted Actions slice is stable.
var baseActions = map[string][]Action{
	TaskTypeBuild: {
		{Verb: "read", Object: "source files", Necessity: NecessityRequired},
		{Verb: "execute", Object: "build toolchain", Necessity: NecessityRequired},
		{Verb: "write", Object: "build output", Necessity: NecessityLikely},
	},
	TaskTypeTest: {
		{Verb: "read", Object: "source files", Necessity: NecessityRequired},
		{Verb: "execute", Object: "test runner", Necessity: NecessityRequired},
		{Verb: "write", Object: "test artifacts", Necessity: NecessityPossible},
	},
	TaskTypeDependencyInstall: {
		{Verb: "fetch", Object: "package registry", Necessity: NecessityRequired},
		{Verb: "write", Object: "dependency tree", Necessity: NecessityRequired},
		{Verb: "execute", Object: "package manager", Necessity: NecessityRequired},
	},
	TaskTypeGitOperation: {
		{Verb: "read", Object: "repository", Necessity: NecessityRequired},
		{Verb: "execute", Object: "git", Necessity: NecessityRequired},
		{Verb: "write", Object: "repository metadata", Necessity: NecessityLikely},
	},
	TaskTypeRefactor: {
		{Verb: "read", Object: "source files", Necessity: NecessityRequired},
		{Verb: "write", Object: "source files", Necessity: NecessityRequired},
	},
	TaskTypeDocsEdit: {
		{Verb: "read", Object: "documentation", Necessity: NecessityRequired},
		{Verb: "write", Object: "documentation", Necessity: NecessityRequired},
	},
	TaskTypeUnknown: nil,
}

// toolSignals maps a phrase to the executable it implies.
var toolSignals = []struct{ phrase, tool string }{
	{"go test", "go"}, {"go build", "go"}, {"go mod", "go"}, {"gofmt", "gofmt"},
	{"npm", "npm"}, {"yarn", "yarn"}, {"pnpm", "pnpm"}, {"node", "node"},
	{"pytest", "pytest"}, {"pip", "pip"}, {"python", "python"},
	{"cargo", "cargo"}, {"make", "make"}, {"git", "git"},
	{"docker", "docker"}, {"curl", "curl"}, {"wget", "wget"},
}

// registries is the host a dependency install implies per language. Named
// because "npm install" reaches the network whether or not the prompt says so.
var registries = []struct{ language, host string }{
	{"go", "proxy.golang.org"},
	{"javascript", "registry.npmjs.org"},
	{"typescript", "registry.npmjs.org"},
	{"python", "pypi.org"},
	{"rust", "crates.io"},
}

var networkSignals = []string{
	"install", "download", "fetch", "clone", "git pull", "git push",
	"push to", "curl", "wget", "http://", "https://", "registry",
	"upgrade the dependencies", "upgrade all dependencies",
}

// destructiveSignals name destruction outright. A prompt carrying one of these
// is destructive whatever else it says.
var destructiveSignals = []string{
	"rm -rf", "rm -r", "force push", "force-push", "push --force",
	"reset --hard", "git clean", "drop the table", "drop table",
	"truncate", "wipe", "purge", "delete the branch", "delete the file",
	"delete the files", "delete the directory", "remove the directory",
}

// weakDestructive are removal verbs with no object attached. They raise an
// ambiguity rather than a finding, because "remove the unused import" and
// "remove the build directory" are the same two words and not the same act.
var weakDestructive = []string{"delete", "remove"}

// escapeSignals mark a request that reaches outside the workspace.
var escapeSignals = []string{
	"~/", "/etc/", "/usr/", "/var/", "/root/", "$home", "home directory",
	"outside the workspace", "system-wide", "/proc/", ".ssh",
}

// unresolvedRefs are phrases that only mean something given a previous turn.
var unresolvedRefs = []string{
	"the same", "do that", "do it", "same thing", "as before", "the other one",
}

// Analyze interprets the request. It never returns a nil Analysis with a nil
// error, and it never reports confidence it cannot justify from the table.
func (a RuleAnalyzer) Analyze(_ context.Context, req Request) (*Analysis, error) {
	raw := strings.TrimSpace(req.Prompt)
	if raw == "" {
		return nil, fmt.Errorf("%w: nothing to analyze", ErrEmptyPrompt)
	}

	p := normalize(raw)
	c := classify(p)

	an := &Analysis{
		Actions:         append([]Action(nil), baseActions[c.taskType]...),
		RequiresNetwork: containsAny(p, networkSignals),
	}

	var ambiguities []string
	ambiguities = append(ambiguities, c.ambiguities...)

	// Destruction. A definite phrase settles it; a bare removal verb does not.
	switch {
	case containsAny(p, destructiveSignals):
		an.Destructive = true
	case containsAny(p, weakDestructive):
		ambiguities = append(ambiguities,
			"prompt asks to remove something without naming what is removed")
	}

	an.Scope = a.scope(p, req)

	// A dependency install reaches a registry even when the prompt is silent.
	if c.taskType == TaskTypeDependencyInstall {
		an.RequiresNetwork = true
	}
	if an.RequiresNetwork && len(an.Scope.NetworkHints) == 0 {
		ambiguities = append(ambiguities,
			"the task reaches the network but names no host")
	}

	// Derived actions, after the base set so ordering stays stable.
	if an.Destructive {
		an.Actions = append(an.Actions,
			Action{Verb: "delete", Object: "files", Necessity: NecessityRequired})
	}
	if an.RequiresNetwork && !hasVerb(an.Actions, "fetch") {
		an.Actions = append(an.Actions,
			Action{Verb: "fetch", Object: "remote resource", Necessity: NecessityLikely})
	}

	confidence := c.confidence
	if containsAny(p, unresolvedRefs) && len(req.PriorTurns) == 0 {
		confidence -= penaltyUnresolvedRef
		ambiguities = append(ambiguities,
			"prompt refers to an earlier turn that was not supplied")
	}
	if len(strings.Fields(p)) < 3 {
		confidence -= penaltyVeryShort
		ambiguities = append(ambiguities, "prompt is too short to ground an interpretation")
	}
	if !an.Scope.WorkspaceOnly {
		ambiguities = append(ambiguities, "prompt reaches outside the workspace root")
	}

	an.Record = ece.IntentRecord{
		RawPrompt:   req.Prompt,
		Summary:     summaries[c.taskType],
		TaskType:    c.taskType,
		Analyzer:    RuleAnalyzerName,
		Confidence:  round2(clamp01(confidence)),
		Ambiguities: dedupe(ambiguities),
	}
	return an, nil
}

// scope infers the blast radius from the prompt and the workspace metadata.
func (RuleAnalyzer) scope(p string, req Request) Scope {
	s := Scope{WorkspaceOnly: !containsAny(p, escapeSignals)}

	tv := tokenView(p)
	for _, t := range toolSignals {
		if containsPhrase(tv, t.phrase) {
			s.ToolHints = append(s.ToolHints, t.tool)
		}
	}
	s.ToolHints = dedupe(s.ToolHints)

	s.PathHints = dedupe(pathHints(p, req.WorkspaceContext.TopLevelDirs))
	s.NetworkHints = dedupe(networkHints(p, req))

	// A named sensitive path is a reach outside the task whether or not it sits
	// under the workspace root.
	for _, sp := range req.WorkspaceContext.SensitivePaths {
		if sp != "" && strings.Contains(p, strings.ToLower(sp)) {
			s.WorkspaceOnly = false
		}
	}
	return s
}

// pathHints picks out tokens that name a location. Conservative on purpose: a
// hint that is not a path costs the generator a narrowing it cannot apply.
func pathHints(p string, topLevel []string) []string {
	var out []string
	for _, tok := range strings.FieldsFunc(p, func(r rune) bool {
		return r == ' ' || r == ',' || r == '"' || r == '\'' || r == '(' || r == ')'
	}) {
		tok = strings.Trim(tok, ".:;")
		if tok == "" {
			continue
		}
		if strings.Contains(tok, "/") || strings.HasPrefix(tok, "~") || hasSourceExt(tok) {
			out = append(out, tok)
			continue
		}
		for _, d := range topLevel {
			if d != "" && tok == strings.ToLower(d) {
				out = append(out, tok)
				break
			}
		}
	}
	return out
}

var sourceExts = []string{
	".go", ".c", ".h", ".py", ".js", ".ts", ".rs", ".md", ".yaml", ".yml", ".json",
}

func hasSourceExt(tok string) bool {
	for _, e := range sourceExts {
		if strings.HasSuffix(tok, e) {
			return true
		}
	}
	return false
}

// networkHints returns hosts the task implies: any host named in the prompt,
// plus the registry a dependency install for a detected language would reach.
func networkHints(p string, req Request) []string {
	var out []string
	for _, tok := range strings.Fields(p) {
		tok = strings.Trim(tok, "\"'(),;:")
		tok = strings.TrimPrefix(strings.TrimPrefix(tok, "https://"), "http://")
		if i := strings.Index(tok, "/"); i > 0 {
			tok = tok[:i]
		}
		if looksLikeHost(tok) {
			out = append(out, tok)
		}
	}

	if containsAny(p, []string{"install", "upgrade the dependencies", "upgrade all dependencies"}) {
		for _, lang := range req.WorkspaceContext.Languages {
			for _, r := range registries {
				if strings.EqualFold(lang, r.language) {
					out = append(out, r.host)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// looksLikeHost is a deliberately narrow test: a dotted token whose last label
// is alphabetic. It is meant to catch github.com, not to parse a URL.
func looksLikeHost(tok string) bool {
	if !strings.Contains(tok, ".") || strings.HasPrefix(tok, ".") || strings.HasSuffix(tok, ".") {
		return false
	}
	if hasSourceExt(tok) || strings.Contains(tok, "/") {
		return false
	}
	labels := strings.Split(tok, ".")
	last := labels[len(labels)-1]
	if len(last) < 2 {
		return false
	}
	for _, r := range last {
		if r < 'a' || r > 'z' {
			return false
		}
	}
	return true
}

// classification is what the task-type table concluded.
type classification struct {
	taskType    string
	confidence  float64
	ambiguities []string
}

// classify runs the ordered table. Every match is recorded, so a prompt that
// names two tasks reports the second as an ambiguity rather than losing it.
func classify(p string) classification {
	var matched []string
	for _, r := range taskRules {
		if containsAny(p, r.signals) {
			matched = append(matched, r.taskType)
		}
	}

	switch len(matched) {
	case 0:
		return classification{
			taskType:    TaskTypeUnknown,
			confidence:  confidenceNoMatch,
			ambiguities: []string{"no task type matched the prompt"},
		}
	case 1:
		return classification{taskType: matched[0], confidence: confidenceSingleMatch}
	default:
		return classification{
			taskType:   matched[0],
			confidence: confidenceMultiMatch,
			ambiguities: []string{
				"prompt matches several task types: " + strings.Join(matched, ", "),
			},
		}
	}
}

func normalize(s string) string { return strings.ToLower(strings.Join(strings.Fields(s), " ")) }

// tokenView pads the prompt and turns sentence punctuation into spaces, so a
// phrase can be matched on word boundaries. Hyphens and slashes survive,
// because a tool name may contain them and a path certainly does.
func tokenView(p string) string {
	repl := strings.NewReplacer(
		",", " ", ".", " ", ";", " ", ":", " ", "!", " ", "?", " ",
		"(", " ", ")", " ", "\"", " ", "'", " ",
	)
	return " " + strings.Join(strings.Fields(repl.Replace(p)), " ") + " "
}

// containsPhrase reports whether a padded token view holds phrase as whole
// words. Without it "node_modules" reports the node executable, which is a
// directory being read as a tool the agent will run.
func containsPhrase(tokenView, phrase string) bool {
	return strings.Contains(tokenView, " "+phrase+" ")
}

func containsAny(p string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(p, n) {
			return true
		}
	}
	return false
}

func hasVerb(actions []Action, verb string) bool {
	for _, a := range actions {
		if a.Verb == verb {
			return true
		}
	}
	return false
}

// dedupe removes repeats while keeping first-seen order, which is what makes
// two runs over the same prompt produce the same slice.
func dedupe(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func clamp01(f float64) float64 { return math.Max(0, math.Min(1, f)) }

// round2 pins confidence to two decimals so the value is stable across runs and
// comparable in a corpus.
func round2(f float64) float64 { return math.Round(f*100) / 100 }
