package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/stringNameMahin/ALLSEER/internal/pipeline"
	"github.com/stringNameMahin/ALLSEER/internal/policy"
	"github.com/stringNameMahin/ALLSEER/internal/session"
	"github.com/stringNameMahin/ALLSEER/internal/telemetry/replay"
	"github.com/stringNameMahin/ALLSEER/internal/validator"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// `policy dry-run` answers the question an operator has to answer before
// trusting a rule change: what would this policy have done?
//
// It is the first command that runs the governance pipeline end to end —
// replay, validation, policy — and it does so by calling the same code the
// daemon will. Nothing here evaluates anything itself. A second evaluator
// living in the CLI would answer the question with a different policy than the
// one that runs in production, which is worse than not answering it.
//
// Nothing is enforced, and nothing can be: the command opens three files read
// only and constructs no decision.Enforcer. Every reported action is what
// enforcement *would* be asked to do.
//
// It does accumulate session state, in memory and discarded when the process
// exits, because grant budgets and session constraints are only answerable
// against a running count. That is a read of the recording, not a write to
// anything: no session is created, nothing is persisted, and the three inputs
// are untouched.

// runPolicy dispatches the policy subcommands.
func runPolicy(args []string) int {
	if len(args) == 0 {
		policyUsage(os.Stderr)
		return 2
	}
	switch args[0] {
	case "dry-run":
		return runPolicyDryRun(args[1:])
	case "-h", "--help", "help":
		policyUsage(os.Stdout)
		return 0
	}
	fmt.Fprintf(os.Stderr, "allseerctl policy: unknown subcommand %q\n\n", args[0])
	policyUsage(os.Stderr)
	return 2
}

func policyUsage(w io.Writer) {
	fmt.Fprint(w, "Usage: allseerctl policy <subcommand> [flags] [arguments]\n\n"+
		"Subcommands:\n"+
		"  dry-run        Replay a recorded stream against a rule set without enforcing\n\n"+
		"Run `allseerctl policy dry-run -h` for flags.\n")
}

// dryRunResult is one event's trip through the pipeline.
//
// Deliberately not a decision.Decision. A Decision carries a RiskAssessment by
// value, and emitting one with no risk stage in the pipeline would publish a
// score of zero and a level of "" as though they had been assessed. Fabricating
// the quiet half of an audit record is exactly the failure the rest of this
// system is built to avoid, so dry-run reports its own shape and says plainly
// which stages ran.
type dryRunResult struct {
	Sequence uint64 `json:"sequence"`
	EventID  string `json:"event_id"`

	Capability string `json:"capability"`
	Target     string `json:"target,omitempty"`

	Verdict    decision.Verdict `json:"verdict"`
	Violations []string         `json:"violations,omitempty"`

	// RuleID is the rule that decided, or "default" when none matched.
	RuleID string     `json:"rule_id"`
	Action ece.Action `json:"action"`

	// Terminal reports that the rule ends the session when it fires.
	Terminal bool `json:"terminal,omitempty"`

	// WouldEnforce is what enforcement would have been asked to do in this
	// mode. Enforced is always false and is emitted anyway: a consumer reading
	// dry-run output alongside real decisions must see the field say so.
	WouldEnforce bool `json:"would_enforce"`
	Enforced     bool `json:"enforced"`

	Reasoning []decision.ReasoningStep `json:"reasoning,omitempty"`
}

func runPolicyDryRun(args []string) int {
	fs := flag.NewFlagSet("policy dry-run", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), "Usage: allseerctl policy dry-run [flags] <events.jsonl>\n\n"+
			"Replay a recorded telemetry stream against a rule set and an envelope,\n"+
			"reporting what policy would have decided. Nothing is enforced.\n\n"+
			"Flags:\n")
		fs.PrintDefaults()
	}

	var (
		rulesPath    = fs.String("rules", "", "Path to a policy rule set (required)")
		envelopePath = fs.String("envelope", "", "Path to the ECE the session was governed by, as JSON (required)")
		modeName     = fs.String("mode", string(policy.ModeMonitor), "Enforcement mode to evaluate under: monitor, warn, interactive, enforce")
		asJSON       = fs.Bool("json", false, "Emit results as JSONL rather than a table")
		quiet        = fs.Bool("quiet", false, "Suppress the trailing summary")
		skipBad      = fs.Bool("skip-malformed", false, "Continue past unparseable records instead of stopping")
	)

	if err := fs.Parse(args); err != nil {
		return 2 // flag package has already reported it
	}
	if fs.NArg() != 1 || *rulesPath == "" || *envelopePath == "" {
		fs.Usage()
		return 2
	}

	mode := policy.Mode(*modeName)
	if !knownMode(mode) {
		fmt.Fprintf(os.Stderr, "allseerctl policy dry-run: unknown mode %q\n", *modeName)
		return 2
	}

	// --- policy: load, lint, admit ------------------------------------------
	rs, err := policy.NewLoader().Load(context.Background(), *rulesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "allseerctl policy dry-run: %v\n", err)
		return 1
	}

	// Linting happens before a single event is evaluated. A rule that cannot
	// fire is the reason a dry-run comes back quieter than expected, and
	// finding that out after reading a page of output is finding it out too
	// late.
	lint := policy.NewLinter().Lint(rs)
	printLintIssues(os.Stderr, lint)
	if blocking := policy.BlockingIssues(lint); len(blocking) > 0 {
		fmt.Fprintf(os.Stderr, "\nallseerctl policy dry-run: %d rule(s) cannot fire; refusing to report a run under a policy that does not do what it says\n", len(blocking))
		return 1
	}

	engine, err := policy.NewEngine(rs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "allseerctl policy dry-run: %v\n", err)
		return 1
	}

	// --- envelope: load and lint --------------------------------------------
	env, err := loadEnvelope(*envelopePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "allseerctl policy dry-run: %v\n", err)
		return 1
	}
	envIssues := validator.LintEnvelope(env)
	printEnvelopeIssues(os.Stderr, envIssues)
	if blocking := validator.BlockingIssues(envIssues); len(blocking) > 0 {
		fmt.Fprintf(os.Stderr, "\nallseerctl policy dry-run: the envelope has %d selector(s) that match nothing; verdicts under it would be meaningless\n", len(blocking))
		return 1
	}

	// --- replay --------------------------------------------------------------
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	src := replay.New(replay.Config{Path: fs.Arg(0), SkipMalformed: *skipBad})
	if err := src.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "allseerctl policy dry-run: %v\n", err)
		return 1
	}
	defer func() { _ = src.Close() }()

	st, results, evalErr := evaluateStream(ctx, src.Events(), env, engine, mode)
	if evalErr != nil {
		fmt.Fprintf(os.Stderr, "allseerctl policy dry-run: %v\n", evalErr)
		return 1
	}

	if *asJSON {
		printResultsJSON(results)
	} else {
		printResultsTable(results)
	}

	streamErr := src.Err()
	if streamErr != nil {
		fmt.Fprintf(os.Stderr, "\nallseerctl policy dry-run: %v\n", streamErr)
	}
	if !*quiet {
		printDryRunSummary(os.Stderr, results, rs, env, st, mode, streamErr)
	}
	if streamErr != nil {
		// A dry run over a truncated stream is a dry run over part of a
		// session, and the conclusions drawn from it are not the ones the
		// operator asked for.
		return 1
	}
	return 0
}

// evaluateStream runs each event through the governance pipeline.
//
// The sequence used to be written out here by hand. It now lives in
// internal/pipeline, which this calls: validate, decide, then commit to session
// state, with the ordering and the single-writer guarantee owned there rather
// than restated at every call site. Two orchestrations of the same stages is
// one more than can be kept in agreement, and the one in the CLI is the one
// that would drift from what the daemon actually does.
//
// Risk is still absent — no stage exists for it — which is reported rather than
// simulated, since a fabricated score would change which rules fire.
func evaluateStream(ctx context.Context, events <-chan event.Event, env *ece.Envelope, engine *policy.RuleEngine, mode policy.Mode) (*session.MemoryState, []dryRunResult, error) {
	// Session state is accumulated rather than left nil, so grant budgets and
	// session constraints are actually evaluated. StartedAt is deliberately
	// unset: that puts elapsed time on the recording's own clock, so a dry run
	// of an archived stream reports the duration the session had rather than
	// the age of the file.
	st := session.NewState(env.SessionID, env)

	p, err := pipeline.New(pipeline.Config{
		Session: pipeline.Session{Envelope: env, Mode: mode, State: st},
		// No sink: a dry run audits nothing, and passing one would write
		// records for a session that never happened.
	}, validator.NewValidator(), engine)
	if err != nil {
		return nil, nil, fmt.Errorf("building pipeline: %w", err)
	}

	var out []dryRunResult
	for e := range events {
		pc, err := p.ProcessContext(ctx, &e)
		if err != nil {
			return nil, nil, fmt.Errorf("processing %s: %w", e.ID, err)
		}

		// The pipeline turns a stage failure into an indeterminate decision and
		// carries on, which is right for a daemon: an event with no record is
		// indistinguishable from an event that never happened. A dry run wants
		// the opposite. It exists to answer "what would this policy have done",
		// and a run where the governance path itself broke cannot answer that,
		// so it stops and says which stage failed rather than reporting a page
		// of indeterminates as though they were findings.
		if pc.Err != nil {
			return nil, nil, fmt.Errorf("%s stage on %s: %w", pc.FailedStage, e.ID, pc.Err)
		}

		out = append(out, dryRunResult{
			Sequence:     e.Sequence,
			EventID:      e.ID,
			Capability:   string(e.Capability),
			Target:       targetOf(&e),
			Verdict:      pc.Validation.Verdict,
			Violations:   violationNames(pc.Validation),
			RuleID:       pc.Outcome.RuleID,
			Action:       pc.Outcome.Action,
			Terminal:     pc.Outcome.Terminal,
			WouldEnforce: wouldEnforce(mode, pc.Outcome.Action),
			Enforced:     false,
			Reasoning:    append(pc.Validation.Reasoning, pc.Outcome.Reasoning...),
		})
	}
	return st, out, nil
}

// wouldEnforce reports whether enforcement would have been asked to act, given
// the mode.
//
// Descriptive, not authoritative: the enforcement layer is M12, and this
// encodes only the mode definitions the project already committed to. Monitor
// and warn never intervene. Interactive suspends and asks, so both block and
// request_approval reach enforcement. Enforce blocks without prompting, and
// request_approval has no one to ask — which is why a CI rule set is expected
// to collapse it to block rather than relying on this function to do it
// silently.
func wouldEnforce(mode policy.Mode, action ece.Action) bool {
	switch mode {
	case policy.ModeMonitor, policy.ModeWarn:
		return false
	case policy.ModeInteractive:
		return action == ece.ActionBlock || action == ece.ActionRequestApproval
	case policy.ModeEnforce:
		return action == ece.ActionBlock
	}
	return false
}

func knownMode(m policy.Mode) bool {
	switch m {
	case policy.ModeMonitor, policy.ModeWarn, policy.ModeInteractive, policy.ModeEnforce:
		return true
	}
	return false
}

// loadEnvelope reads an ECE from JSON.
//
// Unknown fields are allowed, unlike the rule set loader: an envelope is a wire
// document that may have been written by a newer build, and the schema's own
// example carries a $comment. The fields that matter are checked by the
// envelope linter immediately after.
func loadEnvelope(path string) (*ece.Envelope, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading envelope: %w", err)
	}
	var env ece.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("parsing envelope %s: %w", path, err)
	}
	if env.SchemaVersion != "" && env.SchemaVersion != ece.SchemaVersion {
		// Refusing an unknown version is the envelope's own rule: silently
		// ignoring a restriction field this build does not understand would be
		// a security failure rather than a compatibility nicety.
		return nil, fmt.Errorf("envelope %s declares schema version %q, want %q",
			path, env.SchemaVersion, ece.SchemaVersion)
	}
	return &env, nil
}

func targetOf(e *event.Event) string {
	obs, err := validator.ObservationOf(e)
	if err != nil {
		return ""
	}
	return obs.Target
}

func violationNames(res *validator.Result) []string {
	if len(res.Violations) == 0 {
		return nil
	}
	out := make([]string, 0, len(res.Violations))
	for _, v := range res.Violations {
		out = append(out, string(v.Type))
	}
	return out
}

// --- output -----------------------------------------------------------------

func printLintIssues(w io.Writer, issues []policy.LintIssue) {
	if len(issues) == 0 {
		return
	}
	fmt.Fprintf(w, "rule set lint: %d %s\n", len(issues), plural(len(issues), "issue", "issues"))
	for _, i := range issues {
		fmt.Fprintf(w, "  %-8s %-32s %s\n", i.Severity, i.RuleID, i.Message)
	}
}

func printEnvelopeIssues(w io.Writer, issues []ece.Issue) {
	if len(issues) == 0 {
		return
	}
	fmt.Fprintf(w, "envelope lint: %d %s\n", len(issues), plural(len(issues), "issue", "issues"))
	for _, i := range issues {
		fmt.Fprintf(w, "  %-8s %-32s %s\n", i.Severity, i.Field, i.Message)
	}
}

func printResultsJSON(results []dryRunResult) {
	enc := json.NewEncoder(os.Stdout)
	for _, r := range results {
		if err := enc.Encode(r); err != nil {
			fmt.Fprintf(os.Stderr, "allseerctl policy dry-run: writing output: %v\n", err)
			return
		}
	}
}

func printResultsTable(results []dryRunResult) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SEQ\tCAPABILITY\tTARGET\tVERDICT\tRULE\tACTION\tENFORCED")

	for _, r := range results {
		action := string(r.Action)
		if r.Terminal {
			action += " (terminal)"
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r.Sequence,
			r.Capability,
			truncate(r.Target, 44),
			r.Verdict,
			r.RuleID,
			action,
			formatEnforcement(r.WouldEnforce),
		)
	}
	_ = w.Flush()
}

// formatEnforcement never prints a bare "yes". Nothing was enforced by this
// command, and a column that read as though something had been would be the
// same lie as a block that never happened.
func formatEnforcement(would bool) string {
	if would {
		return "would-block"
	}
	return "advisory"
}

// printDryRunSummary reports what the run established and, as importantly,
// what it could not.
func printDryRunSummary(w io.Writer, results []dryRunResult, rs *policy.RuleSet, env *ece.Envelope, st *session.MemoryState, mode policy.Mode, streamErr error) {
	var b strings.Builder

	fmt.Fprintf(&b, "\n%d %s evaluated in %s mode; nothing was enforced\n",
		len(results), plural(len(results), "event", "events"), mode)

	byAction := map[ece.Action]int{}
	byRule := map[string]int{}
	for _, r := range results {
		byAction[r.Action]++
		byRule[r.RuleID]++
	}

	// Actions in escalation order, so the serious end of the run is read first.
	for _, a := range []ece.Action{ece.ActionBlock, ece.ActionRequestApproval, ece.ActionWarn, ece.ActionAllow} {
		if n := byAction[a]; n > 0 {
			fmt.Fprintf(&b, "  %-16s %d\n", a, n)
		}
	}

	if len(byRule) > 0 {
		fmt.Fprint(&b, "\nrules that fired:\n")
		ids := make([]string, 0, len(byRule))
		for id := range byRule {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			fmt.Fprintf(&b, "  %-32s %d\n", id, byRule[id])
		}
	}

	// The honesty section. Every line here is a stage that did not run, and
	// each one changes which rules could have fired. Leaving them out would let
	// a quiet dry run read as a quiet policy.
	var caveats []string
	if n := riskConditionedRules(rs); n > 0 {
		caveats = append(caveats, fmt.Sprintf(
			"%d %s risk-conditioned and could not fire: no risk engine is linked into this build, "+
				"and an unscored event never satisfies a score or confidence condition",
			n, plural(n, "rule is", "rules are")))
	}
	// Grant budgets and session constraints *are* evaluated now — the run
	// accumulates session state as the daemon will. Duration is the one budget
	// that can still go unchecked, and only for a specific reason: a recording
	// is measured by its own wall clocks, so a stream that carries none cannot
	// establish how long the session ran. Saying so is the difference between a
	// constraint that held and a constraint nobody looked at.
	if env.Constraints.MaxDuration > 0 && st.ElapsedSeconds() == 0 {
		caveats = append(caveats, fmt.Sprintf(
			"the envelope's max_duration of %s was not evaluated: the recording carries no wall clocks, "+
				"so the session's elapsed time could not be established from it", env.Constraints.MaxDuration))
	}
	if st.DroppedEvents() > 0 {
		caveats = append(caveats, fmt.Sprintf(
			"%d record(s) were lost before this recording was written, so every count below is a lower bound "+
				"and no conclusion drawn across the gap is sound", st.DroppedEvents()))
	}
	if streamErr != nil {
		caveats = append(caveats, "the stream ended on a malformed record, so this is a partial session")
	}

	if len(caveats) > 0 {
		fmt.Fprint(&b, "\nnot evaluated in this run:\n")
		for _, c := range caveats {
			fmt.Fprintf(&b, "  - %s\n", c)
		}
	}

	fmt.Fprint(w, b.String())
}

func riskConditionedRules(rs *policy.RuleSet) int {
	var n int
	for _, r := range rs.Rules {
		if r.Enabled && policy.RiskConditioned(r) {
			n++
		}
	}
	return n
}

// Done: envelopeHasBudgets is gone. It existed to raise a caveat that grant
// budgets and session constraints went unevaluated, which stopped being true
// when internal/session landed and evaluateStream started accumulating state.
// The narrower caveat that survives is duration, which a recording without wall
// clocks genuinely cannot establish.
