package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/stringNameMahin/ALLSEER/internal/envelope"
	"github.com/stringNameMahin/ALLSEER/internal/ipc"
	"github.com/stringNameMahin/ALLSEER/internal/session"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
)

// Commands that talk to a running daemon.

func defaultSocket() string {
	if v := os.Getenv("ALLSEER_SOCKET"); v != "" {
		return v
	}
	return "/run/allseer/allseerd.sock"
}

type daemonFlags struct {
	fs     *flag.FlagSet
	socket *string
	asJSON *bool
}

func newDaemonFlags(name, usage string) daemonFlags {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: allseerctl %s\n\nFlags:\n", usage)
		fs.PrintDefaults()
	}
	return daemonFlags{fs: fs, socket: fs.String("socket", defaultSocket(), "Daemon socket"), asJSON: fs.Bool("json", false, "Print JSON")}
}

func (f daemonFlags) client() *ipc.SocketClient { return &ipc.SocketClient{Path: *f.socket} }

func printJSONValue(v any) int {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return die("%v", err)
	}
	return 0
}

func die(format string, a ...any) int {
	fmt.Fprintf(os.Stderr, "allseerctl: "+format+"\n", a...)
	return 1
}

func runStatus(args []string) int {
	f := newDaemonFlags("status", "status [-json]")
	if f.fs.Parse(args) != nil {
		return 2
	}
	st, err := f.client().Status(context.Background())
	if err != nil {
		return die("%v", err)
	}
	if *f.asJSON {
		return printJSONValue(st)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "daemon\t%s (protocol %s), up %s\n", st.Version, st.ProtocolVersion, time.Duration(st.Uptime*float64(time.Second)).Round(time.Second))
	fmt.Fprintf(w, "default mode\t%s\n", st.Mode)
	fmt.Fprintf(w, "sessions\t%d live\n", st.ActiveSessions)
	health := "healthy"
	switch {
	case !st.SelfTest.Passed:
		health = "UNHEALTHY: the startup self-test did not pass"
	case !st.TelemetryHealthy:
		health = "UNHEALTHY: attribution floor missing"
	}
	fmt.Fprintf(w, "telemetry\t%s, %d probes attached, %d events, %d dropped\n", health, st.ProbesAttached,
		st.Collector.EventsReceived, st.DroppedEvents)
	if st.SelfTest.Passed {
		fmt.Fprintf(w, "self-test\t%s probe reported a failed open in %s\n", st.SelfTest.Probe, st.SelfTest.Latency.Round(time.Millisecond))
	} else {
		fmt.Fprintf(w, "self-test\tFAILED (%s probe): %s\n", st.SelfTest.Probe, st.SelfTest.Detail)
	}
	for _, g := range st.Coverage.EntryPoints {
		if len(g.SuccessOnly) > 0 {
			fmt.Fprintf(w, "successes only\t%s through %v: refused attempts produce no record\n", g.Kind, g.SuccessOnly)
		}
		// An observable kind is not a fully watched one. Printing only the
		// observable list would let "net.connect" read as "every outbound
		// connection is seen", which is not what watching connect(2) buys.
		if len(g.Missing) > 0 {
			fmt.Fprintf(w, "not watched\t%s through %v: those produce no record\n", g.Kind, g.Missing)
		}
	}
	if st.AuditErrors > 0 {
		fmt.Fprintf(w, "audit log	%d WRITE FAILURES; the log is missing records\n", st.AuditErrors)
	}
	if st.RefusedRequests > 0 {
		fmt.Fprintf(w, "refused requests\t%d (callers inside a governed session, or not locatable)\n", st.RefusedRequests)
	}
	if st.Leftovers > 0 {
		fmt.Fprintf(w, "leftovers\t%d session cgroups an earlier daemon left behind (allseerctl leftovers)\n", st.Leftovers)
	}
	if st.Coverage.Degraded {
		fmt.Fprintf(w, "coverage\tDEGRADED; unobservable: %v\n", st.Coverage.Unobservable)
	}
	fmt.Fprintf(w, "observable\t%v\n", st.Coverage.Observable)
	if len(st.Coverage.Unsupported) > 0 {
		fmt.Fprintf(w, "no probe in this build\t%v\n", st.Coverage.Unsupported)
	}
	fmt.Fprintf(w, "enforcer\t%s (can block: %v, suspend: %v, terminate: %v)\n", st.Enforcer.Mechanism,
		st.Enforcer.CanBlock, st.Enforcer.CanSuspend, st.Enforcer.CanTerminate)
	if !st.Enforcer.CanBlock {
		fmt.Fprintf(w, "\tblocking is post-detection: the triggering operation completes, then the session is contained\n")
	}
	d := st.Dispatch
	fmt.Fprintf(w, "routing\t%d routed, %d unattributed, %d unidentified, %d late\n", d.EventsRouted, d.Unattributed+st.Collector.Unattributed, d.Unidentified, d.NotAccepting)
	_ = w.Flush()
	return 0
}

func runSessions(args []string) int {
	f := newDaemonFlags("sessions", "sessions [-json]")
	if f.fs.Parse(args) != nil {
		return 2
	}
	list, err := f.client().ListSessions(context.Background(), session.Filter{})
	if err != nil {
		return die("%v", err)
	}
	if *f.asJSON {
		return printJSONValue(list)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SESSION\tSTATE\tMODE\tTASK\tEVENTS\tVIOLATIONS\tWORKSPACE")
	for _, s := range list {
		task := ""
		if s.Envelope != nil {
			task = s.Envelope.Intent.TaskType
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%d\t%s\n", s.ID, s.State, s.Mode, task, s.Summary.EventsObserved, s.Outcome.ViolationCount, s.WorkspaceRoot)
	}
	_ = w.Flush()
	return 0
}

func runSession(args []string) int {
	f := newDaemonFlags("session", "session [-json] <id>")
	if f.fs.Parse(args) != nil {
		return 2
	}
	if f.fs.NArg() != 1 {
		f.fs.Usage()
		return 2
	}
	s, err := f.client().GetSession(context.Background(), f.fs.Arg(0))
	if err != nil {
		return die("%v", err)
	}
	if *f.asJSON {
		return printJSONValue(s)
	}
	fmt.Printf("session   %s\nstate     %s\nmode      %s\nworkspace %s\nroot pid  %d\n", s.ID, s.State, s.Mode, s.WorkspaceRoot, s.RootPID)
	if s.Envelope != nil {
		prompt := fmt.Sprintf("%q", s.Envelope.Intent.RawPrompt)
		if s.Envelope.Intent.RawPrompt == "" {
			prompt = "(not retained)"
		}
		fmt.Printf("task      %s (%s)\nprompt    %s\n", s.Envelope.Intent.Summary, s.Envelope.Intent.TaskType, prompt)
	}
	if session.IsTerminal(s.State) {
		fmt.Printf("outcome   %s: %s\n", s.Outcome.Result, s.Outcome.Reason)
		fmt.Printf("summary   %d events, %d decisions, %d violations, %d blocked, peak risk %.0f, telemetry complete %v\n",
			s.Summary.EventsObserved, s.Summary.DecisionsIssued, s.Outcome.ViolationCount, s.Outcome.BlockedCount,
			s.Summary.PeakRiskScore, s.Outcome.TelemetryComplete)
		for _, v := range s.Summary.TopViolations {
			fmt.Printf("          violation: %s\n", v)
		}
		if len(s.Summary.UnusedGrants) > 0 {
			fmt.Printf("unused    %v\n", s.Summary.UnusedGrants)
		}
	}
	return 0
}

func runEnvelope(args []string) int {
	f := newDaemonFlags("envelope", "envelope [-json] <session-id>")
	if f.fs.Parse(args) != nil {
		return 2
	}
	if f.fs.NArg() != 1 {
		f.fs.Usage()
		return 2
	}
	env, err := f.client().GetEnvelope(context.Background(), f.fs.Arg(0))
	if err != nil {
		return die("%v", err)
	}
	if *f.asJSON {
		return printJSONValue(env)
	}
	fmt.Printf("envelope %s for session %s\n", env.ID, env.SessionID)
	fmt.Printf("task: %s (%s, %s, confidence %.2f)\n", env.Intent.Summary, env.Intent.TaskType, env.Intent.Analyzer, env.Intent.Confidence)
	fmt.Printf("sealed %v, digest %s\n", env.Sealed, env.Digest)
	if env.Approval != nil {
		fmt.Printf("approved by %s at %s via %s\n", env.Approval.ApprovedBy, env.Approval.ApprovedAt.Format(time.RFC3339), env.Approval.Method)
	}
	fmt.Println("grants:")
	for _, g := range env.Grants {
		fmt.Printf("  + %-14s %s\n      %s\n", g.Kind, envelope.DescribeSelector(g.Selector), g.Rationale)
	}
	fmt.Println("denials:")
	for _, g := range env.Denials {
		fmt.Printf("  - %-14s %s\n      %s\n", g.Kind, envelope.DescribeSelector(g.Selector), g.Rationale)
	}
	return 0
}

func runWatch(args []string) int {
	f := newDaemonFlags("watch", "watch [-json] [-all] [session-id]")
	all := f.fs.Bool("all", false, "Include allowed decisions")
	if f.fs.Parse(args) != nil {
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ch, err := f.client().StreamDecisions(ctx, f.fs.Arg(0))
	if err != nil {
		return die("%v", err)
	}
	enc := json.NewEncoder(os.Stdout)
	for d := range ch {
		if *f.asJSON {
			_ = enc.Encode(d)
			continue
		}
		if !*all && d.Action == "allow" {
			continue
		}
		fmt.Println(formatDecision(d))
	}
	return 0
}

func formatDecision(d decision.Decision) string {
	target := ""
	for _, r := range d.Reasoning {
		if r.Stage == "validator" && r.Conclusion == "resolved observation" {
			target = r.Detail
		}
	}
	applied := ""
	if d.Enforced {
		applied = " APPLIED"
	}
	return fmt.Sprintf("%s %-26s %-17s %-16s risk %3.0f %-8s %s%s",
		d.Timestamp.Format("15:04:05.000"), d.SessionID, d.Verdict, d.Action, d.Risk.Score, d.Risk.Level, target, applied)
}

func runApprovals(args []string) int {
	f := newDaemonFlags("approvals", "approvals [-json]")
	if f.fs.Parse(args) != nil {
		return 2
	}
	list, err := f.client().PendingApprovals(context.Background())
	if err != nil {
		return die("%v", err)
	}
	if *f.asJSON {
		return printJSONValue(list)
	}
	if len(list) == 0 {
		fmt.Println("no pending approvals")
		return 0
	}
	for _, r := range list {
		fmt.Printf("%s  session %s  deadline %s\n  %s\n", r.ID, r.SessionID, r.Deadline.Format(time.RFC3339), r.Summary)
	}
	return 0
}

func answer(approved bool) func([]string) int {
	name := "deny"
	if approved {
		name = "approve"
	}
	return func(args []string) int {
		f := newDaemonFlags(name, name+" <approval-id> [reason]")
		if f.fs.Parse(args) != nil {
			return 2
		}
		if f.fs.NArg() < 1 {
			f.fs.Usage()
			return 2
		}
		err := f.client().RespondApproval(context.Background(), decision.ApprovalResponse{
			RequestID: f.fs.Arg(0), Approved: approved, Reason: strings.Join(f.fs.Args()[1:], " "),
		})
		if err != nil {
			return die("%v", err)
		}
		past := map[bool]string{true: "approved", false: "denied"}[approved]
		fmt.Printf("%s %s\n", past, f.fs.Arg(0))
		return 0
	}
}

// runLeftovers lists the session cgroups an earlier daemon left behind, or
// thaws or kills one. Root only, like the daemon side.
func runLeftovers(args []string) int {
	f := newDaemonFlags("leftovers", "leftovers [-json] [thaw|kill <name>]")
	if f.fs.Parse(args) != nil {
		return 2
	}
	ctx := context.Background()
	switch f.fs.Arg(0) {
	case "":
		list, err := f.client().ListLeftovers(ctx)
		if err != nil {
			return die("%v", err)
		}
		if *f.asJSON {
			return printJSONValue(list)
		}
		if len(list) == 0 {
			fmt.Println("no leftover session cgroups")
			return 0
		}
		for _, l := range list {
			state := "RUNNING UNGOVERNED"
			if l.Frozen {
				state = "frozen"
			}
			fmt.Printf("%s  %s  pids %v  users %v\n", l.Name, state, l.PIDs, l.Users)
		}
		return 0
	case "thaw", "kill":
		if f.fs.NArg() != 2 {
			f.fs.Usage()
			return 2
		}
		name := f.fs.Arg(1)
		var err error
		if f.fs.Arg(0) == "thaw" {
			err = f.client().ThawLeftover(ctx, name)
		} else {
			err = f.client().KillLeftover(ctx, name)
		}
		if err != nil {
			return die("%v", err)
		}
		if f.fs.Arg(0) == "thaw" {
			fmt.Printf("thawed %s; its processes now run with nothing governing them\n", name)
		} else {
			fmt.Printf("killed %s\n", name)
		}
		return 0
	}
	f.fs.Usage()
	return 2
}
