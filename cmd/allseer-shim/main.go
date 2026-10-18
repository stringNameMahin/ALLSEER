// Command allseer-shim runs an agent under ALLSEER governance.
//
//	allseer-shim --prompt "run the tests" -- claude-code ...
//
// Launch order is the security property: the shim starts a held copy of
// itself, the daemon moves that process into the session's cgroup and attaches
// telemetry, and only then is it released to exec the agent. The agent's first
// instruction runs observed. If the daemon cannot be reached, the agent is not
// launched at all.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/stringNameMahin/ALLSEER/internal/envelope"
	"github.com/stringNameMahin/ALLSEER/internal/ipc"
	"github.com/stringNameMahin/ALLSEER/internal/policy"
	"github.com/stringNameMahin/ALLSEER/internal/session"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
)

// Exit codes the shim itself produces. Anything else is the agent's.
const (
	exitNotLaunched = 125
	exitHoldFailed  = 126
	holdArg         = "__allseer_hold"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == holdArg {
		os.Exit(hold(os.Args[2:]))
	}
	os.Exit(run(os.Args[1:]))
}

// hold is the launcher half: it waits for the release byte on fd 3 and then
// becomes the agent. Without the byte it exits without running anything.
func hold(args []string) int {
	if len(args) < 2 || args[0] != "--" {
		return exitHoldFailed
	}
	gate := os.NewFile(3, "gate")
	var b [1]byte
	n, _ := gate.Read(b[:])
	_ = gate.Close()
	if n != 1 || b[0] != 'g' {
		return exitHoldFailed
	}
	path, argv := args[1], args[2:]
	err := syscall.Exec(path, argv, os.Environ())
	fmt.Fprintf(os.Stderr, "allseer-shim: exec %s: %v\n", path, err)
	return exitHoldFailed
}

func run(args []string) int {
	fs := flag.NewFlagSet("allseer-shim", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), "Usage: allseer-shim [flags] -- <agent> [args...]\n\nRun an agent under ALLSEER governance.\n\nFlags:\n")
		fs.PrintDefaults()
	}
	var (
		socket     = fs.String("socket", envOr("ALLSEER_SOCKET", "/run/allseer/allseerd.sock"), "Daemon socket")
		prompt     = fs.String("prompt", "", "The task the agent is given (the envelope is derived from it)")
		promptFile = fs.String("prompt-file", "", "Read the prompt from a file")
		workspace  = fs.String("workspace", "", "Workspace root (default: current directory)")
		mode       = fs.String("mode", "", "Request a stricter enforcement mode (monitor, warn, interactive, enforce)")
		yes        = fs.Bool("yes", false, "Approve the envelope without asking (it is still printed)")
		noTTY      = fs.Bool("no-tty-approvals", false, "Do not prompt on the terminal for runtime approvals; use allseerctl approve")
		quiet      = fs.Bool("quiet", false, "Print less")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	agent := fs.Args()
	if len(agent) == 0 {
		fs.Usage()
		return 2
	}
	text := *prompt
	if *promptFile != "" {
		b, err := os.ReadFile(*promptFile)
		if err != nil {
			return fail("reading the prompt: %v", err)
		}
		text = string(b)
	}
	if strings.TrimSpace(text) == "" {
		return fail("a prompt is required (--prompt or --prompt-file): the envelope is derived from it")
	}
	ws := *workspace
	if ws == "" {
		ws, _ = os.Getwd()
	}
	ws, _ = filepath.Abs(ws)

	agentPath, err := exec.LookPath(agent[0])
	if err != nil {
		return fail("agent %q: %v", agent[0], err)
	}
	agentPath, _ = filepath.Abs(agentPath)

	ctx := context.Background()
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	client, err := ipc.Dial(dialCtx, *socket)
	cancel()
	if err != nil {
		return fail("the governance daemon is not reachable (%v); refusing to launch the agent ungoverned", err)
	}

	resp, err := client.CreateSession(ctx, ipc.CreateSessionRequest{
		Prompt: text, WorkspaceRoot: ws, Mode: policy.Mode(*mode),
		AgentIdentity: filepath.Base(agentPath), Workspace: gatherWorkspace(ws),
	})
	if err != nil {
		return fail("creating the session: %v", err)
	}
	sid := resp.SessionID
	printEnvelope(resp, *quiet)

	if resp.RequiresApproval {
		ok := *yes
		if *yes {
			note("envelope approved by --yes")
		} else {
			ok, err = askTTY("Approve this envelope and launch the agent? [y/N] ")
			if err != nil {
				_ = client.ApproveEnvelope(ctx, ipc.ApproveEnvelopeRequest{SessionID: sid, Approved: false, Reason: "no terminal to approve on"})
				return fail("approval needs a terminal or --yes: %v", err)
			}
		}
		if err := client.ApproveEnvelope(ctx, ipc.ApproveEnvelopeRequest{SessionID: sid, Approved: ok}); err != nil {
			return fail("recording approval: %v", err)
		}
		if !ok {
			note("envelope rejected; the agent was not launched")
			return exitNotLaunched
		}
	}

	self, err := os.Executable()
	if err != nil {
		return fail("locating the shim binary: %v", err)
	}
	gateR, gateW, err := os.Pipe()
	if err != nil {
		return fail("%v", err)
	}
	child := exec.Command(self, append([]string{holdArg, "--", agentPath}, agent...)...)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	child.ExtraFiles = []*os.File{gateR}
	if err := child.Start(); err != nil {
		return fail("starting the agent launcher: %v", err)
	}
	_ = gateR.Close()

	if err := client.StartSession(ctx, sid, int32(child.Process.Pid)); err != nil {
		_ = gateW.Close()
		_ = child.Wait()
		return fail("the daemon could not govern the agent (%v); it was not launched", err)
	}

	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	go func() {
		for s := range sigs {
			if s != syscall.SIGINT {
				_ = child.Process.Signal(s)
			}
		}
	}()

	approvalsCtx, stopApprovals := context.WithCancel(ctx)
	var daemonGone atomic.Bool
	go watchApprovals(approvalsCtx, client, sid, !*noTTY)
	go watchDaemon(approvalsCtx, client, func() {
		daemonGone.Store(true)
		_ = child.Process.Kill()
	})

	if _, err := gateW.Write([]byte{'g'}); err != nil {
		stopApprovals()
		return fail("releasing the agent: %v", err)
	}
	_ = gateW.Close()

	code := exitCode(child.Wait())
	stopApprovals()
	signal.Stop(sigs)

	// Nothing to report the end to, and the agent was stopped because of it.
	if daemonGone.Load() {
		note("the session was not ended cleanly: the governance daemon is gone")
		return code
	}
	endCtx, cancelEnd := context.WithTimeout(ctx, 30*time.Second)
	s, err := client.EndSession(endCtx, sid, code)
	cancelEnd()
	if err != nil {
		note("ending the session: %v", err)
		return code
	}
	printOutcome(s)
	return code
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal())
		}
		return ee.ExitCode()
	}
	return exitNotLaunched
}

// watchApprovals tells the user why their agent stopped, and asks on the
// terminal when one is available.
func watchApprovals(ctx context.Context, c *ipc.SocketClient, sid string, useTTY bool) {
	ch, err := c.StreamApprovals(ctx)
	if err != nil {
		return
	}
	for req := range ch {
		if req.SessionID != sid {
			continue
		}
		fmt.Fprintf(os.Stderr, "\n[allseer] agent SUSPENDED, approval %s required\n[allseer] %s\n", req.ID, req.Summary)
		if !useTTY {
			fmt.Fprintf(os.Stderr, "[allseer] answer with: allseerctl approve %s   or   allseerctl deny %s\n", req.ID, req.ID)
			continue
		}
		ok, err := askTTY("[allseer] approve and resume? [y/N] ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "[allseer] no terminal (%v); answer with allseerctl approve %s\n", err, req.ID)
			continue
		}
		if err := c.RespondApproval(ctx, decision.ApprovalResponse{RequestID: req.ID, Approved: ok}); err != nil {
			fmt.Fprintf(os.Stderr, "[allseer] answering %s: %v\n", req.ID, err)
		}
	}
}

// watchDaemon stops the agent if the daemon stops answering.
//
// The shim refuses to launch an agent with no daemon reachable. A daemon that
// disappears mid-session leaves the agent running with nothing observing it,
// which is the same situation, so it gets the same answer. The grace period is
// there so a restart or a slow reply does not kill a long build.
//
// It kills the launcher it started. Descendants that have left that process
// behind are out of reach: killing the session cgroup needs the daemon, and
// the shim is unprivileged by design.
func watchDaemon(ctx context.Context, c *ipc.SocketClient, kill func()) {
	const (
		every = 2 * time.Second
		grace = 10 * time.Second
	)
	t := time.NewTicker(every)
	defer t.Stop()
	var downSince time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		callCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		_, err := c.Status(callCtx)
		cancel()
		if err == nil {
			downSince = time.Time{}
			continue
		}
		if downSince.IsZero() {
			downSince = time.Now()
			continue
		}
		if time.Since(downSince) < grace {
			continue
		}
		fmt.Fprintf(os.Stderr,
			"\n[allseer] the governance daemon has not answered for %s; stopping the agent\n", grace)
		kill()
		return
	}
}

func askTTY(question string) (bool, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return false, err
	}
	defer tty.Close()
	fmt.Fprint(tty, question)
	line, err := bufio.NewReader(tty).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	a := strings.ToLower(strings.TrimSpace(line))
	return a == "y" || a == "yes", nil
}

func printEnvelope(r *ipc.CreateSessionResponse, quiet bool) {
	env := r.Envelope
	w := os.Stderr
	fmt.Fprintf(w, "[allseer] session %s\n", r.SessionID)
	fmt.Fprintf(w, "[allseer] task: %s (%s, confidence %.2f)\n", env.Intent.Summary, env.Intent.TaskType, env.Intent.Confidence)
	for _, a := range env.Intent.Ambiguities {
		fmt.Fprintf(w, "[allseer]   ambiguity: %s\n", a)
	}
	if !quiet {
		fmt.Fprintf(w, "[allseer] expected capabilities (workspace %s):\n", env.Constraints.WorkspaceRoot)
		for _, g := range env.Grants {
			fmt.Fprintf(w, "[allseer]   + %-13s %s\n", g.Kind, selector(g))
		}
		for _, g := range env.Denials {
			fmt.Fprintf(w, "[allseer]   - %-13s %s\n", g.Kind, selector(g))
		}
	}
	for _, warn := range r.Warnings {
		fmt.Fprintf(w, "[allseer] WARNING: %s\n", warn)
	}
	fmt.Fprintf(w, "[allseer] digest %s\n", env.Digest)
}

func selector(g capability.Grant) string { return envelope.DescribeSelector(g.Selector) }

func printOutcome(s *session.Session) {
	w := os.Stderr
	o, sum := s.Outcome, s.Summary
	fmt.Fprintf(w, "[allseer] session %s %s: %s\n", s.ID, s.State, o.Reason)
	fmt.Fprintf(w, "[allseer]   %d events, %d decisions, %d violations, %d blocked, peak risk %.0f\n",
		sum.EventsObserved, sum.DecisionsIssued, o.ViolationCount, o.BlockedCount, sum.PeakRiskScore)
	if !o.TelemetryComplete {
		fmt.Fprintln(w, "[allseer]   TELEMETRY INCOMPLETE: conclusions about this session are unsound")
	}
	for _, v := range sum.TopViolations {
		fmt.Fprintf(w, "[allseer]   violation: %s\n", v)
	}
}

func note(format string, a ...any) { fmt.Fprintf(os.Stderr, "[allseer] "+format+"\n", a...) }

func fail(format string, a ...any) int {
	fmt.Fprintf(os.Stderr, "allseer-shim: "+format+"\n", a...)
	return exitNotLaunched
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
