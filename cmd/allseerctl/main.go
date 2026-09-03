// Command allseerctl is the ALLSEER operator CLI.
//
// It is the human interface to a running daemon: inspecting sessions and
// envelopes, answering approval requests, and managing policy. It holds no
// governance state and makes no decisions; everything goes through the control
// socket, so the CLI can be run by an unprivileged user.
//
// Planned commands:
//
//	allseerctl status                    daemon health and probe coverage
//	allseerctl session list              list governed sessions
//	allseerctl session show <id>         session detail and summary
//	allseerctl session watch <id>        live decision stream
//	allseerctl envelope show <id>        the envelope governing a session
//	allseerctl envelope diff <id>        how it differs from its base profile
//	allseerctl approve                   interactive approval prompt
//	allseerctl policy lint <file>        check a rule set for problems
//	allseerctl policy reload             reload the active rule set
//	allseerctl policy dry-run <session>  replay a session against a rule set
//	allseerctl config validate <file>    check configuration
//	allseerctl replay <file>             replay recorded telemetry
//
// Implemented so far: replay, policy dry-run, capabilities, version. Everything
// else needs the control socket, which arrives with the daemon in Phase 2.
//
// Dispatch uses the standard library flag package with subcommands. A CLI
// framework is a dependency this project does not need.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/stringNameMahin/ALLSEER/internal/buildinfo"
)

// TODO(allseerctl): implement the control socket client.
// TODO(allseerctl): render envelopes and decisions for humans. This is the main
// usability surface: an approval prompt nobody can understand in a few seconds
// gets approved reflexively, which is worse than not asking.
// TODO(allseerctl): add `policy lint <file>`, which is the dry-run command's
// first two steps with the replay left off.

// command is one subcommand.
//
// A table, so help is generated from what is actually dispatchable.
// Hand-maintained help text drifts, and a CLI advertising a command it does not
// have wastes the operator's time at the moment they are trying to work out why
// their agent stopped.
type command struct {
	name    string
	summary string

	// run receives the arguments following the subcommand name and returns the
	// process exit code.
	run func(args []string) int
}

func commands() []command {
	return []command{
		{"replay", "Replay a recorded telemetry stream", runReplay},
		{"policy", "Inspect policy rule sets; dry-run one against a recording", runPolicy},
		{"capabilities", "List the capability catalog this build knows", runCapabilities},
		{"version", "Print build metadata", runVersion},
		{"help", "Show this help", func([]string) int { usage(os.Stdout); return 0 }},
	}
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage(os.Stderr)
		return 2
	}

	name := args[0]
	// Accept the usual help spellings so they do not fall through to the
	// unknown-command path.
	if name == "-h" || name == "--help" {
		usage(os.Stdout)
		return 0
	}

	for _, c := range commands() {
		if c.name == name {
			return c.run(args[1:])
		}
	}

	fmt.Fprintf(os.Stderr, "allseerctl: unknown command %q\n\n", name)
	usage(os.Stderr)
	return 2
}

func usage(w io.Writer) {
	fmt.Fprintf(w, "allseerctl %s\n\n", buildinfo.String())
	fmt.Fprint(w, "Usage: allseerctl <command> [flags] [arguments]\n\nCommands:\n")
	for _, c := range commands() {
		fmt.Fprintf(w, "  %-14s %s\n", c.name, c.summary)
	}
	fmt.Fprint(w, "\nRun `allseerctl <command> -h` for command flags.\n")
}

func runVersion([]string) int {
	fmt.Println(buildinfo.String())
	return 0
}
