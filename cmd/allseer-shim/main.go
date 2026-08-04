// Command allseer-shim launches an agent under ALLSEER governance.
//
// The shim is what a user actually runs:
//
//	allseer-shim --prompt "refactor the parser package" -- claude-code
//
// The sequence matters more than the size:
//
//  1. Create a session with the daemon, passing the prompt and workspace. The
//     daemon analyzes intent and generates an envelope.
//  2. Present the envelope for approval if required.
//  3. Fork, register the child PID with the daemon, then exec the agent.
//     Registering before exec is the critical ordering: attaching afterwards
//     leaves a window in which the agent's first actions go unobserved.
//  4. Wait for exit, propagate the exit code, and print the session summary.
//
// The shim runs unprivileged and holds no governance authority. Subverting it
// can only prevent a session from starting; it cannot widen what the agent may
// do, because the daemon owns the envelope.
//
// If the daemon is unreachable the shim refuses to launch. Launching ungoverned
// would quietly nullify the whole system.
package main

import (
	"fmt"
	"os"

	"github.com/stringNameMahin/ALLSEER/internal/buildinfo"
)

// TODO(shim): flags (--prompt, --workspace, --mode, --profile, trailing --),
// daemon connection, workspace context gathering, CreateSession,
// fork/register/exec, stdio forwarding, suspension handling, EndSession.

func main() {
	fmt.Fprintf(os.Stderr, "allseer-shim %s: not implemented\n", buildinfo.String())
	os.Exit(1)
}
