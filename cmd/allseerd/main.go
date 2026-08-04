// Command allseerd is the ALLSEER governance daemon.
//
// The daemon is the privileged component. It loads eBPF programs, owns the
// decision path, and holds all governance state. It is the only part of the
// system that needs kernel capabilities, and it drops what it can once probes
// are attached.
//
// It does not launch agents. That is the shim's job, which keeps the privileged
// process out of the business of executing untrusted commands.
//
// Usage:
//
//	allseerd --config /etc/allseer/config.yaml
package main

import (
	"fmt"
	"os"

	"github.com/stringNameMahin/ALLSEER/internal/buildinfo"
)

// TODO(allseerd): flags, config load, logging init, prerequisite checks
// (kernel version, BTF, capabilities), probe attach, privilege drop, pipeline
// construction, IPC server, signal handling.

func main() {
	fmt.Fprintf(os.Stderr, "allseerd %s: not implemented\n", buildinfo.String())
	os.Exit(1)
}
