// Command abigen regenerates the Go view of the kernel/user ABI from
// bpf/include/allseer_event.h.
//
// A development tool, not a shipped binary, which is why it lives under
// internal/ rather than cmd/. It is invoked by `go generate ./internal/telemetry/abi/`
// and by the `gen` and `gen-check` Makefile targets.
//
// All the work is in internal/telemetry/abigen, so the staleness test can run
// exactly this pipeline in memory rather than shelling out to a binary and
// trusting that it was rebuilt.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"

	"github.com/stringNameMahin/ALLSEER/internal/telemetry/abigen"
)

func main() {
	header := flag.String("header", "bpf/include/allseer_event.h", "path to the C ABI header")
	out := flag.String("out", "", "output file; empty writes to stdout")
	pkg := flag.String("package", "abi", "package name for the generated file")
	check := flag.Bool("check", false, "verify the output file is up to date; write nothing and exit non-zero if not")
	flag.Parse()

	if err := run(*header, *out, *pkg, *check); err != nil {
		fmt.Fprintf(os.Stderr, "abigen: %v\n", err)
		os.Exit(1)
	}
}

func run(headerPath, outPath, pkg string, check bool) error {
	src, err := os.ReadFile(headerPath)
	if err != nil {
		return fmt.Errorf("reading the header: %w", err)
	}

	generated, err := abigen.Generate(src, headerPath, pkg)
	if err != nil {
		return err
	}

	if outPath == "" {
		_, err := os.Stdout.Write(generated)
		return err
	}

	if check {
		committed, err := os.ReadFile(outPath)
		if err != nil {
			return fmt.Errorf("reading %s to check it: %w", outPath, err)
		}
		// Compared after normalizing, for the reason abigen.Normalize gives:
		// the committed .go file is CRLF on a Windows checkout and LF on a
		// Linux one, and a line-ending difference is not drift.
		if !bytes.Equal(abigen.Normalize(committed), abigen.Normalize(generated)) {
			return fmt.Errorf("%s is stale relative to %s\n\n"+
				"The generated ABI and the header have diverged. Regenerate with:\n"+
				"    go generate ./internal/telemetry/abi/\n\n"+
				"then review the diff — a change here is a change in how kernel bytes are read",
				outPath, headerPath)
		}
		fmt.Printf("abigen: %s is up to date with %s\n", outPath, headerPath)
		return nil
	}

	// Written with LF regardless of platform. The file is generated output
	// compared byte for byte by a test, and committing whichever line ending
	// the generating host happened to use is how that comparison starts failing
	// for reasons that have nothing to do with the ABI.
	if err := os.WriteFile(outPath, abigen.Normalize(generated), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", outPath, err)
	}
	fmt.Printf("abigen: wrote %s from %s\n", outPath, headerPath)
	return nil
}
