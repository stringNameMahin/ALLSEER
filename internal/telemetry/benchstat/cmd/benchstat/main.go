// Command benchstat turns a probe-overhead session into a verdict.
//
//	benchstat -runs bench/session.jsonl [-seed N] [-json] [-o report.md]
//	benchstat -order -seed N -replicate R [-arms A0,A1,A2,A3,A4]
//
// The first form analyses a session. It exits 0 on PASS and 1 on anything else,
// so a shell can gate on it, and it prints the verdict either way. The exit
// code deliberately does not distinguish FAIL from INCONCLUSIVE: neither is a
// measurement that the target was met, and a caller that treated "we could not
// tell" as success would be the exact failure the acceptance rule exists to
// prevent.
//
// The second form prints one replicate's arm order and exits, and is what
// scripts/bench-overhead.sh builds its schedule from. It lives in this command
// rather than in the shell because the shell's own attempt at it —
// `shuf --random-source=<(yes "$SEED-$rep")` — returned the same permutation
// for every replicate, and nothing in a session's output said so. See
// benchstat.ArmOrder.
//
// The same split internal/telemetry/abigen uses: a package that does the work
// and a command that does the file handling.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/stringNameMahin/ALLSEER/internal/telemetry/benchstat"
)

func main() {
	runsPath := flag.String("runs", "", "path to the session's JSONL run records (required)")
	out := flag.String("o", "", "write the Markdown report here instead of stdout")
	asJSON := flag.Bool("json", false, "emit the analysis as JSON instead of Markdown")
	seed := flag.Int64("seed", 1, "the session seed: the bootstrap's, and with -order the schedule's")
	order := flag.Bool("order", false, "print one replicate's arm order and exit, instead of analysing a session")
	replicate := flag.Int("replicate", 0, "with -order: which replicate to order the arms for, from 1")
	arms := flag.String("arms", strings.Join(benchstat.Arms(), ","),
		"with -order: comma-separated arms to order (default: the acceptance arms; "+
			"benchstat.KnownArms names the diagnostic ones that can be added explicitly)")
	flag.Parse()

	if *order {
		printArmOrder(*seed, *replicate, *arms)
		return
	}

	if *runsPath == "" {
		fmt.Fprintln(os.Stderr, "benchstat: -runs is required")
		flag.Usage()
		os.Exit(2)
	}

	f, err := os.Open(*runsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "benchstat: %v\n", err)
		os.Exit(2)
	}
	defer f.Close()

	runs, err := benchstat.ReadRuns(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "benchstat: %v\n", err)
		os.Exit(2)
	}
	if len(runs) == 0 {
		fmt.Fprintf(os.Stderr, "benchstat: %s holds no run records\n", *runsPath)
		os.Exit(2)
	}

	res, err := benchstat.Analyze(runs, *seed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "benchstat: %v\n", err)
		os.Exit(2)
	}

	w := os.Stdout
	if *out != "" {
		w, err = os.Create(*out)
		if err != nil {
			fmt.Fprintf(os.Stderr, "benchstat: %v\n", err)
			os.Exit(2)
		}
		defer w.Close()
	}

	if *asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			fmt.Fprintf(os.Stderr, "benchstat: %v\n", err)
			os.Exit(2)
		}
	} else if err := benchstat.Report(w, res); err != nil {
		fmt.Fprintf(os.Stderr, "benchstat: %v\n", err)
		os.Exit(2)
	}

	if *out != "" {
		fmt.Fprintf(os.Stderr, "benchstat: %s — report written to %s\n", res.Verdict, *out)
	}
	if res.Verdict != benchstat.Pass {
		os.Exit(1)
	}
}

// printArmOrder emits one replicate's arm order, space separated, on one line.
//
// One line of plain tokens because the caller is a shell loop. Any failure is
// an exit 2 with a message on stderr rather than a partial schedule on stdout:
// an orchestrator that silently fell back to the arms' declared order would
// reintroduce the exact confound this command exists to remove.
func printArmOrder(seed int64, replicate int, armList string) {
	var arms []string
	for _, a := range strings.Split(armList, ",") {
		if a = strings.TrimSpace(a); a != "" {
			arms = append(arms, a)
		}
	}

	ordered, err := benchstat.ArmOrder(seed, replicate, arms)
	if err != nil {
		// No "benchstat:" prefix here: the package's errors already carry one.
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(2)
	}
	fmt.Println(strings.Join(ordered, " "))
}
