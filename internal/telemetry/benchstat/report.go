package benchstat

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// ReadRuns parses a JSONL stream of Run records.
//
// A malformed line is an error rather than a skip. The alternative — dropping
// what it cannot read — would silently shrink the sample, and a smaller sample
// widens the interval, which is the direction that turns a real failure into an
// inconclusive result.
func ReadRuns(r io.Reader) ([]Run, error) {
	var runs []Run
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		var run Run
		if err := json.Unmarshal([]byte(text), &run); err != nil {
			return nil, fmt.Errorf("benchstat: line %d: %w", line, err)
		}
		runs = append(runs, run)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("benchstat: reading runs: %w", err)
	}
	return runs, nil
}

// Report renders a Result as Markdown.
func Report(w io.Writer, res *Result) error {
	b := &strings.Builder{}

	fmt.Fprintf(b, "# ALLSEER probe overhead — W3\n\n")
	fmt.Fprintf(b, "**Verdict: %s**\n\n", res.Verdict)
	for _, r := range res.Reasons {
		fmt.Fprintf(b, "- %s\n", r)
	}
	fmt.Fprintf(b, "\nSession `%s`.\n\n", res.SessionID)

	fmt.Fprintf(b, "## Headline — %s vs %s, %s workload\n\n",
		res.Headline.Treatment, res.Headline.Baseline, res.Headline.Workload)
	writeComparison(b, res.Headline)

	fmt.Fprintf(b, "\n## Control — %s vs %s\n\n", res.Control.Treatment, res.Control.Baseline)
	if res.Control.Pairs == 0 {
		fmt.Fprintf(b, "Not run. The harness's own cost is unknown.\n")
	} else {
		writeComparison(b, res.Control)
		if res.Control.ContainsZero() {
			fmt.Fprintf(b, "\nThe interval contains zero: the harness is indistinguishable from the baseline.\n")
		} else {
			fmt.Fprintf(b, "\n**The interval excludes zero.** The harness itself costs something, so the "+
				"headline is not measuring the probes alone.\n")
		}
	}

	if len(res.Diagnostics) > 0 {
		fmt.Fprintf(b, "\n## Diagnostics — not gating\n\n")
		fmt.Fprintf(b, "| Comparison | Pairs | Median | 95%% CI |\n|---|---:|---:|---|\n")
		for _, c := range res.Diagnostics {
			fmt.Fprintf(b, "| %s vs %s | %d | %+.2f%% | [%+.2f%%, %+.2f%%] |\n",
				c.Treatment, c.Baseline, c.Pairs, c.MedianOverhead*100, c.CILow*100, c.CIHigh*100)
		}
		fmt.Fprintf(b, "\n`%s` vs `%s` is the decomposition: how much of the headline is paid before a "+
			"single event is reported.\n", ArmTracked, ArmAttachedUntracked)
	}

	if len(res.Startup) > 0 {
		fmt.Fprintf(b, "\n## One-off startup cost — not part of any ratio\n\n")
		fmt.Fprintf(b, "What ALLSEER pays once when a session starts, in seconds. It is kept out of "+
			"every wall-clock ratio on purpose: a governed session pays it at startup and then runs "+
			"for days, so folding a fixed cost into a per-build percentage would make the reported "+
			"overhead depend on how long the build was.\n\n")
		fmt.Fprintf(b, "| Arm | Runs | Median load | Max load | Median attach | Max attach |\n")
		fmt.Fprintf(b, "|---|---:|---:|---:|---:|---:|\n")
		for _, sc := range res.Startup {
			fmt.Fprintf(b, "| %s | %d | %.3fs | %.3fs | %.3fs | %.3fs |\n",
				sc.Arm, sc.Runs, sc.MedianLoadSeconds, sc.MaxLoadSeconds,
				sc.MedianAttachSeconds, sc.MaxAttachSeconds)
		}
		fmt.Fprintf(b, "\n`%s` loads the object and attaches nothing, so its attach column is the "+
			"floor. The difference between it and the attached arms is what attaching every program "+
			"costs.\n", ArmLoaded)
	}

	if res.Storm != nil {
		fmt.Fprintf(b, "\n## Adversarial workload — %s\n\n", WorkloadOpenatStorm)
		fmt.Fprintf(b, "Reported separately and gating nothing. It bounds the worst case rather than "+
			"describing a build.\n\n")
		writeComparison(b, *res.Storm)
	}

	fmt.Fprintf(b, "\n## Integrity\n\n")
	fmt.Fprintf(b, "| Check | Value |\n|---|---|\n")
	fmt.Fprintf(b, "| Ring buffer drops | %d across %d run(s) |\n", res.TotalDrops, res.DroppedRuns)
	fmt.Fprintf(b, "| Tracked runs observing no events | %d |\n", res.ZeroEventA3)
	fmt.Fprintf(b, "| Runs that failed or exited non-zero | %d |\n", res.FailedRuns)

	if res.Env != nil {
		writeEnvironment(b, res.Env)
	}

	_, err := io.WriteString(w, b.String())
	return err
}

func writeComparison(b *strings.Builder, c Comparison) {
	if c.Pairs == 0 {
		fmt.Fprintf(b, "No paired observations.\n")
		return
	}
	fmt.Fprintf(b, "| | |\n|---|---|\n")
	fmt.Fprintf(b, "| Paired observations | %d |\n", c.Pairs)
	fmt.Fprintf(b, "| **Median overhead** | **%+.2f%%** |\n", c.MedianOverhead*100)
	fmt.Fprintf(b, "| 95%% CI (%d bootstrap resamples) | [%+.2f%%, %+.2f%%] |\n",
		BootstrapResamples, c.CILow*100, c.CIHigh*100)
	fmt.Fprintf(b, "| Mean overhead | %+.2f%% |\n", c.MeanOverhead*100)
	fmt.Fprintf(b, "| Std. deviation | %.2f%% |\n", c.StdDev*100)
	fmt.Fprintf(b, "| Min / max | %+.2f%% / %+.2f%% |\n", c.MinOverhead*100, c.MaxOverhead*100)

	fmt.Fprintf(b, "\n<details><summary>Per-pair observations</summary>\n\n")
	fmt.Fprintf(b, "| Replicate | Overhead |\n|---:|---:|\n")
	for i, o := range c.Overheads {
		fmt.Fprintf(b, "| %d | %+.2f%% |\n", c.Replicates[i], o*100)
	}
	fmt.Fprintf(b, "\n</details>\n")
}

func writeEnvironment(b *strings.Builder, e *Environment) {
	fmt.Fprintf(b, "\n## Environment\n\n| | |\n|---|---|\n")
	rows := [][2]string{
		{"Captured", e.CapturedAt},
		{"Kernel", e.KernelRelease},
		{"BTF available", fmt.Sprint(e.BTFAvailable)},
		{"Virtualization", e.Virtualization},
		{"CPU", e.CPUModel},
		{"Cores", fmt.Sprint(e.CPUCores)},
		{"Governor", e.Governor},
		{"Turbo", e.TurboState},
		{"RAM total / free (KB)", fmt.Sprintf("%d / %d", e.MemTotalKB, e.MemFreeKB)},
		{"Go", e.GoVersion},
		{"clang", e.ClangVersion},
		{"libbpf", e.LibbpfVersion},
		{"ALLSEER commit", e.AllseerCommit},
		{"Object SHA-256", e.ObjectSHA256},
		{"ABI version", fmt.Sprint(e.ABIVersion)},
		{"Record size", fmt.Sprintf("%d bytes", e.RecordSize)},
		{"Programs attached", fmt.Sprint(len(e.AttachedPrograms))},
		{"Workload cgroup", e.WorkloadCgroup},
		{"Workload cgroup ID", fmt.Sprint(e.WorkloadCgroupID)},
		{"GOCACHE", e.GOCACHE},
		{"GOMODCACHE", e.GOMODCACHE},
		{"GOMAXPROCS", fmt.Sprint(e.GOMAXPROCS)},
		{"Ring buffer", fmt.Sprintf("%d bytes", e.RingBufferSize)},
		{"Load average before / after", e.LoadAvgBefore + " / " + e.LoadAvgAfter},
		{"Arm-ordering seed", fmt.Sprint(e.Seed)},
		{"Replicates", fmt.Sprint(e.Replicates)},
	}
	for _, r := range rows {
		v := r[1]
		if strings.TrimSpace(v) == "" {
			v = "unavailable"
		}
		fmt.Fprintf(b, "| %s | %s |\n", r[0], v)
	}
	if len(e.AttachedPrograms) > 0 {
		fmt.Fprintf(b, "\n<details><summary>Attached programs</summary>\n\n")
		for _, p := range e.AttachedPrograms {
			fmt.Fprintf(b, "- `%s`\n", p)
		}
		fmt.Fprintf(b, "\n</details>\n")
	}
}
