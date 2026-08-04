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

	"github.com/stringNameMahin/ALLSEER/internal/telemetry/replay"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// runReplay streams a recorded telemetry file through event.Source and prints
// it.
//
// The first end-to-end path through the tree, and more than a debugging
// convenience: it is how a corpus fixture is inspected before being trusted,
// and it is the skeleton `policy dry-run` becomes once the validator and policy
// engine exist. The stages slot in between the source and the printer without
// changing anything here.
func runReplay(args []string) int {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), "Usage: allseerctl replay [flags] <file.jsonl>\n\n"+
			"Stream a recorded telemetry file through the event source and print it.\n\n"+
			"Flags:\n")
		fs.PrintDefaults()
	}

	var (
		asJSON  = fs.Bool("json", false, "Emit events as JSONL rather than a table")
		speed   = fs.Float64("speed", 0, "Wall-clock playback multiplier; 0 replays as fast as possible")
		session = fs.String("session", "", "Override the session ID on every record")
		skipBad = fs.Bool("skip-malformed", false, "Continue past unparseable records instead of stopping")
		quiet   = fs.Bool("quiet", false, "Suppress the trailing summary")
	)

	if err := fs.Parse(args); err != nil {
		return 2 // flag package has already reported it
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}

	// Ctrl-C stops playback cleanly instead of killing the process mid-stream,
	// which matters for paced replay of a long recording.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	src := replay.New(replay.Config{
		Path:          fs.Arg(0),
		Speed:         *speed,
		SessionID:     *session,
		SkipMalformed: *skipBad,
	})
	if err := src.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "allseerctl replay: %v\n", err)
		return 1
	}
	defer func() { _ = src.Close() }()

	var n int
	if *asJSON {
		n = printJSON(src.Events())
	} else {
		n = printTable(src.Events())
	}

	// The stream ending is not the same as ending cleanly. A corrupt recording
	// must exit non-zero, or a truncated capture reads as a complete session to
	// whatever consumed this.
	streamErr := src.Err()
	if streamErr != nil {
		fmt.Fprintf(os.Stderr, "\nallseerctl replay: %v\n", streamErr)
	}
	if !*quiet {
		printSummary(src, n, streamErr)
	}
	if streamErr != nil {
		return 1
	}
	return 0
}

func printJSON(events <-chan event.Event) int {
	enc := json.NewEncoder(os.Stdout)
	var n int
	for e := range events {
		if err := enc.Encode(e); err != nil {
			fmt.Fprintf(os.Stderr, "allseerctl replay: writing output: %v\n", err)
			return n
		}
		n++
	}
	return n
}

func printTable(events <-chan event.Event) int {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SEQ\tTIME\tCAPABILITY\tPROCESS\tTARGET\tRESULT")

	var (
		n    int
		base uint64
		have bool
	)
	for e := range events {
		if !have {
			base, have = e.KernelTimestamp, true
		}

		// A gap is evidence of ring buffer loss, called out inline as well as
		// in the summary: an operator scanning the stream needs to see where
		// the hole is, because conclusions drawn across it are unsound. It goes
		// in the TARGET column, already the widest, so the marker does not
		// stretch the narrow columns around it.
		if e.Dropped > 0 {
			fmt.Fprintf(w, "\t\t\t\t--- %d events lost before this record ---\t\n", e.Dropped)
		}

		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\n",
			e.Sequence,
			formatOffset(e.KernelTimestamp, base),
			e.Capability,
			formatProcess(e),
			truncate(e.Observation.Target, 56),
			formatResult(e),
		)
		n++
	}

	_ = w.Flush()
	return n
}

// formatOffset renders the event's time relative to the first event, which is
// what matters when reading a stream. Absolute ktime since boot is not.
func formatOffset(ts, base uint64) string {
	if ts < base {
		return "-"
	}
	ms := float64(ts-base) / 1e6
	return fmt.Sprintf("%8.3fms", ms)
}

func formatProcess(e event.Event) string {
	name := e.Process.Comm
	if name == "" {
		name = "?"
	}
	s := fmt.Sprintf("%s[%d]", name, e.Process.PID)
	// Depth is a governance signal on its own: an agent shelling out three
	// levels deep to reach the network behaves differently from one that
	// connects directly.
	if e.Process.AncestryDepth > 0 {
		s += fmt.Sprintf("+%d", e.Process.AncestryDepth)
	}
	return s
}

// formatResult keeps failures visible. A denied or failed action is still a
// governance signal: an agent repeatedly failing to open credential material is
// more alarming than one that succeeds once.
func formatResult(e event.Event) string {
	if e.Result.Succeeded {
		return "ok"
	}
	if e.Result.Errno != "" {
		return e.Result.Errno
	}
	return fmt.Sprintf("%d", e.Result.ReturnCode)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	// Elide the middle: for a path, the leading directories and the file name
	// are both more informative than the middle.
	keep := (max - 3) / 2
	return s[:keep] + "..." + s[len(s)-keep:]
}

// printSummary reports what the replay actually established.
//
// The completeness line is the part that matters. It may claim complete only
// when nothing was lost and nothing failed to parse. A stream that stopped on a
// corrupt record, or skipped past one, is a partial view of the session, and
// calling that complete would manufacture the false assurance this system
// exists to prevent.
func printSummary(src *replay.Source, printed int, err error) {
	st := src.Stats()
	gaps := src.SequenceGaps()

	var b strings.Builder
	fmt.Fprintf(&b, "\n%d %s", printed, plural(printed, "event", "events"))
	if st.DecodeErrors > 0 {
		fmt.Fprintf(&b, ", %d malformed", st.DecodeErrors)
	}

	var reasons []string
	if st.DroppedEvents > 0 || gaps > 0 {
		reasons = append(reasons, fmt.Sprintf("%d dropped, %d sequence %s",
			st.DroppedEvents, gaps, plural(int(gaps), "gap", "gaps")))
	}
	if err != nil {
		reasons = append(reasons, "stream ended on a malformed record")
	} else if st.DecodeErrors > 0 {
		reasons = append(reasons, "malformed records were skipped")
	}

	if len(reasons) == 0 {
		fmt.Fprint(&b, "\ntelemetry complete: no drops, no gaps, no malformed records")
	} else {
		// Telemetry loss is a correctness problem, not a performance note.
		// Across a hole, "the agent never did X" is unsound, including the
		// conclusion that nothing bad happened.
		fmt.Fprintf(&b, "\ntelemetry INCOMPLETE: %s", strings.Join(reasons, "; "))
		fmt.Fprint(&b, "\n  conclusions drawn from an incomplete stream are unsound, including \"nothing happened\"")
	}

	fmt.Fprintln(os.Stderr, b.String())
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
