package benchstat

import (
	"math"
	"math/rand/v2"
	"strings"
	"testing"
)

// synth builds a session: one run per arm per replicate, with each arm's wall
// time a fixed multiple of that replicate's baseline.
//
// The baselines vary far more than the multipliers do — 60 to 80 seconds against
// overheads of a few percent — because that is the situation the design exists
// for. An analysis that cannot recover a 2% effect from data whose between-
// replicate spread is 30% would be measuring the machine rather than ALLSEER.
func synth(t *testing.T, replicates int, factors map[string]float64) []Run {
	t.Helper()

	var runs []Run
	seq := 0
	for rep := 1; rep <= replicates; rep++ {
		// A deliberately wide, deterministic wander in the baseline.
		base := 60.0 + float64((rep*37)%21)
		for _, arm := range KnownArms() {
			f, ok := factors[arm]
			if !ok {
				continue
			}
			seq++
			runs = append(runs, Run{
				Schema:      Schema,
				SessionID:   "synthetic",
				Replicate:   rep,
				Sequence:    seq,
				Arm:         arm,
				Workload:    WorkloadColdBuild,
				WallSeconds: base * f,
				EventsTotal: eventsFor(arm),
			})
		}
	}
	return runs
}

func eventsFor(arm string) uint64 {
	if arm == ArmTracked || arm == ArmDecoded || arm == ArmTrackedForceWake {
		return 48000
	}
	return 0
}

// The headline recovers a known overhead from data whose baseline varies far
// more than the effect does. This is the property the whole pairing design
// exists to provide.
func TestPairingRecoversTheEffectThroughBaselineNoise(t *testing.T) {
	runs := synth(t, 21, map[string]float64{ArmOff: 1.0, ArmLoaded: 1.0, ArmTracked: 1.02})

	res, err := Analyze(runs, 1)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if got, want := res.Headline.MedianOverhead, 0.02; math.Abs(got-want) > 1e-9 {
		t.Errorf("median overhead = %.6f, want %.6f", got, want)
	}
	if res.Headline.Pairs != 21 {
		t.Errorf("pairs = %d, want 21", res.Headline.Pairs)
	}
	// With no noise on the ratio the interval collapses onto the point.
	if res.Headline.CIHigh-res.Headline.CILow > 1e-9 {
		t.Errorf("CI = [%.6f, %.6f]; a noiseless ratio should give a degenerate interval",
			res.Headline.CILow, res.Headline.CIHigh)
	}
	if res.Verdict != Pass {
		t.Errorf("verdict = %s (%v), want %s", res.Verdict, res.Reasons, Pass)
	}
}

// A 2% overhead measured over enough pairs passes; the same point estimate
// measured over too few does not.
//
// This is the rule that makes "measured rather than assumed" mean something: the
// number is identical in both halves and only the evidence behind it differs.
func TestTooFewPairsIsInconclusiveNotPass(t *testing.T) {
	factors := map[string]float64{ArmOff: 1.0, ArmLoaded: 1.0, ArmTracked: 1.02}

	full, err := Analyze(synth(t, 21, factors), 1)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if full.Verdict != Pass {
		t.Fatalf("21 replicates: verdict = %s, want %s", full.Verdict, Pass)
	}

	few, err := Analyze(synth(t, 6, factors), 1)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if few.Verdict != Inconclusive {
		t.Errorf("6 replicates: verdict = %s, want %s", few.Verdict, Inconclusive)
	}
	if math.Abs(few.Headline.MedianOverhead-full.Headline.MedianOverhead) > 1e-9 {
		t.Error("the two sessions must report the same median; only the confidence in it differs")
	}
	if !strings.Contains(strings.Join(few.Reasons, " "), "below the 20") {
		t.Errorf("reasons do not name the sample size: %v", few.Reasons)
	}
}

// An overhead above the target fails, and the reason names the bound rather
// than the point estimate.
func TestOverTargetFails(t *testing.T) {
	res, err := Analyze(synth(t, 21, map[string]float64{
		ArmOff: 1.0, ArmLoaded: 1.0, ArmTracked: 1.08,
	}), 1)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if res.Verdict != Fail {
		t.Fatalf("verdict = %s, want %s", res.Verdict, Fail)
	}
	if !strings.Contains(res.Reasons[0], "upper bound") {
		t.Errorf("the failure does not cite the interval's upper bound: %v", res.Reasons)
	}
}

// The verdict is taken from the interval's upper bound, not its centre.
//
// The pathological case the design was written against: a point estimate
// comfortably under the target on data too noisy to support it. A reading based
// on the median alone would call this a pass.
func TestVerdictIsTakenFromTheUpperBoundNotTheMedian(t *testing.T) {
	var runs []Run
	seq := 0
	// Overheads centred near 3% but spread from -6% to +14%.
	spread := []float64{-0.06, 0.14, -0.04, 0.12, -0.02, 0.10, 0.00, 0.09, 0.01, 0.08,
		0.02, 0.07, 0.03, 0.06, 0.03, 0.05, 0.04, 0.05, 0.04, 0.04, 0.03}
	for rep, o := range spread {
		base := 70.0
		for _, a := range []struct {
			arm  string
			wall float64
		}{{ArmOff, base}, {ArmLoaded, base}, {ArmTracked, base * (1 + o)}} {
			seq++
			runs = append(runs, Run{
				Schema: Schema, SessionID: "wide", Replicate: rep + 1, Sequence: seq,
				Arm: a.arm, Workload: WorkloadColdBuild, WallSeconds: a.wall,
				EventsTotal: eventsFor(a.arm),
			})
		}
	}

	res, err := Analyze(runs, 7)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if res.Headline.MedianOverhead >= OverheadTarget {
		t.Fatalf("this fixture is meant to have a median under the target; got %.4f",
			res.Headline.MedianOverhead)
	}
	if res.Verdict == Pass {
		t.Errorf("verdict = PASS on a median of %.2f%% with CI [%.2f%%, %.2f%%]; the bound, not the "+
			"centre, decides", res.Headline.MedianOverhead*100,
			res.Headline.CILow*100, res.Headline.CIHigh*100)
	}
}

// A dropped record makes a session inconclusive however good the timing looks.
func TestRingBufferDropsBlockAPass(t *testing.T) {
	runs := synth(t, 21, map[string]float64{ArmOff: 1.0, ArmLoaded: 1.0, ArmTracked: 1.01})
	for i := range runs {
		if runs[i].Arm == ArmTracked && runs[i].Replicate == 5 {
			runs[i].RingbufDrops = 12
		}
	}
	res, err := Analyze(runs, 1)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if res.Verdict != Inconclusive {
		t.Errorf("verdict = %s, want %s", res.Verdict, Inconclusive)
	}
	if res.TotalDrops != 12 || res.DroppedRuns != 1 {
		t.Errorf("drops = %d over %d run(s), want 12 over 1", res.TotalDrops, res.DroppedRuns)
	}
}

// A tracked arm that observed nothing is the signature of a broken cgroup
// registration, and it is indistinguishable from a fast one by timing alone.
func TestATrackedRunSeeingNoEventsBlocksAPass(t *testing.T) {
	runs := synth(t, 21, map[string]float64{ArmOff: 1.0, ArmLoaded: 1.0, ArmTracked: 1.001})
	for i := range runs {
		if runs[i].Arm == ArmTracked && runs[i].Replicate == 9 {
			runs[i].EventsTotal = 0
		}
	}
	res, err := Analyze(runs, 1)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if res.Verdict != Inconclusive {
		t.Fatalf("verdict = %s, want %s", res.Verdict, Inconclusive)
	}
	if !strings.Contains(strings.Join(res.Reasons, " "), "no events") {
		t.Errorf("reasons do not name the zero-event run: %v", res.Reasons)
	}
}

// A control arm that costs something means the headline is not measuring the
// probes alone.
func TestAControlArmThatMovedBlocksAPass(t *testing.T) {
	res, err := Analyze(synth(t, 21, map[string]float64{
		ArmOff: 1.0, ArmLoaded: 1.03, ArmTracked: 1.04,
	}), 1)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if res.Verdict != Inconclusive {
		t.Fatalf("verdict = %s, want %s", res.Verdict, Inconclusive)
	}
	if !strings.Contains(strings.Join(res.Reasons, " "), "control arm") {
		t.Errorf("reasons do not name the control: %v", res.Reasons)
	}
}

// A session with no treatment runs at all is NOT MEASURED, which is neither a
// pass nor a failure.
func TestNoDataIsNotMeasured(t *testing.T) {
	res, err := Analyze(synth(t, 21, map[string]float64{ArmOff: 1.0}), 1)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if res.Verdict != NotMeasured {
		t.Errorf("verdict = %s, want %s", res.Verdict, NotMeasured)
	}
}

// Warm-up runs are excluded, and excluding them changes which replicates pair.
func TestWarmUpRunsAreExcluded(t *testing.T) {
	runs := synth(t, 21, map[string]float64{ArmOff: 1.0, ArmLoaded: 1.0, ArmTracked: 1.02})
	for i := range runs {
		if runs[i].Replicate == 1 {
			runs[i].WarmUp = true
		}
	}
	res, err := Analyze(runs, 1)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if res.Headline.Pairs != 20 {
		t.Errorf("pairs = %d, want 20 after the warm-up replicate is dropped", res.Headline.Pairs)
	}
	for _, rep := range res.Headline.Replicates {
		if rep == 1 {
			t.Error("replicate 1 was marked warm-up and still reached the analysis")
		}
	}
}

// A failed run is counted and excluded rather than contributing a wall time.
func TestFailedRunsAreExcludedAndCounted(t *testing.T) {
	runs := synth(t, 21, map[string]float64{ArmOff: 1.0, ArmLoaded: 1.0, ArmTracked: 1.02})
	for i := range runs {
		if runs[i].Arm == ArmTracked && runs[i].Replicate == 3 {
			runs[i].ExitCode = 2
			runs[i].Error = "build failed"
		}
	}
	res, err := Analyze(runs, 1)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if res.FailedRuns != 1 {
		t.Errorf("failed runs = %d, want 1", res.FailedRuns)
	}
	if res.Headline.Pairs != 20 {
		t.Errorf("pairs = %d, want 20 with one treatment run excluded", res.Headline.Pairs)
	}
}

// The interval is a property of the data rather than of the seed.
//
// Two facts, and the second is the one worth having. The same seed must give the
// same answer, or a report could not be reproduced from its inputs. And at
// BootstrapResamples the percentile bootstrap has converged far enough that a
// *different* seed gives the same answer too — which is what makes the published
// interval a statement about the measurements rather than about the random
// number generator that summarised them.
//
// That convergence is asserted rather than assumed. If someone lowers
// BootstrapResamples for speed, this test is what notices that the reported
// interval has started to depend on the seed.
func TestIntervalIsConvergedAndSeedIndependent(t *testing.T) {
	var runs []Run
	seq := 0
	for rep := 1; rep <= 21; rep++ {
		o := 0.02 + float64((rep*7919)%1000)*0.00004
		for _, a := range []struct {
			arm  string
			wall float64
		}{{ArmOff, 70}, {ArmLoaded, 70}, {ArmTracked, 70 * (1 + o)}} {
			seq++
			runs = append(runs, Run{
				Schema: Schema, SessionID: "seeded", Replicate: rep, Sequence: seq,
				Arm: a.arm, Workload: WorkloadColdBuild, WallSeconds: a.wall,
				EventsTotal: eventsFor(a.arm),
			})
		}
	}

	first, err := Analyze(runs, 42)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	for _, seed := range []int64{42, 43, 1, 9999} {
		got, err := Analyze(runs, seed)
		if err != nil {
			t.Fatalf("Analyze(seed %d): %v", seed, err)
		}
		if got.Headline.CILow != first.Headline.CILow || got.Headline.CIHigh != first.Headline.CIHigh {
			t.Errorf("seed %d gave CI [%.6f, %.6f], seed 42 gave [%.6f, %.6f]; at %d resamples the "+
				"interval must not depend on the seed", seed,
				got.Headline.CILow, got.Headline.CIHigh,
				first.Headline.CILow, first.Headline.CIHigh, BootstrapResamples)
		}
		if got.Headline.MedianOverhead != first.Headline.MedianOverhead {
			t.Errorf("seed %d moved the median; the point estimate is not resampled at all", seed)
		}
	}
}

// The seed does reach the bootstrap, shown where sampling noise is still
// visible. Without this, TestIntervalIsConvergedAndSeedIndependent above would
// pass just as well against an implementation that ignored the seed entirely.
func TestSeedReachesTheBootstrap(t *testing.T) {
	xs := make([]float64, 21)
	for i := range xs {
		xs[i] = 0.02 + float64((i*7919)%1000)*0.00004
	}

	const tooFewToConverge = 25
	seen := map[[2]float64]bool{}
	for seed := int64(1); seed <= 12; seed++ {
		rng := rand.New(rand.NewPCG(uint64(seed), 0x9E3779B97F4A7C15))
		lo, hi := bootstrapMedianCI(xs, tooFewToConverge, ConfidenceLevel, rng)
		seen[[2]float64{lo, hi}] = true
	}
	if len(seen) < 2 {
		t.Errorf("twelve seeds at %d resamples produced %d distinct interval(s); the seed is not "+
			"reaching the resampler", tooFewToConverge, len(seen))
	}
}

// The A2-to-A3 decomposition survives into the diagnostics, because it is what
// says whether the cost is in tracepoint dispatch or in reporting.
func TestDecompositionIsReported(t *testing.T) {
	res, err := Analyze(synth(t, 21, map[string]float64{
		ArmOff: 1.0, ArmLoaded: 1.0, ArmAttachedUntracked: 1.01, ArmTracked: 1.03, ArmDecoded: 1.05,
	}), 1)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	var found bool
	for _, d := range res.Diagnostics {
		if d.Treatment == ArmTracked && d.Baseline == ArmAttachedUntracked {
			found = true
			// 1.03/1.01 - 1 ≈ 1.98%
			if math.Abs(d.MedianOverhead-(1.03/1.01-1)) > 1e-9 {
				t.Errorf("decomposition median = %.6f, want %.6f", d.MedianOverhead, 1.03/1.01-1)
			}
		}
	}
	if !found {
		t.Errorf("the %s vs %s decomposition is missing from the diagnostics", ArmTracked, ArmAttachedUntracked)
	}
}

// The adversarial workload is analysed and reported, and does not gate.
func TestStormIsReportedAndDoesNotGate(t *testing.T) {
	runs := synth(t, 21, map[string]float64{ArmOff: 1.0, ArmLoaded: 1.0, ArmTracked: 1.01})
	seq := len(runs)
	for rep := 1; rep <= 21; rep++ {
		for _, a := range []struct {
			arm  string
			wall float64
		}{{ArmOff, 10}, {ArmTracked, 10 * 1.9}} { // 90% overhead on the storm
			seq++
			runs = append(runs, Run{
				Schema: Schema, SessionID: "synthetic", Replicate: rep, Sequence: seq,
				Arm: a.arm, Workload: WorkloadOpenatStorm, WallSeconds: a.wall,
				EventsTotal: eventsFor(a.arm),
			})
		}
	}

	res, err := Analyze(runs, 1)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if res.Storm == nil {
		t.Fatal("the storm workload was not analysed")
	}
	if math.Abs(res.Storm.MedianOverhead-0.9) > 1e-9 {
		t.Errorf("storm median = %.4f, want 0.9", res.Storm.MedianOverhead)
	}
	if res.Verdict != Pass {
		t.Errorf("verdict = %s; a 90%% storm overhead must not gate the headline", res.Verdict)
	}
}

// A record from another schema is refused rather than read with this build's
// field meanings.
func TestForeignSchemaIsRefused(t *testing.T) {
	_, err := Analyze([]Run{{Schema: "allseer.dev/bench/v99", Arm: ArmOff}}, 1)
	if err == nil {
		t.Fatal("a record from an unknown schema was accepted")
	}
}

// The reader refuses a malformed line rather than skipping it: a silently
// shrunken sample widens the interval, which is the direction that turns a
// failure into an inconclusive result.
func TestMalformedLineIsRefused(t *testing.T) {
	_, err := ReadRuns(strings.NewReader(`{"schema":"allseer.dev/bench/v1","arm":"A0"}` + "\n{ not json\n"))
	if err == nil {
		t.Fatal("a malformed line was skipped instead of refused")
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Errorf("the error does not name the line: %v", err)
	}
}

// Blank lines and comments are ignored, so a session file can carry a header.
func TestReaderIgnoresBlanksAndComments(t *testing.T) {
	runs, err := ReadRuns(strings.NewReader(
		"# a session\n\n" + `{"schema":"allseer.dev/bench/v1","arm":"A0","wall_seconds":1}` + "\n"))
	if err != nil {
		t.Fatalf("ReadRuns: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("read %d runs, want 1", len(runs))
	}
}

// The report renders every gating fact, so a reader never has to consult the
// JSON to learn why a session did not pass.
func TestReportStatesTheVerdictAndItsReasons(t *testing.T) {
	runs := synth(t, 6, map[string]float64{ArmOff: 1.0, ArmLoaded: 1.0, ArmTracked: 1.02})
	res, err := Analyze(runs, 1)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	var b strings.Builder
	if err := Report(&b, res); err != nil {
		t.Fatalf("Report: %v", err)
	}
	out := b.String()
	for _, want := range []string{"Verdict: " + Inconclusive, "Median overhead", "95% CI", "Integrity", "below the 20"} {
		if !strings.Contains(out, want) {
			t.Errorf("report does not contain %q", want)
		}
	}
}

// The percentile reader never invents a value the resamples did not produce.
func TestPercentileIsNearestRank(t *testing.T) {
	xs := []float64{1, 2, 3, 4, 5}
	for _, p := range []float64{0, 0.25, 0.5, 0.75, 1} {
		got := percentileSorted(xs, p)
		var in bool
		for _, x := range xs {
			if x == got {
				in = true
			}
		}
		if !in {
			t.Errorf("percentile %.2f = %v, which is not one of the inputs", p, got)
		}
	}
}

// Two sessions in one file are refused rather than merged.
//
// Replicate numbers restart at 1 in every session, so merging pairs a run
// against a run from another machine, another day or another object, and the
// ratio that comes out looks exactly like a valid one. There is nothing in the
// output that would reveal it, which is why it is stopped at the input.
func TestMixedSessionsAreRefused(t *testing.T) {
	a := synth(t, 21, map[string]float64{ArmOff: 1.0, ArmLoaded: 1.0, ArmTracked: 1.02})
	b := synth(t, 21, map[string]float64{ArmOff: 1.0, ArmLoaded: 1.0, ArmTracked: 1.02})
	for i := range b {
		b[i].SessionID = "a-different-session"
	}

	if _, err := Analyze(append(a, b...), 1); err == nil {
		t.Fatal("runs from two sessions were analysed as one")
	} else if !strings.Contains(err.Error(), "more than one session") {
		t.Errorf("error does not name the cause: %v", err)
	}

	// One session still analyses, so the guard is not refusing everything.
	if _, err := Analyze(a, 1); err != nil {
		t.Errorf("a single session was refused: %v", err)
	}
}

// The one-off load and attach cost is reported per arm, and it stays out of
// every wall-clock ratio.
//
// Both halves matter. A milestone that asks what instrumentation costs is
// entitled to the startup number, and a per-build percentage that quietly
// included it would rise and fall with the length of the build rather than with
// anything ALLSEER does.
func TestStartupCostIsReportedAndKeptOutOfTheRatios(t *testing.T) {
	runs := synth(t, 21, map[string]float64{ArmOff: 1.0, ArmLoaded: 1.0, ArmTracked: 1.02})
	for i := range runs {
		switch runs[i].Arm {
		case ArmLoaded:
			runs[i].LoadSeconds = 0.40
		case ArmTracked:
			// Deliberately enormous next to a seventy-second build: if it were
			// folded into the ratio the headline could not still be 2%.
			runs[i].LoadSeconds = 0.50
			runs[i].AttachSeconds = 3.00
		}
	}

	res, err := Analyze(runs, 1)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if got, want := res.Headline.MedianOverhead, 0.02; math.Abs(got-want) > 1e-9 {
		t.Errorf("median overhead = %.6f, want %.6f; startup cost reached a wall-clock ratio", got, want)
	}

	byArm := map[string]StartupCost{}
	for _, sc := range res.Startup {
		byArm[sc.Arm] = sc
	}
	if _, ok := byArm[ArmOff]; ok {
		t.Errorf("%s has a startup entry; nothing is loaded on the baseline, and a zero there would "+
			"read as 'loading is free' rather than 'loading did not happen'", ArmOff)
	}
	if got := byArm[ArmTracked].MedianLoadSeconds; math.Abs(got-0.50) > 1e-9 {
		t.Errorf("%s median load = %.3fs, want 0.500s", ArmTracked, got)
	}
	if got := byArm[ArmTracked].MedianAttachSeconds; math.Abs(got-3.00) > 1e-9 {
		t.Errorf("%s median attach = %.3fs, want 3.000s", ArmTracked, got)
	}
	if got := byArm[ArmLoaded].MedianAttachSeconds; got != 0 {
		t.Errorf("%s attaches nothing, so its attach cost should be 0, got %.3fs", ArmLoaded, got)
	}
	if got, want := byArm[ArmTracked].Runs, 21; got != want {
		t.Errorf("%s startup runs = %d, want %d", ArmTracked, got, want)
	}

	var b strings.Builder
	if err := Report(&b, res); err != nil {
		t.Fatalf("Report: %v", err)
	}
	for _, want := range []string{"One-off startup cost", "Median attach", "3.000s"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("report does not contain %q", want)
		}
	}
}
