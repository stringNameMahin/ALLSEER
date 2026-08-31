package benchstat

// The forced-wakeup arm, from the analysis side.
//
// ArmTrackedForceWake is an instrument rather than a configuration, so what has
// to be true of it is mostly negative: it must be schedulable like any other
// arm, it must be reported, it must be subject to the same validity checks as
// the other tracked arms, and it must not be able to change a verdict. The
// tests below are in that order.

import (
	"strings"
	"testing"
)

// --- the arm exists and the four the milestone is defined in terms of do not move ---

// The property that keeps the instrument from moving the experiment: the
// acceptance arm list is exactly what it was, so a session recorded before the
// diagnostic arm existed still reproduces from its own seed.
func TestTheDiagnosticArmIsNotAnAcceptanceArm(t *testing.T) {
	want := []string{ArmOff, ArmLoaded, ArmAttachedUntracked, ArmTracked, ArmDecoded}
	got := Arms()
	if len(got) != len(want) {
		t.Fatalf("Arms() = %v, want exactly the five acceptance arms %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Arms()[%d] = %q, want %q: the acceptance arms must not move", i, got[i], want[i])
		}
	}
	for _, a := range got {
		if a == ArmTrackedForceWake {
			t.Fatalf("%s is in Arms(); it would change the default schedule for every seed",
				ArmTrackedForceWake)
		}
	}
}

func TestForceWakeArmIsKnownAndLast(t *testing.T) {
	known := KnownArms()
	if len(known) != 6 {
		t.Fatalf("KnownArms() = %v, want 6", known)
	}
	for i, a := range Arms() {
		if known[i] != a {
			t.Errorf("KnownArms()[%d] = %q, want %q", i, known[i], a)
		}
	}
	if known[5] != ArmTrackedForceWake {
		t.Errorf("KnownArms()[5] = %q, want %q", known[5], ArmTrackedForceWake)
	}
}

// KnownArms is built with append(Arms(), ...), which would alias and clobber
// the caller's slice if Arms ever returned a shared backing array.
func TestKnownArmsDoesNotCorruptArms(t *testing.T) {
	_ = KnownArms()
	if got := Arms(); len(got) != 5 || got[4] != ArmDecoded {
		t.Fatalf("Arms() = %v after KnownArms(), want the five acceptance arms", got)
	}
}

func TestForceWakeArmNamesAreDistinct(t *testing.T) {
	seen := map[string]bool{}
	for _, a := range KnownArms() {
		if seen[a] {
			t.Fatalf("arm %q appears twice in KnownArms()", a)
		}
		seen[a] = true
	}
	if ArmTrackedForceWake == ArmTracked {
		t.Fatal("the forced-wakeup arm and the tracked arm share a name; nothing could tell their runs apart")
	}
}

// --- it schedules like any other arm ---

func TestForceWakeArmCanBeScheduled(t *testing.T) {
	arms := []string{ArmOff, ArmTracked, ArmTrackedForceWake}

	seen := map[string]bool{}
	for rep := 1; rep <= 9; rep++ {
		got, err := ArmOrder(recordedSeed, rep, arms)
		if err != nil {
			t.Fatalf("ArmOrder(%d, %d, %v): %v", recordedSeed, rep, arms, err)
		}
		if len(got) != len(arms) {
			t.Fatalf("replicate %d: got %v, want %d arms", rep, got, len(arms))
		}
		count := map[string]int{}
		for _, a := range got {
			count[a]++
		}
		for _, a := range arms {
			if count[a] != 1 {
				t.Errorf("replicate %d: arm %s appears %d times in %v", rep, a, count[a], got)
			}
		}
		seen[strings.Join(got, " ")] = true
	}
	if len(seen) < 2 {
		t.Errorf("all 9 replicates share one permutation of %v", arms)
	}
}

// --- the validity checks apply to it ---

// The failure this arm can produce that the others cannot. Coalescing wakeups
// is exactly the change that could stop the consumer draining, and an arm that
// stopped draining would be fast rather than broken-looking: no record copies,
// no notifications, and reserve failing cheaply once the ring filled. The
// zero-event check is what makes that visible instead of persuasive.
func TestForceWakeArmSeeingNoEventsBlocksAPass(t *testing.T) {
	runs := synth(t, 23, map[string]float64{
		ArmOff: 1.0, ArmLoaded: 1.0, ArmTracked: 1.02, ArmTrackedForceWake: 1.01,
	})
	for i := range runs {
		if runs[i].Arm == ArmTrackedForceWake {
			runs[i].EventsTotal = 0
		}
	}

	res, err := Analyze(runs, 1)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if res.ZeroEventA3 == 0 {
		t.Fatal("a forced-wakeup arm that drained nothing was not counted as a tracked run with no events")
	}
	if res.Verdict != Inconclusive {
		t.Fatalf("verdict = %s, want %s: an arm that stopped draining must not leave a pass standing",
			res.Verdict, res.Verdict)
	}
}

func TestForceWakeArmDropsAreCounted(t *testing.T) {
	runs := synth(t, 23, map[string]float64{
		ArmOff: 1.0, ArmLoaded: 1.0, ArmTracked: 1.02, ArmTrackedForceWake: 1.01,
	})
	for i := range runs {
		if runs[i].Arm == ArmTrackedForceWake && runs[i].Replicate == 4 {
			runs[i].RingbufDrops = 17
		}
	}

	res, err := Analyze(runs, 1)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if res.TotalDrops != 17 || res.DroppedRuns != 1 {
		t.Errorf("drops = %d over %d run(s), want 17 over 1", res.TotalDrops, res.DroppedRuns)
	}
	if res.Verdict != Inconclusive {
		t.Errorf("verdict = %s, want %s", res.Verdict, Inconclusive)
	}
}

// --- it is reported, and it gates nothing ---

func TestForceWakeArmIsReportedAsADiagnostic(t *testing.T) {
	runs := synth(t, 23, map[string]float64{
		ArmOff: 1.0, ArmLoaded: 1.0, ArmTracked: 1.21, ArmTrackedForceWake: 1.02,
	})
	markWarmUp(runs)

	res, err := Analyze(runs, 1)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	var vsOff, vsTracked *Comparison
	for i := range res.Diagnostics {
		switch d := &res.Diagnostics[i]; {
		case d.Treatment == ArmTrackedForceWake && d.Baseline == ArmOff:
			vsOff = d
		case d.Treatment == ArmTrackedForceWake && d.Baseline == ArmTracked:
			vsTracked = d
		}
	}
	if vsOff == nil {
		t.Fatalf("%s vs %s is missing from the diagnostics", ArmTrackedForceWake, ArmOff)
	}
	if vsTracked == nil {
		t.Fatalf("%s vs %s is missing from the diagnostics: that is the comparison the arm exists for",
			ArmTrackedForceWake, ArmTracked)
	}
	if vsOff.Pairs != 22 || vsTracked.Pairs != 22 {
		t.Errorf("pairs = %d and %d, want 22 each", vsOff.Pairs, vsTracked.Pairs)
	}
	// 1.02/1.21 - 1: the forced-wakeup arm is much faster than the tracked one, so
	// the decomposition must come out clearly negative.
	if vsTracked.MedianOverhead > -0.10 {
		t.Errorf("%s vs %s median = %+.2f%%, want clearly negative for a much faster arm",
			ArmTrackedForceWake, ArmTracked, vsTracked.MedianOverhead*100)
	}
}

// The headline is A3 against A0 whatever the forced-wakeup arm does. A session that
// ran it must reach the same verdict, on the same pairs, as one that did not.
func TestForceWakeArmCannotChangeTheVerdict(t *testing.T) {
	base := map[string]float64{ArmOff: 1.0, ArmLoaded: 1.0, ArmTracked: 1.02}

	without, err := Analyze(synth(t, 23, base), 1)
	if err != nil {
		t.Fatal(err)
	}

	// Absurdly slow, to make the point that no value of it is consulted.
	with := map[string]float64{ArmOff: 1.0, ArmLoaded: 1.0, ArmTracked: 1.02, ArmTrackedForceWake: 9.0}
	slow, err := Analyze(synth(t, 23, with), 1)
	if err != nil {
		t.Fatal(err)
	}
	// And absurdly fast, so the test covers the direction the experiment hopes
	// for as well as the one it does not.
	with[ArmTrackedForceWake] = 0.2
	fast, err := Analyze(synth(t, 23, with), 1)
	if err != nil {
		t.Fatal(err)
	}

	for _, got := range []*Result{slow, fast} {
		if got.Verdict != without.Verdict {
			t.Errorf("verdict = %s with the forced-wakeup arm, %s without", got.Verdict, without.Verdict)
		}
		if got.Headline.Pairs != without.Headline.Pairs {
			t.Errorf("headline pairs = %d with, %d without", got.Headline.Pairs, without.Headline.Pairs)
		}
		if got.Headline.MedianOverhead != without.Headline.MedianOverhead {
			t.Errorf("headline median = %v with, %v without",
				got.Headline.MedianOverhead, without.Headline.MedianOverhead)
		}
	}
}

// A session that does not run the arm must be unchanged in every respect,
// including that it grows no empty diagnostic row.
func TestSessionsWithoutTheForceWakeArmAreUnchanged(t *testing.T) {
	res, err := Analyze(synth(t, 23, map[string]float64{
		ArmOff: 1.0, ArmLoaded: 1.0, ArmAttachedUntracked: 1.002, ArmTracked: 1.02, ArmDecoded: 1.022,
	}), 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range res.Diagnostics {
		if d.Treatment == ArmTrackedForceWake || d.Baseline == ArmTrackedForceWake {
			t.Errorf("a session that never ran %s reported it anyway: %+v", ArmTrackedForceWake, d)
		}
	}
	for _, s := range res.Startup {
		if s.Arm == ArmTrackedForceWake {
			t.Errorf("a session that never ran %s reported a startup cost for it", ArmTrackedForceWake)
		}
	}
	if res.Verdict != Pass {
		t.Errorf("verdict = %s, want %s: %v", res.Verdict, Pass, res.Reasons)
	}
}
