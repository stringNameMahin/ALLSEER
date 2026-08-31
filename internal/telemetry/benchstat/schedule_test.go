package benchstat

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The session seed the recorded sessions actually ran with. Used throughout so
// that a failure here is a statement about the schedule those sessions would
// get today, not about an abstract one.
const recordedSeed = 1788042228

func orderOrFatal(t *testing.T, seed int64, rep int, arms []string) []string {
	t.Helper()
	got, err := ArmOrder(seed, rep, arms)
	if err != nil {
		t.Fatalf("ArmOrder(%d, %d, %v): %v", seed, rep, arms, err)
	}
	return got
}

// --- the defect this file exists to close ----------------------------------------

// The regression test for the actual bug. `shuf --random-source=<(yes
// "$SEED-$rep")` returned A4 A2 A0 A3 A1 for every replicate of every session,
// because GNU shuf reads one byte to permute five items and $rep sat behind a
// constant prefix. Twenty-three replicates, one permutation, arm perfectly
// confounded with position.
func TestReplicatesDoNotAllShareOnePermutation(t *testing.T) {
	const replicates = 23 // what the recorded session ran

	seen := map[string]bool{}
	for rep := 1; rep <= replicates; rep++ {
		seen[strings.Join(orderOrFatal(t, recordedSeed, rep, Arms()), " ")] = true
	}
	if len(seen) < 2 {
		t.Fatalf("all %d replicates share one permutation; this is the shuf defect, unfixed", replicates)
	}
	t.Logf("%d distinct permutations across %d replicates", len(seen), replicates)
}

// No arm may be systematically first or last. Asserted as full coverage rather
// than as a statistic: over the replicate count an acceptance run uses, every
// arm must occupy every position at least once. It is a deterministic fact
// about a deterministic function, so it either holds or it does not.
func TestNoArmIsPinnedToAPosition(t *testing.T) {
	const replicates = 21 // the orchestrator's default

	arms := Arms()
	positions := make(map[string]map[int]bool, len(arms))
	for _, a := range arms {
		positions[a] = map[int]bool{}
	}
	for rep := 1; rep <= replicates; rep++ {
		for i, a := range orderOrFatal(t, recordedSeed, rep, arms) {
			positions[a][i] = true
		}
	}
	for _, a := range arms {
		if len(positions[a]) != len(arms) {
			t.Errorf("arm %s occupies only %d of %d positions across %d replicates; "+
				"its measurement is confounded with where it runs",
				a, len(positions[a]), len(arms), replicates)
		}
	}
}

// --- determinism and reproducibility ---------------------------------------------

func TestArmOrderIsDeterministic(t *testing.T) {
	for rep := 1; rep <= 10; rep++ {
		first := orderOrFatal(t, recordedSeed, rep, Arms())
		for i := range 4 {
			again := orderOrFatal(t, recordedSeed, rep, Arms())
			if !equal(first, again) {
				t.Fatalf("replicate %d call %d: %v, first call %v", rep, i+2, again, first)
			}
		}
	}
}

func TestSameSeedAndReplicateReproduceTheSameOrder(t *testing.T) {
	for rep := 1; rep <= 10; rep++ {
		a := orderOrFatal(t, recordedSeed, rep, Arms())
		b := orderOrFatal(t, recordedSeed, rep, Arms())
		if !equal(a, b) {
			t.Fatalf("replicate %d: %v then %v", rep, a, b)
		}
	}
}

func TestDifferentSeedsGiveDifferentSchedules(t *testing.T) {
	const replicates = 10

	same := 0
	for rep := 1; rep <= replicates; rep++ {
		if equal(orderOrFatal(t, 1, rep, Arms()), orderOrFatal(t, 2, rep, Arms())) {
			same++
		}
	}
	if same == replicates {
		t.Fatalf("seeds 1 and 2 produce an identical schedule across %d replicates; "+
			"the seed does not reach the permutation", replicates)
	}
}

// A session must stay reproducible from its recorded seed. Pinned so that a
// change to the generator or to the shuffle is a visible diff here rather than
// a silent break of that promise.
func TestArmOrderIsPinnedForARecordedSeed(t *testing.T) {
	want := [][]string{
		{"A1", "A0", "A4", "A3", "A2"},
		{"A1", "A2", "A3", "A0", "A4"},
		{"A2", "A3", "A0", "A4", "A1"},
		{"A1", "A2", "A3", "A4", "A0"},
		{"A2", "A1", "A3", "A0", "A4"},
	}
	for i, w := range want {
		rep := i + 1
		if got := orderOrFatal(t, recordedSeed, rep, Arms()); !equal(got, w) {
			t.Errorf("seed %d replicate %d: got %v, want %v", recordedSeed, rep, got, w)
		}
	}
}

// --- the permutation invariant ----------------------------------------------------

func TestEveryOrderHoldsEveryArmExactlyOnce(t *testing.T) {
	subsets := [][]string{
		Arms(),
		{ArmOff, ArmTracked},
		{ArmOff, ArmLoaded, ArmTracked},
		{ArmDecoded, ArmOff, ArmAttachedUntracked, ArmLoaded},
	}
	for _, arms := range subsets {
		for _, seed := range []int64{0, 1, -1, recordedSeed, 1 << 40} {
			for rep := 1; rep <= 40; rep++ {
				got := orderOrFatal(t, seed, rep, arms)
				if len(got) != len(arms) {
					t.Fatalf("seed %d rep %d arms %v: got %d arms, want %d",
						seed, rep, arms, len(got), len(arms))
				}
				count := map[string]int{}
				for _, a := range got {
					count[a]++
				}
				for _, a := range arms {
					if count[a] != 1 {
						t.Fatalf("seed %d rep %d arms %v: %s appears %d times in %v",
							seed, rep, arms, a, count[a], got)
					}
				}
			}
		}
	}
}

// The caller passes the session's arm list once and reuses it for every
// replicate. Shuffling it in place would make each replicate's order depend on
// the previous one, which is exactly the between-replicate dependence the
// design forbids.
func TestArmOrderDoesNotMutateItsInput(t *testing.T) {
	arms := Arms()
	before := append([]string(nil), arms...)
	for rep := 1; rep <= 20; rep++ {
		orderOrFatal(t, recordedSeed, rep, arms)
	}
	if !equal(arms, before) {
		t.Fatalf("input was reordered: %v, was %v", arms, before)
	}
}

func TestArmOrderRejectsBadInput(t *testing.T) {
	cases := []struct {
		name      string
		seed      int64
		replicate int
		arms      []string
	}{
		{"no arms", 1, 1, nil},
		{"empty arms", 1, 1, []string{}},
		{"unknown arm", 1, 1, []string{ArmOff, "A9"}},
		{"typo", 1, 1, []string{"a0", ArmTracked}},
		{"duplicate arm", 1, 1, []string{ArmOff, ArmTracked, ArmOff}},
		{"replicate zero", 1, 0, Arms()},
		{"negative replicate", 1, -3, Arms()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got, err := ArmOrder(c.seed, c.replicate, c.arms); err == nil {
				t.Fatalf("accepted %v, returned %v", c.arms, got)
			}
		})
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- the cold-cache guard ----------------------------------------------------------

func TestEmptyCacheIsAccepted(t *testing.T) {
	if err := VerifyColdCache(t.TempDir()); err != nil {
		t.Fatalf("an empty directory was refused: %v", err)
	}
}

func TestNonEmptyCacheIsRejected(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "trim.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "ab"), 0o755); err != nil {
		t.Fatal(err)
	}

	err := VerifyColdCache(dir)
	if err == nil {
		t.Fatal("a populated GOCACHE was accepted; the run would not have been cold")
	}
	if !errors.Is(err, ErrCacheNotCold) {
		t.Fatalf("error does not wrap ErrCacheNotCold: %v", err)
	}
	// The message has to be enough to fix the problem with.
	for _, want := range []string{dir, "trim.txt"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
}

// The half that used to fail open: os.ReadDir on a missing directory returns an
// error, the old guard's `err == nil &&` swallowed it, and the run proceeded as
// though the cache had been inspected and found empty.
func TestMissingCacheIsRejected(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "never-created")

	err := VerifyColdCache(missing)
	if err == nil {
		t.Fatal("a GOCACHE that does not exist was accepted")
	}
	if !errors.Is(err, ErrCacheNotCold) {
		t.Fatalf("error does not wrap ErrCacheNotCold: %v", err)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the cause is not discoverable as os.ErrNotExist: %v", err)
	}
}

func TestEmptyPathIsRejected(t *testing.T) {
	err := VerifyColdCache("")
	if err == nil {
		t.Fatal("an unset GOCACHE was accepted")
	}
	if !errors.Is(err, ErrCacheNotCold) {
		t.Fatalf("error does not wrap ErrCacheNotCold: %v", err)
	}
}

// A stat that succeeds on something that is not a directory. This is the shape
// the orchestrator's own O_CREATE bug produced elsewhere in the harness — a
// path that was meant to be a directory and is a regular file.
func TestAFileWhereTheCacheShouldBeIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gocache")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	err := VerifyColdCache(path)
	if err == nil {
		t.Fatal("a regular file was accepted as an empty GOCACHE")
	}
	if !errors.Is(err, ErrCacheNotCold) {
		t.Fatalf("error does not wrap ErrCacheNotCold: %v", err)
	}
	if !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("error does not say what was wrong: %v", err)
	}
}

// An existing, empty, *unreadable* directory: stat succeeds and ReadDir fails
// with EACCES. The old guard accepted it.
//
// Skipped rather than faked where the platform cannot produce it. Root ignores
// the mode bits, and the acceptance session runs as root — which is precisely
// why this case is worth a test on the developer's unprivileged run rather than
// being assumed unreachable.
func TestUnreadableCacheIsRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory permissions do not work this way on windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: the mode bits would be ignored and the read would succeed")
	}

	dir := filepath.Join(t.TempDir(), "locked")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	err := VerifyColdCache(dir)
	if err == nil {
		t.Fatal("an unreadable GOCACHE was accepted; 'could not inspect' is not 'is empty'")
	}
	if !errors.Is(err, ErrCacheNotCold) {
		t.Fatalf("error does not wrap ErrCacheNotCold: %v", err)
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Errorf("the cause is not discoverable as os.ErrPermission: %v", err)
	}
}

// The property behind every case above, stated once: there is no input for
// which VerifyColdCache returns nil without having listed the directory and
// found it empty.
func TestOnlyAVerifiedEmptyDirectoryIsAccepted(t *testing.T) {
	root := t.TempDir()

	empty := filepath.Join(root, "empty")
	if err := os.Mkdir(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	populated := filepath.Join(root, "populated")
	if err := os.Mkdir(populated, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(populated, "00"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	cases := map[string]bool{ // path -> should be accepted
		empty:                          true,
		populated:                      false,
		file:                           false,
		filepath.Join(root, "missing"): false,
		"":                             false,
	}
	for path, accept := range cases {
		err := VerifyColdCache(path)
		if accept && err != nil {
			t.Errorf("%q: refused, want accepted: %v", path, err)
		}
		if !accept && err == nil {
			t.Errorf("%q: accepted, want refused", path)
		}
	}
}

// --- replicate headroom ------------------------------------------------------------

// markWarmUp applies the orchestrator's fixed rule: replicate 1 is warm-up.
func markWarmUp(runs []Run) {
	for i := range runs {
		if runs[i].Replicate == 1 {
			runs[i].WarmUp = true
		}
	}
}

// failReplicate simulates one run of one arm failing — a fail-closed GOCACHE
// check, a preempted build, anything that makes the orchestrator record rc != 0.
func failReplicate(runs []Run, rep int, arm string) {
	for i := range runs {
		if runs[i].Replicate == rep && runs[i].Arm == arm {
			runs[i].ExitCode = 2
			runs[i].Error = "run failed"
		}
	}
}

var acceptanceFactors = map[string]float64{ArmOff: 1.0, ArmLoaded: 1.0, ArmTracked: 1.02}

// The defect the new default fixes: at 21 replicates a single lost run drops the
// session below MinPairs and the verdict becomes INCONCLUSIVE on sample size
// alone, after two hours of measurement.
func TestTwentyOneReplicatesHaveNoHeadroom(t *testing.T) {
	runs := synth(t, 21, acceptanceFactors)
	markWarmUp(runs)
	failReplicate(runs, 7, ArmTracked)

	res, err := Analyze(runs, 1)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if res.Headline.Pairs != 19 {
		t.Fatalf("pairs = %d, want 19", res.Headline.Pairs)
	}
	if res.Verdict != Inconclusive {
		t.Fatalf("verdict = %s, want %s", res.Verdict, Inconclusive)
	}
	if !mentionsPairCount(res.Reasons) {
		t.Errorf("the verdict does not blame the pair count: %v", res.Reasons)
	}
}

// The acceptance invocation the orchestrator now defaults to.
func TestTwentyThreeReplicatesGiveTwentyTwoPairs(t *testing.T) {
	runs := synth(t, 23, acceptanceFactors)
	markWarmUp(runs)

	res, err := Analyze(runs, 1)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if res.Headline.Pairs != 22 {
		t.Errorf("pairs = %d, want 22 (23 replicates minus the warm-up)", res.Headline.Pairs)
	}
	if res.Headline.Pairs-MinPairs != 2 {
		t.Errorf("headroom = %d spare pairs, want 2", res.Headline.Pairs-MinPairs)
	}
	for _, rep := range res.Headline.Replicates {
		if rep == 1 {
			t.Error("the warm-up replicate reached the analysis")
		}
	}
}

// Two lost replicates — one on each side of the headline comparison — still
// leave exactly MinPairs, so the session is decided on its measurements rather
// than thrown away on its sample size.
func TestTwoLostReplicatesStillReachMinPairs(t *testing.T) {
	runs := synth(t, 23, acceptanceFactors)
	markWarmUp(runs)
	failReplicate(runs, 5, ArmTracked) // a treatment run lost
	failReplicate(runs, 9, ArmOff)     // a baseline run lost

	res, err := Analyze(runs, 1)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if res.Headline.Pairs != MinPairs {
		t.Fatalf("pairs = %d, want exactly MinPairs (%d)", res.Headline.Pairs, MinPairs)
	}
	if res.FailedRuns != 2 {
		t.Errorf("failed runs = %d, want 2", res.FailedRuns)
	}
	if mentionsPairCount(res.Reasons) {
		t.Errorf("the sample size was still blamed at %d pairs: %v", res.Headline.Pairs, res.Reasons)
	}
	if res.Verdict != Pass {
		t.Errorf("verdict = %s, want %s: %v", res.Verdict, Pass, res.Reasons)
	}
}

// A failure on an arm the headline does not use costs no pair at all. This is
// why two spare replicates is a larger margin than it looks: only A0 and A3
// failures can cost one.
func TestAFailureOnADiagnosticArmCostsNoPair(t *testing.T) {
	runs := synth(t, 23, map[string]float64{
		ArmOff: 1.0, ArmLoaded: 1.0, ArmAttachedUntracked: 1.01, ArmTracked: 1.02,
	})
	markWarmUp(runs)
	failReplicate(runs, 4, ArmAttachedUntracked)

	res, err := Analyze(runs, 1)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if res.Headline.Pairs != 22 {
		t.Errorf("pairs = %d, want 22: an %s failure must not cost a headline pair",
			res.Headline.Pairs, ArmAttachedUntracked)
	}
}

func mentionsPairCount(reasons []string) bool {
	for _, r := range reasons {
		if strings.Contains(r, "paired observations, below the") {
			return true
		}
	}
	return false
}
