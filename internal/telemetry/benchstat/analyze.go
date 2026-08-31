package benchstat

import (
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"sort"
)

// Errors an analysis can refuse with.
var (
	// ErrNoPairs: the two arms share no replicate. Usually a session that died
	// before the treatment arm ran, or a mis-set arm name.
	ErrNoPairs = errors.New("benchstat: the two arms share no replicate, so nothing can be paired")

	// ErrSchema: a record from a format this build does not read.
	ErrSchema = errors.New("benchstat: record carries an unknown schema")

	// ErrMixedSessions: records from more than one session in one analysis.
	//
	// Refused rather than merged. Replicate numbers restart at 1 in every
	// session, so two sessions in one file pair a run against a run from a
	// different machine, a different day or a different object, and the ratio
	// that comes out is a comparison of two hosts wearing the arm names of one
	// experiment. There is no way to detect that in the output, which is why it
	// is stopped at the input.
	ErrMixedSessions = errors.New("benchstat: records come from more than one session")
)

// The acceptance constants. These are the project's stated target and the
// conventional interval width, named rather than inlined so that a reader
// checking the verdict against M5's wording does not have to find them in an
// expression.
const (
	// OverheadTarget is M5's "under 5% wall clock".
	OverheadTarget = 0.05

	// ConfidenceLevel is the two-sided interval the verdict is taken from.
	ConfidenceLevel = 0.95

	// BootstrapResamples is the number of resamples behind every interval.
	BootstrapResamples = 10000

	// MinPairs is the minimum number of paired observations an acceptance-grade
	// comparison needs. Below this the interval is reported and the verdict is
	// INCONCLUSIVE regardless of where the bound falls, because a narrow
	// interval over six pairs is a statement about six pairs.
	MinPairs = 20
)

// Comparison is one arm measured against another, paired by replicate.
type Comparison struct {
	Treatment string `json:"treatment"`
	Baseline  string `json:"baseline"`
	Workload  string `json:"workload"`

	Pairs int `json:"pairs"`

	// MedianOverhead is median(wall_treatment/wall_baseline) - 1 over the
	// pairs. The median rather than the mean: build times are right-skewed —
	// a run can be arbitrarily slow and cannot be arbitrarily fast — so one
	// preempted run moves a mean and should not decide a milestone.
	MedianOverhead float64 `json:"median_overhead"`

	// CILow and CIHigh bound MedianOverhead at ConfidenceLevel. CIHigh is the
	// number the verdict is taken from.
	CILow  float64 `json:"ci_low"`
	CIHigh float64 `json:"ci_high"`

	MeanOverhead float64 `json:"mean_overhead"`
	StdDev       float64 `json:"stddev"`
	MinOverhead  float64 `json:"min_overhead"`
	MaxOverhead  float64 `json:"max_overhead"`

	// Overheads is every paired observation, in replicate order. Reported in
	// full because a summary of twenty numbers should not be the only place
	// those numbers exist.
	Overheads []float64 `json:"overheads"`

	// Replicates names the replicate behind each entry of Overheads.
	Replicates []int `json:"replicates"`
}

// ContainsZero reports whether the interval admits "no difference".
func (c Comparison) ContainsZero() bool { return c.CILow <= 0 && c.CIHigh >= 0 }

// StartupCost is what one arm paid once, before its workload started.
//
// Load and attach are deliberately kept out of every wall-clock ratio: a
// governed session pays them at startup and then runs for days, so folding a
// fixed cost into a per-build percentage would make the reported overhead a
// function of how long the build happened to be. They are still a real cost and
// the milestone asks for them separately, so they are aggregated here and
// reported in seconds rather than as a share of anything.
type StartupCost struct {
	Arm  string `json:"arm"`
	Runs int    `json:"runs"`

	MedianLoadSeconds   float64 `json:"median_load_seconds"`
	MedianAttachSeconds float64 `json:"median_attach_seconds"`
	MaxLoadSeconds      float64 `json:"max_load_seconds"`
	MaxAttachSeconds    float64 `json:"max_attach_seconds"`
}

// Verdict values.
const (
	Pass         = "PASS"
	Fail         = "FAIL"
	Inconclusive = "INCONCLUSIVE"
	NotMeasured  = "NOT MEASURED"
)

// Result is the whole analysis of one session.
type Result struct {
	SessionID string       `json:"session_id"`
	Env       *Environment `json:"env,omitempty"`

	// Headline is ArmTracked against ArmOff on the cold build: the comparison
	// M5's target is about.
	Headline Comparison `json:"headline"`

	// Control is ArmLoaded against ArmOff. If the harness itself costs
	// something, the headline is measuring the harness as well as the probes.
	Control Comparison `json:"control"`

	// Diagnostics are the remaining arms against ArmOff, and the A2-to-A3
	// decomposition. None gates the verdict.
	Diagnostics []Comparison `json:"diagnostics"`

	// Storm is the adversarial workload, when the session ran one. Reported,
	// never gating.
	Storm *Comparison `json:"storm,omitempty"`

	// Startup is the one-off load and attach cost per arm. Reported, never
	// gating: it is not part of any wall-clock ratio, by design.
	Startup []StartupCost `json:"startup,omitempty"`

	TotalDrops  uint64 `json:"total_ringbuf_drops"`
	DroppedRuns int    `json:"runs_with_drops"`
	FailedRuns  int    `json:"failed_runs"`
	ZeroEventA3 int    `json:"tracked_runs_with_no_events"`

	Verdict string   `json:"verdict"`
	Reasons []string `json:"reasons"`
}

// Analyze turns a session's runs into a verdict.
//
// The verdict rules are M5's, restated exactly once here so there is one place
// to check them against the milestone's wording:
//
//	PASS          the headline interval's upper bound is below the target, no
//	              tracked run dropped a record, every tracked run saw events,
//	              and the control arm is indistinguishable from the baseline.
//	FAIL          the upper bound is at or above the target.
//	INCONCLUSIVE  anything else — too few pairs, an interval straddling the
//	              target, a dropped record, a tracked run that saw nothing, or a
//	              control arm that moved.
//
// The asymmetry between FAIL and INCONCLUSIVE is deliberate. An upper bound at
// or above the target is evidence of a real problem whatever else is true, so
// it is reported as a failure. Everything else is a statement that this session
// cannot answer the question, and must not be recorded as though it had.
func Analyze(runs []Run, seed int64) (*Result, error) {
	for i := range runs {
		if runs[i].Schema != "" && runs[i].Schema != Schema {
			return nil, fmt.Errorf("%w: %q (this build reads %q)", ErrSchema, runs[i].Schema, Schema)
		}
	}

	res := &Result{}
	usable := make([]Run, 0, len(runs))
	for _, r := range runs {
		if r.Env != nil && res.Env == nil {
			res.Env = r.Env
		}
		if res.SessionID == "" {
			res.SessionID = r.SessionID
		}
		if r.SessionID != "" && res.SessionID != "" && r.SessionID != res.SessionID {
			return nil, fmt.Errorf("%w: %q and %q", ErrMixedSessions, res.SessionID, r.SessionID)
		}
		if r.WarmUp {
			continue
		}
		if r.Error != "" || r.ExitCode != 0 {
			res.FailedRuns++
			continue
		}
		usable = append(usable, r)
	}

	for _, r := range usable {
		if r.RingbufDrops > 0 {
			res.TotalDrops += r.RingbufDrops
			res.DroppedRuns++
		}
		// ArmTrackedForceWake is checked alongside them. It cannot strand a
		// record the way the abandoned suppression arm could — forcing a wakeup
		// only ever delivers more of them — but a tracked arm that observed
		// nothing is the signature of a broken cgroup registration whichever arm
		// it is, and it is indistinguishable from a fast one by timing alone.
		if (r.Arm == ArmTracked || r.Arm == ArmDecoded || r.Arm == ArmTrackedForceWake) && r.EventsTotal == 0 {
			res.ZeroEventA3++
		}
	}

	rng := rand.New(rand.NewPCG(uint64(seed), 0x9E3779B97F4A7C15))

	// A missing arm is a fact about the session, not a parse failure. A session
	// that never ran the treatment has measured nothing, and the verdict below
	// says so — returning an error here would make "we did not collect the
	// data" indistinguishable from "the file is corrupt".
	res.Headline = compareOrEmpty(usable, ArmTracked, ArmOff, WorkloadColdBuild, rng)
	res.Control = compareOrEmpty(usable, ArmLoaded, ArmOff, WorkloadColdBuild, rng)

	for _, arm := range []string{ArmAttachedUntracked, ArmDecoded, ArmTrackedForceWake} {
		if c, e := compare(usable, arm, ArmOff, WorkloadColdBuild, rng); e == nil {
			res.Diagnostics = append(res.Diagnostics, c)
		}
	}
	// The decomposition the design exists to preserve: how much of the headline
	// is already paid before a single event is reported.
	if c, e := compare(usable, ArmTracked, ArmAttachedUntracked, WorkloadColdBuild, rng); e == nil {
		res.Diagnostics = append(res.Diagnostics, c)
	}
	// The second decomposition: of what is paid after that point, how much is
	// the notification rather than the record. Present only in a session that
	// ran the forced-wakeup arm, and gating nothing either way.
	if c, e := compare(usable, ArmTrackedForceWake, ArmTracked, WorkloadColdBuild, rng); e == nil {
		res.Diagnostics = append(res.Diagnostics, c)
	}
	if c, e := compare(usable, ArmTracked, ArmOff, WorkloadOpenatStorm, rng); e == nil {
		res.Storm = &c
	}

	res.Startup = startupCosts(usable)

	res.Verdict, res.Reasons = verdict(res)
	return res, nil
}

// startupCosts summarises the one-off cost per arm.
//
// The median rather than the mean, for the reason the ratios use it: one run
// that waited on a busy verifier should not move the number a reader quotes.
func startupCosts(runs []Run) []StartupCost {
	loads := map[string][]float64{}
	attaches := map[string][]float64{}
	counts := map[string]int{}

	for _, r := range runs {
		if r.Arm == ArmOff {
			// Nothing is loaded, so there is nothing to time. Reporting a zero
			// here would read as "loading is free" rather than "loading did not
			// happen".
			continue
		}
		counts[r.Arm]++
		loads[r.Arm] = append(loads[r.Arm], r.LoadSeconds)
		attaches[r.Arm] = append(attaches[r.Arm], r.AttachSeconds)
	}

	var out []StartupCost
	for _, arm := range KnownArms() {
		if counts[arm] == 0 {
			continue
		}
		_, maxLoad := minMax(loads[arm])
		_, maxAttach := minMax(attaches[arm])
		out = append(out, StartupCost{
			Arm:                 arm,
			Runs:                counts[arm],
			MedianLoadSeconds:   median(loads[arm]),
			MedianAttachSeconds: median(attaches[arm]),
			MaxLoadSeconds:      maxLoad,
			MaxAttachSeconds:    maxAttach,
		})
	}
	return out
}

// verdict applies the rules in Analyze's comment.
func verdict(res *Result) (string, []string) {
	var reasons []string

	h := res.Headline
	switch {
	case h.Pairs == 0:
		return NotMeasured, []string{
			fmt.Sprintf("no paired %s/%s observations on the %s workload; nothing was measured",
				ArmTracked, ArmOff, WorkloadColdBuild),
		}
	case h.CIHigh >= OverheadTarget:
		// Reported before the inconclusive checks, because an upper bound at or
		// above the target is a finding regardless of what else is wrong.
		reasons = append(reasons, fmt.Sprintf(
			"the 95%% CI upper bound on median overhead is %.2f%%, at or above the %.0f%% target",
			h.CIHigh*100, OverheadTarget*100))
		return Fail, reasons
	}

	if h.Pairs < MinPairs {
		reasons = append(reasons, fmt.Sprintf(
			"%d paired observations, below the %d an acceptance-grade comparison needs",
			h.Pairs, MinPairs))
	}
	if res.DroppedRuns > 0 {
		reasons = append(reasons, fmt.Sprintf(
			"%d run(s) lost %d record(s) to the ring buffer; a run that dropped records did less work "+
				"than one that did not, so its wall clock understates the cost", res.DroppedRuns, res.TotalDrops))
	}
	if res.ZeroEventA3 > 0 {
		reasons = append(reasons, fmt.Sprintf(
			"%d tracked run(s) observed no events at all, which is what a broken cgroup registration "+
				"looks like and is indistinguishable from low overhead", res.ZeroEventA3))
	}
	if res.Control.Pairs == 0 {
		reasons = append(reasons, fmt.Sprintf(
			"the %s control arm was not run, so the harness's own cost is unknown", ArmLoaded))
	} else if !res.Control.ContainsZero() {
		reasons = append(reasons, fmt.Sprintf(
			"the %s control arm differs from %s (median %.2f%%, CI [%.2f%%, %.2f%%] excludes zero), so "+
				"the headline is measuring the harness as well as the probes",
			ArmLoaded, ArmOff, res.Control.MedianOverhead*100,
			res.Control.CILow*100, res.Control.CIHigh*100))
	}

	if len(reasons) > 0 {
		return Inconclusive, reasons
	}
	return Pass, []string{fmt.Sprintf(
		"median overhead %.2f%%, 95%% CI [%.2f%%, %.2f%%] over %d pairs; the upper bound is below the %.0f%% target",
		h.MedianOverhead*100, h.CILow*100, h.CIHigh*100, h.Pairs, OverheadTarget*100)}
}

// compareOrEmpty is compare with a missing arm reported as zero pairs rather
// than as an error, for the arms whose absence the verdict already speaks about.
func compareOrEmpty(runs []Run, treatment, baseline, workload string, rng *rand.Rand) Comparison {
	c, err := compare(runs, treatment, baseline, workload, rng)
	if err != nil {
		return Comparison{Treatment: treatment, Baseline: baseline, Workload: workload}
	}
	return c
}

// compare pairs two arms by replicate and bootstraps the median ratio.
//
// Pairing by replicate rather than by position is what removes the between-
// replicate variance that dominates a build-time measurement. Two runs in one
// replicate saw the same thermal state, the same page cache and the same host
// contention; two runs in different replicates did not, and on the machine this
// was designed for that difference is fifteen percent — three times the effect
// being measured.
func compare(runs []Run, treatment, baseline, workload string, rng *rand.Rand) (Comparison, error) {
	c := Comparison{Treatment: treatment, Baseline: baseline, Workload: workload}

	byRep := map[int]map[string]float64{}
	for _, r := range runs {
		if r.Workload != workload || r.WallSeconds <= 0 {
			continue
		}
		if r.Arm != treatment && r.Arm != baseline {
			continue
		}
		if byRep[r.Replicate] == nil {
			byRep[r.Replicate] = map[string]float64{}
		}
		byRep[r.Replicate][r.Arm] = r.WallSeconds
	}

	reps := make([]int, 0, len(byRep))
	for rep := range byRep {
		reps = append(reps, rep)
	}
	sort.Ints(reps)

	for _, rep := range reps {
		t, okT := byRep[rep][treatment]
		b, okB := byRep[rep][baseline]
		if !okT || !okB || b <= 0 {
			continue
		}
		c.Overheads = append(c.Overheads, t/b-1)
		c.Replicates = append(c.Replicates, rep)
	}

	c.Pairs = len(c.Overheads)
	if c.Pairs == 0 {
		return c, ErrNoPairs
	}

	c.MedianOverhead = median(c.Overheads)
	c.MeanOverhead = mean(c.Overheads)
	c.StdDev = stddev(c.Overheads)
	c.MinOverhead, c.MaxOverhead = minMax(c.Overheads)
	c.CILow, c.CIHigh = bootstrapMedianCI(c.Overheads, BootstrapResamples, ConfidenceLevel, rng)
	return c, nil
}

// bootstrapMedianCI is a percentile bootstrap of the median.
//
// Non-parametric on purpose. A t-interval assumes a symmetric sampling
// distribution, and build times are not symmetric: the right tail is
// unbounded — a preemption, a page-cache miss, a noisy neighbour — and the left
// tail stops at the machine's best case. Resampling makes no assumption about
// the shape and is the reason the interval can be trusted on twenty points.
func bootstrapMedianCI(xs []float64, resamples int, level float64, rng *rand.Rand) (lo, hi float64) {
	n := len(xs)
	if n == 0 {
		return 0, 0
	}
	if n == 1 {
		return xs[0], xs[0]
	}

	meds := make([]float64, resamples)
	sample := make([]float64, n)
	for i := range resamples {
		for j := range n {
			sample[j] = xs[rng.IntN(n)]
		}
		meds[i] = median(sample)
	}
	sort.Float64s(meds)

	alpha := (1 - level) / 2
	return percentileSorted(meds, alpha), percentileSorted(meds, 1-alpha)
}

// percentileSorted reads a percentile off an already-sorted slice by nearest
// rank, which needs no interpolation and cannot invent a value the resamples
// did not produce.
func percentileSorted(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(math.Round(p * float64(len(sorted)-1)))
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func median(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

func mean(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	var sum float64
	for _, x := range xs {
		sum += x
	}
	return sum / float64(len(xs))
}

// stddev is the sample standard deviation, with Bessel's correction because
// these are a sample of the runs that could have happened rather than the
// population of them.
func stddev(xs []float64) float64 {
	if len(xs) < 2 {
		return 0
	}
	m := mean(xs)
	var ss float64
	for _, x := range xs {
		ss += (x - m) * (x - m)
	}
	return math.Sqrt(ss / float64(len(xs)-1))
}

func minMax(xs []float64) (float64, float64) {
	if len(xs) == 0 {
		return 0, 0
	}
	lo, hi := xs[0], xs[0]
	for _, x := range xs[1:] {
		lo = math.Min(lo, x)
		hi = math.Max(hi, x)
	}
	return lo, hi
}
