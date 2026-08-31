package benchstat

// The /proc/interrupts half of the per-run host state.
//
// It exists to answer one question the acceptance session could not: whether a
// tracked arm's ring buffer notifications show up as irq_work interrupts, and
// whether forcing them shows up as more. Like everything else in hoststate.go
// it is evidence and never a gate, so the tests below are as much about what it
// must not do as what it must.

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The real shape, from the host this was written against: a header naming the
// CPUs, numbered rows, named rows, and a free-text description after the counts.
const procInterruptsFixture = `           CPU0       CPU1       CPU2
  0:         31          0          0   IO-APIC    2-edge      timer
  1:          9          0          0   IO-APIC    1-edge      i8042
NMI:          0          0          0   Non-maskable interrupts
LOC:    2876758    3051250    3105000   Local timer interrupts
IWI:      27105      27397      28341   IRQ work interrupts
RES:     117026     123142     122210   Rescheduling interrupts
CAL:    1802901    1570178    1546124   Function call interrupts
TLB:    1107905    1112330    1110152   TLB shootdowns
ERR:          0
`

func TestInterruptsAreSummedAcrossCPUs(t *testing.T) {
	root := writeProc(t, map[string]string{"interrupts": procInterruptsFixture})

	got, ok := readInterrupts(filepath.Join(root, "interrupts"))
	if !ok {
		t.Fatal("readInterrupts refused a well-formed file")
	}
	for name, want := range map[string]int64{
		"IWI": 27105 + 27397 + 28341,
		"RES": 117026 + 123142 + 122210,
		"CAL": 1802901 + 1570178 + 1546124,
		"TLB": 1107905 + 1112330 + 1110152,
		"LOC": 2876758 + 3051250 + 3105000,
	} {
		if got[name] != want {
			t.Errorf("%s = %d, want %d", name, got[name], want)
		}
	}
}

// The description is words, and the counts stop where the words start. A parser
// that took every field would either fail or, worse, coerce part of "IRQ work
// interrupts" into a number.
func TestInterruptDescriptionsAreNotCounted(t *testing.T) {
	root := writeProc(t, map[string]string{"interrupts": procInterruptsFixture})
	got, _ := readInterrupts(filepath.Join(root, "interrupts"))
	if got["IWI"] != 27105+27397+28341 {
		t.Errorf("IWI = %d; the trailing description leaked into the sum", got["IWI"])
	}
}

// Only the named rows are kept. The numbered per-device rows are not stable
// across boots, so recording them would produce a column that cannot be
// compared against the same column in another session.
func TestOnlyNamedInterruptRowsAreKept(t *testing.T) {
	root := writeProc(t, map[string]string{"interrupts": procInterruptsFixture})
	got, _ := readInterrupts(filepath.Join(root, "interrupts"))

	if len(got) != len(InterruptsOfInterest) {
		t.Errorf("kept %d rows (%v), want exactly %v", len(got), got, InterruptsOfInterest)
	}
	for _, unwanted := range []string{"0", "1", "NMI", "ERR"} {
		if _, ok := got[unwanted]; ok {
			t.Errorf("row %q was kept and should not have been", unwanted)
		}
	}
}

func TestMissingInterruptsFileIsNamedNotFatal(t *testing.T) {
	root := writeProc(t, map[string]string{"loadavg": "0 0 0 1/1 1\n"})

	if _, ok := readInterrupts(filepath.Join(root, "interrupts")); ok {
		t.Error("a missing file was reported as read")
	}

	s := SampleHost(root)
	if s.Interrupts != nil {
		t.Errorf("Interrupts = %v, want nil when the file is absent", s.Interrupts)
	}
	if !containsSource(s.Unavailable, "interrupts") {
		t.Errorf("Unavailable = %q, want it to name interrupts", s.Unavailable)
	}
	// The rest of the sample still came back.
	if s.LoadAvg != "0 0 0 1/1 1" {
		t.Errorf("LoadAvg = %q; a missing interrupts file cost an unrelated field", s.LoadAvg)
	}
}

func containsSource(list, want string) bool {
	return slices.Contains(strings.Split(list, ","), want)
}

// --- deltas ------------------------------------------------------------------------

func TestInterruptDeltasAreDifferences(t *testing.T) {
	before := HostSample{Interrupts: map[string]int64{"IWI": 100, "RES": 50, "LOC": 7}}
	after := HostSample{Interrupts: map[string]int64{"IWI": 35274, "RES": 90, "LOC": 9}}

	h := HostStateBetween(before, after)
	for name, want := range map[string]int64{"IWI": 35174, "RES": 40, "LOC": 2} {
		if h.InterruptDeltas[name] != want {
			t.Errorf("%s delta = %d, want %d", name, h.InterruptDeltas[name], want)
		}
	}
}

// A counter that appeared mid-run has no baseline. Differencing it against an
// implied zero would report its whole value since boot as this run's, which for
// IWI on a busy host is a number three orders of magnitude too large.
func TestInterruptKeysMissingABaselineAreDropped(t *testing.T) {
	before := HostSample{Interrupts: map[string]int64{"IWI": 10}}
	after := HostSample{Interrupts: map[string]int64{"IWI": 20, "RES": 4_000_000}}

	h := HostStateBetween(before, after)
	if _, ok := h.InterruptDeltas["RES"]; ok {
		t.Error("a counter with no before-sample was differenced against zero")
	}
	if h.InterruptDeltas["IWI"] != 10 {
		t.Errorf("IWI delta = %d, want 10", h.InterruptDeltas["IWI"])
	}
}

func TestInterruptDeltasAbsentWhenEitherSampleIsMissing(t *testing.T) {
	full := HostSample{Interrupts: map[string]int64{"IWI": 1}}
	if h := HostStateBetween(HostSample{}, full); h.InterruptDeltas != nil {
		t.Errorf("deltas = %v, want nil when the before-sample has none", h.InterruptDeltas)
	}
	if h := HostStateBetween(full, HostSample{}); h.InterruptDeltas != nil {
		t.Errorf("deltas = %v, want nil when the after-sample has none", h.InterruptDeltas)
	}
}

// --- it is evidence, not a gate -----------------------------------------------------

func TestInterruptDeltasDoNotChangeAnyVerdict(t *testing.T) {
	factors := map[string]float64{ArmOff: 1.0, ArmLoaded: 1.0, ArmTracked: 1.02}

	plain := synth(t, 23, factors)
	withIRQ := synth(t, 23, factors)
	for i := range withIRQ {
		withIRQ[i].Host = &HostState{InterruptDeltas: map[string]int64{
			"IWI": 9_000_000, "RES": 9_000_000, "CAL": 9_000_000,
		}}
	}

	a, err := Analyze(plain, 1)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Analyze(withIRQ, 1)
	if err != nil {
		t.Fatal(err)
	}
	if a.Verdict != b.Verdict || a.Headline.MedianOverhead != b.Headline.MedianOverhead {
		t.Errorf("interrupt counters changed the analysis: %s/%v vs %s/%v",
			a.Verdict, a.Headline.MedianOverhead, b.Verdict, b.Headline.MedianOverhead)
	}
}

// Records written before this field existed must still decode and analyse.
func TestRecordsWithoutInterruptDeltasStillParse(t *testing.T) {
	const old = `{"schema":"allseer.dev/bench/v1","session_id":"s","replicate":2,"arm":"A0","workload":"cold-build","wall_seconds":63.2,"exit_code":0,"host":{"load_avg_before":"1 2 3 4/5 6","num_cpu":6}}
{"schema":"allseer.dev/bench/v1","session_id":"s","replicate":2,"arm":"A3","workload":"cold-build","wall_seconds":76.8,"events_total":35174,"exit_code":0,"host":{"load_avg_before":"1 2 3 4/5 6","num_cpu":6}}`

	runs, err := ReadRuns(strings.NewReader(old))
	if err != nil {
		t.Fatalf("ReadRuns: %v", err)
	}
	for _, r := range runs {
		if r.Host == nil {
			t.Fatalf("arm %s lost its host block", r.Arm)
		}
		if r.Host.InterruptDeltas != nil {
			t.Errorf("arm %s invented interrupt deltas: %v", r.Arm, r.Host.InterruptDeltas)
		}
	}
	if _, err := Analyze(runs, 1); err != nil {
		t.Errorf("Analyze on pre-change records: %v", err)
	}
}
