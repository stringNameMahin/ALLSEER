package benchstat

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// writeProc builds a procfs-shaped fixture tree.
func writeProc(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// A fixture taken from the shape the real host produces, so the parsing is
// tested against the format it will actually meet rather than an invented one.
func fullProc(t *testing.T) string {
	t.Helper()
	return writeProc(t, map[string]string{
		"loadavg": "1.09 0.43 0.16 1/226 8377\n",
		"meminfo": "MemTotal:        7601592 kB\nMemAvailable:    6814408 kB\nCached:  123 kB\n",
		// user nice system idle iowait irq softirq steal guest guest_nice
		"stat": "cpu  1000 0 2000 300000 400 0 100 0 0 0\n" +
			"cpu0 100 0 200 50000 50 0 10 0 0 0\n" +
			"cpu1 100 0 200 50000 50 0 10 0 0 0\n" +
			"cpu2 100 0 200 50000 50 0 10 0 0 0\n" +
			"intr 12345\nctxt 999\n",
		"pressure/cpu": "some avg10=1.75 avg60=1.08 avg300=0.54 total=36615775\n" +
			"full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
		"interrupts": procInterruptsFixture,
	})
}

func TestSampleHostParsesAProcTree(t *testing.T) {
	s := SampleHost(fullProc(t))

	if s.Unavailable != "" {
		t.Fatalf("a complete tree reported gaps: %q", s.Unavailable)
	}
	if want := "1.09 0.43 0.16 1/226 8377"; s.LoadAvg != want {
		t.Errorf("LoadAvg = %q, want %q", s.LoadAvg, want)
	}
	if s.MemAvailableKB != 6814408 {
		t.Errorf("MemAvailableKB = %d, want 6814408", s.MemAvailableKB)
	}
	// busy = user+nice+system+irq+softirq = 1000+0+2000+0+100 = 3100 ticks
	if s.CPUBusySeconds != 31 {
		t.Errorf("CPUBusySeconds = %v, want 31", s.CPUBusySeconds)
	}
	// idle = idle+iowait = 300000+400 = 300400 ticks
	if s.CPUIdleSeconds != 3004 {
		t.Errorf("CPUIdleSeconds = %v, want 3004", s.CPUIdleSeconds)
	}
	if s.CPUStealSeconds != 0 {
		t.Errorf("CPUStealSeconds = %v, want 0", s.CPUStealSeconds)
	}
	if s.PSICPUStallSeconds != 36.615775 {
		t.Errorf("PSICPUStallSeconds = %v, want 36.615775", s.PSICPUStallSeconds)
	}
	if s.NumCPU != 3 {
		t.Errorf("NumCPU = %d, want 3 (the per-cpu lines, not the aggregate)", s.NumCPU)
	}
}

// iowait belongs with idle. A CPU in iowait is available to anything runnable,
// so counting it as busy would make a run that touched the disk look like a run
// that was competing for a core.
func TestIOWaitCountsAsIdleNotBusy(t *testing.T) {
	root := writeProc(t, map[string]string{
		"stat": "cpu  100 0 100 1000 5000 0 0 0 0 0\ncpu0 1 0 1 1 1 0 0 0 0 0\n",
	})
	s := SampleHost(root)
	if s.CPUBusySeconds != 2 {
		t.Errorf("CPUBusySeconds = %v, want 2", s.CPUBusySeconds)
	}
	if s.CPUIdleSeconds != 60 {
		t.Errorf("CPUIdleSeconds = %v, want 60 (idle 1000 + iowait 5000 ticks)", s.CPUIdleSeconds)
	}
}

// Steal is read even though this hypervisor cannot populate it.
func TestStealIsReadWhenThePlatformDoesReportIt(t *testing.T) {
	root := writeProc(t, map[string]string{
		"stat": "cpu  100 0 100 1000 0 0 0 4200 0 0\ncpu0 1 0 1 1 0 0 0 42 0 0\n",
	})
	if got := SampleHost(root).CPUStealSeconds; got != 42 {
		t.Errorf("CPUStealSeconds = %v, want 42", got)
	}
}

// Sampling never fails. A source that cannot be read names itself instead.
func TestMissingSourcesAreNamedNotFatal(t *testing.T) {
	s := SampleHost(t.TempDir())

	for _, want := range []string{"loadavg", "meminfo", "stat", "pressure/cpu"} {
		if !strings.Contains(s.Unavailable, want) {
			t.Errorf("Unavailable = %q, does not name %q", s.Unavailable, want)
		}
	}
}

func TestPartialProcfsKeepsWhatItCanRead(t *testing.T) {
	root := writeProc(t, map[string]string{
		"loadavg": "0.50 0.20 0.10 1/100 42\n",
	})
	s := SampleHost(root)

	if s.LoadAvg != "0.50 0.20 0.10 1/100 42" {
		t.Errorf("LoadAvg = %q", s.LoadAvg)
	}
	if strings.Contains(s.Unavailable, "loadavg") {
		t.Errorf("loadavg was read but reported unavailable: %q", s.Unavailable)
	}
	for _, want := range []string{"meminfo", "stat", "pressure/cpu"} {
		if !strings.Contains(s.Unavailable, want) {
			t.Errorf("Unavailable = %q, does not name %q", s.Unavailable, want)
		}
	}
}

func TestMalformedStatIsReportedNotGuessed(t *testing.T) {
	root := writeProc(t, map[string]string{"stat": "cpu  not a number\n"})
	if s := SampleHost(root); !strings.Contains(s.Unavailable, "stat") {
		t.Errorf("a malformed stat line was accepted: %+v", s)
	}
}

// --- the delta ---------------------------------------------------------------------

func TestHostStateBetweenIsADelta(t *testing.T) {
	before := HostSample{
		LoadAvg: "1.00 1.00 1.00 1/1 1", MemAvailableKB: 5000,
		CPUBusySeconds: 100, CPUIdleSeconds: 900, CPUStealSeconds: 3,
		PSICPUStallSeconds: 10, NumCPU: 6,
	}
	after := HostSample{
		LoadAvg: "9.00 4.00 2.00 6/9 9", MemAvailableKB: 4000,
		CPUBusySeconds: 460, CPUIdleSeconds: 1100, CPUStealSeconds: 3,
		PSICPUStallSeconds: 25, NumCPU: 6,
	}

	h := HostStateBetween(before, after)
	if h == nil {
		t.Fatal("HostStateBetween returned nil")
	}
	if h.LoadAvgBefore != before.LoadAvg || h.LoadAvgAfter != after.LoadAvg {
		t.Errorf("load averages not carried through: %+v", h)
	}
	if h.MemAvailableKBBefore != 5000 || h.MemAvailableKBAfter != 4000 {
		t.Errorf("MemAvailable pair = %d/%d", h.MemAvailableKBBefore, h.MemAvailableKBAfter)
	}
	if h.CPUBusySeconds != 360 {
		t.Errorf("CPUBusySeconds = %v, want 360", h.CPUBusySeconds)
	}
	if h.CPUIdleSeconds != 200 {
		t.Errorf("CPUIdleSeconds = %v, want 200", h.CPUIdleSeconds)
	}
	if h.CPUStealSeconds != 0 {
		t.Errorf("CPUStealSeconds = %v, want 0", h.CPUStealSeconds)
	}
	if h.PSICPUStallSeconds != 15 {
		t.Errorf("PSICPUStallSeconds = %v, want 15", h.PSICPUStallSeconds)
	}
	if h.NumCPU != 6 {
		t.Errorf("NumCPU = %d, want 6", h.NumCPU)
	}
}

// Every run that reaches the timing function gets a state, so "no host state"
// in a record means the record predates the field rather than that the sample
// silently failed.
func TestHostStateBetweenAlwaysReturnsAState(t *testing.T) {
	if HostStateBetween(HostSample{}, HostSample{}) == nil {
		t.Fatal("two empty samples produced no host state")
	}
	if h := HostStateBetween(HostSample{Unavailable: "stat"}, HostSample{}); h.Unavailable == "" {
		t.Error("a gap in the before sample was not carried into the state")
	}
	if h := HostStateBetween(HostSample{}, HostSample{Unavailable: "stat"}); h.Unavailable == "" {
		t.Error("a gap in the after sample was not carried into the state")
	}
}

// The number the recorded sessions could not produce: CPU the machine spent on
// something other than the workload being measured.
func TestOtherCPUSecondsSeparatesTheWorkloadFromTheMachine(t *testing.T) {
	quiet := Run{
		UserSeconds: 90, SysSeconds: 250,
		Host: &HostState{CPUBusySeconds: 345},
	}
	if got, ok := quiet.OtherCPUSeconds(); !ok || got < 4 || got > 6 {
		t.Errorf("quiet host: got %v (ok=%v), want about 5", got, ok)
	}

	contended := Run{
		UserSeconds: 90, SysSeconds: 250,
		Host: &HostState{CPUBusySeconds: 900},
	}
	if got, _ := contended.OtherCPUSeconds(); got != 560 {
		t.Errorf("contended host: got %v, want 560", got)
	}

	if _, ok := (Run{UserSeconds: 1}).OtherCPUSeconds(); ok {
		t.Error("a run with no host state claimed to know what else the machine did")
	}
}

// --- the schema change -------------------------------------------------------------

// The field is additive: a record written before it existed still reads, still
// analyses, and reaches the same verdict it always did.
func TestRecordsWithoutHostStateStillAnalyse(t *testing.T) {
	// Two real lines from bench/20260830T093649Z-1788082609.jsonl, trimmed to
	// the fields that matter, with no "host" key — the pre-change format.
	const old = `{"schema":"allseer.dev/bench/v1","session_id":"s","replicate":2,"sequence":5,"arm":"A0","workload":"cold-build","warmup":false,"wall_seconds":63.2753,"events_total":0,"ringbuf_drops":0,"exit_code":0}
{"schema":"allseer.dev/bench/v1","session_id":"s","replicate":2,"sequence":6,"arm":"A3","workload":"cold-build","warmup":false,"wall_seconds":76.8620,"events_total":35149,"ringbuf_drops":0,"exit_code":0}`

	runs, err := ReadRuns(strings.NewReader(old))
	if err != nil {
		t.Fatalf("ReadRuns on pre-change records: %v", err)
	}
	if len(runs) != 2 {
		t.Fatalf("got %d runs, want 2", len(runs))
	}
	for _, r := range runs {
		if r.Host != nil {
			t.Errorf("arm %s: Host = %+v, want nil on a record that has no host key", r.Arm, r.Host)
		}
	}

	res, err := Analyze(runs, 1)
	if err != nil {
		t.Fatalf("Analyze on pre-change records: %v", err)
	}
	if res.Headline.Pairs != 1 {
		t.Errorf("pairs = %d, want 1", res.Headline.Pairs)
	}
}

// Every session file already on disk must still parse and analyse unchanged.
func TestExistingSessionFilesStillParse(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "..", "bench", "*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Skip("no recorded sessions on this machine")
	}
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		runs, err := ReadRuns(f)
		f.Close()
		if err != nil {
			t.Errorf("%s: ReadRuns: %v", filepath.Base(p), err)
			continue
		}
		if _, err := Analyze(runs, 1); err != nil {
			t.Errorf("%s: Analyze: %v", filepath.Base(p), err)
		}
	}
}

func TestHostStateSurvivesTheRecordRoundTrip(t *testing.T) {
	in := Run{
		Schema: Schema, SessionID: "s", Replicate: 4, Arm: ArmTracked,
		Workload: WorkloadColdBuild, WallSeconds: 8.25,
		Host: HostStateBetween(
			HostSample{LoadAvg: "1 2 3 4/5 6", MemAvailableKB: 100, CPUBusySeconds: 1, NumCPU: 6},
			HostSample{LoadAvg: "7 8 9 1/2 3", MemAvailableKB: 90, CPUBusySeconds: 40, NumCPU: 6},
		),
	}

	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	// Steal carries no omitempty on purpose: a recorded zero is the evidence
	// that this hypervisor does not account steal, which is a different fact
	// from the field being absent.
	if !strings.Contains(string(b), `"cpu_steal_seconds"`) {
		t.Errorf("a zero steal reading was omitted from the record: %s", b)
	}

	var out Run
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.Host == nil {
		t.Fatal("host state did not survive the round trip")
	}
	if out.Host.CPUBusySeconds != 39 || out.Host.NumCPU != 6 {
		t.Errorf("host state came back as %+v", out.Host)
	}
	if out.Host.LoadAvgBefore != "1 2 3 4/5 6" || out.Host.LoadAvgAfter != "7 8 9 1/2 3" {
		t.Errorf("load averages came back as %q / %q", out.Host.LoadAvgBefore, out.Host.LoadAvgAfter)
	}
}

// Host state must never reach the verdict. It is evidence, not a gate.
func TestHostStateDoesNotChangeAnyVerdict(t *testing.T) {
	factors := map[string]float64{ArmOff: 1.0, ArmLoaded: 1.0, ArmTracked: 1.02}

	plain := synth(t, 23, factors)
	withHost := synth(t, 23, factors)
	for i := range withHost {
		// A wildly contended machine, which must not matter.
		withHost[i].Host = &HostState{
			LoadAvgBefore: "99.0 99.0 99.0 1/1 1", CPUBusySeconds: 100000,
			PSICPUStallSeconds: 5000, NumCPU: 6,
		}
	}

	a, err := Analyze(plain, 1)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Analyze(withHost, 1)
	if err != nil {
		t.Fatal(err)
	}
	if a.Verdict != b.Verdict || a.Headline.Pairs != b.Headline.Pairs ||
		a.Headline.MedianOverhead != b.Headline.MedianOverhead {
		t.Errorf("host state changed the analysis: %s/%d/%v vs %s/%d/%v",
			a.Verdict, a.Headline.Pairs, a.Headline.MedianOverhead,
			b.Verdict, b.Headline.Pairs, b.Headline.MedianOverhead)
	}
}

// --- the real machine ----------------------------------------------------------------

// The fixtures prove the parsing; this proves the parsing meets the format this
// host actually publishes. It is the evidence that every run of the next
// session will carry a populated host state rather than a struct of zeroes.
func TestSampleHostReadsThisMachine(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("procfs is linux-only")
	}

	s := SampleHost("/proc")
	t.Logf("live sample: %+v", s)

	if s.Unavailable != "" {
		t.Errorf("this host could not supply: %s", s.Unavailable)
	}
	if s.LoadAvg == "" {
		t.Error("LoadAvg is empty")
	}
	if s.MemAvailableKB <= 0 {
		t.Error("MemAvailableKB is not positive")
	}
	if s.CPUBusySeconds <= 0 || s.CPUIdleSeconds <= 0 {
		t.Errorf("CPU counters look wrong: busy %v idle %v", s.CPUBusySeconds, s.CPUIdleSeconds)
	}
	if s.NumCPU <= 0 {
		t.Error("NumCPU is not positive")
	}
	if s.NumCPU != runtime.NumCPU() {
		t.Errorf("NumCPU = %d from /proc/stat, runtime reports %d", s.NumCPU, runtime.NumCPU())
	}

	// The counters must advance, or a delta across a run would always be zero.
	again := SampleHost("/proc")
	if again.CPUBusySeconds+again.CPUIdleSeconds < s.CPUBusySeconds+s.CPUIdleSeconds {
		t.Error("total CPU time went backwards between two samples")
	}
}
