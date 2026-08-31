package benchstat

// Per-run host state: what the machine was doing while one run's workload ran.
//
// # Why this exists
//
// The single largest threat to this measurement is not the probes, it is the
// machine. The same VirtualBox guest produced an A0 baseline of 70.4s wall /
// 94.1s user / 264.3s sys one day and 6.3s / 15.4s / 12.3s the next, on the
// same commit, the same object and the same workload — an eleven-fold change in
// delivered performance with nothing in ALLSEER different. Pairing arms by
// replicate absorbs drift that is slow relative to a replicate. It does not
// absorb a state change that lands between two arms of the same replicate, and
// nothing in a session's output would show that it had.
//
// Before this file, the only host-state evidence a session carried was
// Environment.LoadAvgBefore/After, and Environment is attached to the session's
// first successful run alone. A 115-run acceptance session therefore recorded
// host state for exactly one run and nothing for the other 114. This adds a
// sample to every run.
//
// # What this is not
//
// It is evidence, not a gate. Nothing here feeds the verdict, and no threshold
// on any field appears anywhere in this package. The acceptance rules stay
// exactly what Analyze documents. A number that made a session fail because a
// load average crossed a line chosen after the fact would be a worse instrument
// than no number at all.
//
// # What this guest can and cannot report
//
// Measured on the host in question rather than assumed:
//
//   - /proc/loadavg, /proc/meminfo, /proc/stat, /proc/pressure/*: all present
//     and moving. PSI's cumulative `total` counters separated an idle window
//     from a loaded one by better than tenfold in direct testing.
//   - CPU steal: structurally zero. VirtualBox exposes no paravirtualised steal
//     clock to this guest — /proc/cpuinfo advertises `hypervisor` but neither
//     `steal_time` nor `kvmclock`, and there is no /sys/hypervisor — so
//     /proc/stat's steal column can never leave zero. It is recorded anyway,
//     because "this hypervisor does not account steal" and "no time was stolen"
//     are different facts and only one of them is a reason to look elsewhere.
//   - CPU frequency, governor and turbo: genuinely unavailable, and not
//     recoverable from inside the guest by any means. There is no
//     /sys/devices/system/cpu/cpu0/cpufreq and no intel_pstate, and
//     /proc/cpuinfo's "cpu MHz" is a fixed 2304.000 on every core, unchanged
//     between an idle machine and a fully loaded one — it is the nominal TSC
//     rate, not a reading. Environment already reports both as "unavailable"
//     and that remains the honest answer.
//   - Temperature: no thermal zones exist in this guest.

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// userHZ is the unit /proc/stat's CPU columns are published in.
//
// Fixed at 100 by the kernel's user-space ABI regardless of CONFIG_HZ, so it is
// a constant rather than a getconf call.
const userHZ = 100.0

// HostSample is one reading of the machine's state, taken from procfs.
//
// Cumulative counters are kept as read; turning two samples into what happened
// between them is HostStateBetween's job. Keeping the raw reading separate from
// the difference is what lets the parsing be tested against a fixture without a
// running machine.
type HostSample struct {
	// LoadAvg is /proc/loadavg verbatim, in the same form Environment records
	// it, so the two can be compared without reformatting either.
	LoadAvg string

	MemAvailableKB int64

	// Cumulative CPU seconds across all CPUs since boot.
	CPUBusySeconds  float64
	CPUIdleSeconds  float64
	CPUStealSeconds float64

	// PSICPUStallSeconds is /proc/pressure/cpu's `some total`: cumulative time
	// during which at least one runnable task was waiting for a CPU. The
	// cumulative counter rather than the avg10/avg60/avg300 fields, because a
	// decaying average over a fixed window cannot be attributed to a run whose
	// length is not that window.
	PSICPUStallSeconds float64

	// NumCPU is the number of per-CPU lines in /proc/stat, which is the set the
	// figures above are summed over.
	NumCPU int

	// Interrupts is /proc/interrupts summed across CPUs, keyed by the short
	// name in the first column, for the counters InterruptsOfInterest names.
	// Cumulative since boot, like everything else here.
	Interrupts map[string]int64

	// Unavailable names the sources that could not be read, comma separated.
	Unavailable string
}

// InterruptsOfInterest are the /proc/interrupts rows recorded per run.
//
// Five, not the whole file. The per-device rows are numbered rather than named
// and their numbering is not stable across boots, so recording them would put a
// column in the session file that cannot be compared to the same column in
// another session. These five are named by the kernel, present on every x86_64
// host, and are the ones a ring buffer's notification path can move:
//
//	IWI  IRQ work interrupts. bpf_ringbuf_commit's wakeup is an irq_work, so
//	     this is the counter that should move if notification is the cost.
//	RES  Rescheduling interrupts: a task made runnable on another CPU.
//	CAL  Function call interrupts, the general smp_call_function path.
//	TLB  TLB shootdowns, unrelated to the ring buffer and recorded as a control:
//	     a run where everything moved together was a busy machine, not a busy
//	     probe.
//	LOC  Local timer interrupts, recorded for the same reason.
//
// Evidence, not a gate. Nothing in this package reads them and no verdict
// depends on them, for the reason this file's doc comment gives about every
// other field it records.
var InterruptsOfInterest = []string{"IWI", "RES", "CAL", "TLB", "LOC"}

// SampleHost reads the machine's state from a procfs-shaped directory.
//
// procRoot is a parameter rather than a hardcoded "/proc" so the parsing can be
// tested against fixtures on any machine, including one with no procfs at all.
// The runner passes "/proc".
//
// It never fails. A source that cannot be read leaves its fields zero and names
// itself in Unavailable: this is diagnostic data collected around a measurement
// that took a minute to produce, and losing the measurement because /proc
// changed shape would be the wrong trade in every direction.
func SampleHost(procRoot string) HostSample {
	var s HostSample
	var missing []string

	if b, err := os.ReadFile(filepath.Join(procRoot, "loadavg")); err == nil {
		s.LoadAvg = strings.TrimSpace(string(b))
	} else {
		missing = append(missing, "loadavg")
	}

	if kb, ok := readMemAvailable(filepath.Join(procRoot, "meminfo")); ok {
		s.MemAvailableKB = kb
	} else {
		missing = append(missing, "meminfo")
	}

	if ok := s.readStat(filepath.Join(procRoot, "stat")); !ok {
		missing = append(missing, "stat")
	}

	if secs, ok := readPSITotal(filepath.Join(procRoot, "pressure", "cpu"), "some"); ok {
		s.PSICPUStallSeconds = secs
	} else {
		missing = append(missing, "pressure/cpu")
	}

	if irq, ok := readInterrupts(filepath.Join(procRoot, "interrupts")); ok {
		s.Interrupts = irq
	} else {
		missing = append(missing, "interrupts")
	}

	s.Unavailable = strings.Join(missing, ",")
	return s
}

func readMemAvailable(path string) (int64, bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, false
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		key, val, ok := strings.Cut(sc.Text(), ":")
		if !ok || key != "MemAvailable" {
			continue
		}
		fields := strings.Fields(val)
		if len(fields) == 0 {
			return 0, false
		}
		n, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

// readStat parses the aggregate "cpu" line and counts the per-CPU lines.
//
// The columns are user, nice, system, idle, iowait, irq, softirq, steal, and
// two guest fields this does not use. iowait is counted as idle rather than as
// busy: a CPU in iowait is available to anything runnable, and counting it as
// work would make a run that touched the disk look like a run that was
// competing for a core.
func (s *HostSample) readStat(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	found := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 || !strings.HasPrefix(fields[0], "cpu") {
			continue
		}
		if fields[0] != "cpu" {
			s.NumCPU++
			continue
		}
		if len(fields) < 9 {
			return false
		}
		var v [8]float64
		for i := range v {
			n, err := strconv.ParseFloat(fields[i+1], 64)
			if err != nil {
				return false
			}
			v[i] = n / userHZ
		}
		s.CPUBusySeconds = v[0] + v[1] + v[2] + v[5] + v[6] // user nice system irq softirq
		s.CPUIdleSeconds = v[3] + v[4]                      // idle iowait
		s.CPUStealSeconds = v[7]
		found = true
	}
	return found
}

// readPSITotal reads the cumulative `total=` microseconds from a PSI file's
// "some" or "full" line.
func readPSITotal(path, prefix string) (float64, bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, false
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 || fields[0] != prefix {
			continue
		}
		for _, field := range fields[1:] {
			if after, ok := strings.CutPrefix(field, "total="); ok {
				n, err := strconv.ParseFloat(after, 64)
				if err != nil {
					return 0, false
				}
				return n / 1e6, true
			}
		}
	}
	return 0, false
}

// readInterrupts sums each named row of /proc/interrupts across every CPU
// column.
//
// The file is a table: a header naming the CPUs, then one row per interrupt
// source whose first field is the source's name followed by a colon, then one
// count per CPU, then a free-text description. The description is why the
// numeric fields are taken while they parse and the rest discarded rather than
// the row being split at a fixed width — "IRQ work interrupts" is three fields
// and "Function call interrupts" is three more, and neither is a number.
//
// Only InterruptsOfInterest is kept. A missing row leaves its key absent rather
// than zero, because a counter that is not published and a counter that has not
// moved are different facts about a host and only one of them is a reason to
// distrust a delta.
func readInterrupts(path string) (map[string]int64, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()

	want := make(map[string]bool, len(InterruptsOfInterest))
	for _, k := range InterruptsOfInterest {
		want[k] = true
	}

	out := make(map[string]int64, len(InterruptsOfInterest))
	sc := bufio.NewScanner(f)
	// The rows are short but the header is one field per CPU, and a large
	// machine's per-device rows are longer than the default 64kB token.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		name, ok := strings.CutSuffix(fields[0], ":")
		if !ok || !want[name] {
			continue
		}
		var sum int64
		for _, v := range fields[1:] {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				// The first non-numeric field is the description; the counts
				// are contiguous and come first.
				break
			}
			sum += n
		}
		out[name] = sum
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

// HostStateBetween turns two samples into what the machine did between them.
//
// Cumulative counters become differences; instantaneous readings are kept as
// the pair. A difference is what can be attributed to the run: a load average
// is a decaying window that a sixty-second build only partly fills, whereas
// "the machine burned 340 CPU-seconds while this run's own workload accounted
// for 310 of them" is a statement about this run.
func HostStateBetween(before, after HostSample) *HostState {
	h := &HostState{
		LoadAvgBefore:        before.LoadAvg,
		LoadAvgAfter:         after.LoadAvg,
		MemAvailableKBBefore: before.MemAvailableKB,
		MemAvailableKBAfter:  after.MemAvailableKB,
		CPUBusySeconds:       after.CPUBusySeconds - before.CPUBusySeconds,
		CPUIdleSeconds:       after.CPUIdleSeconds - before.CPUIdleSeconds,
		CPUStealSeconds:      after.CPUStealSeconds - before.CPUStealSeconds,
		PSICPUStallSeconds:   after.PSICPUStallSeconds - before.PSICPUStallSeconds,
		NumCPU:               before.NumCPU,
		InterruptDeltas:      interruptDeltas(before.Interrupts, after.Interrupts),
	}
	switch {
	case before.Unavailable != "" && after.Unavailable != "":
		h.Unavailable = before.Unavailable
	case before.Unavailable != "":
		h.Unavailable = "before:" + before.Unavailable
	case after.Unavailable != "":
		h.Unavailable = "after:" + after.Unavailable
	}
	return h
}

// interruptDeltas is what each recorded counter advanced by across the run.
//
// A key present in only one of the two samples is dropped rather than treated
// as having started or ended at zero: /proc/interrupts gains a row the first
// time a source fires, so a key that appeared mid-run has no baseline and a
// difference computed against an implied zero would report the counter's whole
// value since boot as this run's.
func interruptDeltas(before, after map[string]int64) map[string]int64 {
	if before == nil || after == nil {
		return nil
	}
	out := make(map[string]int64, len(before))
	for k, b := range before {
		a, ok := after[k]
		if !ok {
			continue
		}
		out[k] = a - b
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// OtherCPUSeconds is the CPU time the machine spent on anything other than this
// run's own workload.
//
// The workload's own user+sys is already recorded, so subtracting it from what
// the whole machine burned during the same interval leaves what else was
// running. This is the number that answers the question the recorded sessions
// could not: was the box quiet while this arm was measured?
//
// It is a derived convenience for a reader, not a stored field and not a gate.
// It can be slightly negative — the two figures come from different accounting
// paths sampled a few hundred microseconds apart — and a small negative value
// means "nothing else was running", not that something is wrong.
func (r Run) OtherCPUSeconds() (float64, bool) {
	if r.Host == nil {
		return 0, false
	}
	return r.Host.CPUBusySeconds - (r.UserSeconds + r.SysSeconds), true
}

// String renders a host state compactly, for a log line rather than a report.
func (h *HostState) String() string {
	if h == nil {
		return "no host state"
	}
	return fmt.Sprintf("load %q->%q, machine busy %.1fs idle %.1fs, cpu stall %.2fs, memavail %dkB->%dkB",
		h.LoadAvgBefore, h.LoadAvgAfter, h.CPUBusySeconds, h.CPUIdleSeconds,
		h.PSICPUStallSeconds, h.MemAvailableKBBefore, h.MemAvailableKBAfter)
}
