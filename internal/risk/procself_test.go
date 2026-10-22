package risk

import (
	"testing"

	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// The reader is pid 4242, thread 4243.
var procReader = event.Process{PID: 4242, TID: 4243}

func TestOwnProcEntryIsOnlyTheReadersOwnFiles(t *testing.T) {
	for _, c := range []struct {
		path string
		own  bool
	}{
		{"/proc/4242/maps", true},
		{"/proc/4242/environ", true},
		{"/proc/4242/mem", true},
		{"/proc/4243/maps", true},
		{"/proc/4242/task/4243/maps", true},
		{"/proc/4242/task/9999/environ", true},
		{"/proc/self/maps", true},
		{"/proc/thread-self/maps", true},

		{"/proc/4241/maps", false},
		{"/proc/1/environ", false},
		{"/proc/9999/task/4242/environ", false},
		{"/proc/04242/maps", false},
		{"/proc/+4242/maps", false},
		{"/proc/4242", false},
		{"/proc/4242/", false},
		{"/proc/4242/root/home/dev/.aws/credentials", false},
		{"/proc/4242/root", false},
		{"/proc/4242/cwd", false},
		{"/proc/4242/exe", false},
		{"/proc/4242/fd/3", false},
		{"/proc/4242/map_files/7f00-7f01", false},
		{"/proc/4242/task/4243/fd/3", false},
		{"/proc/4242/task/x/maps", false},
		{"/home/dev/proc/4242/maps", false},
		{"/proc/4242/../1/environ", false},
	} {
		if got := ownProcEntry(c.path, procReader); got != c.own {
			t.Errorf("ownProcEntry(%q) = %v, want %v", c.path, got, c.own)
		}
	}
	if ownProcEntry("/proc/0/maps", event.Process{}) {
		t.Error("a reader with no pid owns /proc/0")
	}
}

// Rust's standard library opens /proc/self/maps at start, so every uutils
// coreutils command does. That is the process's own state: graded info, at no
// points, with the reason, while another process's maps keeps its grade.
func TestOwnProcReadIsGradedInfo(t *testing.T) {
	own := departure(capability.KindFileRead, "/proc/4242/maps")
	own.Event.Process = procReader
	a := scoreWith(t, seqEngine(t), own)
	if grade, _, points, ok := sensitivityOf(a); !ok || grade != string(capability.SeverityInfo) || points != 0 {
		t.Errorf("own maps: grade %q points %v present %v, want info at 0", grade, points, ok)
	}
	if f := factor(a, FactorSensitivePath); f == nil || f.Evidence[EvidenceReason] != ownProcReason {
		t.Errorf("own maps: the factor does not say why: %+v", f)
	}

	for _, path := range []string{"/proc/1/maps", "/proc/1/environ", "/proc/1/task/1/environ", "/proc/4242/root/home/dev/.aws/credentials"} {
		other := departure(capability.KindFileRead, path)
		other.Event.Process = procReader
		grade, _, points, _ := sensitivityOf(scoreWith(t, seqEngine(t), other))
		if !AccessSensitivityQualifies(capability.Severity(grade)) || points == 0 {
			t.Errorf("%s: grade %q points %v, want high or above and charged", path, grade, points)
		}
	}
}

// The sequence the false positive came from: a command reads its own maps,
// then the agent connects somewhere. Not credential access. Another process's
// maps, environ or memory before the same connect still is, through the
// thread paths too.
func TestOwnProcReadIsNotTheFirstHalfOfASequence(t *testing.T) {
	read := func(id, path string, pid int32) event.Event {
		e := readAt(id, path, true)
		e.Process = event.Process{PID: pid, TID: pid}
		return e
	}
	for _, path := range []string{"/proc/4242/maps", "/proc/4242/environ", "/proc/4242/task/4242/mem", "/proc/self/maps"} {
		h := history().withRecent(read("a-1", path, 4242))
		if f := seq(scoreWith(t, seqEngine(t), egressReq("e-1", capability.KindNetConnect, egressTarget, h))); f != nil {
			t.Errorf("own %s then connect: %s %+v", path, FactorCredentialEgress, f.Evidence)
		}
	}
	for _, path := range []string{"/proc/1/maps", "/proc/1/environ", "/proc/1/task/1/environ", "/proc/1/task/1/mem"} {
		h := history().withRecent(read("a-1", path, 4242))
		f := seq(scoreWith(t, seqEngine(t), egressReq("e-1", capability.KindNetConnect, egressTarget, h)))
		if f == nil || f.Weight != SequencePoints {
			t.Errorf("another process's %s then connect: %+v, want %s charged", path, f, FactorCredentialEgress)
		}
	}
}
