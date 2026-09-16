//go:build linux && ebpf

package telemetry

import (
	"context"
	"testing"

	"github.com/stringNameMahin/ALLSEER/pkg/capability"
)

// Coverage has to describe a real load, not just a table. These tests attach
// against the compiled object on a live kernel, which is the only place the
// loader's bookkeeping and the probe table can be shown to agree.

// Every program in the table must be present in the object. A name that drifted
// would report as a permanent blind spot on every host.
func TestLoadedObjectCarriesEveryProbeInTheTable(t *testing.T) {
	l, _ := loadAndAttachPrograms(t)

	for _, p := range l.Probes() {
		if !p.Loaded {
			t.Errorf("program %q is in the probe table but not in the loaded object", p.Name)
		}
	}
}

// A load with nothing attached observes nothing, and says so. This is the shape
// a daemon must never mistake for a quiet host.
func TestUnattachedLoadReportsNoCoverage(t *testing.T) {
	l, _ := loadAndAttachPrograms(t)

	cov := l.Coverage()
	if len(cov.Observable) != 0 {
		t.Errorf("Observable = %v with nothing attached", cov.Observable)
	}
	if !cov.Degraded {
		t.Error("a load with nothing attached does not report Degraded")
	}
	if cov.FloorIntact {
		t.Error("FloorIntact is true with proc_exec and proc_exit unattached")
	}
}

// The milestone's own note: partial reporting is testable without a partial
// load, by deliberately not attaching a family. This is that test against the
// real object.
func TestDeliberatelyOmittedFamilyIsReportedAsAGap(t *testing.T) {
	l, _ := loadAndAttachPrograms(t,
		ProgProcExec, ProgProcExit,
		ProgConnectEnter, ProgConnectExit)

	cov := l.Coverage()

	if !cov.FloorIntact {
		t.Error("the floor was attached but reports broken")
	}
	if !cov.Degraded {
		t.Error("openat was never attached but coverage is not degraded")
	}

	for _, k := range []capability.Kind{
		capability.KindProcessExec, capability.KindProcessExit,
		capability.KindNetConnect, capability.KindIPCUnixSock,
	} {
		if !contains(cov.Observable, k) {
			t.Errorf("%s was attached but is not observable", k)
		}
	}
	for _, k := range []capability.Kind{
		capability.KindFileRead, capability.KindFileWrite, capability.KindFileCreate,
	} {
		if contains(cov.Observable, k) {
			t.Errorf("%s is observable though no openat program was attached", k)
		}
		if !contains(cov.Unobservable, k) {
			t.Errorf("%s is not reported as a gap", k)
		}
	}

	// The catalog is the end of the chain, and the thing an envelope is
	// validated against.
	cat := capability.NewCatalog()
	cov.Apply(cat)
	if !cat.Observable(capability.KindNetConnect) {
		t.Error("net.connect is not observable on the catalog after Apply")
	}
	if cat.Observable(capability.KindFileRead) {
		t.Error("fs.read is observable on the catalog though openat was not attached")
	}
}

// Half a pair on a live kernel: the exit program attached alone emits nothing,
// so the family must contribute nothing.
func TestHalfAPairAttachedObservesNothingOnALiveKernel(t *testing.T) {
	l, _ := loadAndAttachPrograms(t,
		ProgProcExec, ProgProcExit, ProgOpenatExit)

	cov := l.Coverage()

	if contains(cov.Observable, capability.KindFileRead) {
		t.Error("fs.read is observable with only openat_exit attached, which emits nothing")
	}
	if !contains(cov.Unobservable, capability.KindFileRead) {
		t.Error("fs.read is not reported as a gap")
	}

	var openat FamilyCoverage
	for _, f := range cov.Families {
		if f.Name == FamilyOpenat {
			openat = f
		}
	}
	if openat.Complete {
		t.Error("the openat family reports complete with only its exit side attached")
	}
	if len(openat.Missing) != 1 || openat.Missing[0] != ProgOpenatEnter {
		t.Errorf("openat Missing = %v, want [%s]", openat.Missing, ProgOpenatEnter)
	}
}

// A failed attach has to reach the report with its reason, because the reason
// is what separates a missing tracepoint from a verifier rejection.
func TestFailedAttachIsRecordedWithItsReason(t *testing.T) {
	l, _ := loadAndAttachPrograms(t, ProgProcExec)

	if err := l.Attach(context.Background(), "no_such_program"); err == nil {
		t.Fatal("attaching a program that does not exist succeeded")
	}

	// The failure is not in the probe table, so it must not invent a row.
	for _, p := range l.Probes() {
		if p.Name == "no_such_program" {
			t.Error("an unknown program appeared in the probe report")
		}
	}

	// A known program that never attached reports as a blind spot with no
	// error, which is the honest distinction: not tried is not the same as
	// tried and refused.
	for _, p := range l.Probes() {
		if p.Name == ProgProcExit && (p.Attached || p.Error != "") {
			t.Errorf("proc_exit was never attached: Attached=%v Error=%q", p.Attached, p.Error)
		}
	}
}

// Detaching returns coverage to nothing observable, so a stopped collector
// cannot leave a stale claim of coverage behind.
func TestDetachAllClearsCoverage(t *testing.T) {
	l, _ := loadAndAttachPrograms(t, ProgProcExec, ProgProcExit)

	if !l.Coverage().FloorIntact {
		t.Fatal("the floor did not attach")
	}
	if err := l.DetachAll(context.Background()); err != nil {
		t.Fatalf("DetachAll: %v", err)
	}

	cov := l.Coverage()
	if cov.FloorIntact {
		t.Error("FloorIntact survives DetachAll")
	}
	if len(cov.Observable) != 0 {
		t.Errorf("Observable = %v after DetachAll", cov.Observable)
	}
}
