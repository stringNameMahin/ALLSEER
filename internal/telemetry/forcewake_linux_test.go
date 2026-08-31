//go:build linux && ebpf

package telemetry

// The forced-wakeup instrument, from the object and loader side.
//
// bench_linux_test.go's arms are only as trustworthy as the two facts checked
// here: that the object really declares the tunable this package writes, and
// that every arm but the coalesced one leaves it alone. Neither needs root, a
// kernel, or a workload — the first reads the compiled ELF, the second is
// arithmetic on an arm name — so both fail on a developer's machine rather than
// two hours into a session.

import (
	"debug/elf"
	"testing"

	"github.com/stringNameMahin/ALLSEER/internal/telemetry/benchstat"
)

// --- the arm definitions -------------------------------------------------------

// The whole semantic difference between A3 and A3F, stated as a table so that a
// change to either one is a diff here.
func TestForceWakeupForArm(t *testing.T) {
	for _, tc := range []struct {
		arm  string
		want bool
		why  string
	}{
		{benchstat.ArmOff, false, "A0 loads nothing at all"},
		{benchstat.ArmLoaded, false, "A1 must be the object the control arm has always been"},
		{benchstat.ArmAttachedUntracked, false, "A2 emits no records, so notification cannot apply"},
		{benchstat.ArmTracked, false, "A3 is the acceptance configuration and must not move"},
		{benchstat.ArmDecoded, false, "A4 is A3 plus decode, and nothing else"},
		{benchstat.ArmTrackedForceWake, true, "A3F is the experiment"},
	} {
		if got := forceWakeupForArm(tc.arm); got != tc.want {
			t.Errorf("forceWakeupForArm(%s) = %v, want %v: %s", tc.arm, got, tc.want, tc.why)
		}
	}
}

// A3 specifically. Called out on its own because the experiment is worthless if
// the arm it compares against is not the one the acceptance session ran: a
// non-zero here would mean A3 loaded a different object configuration than the
// +21.01% was measured with, and the comparison would be against a moved
// baseline without anything saying so.
func TestTrackedArmStillLoadsWithoutForcedWakeups(t *testing.T) {
	if forceWakeupForArm(benchstat.ArmTracked) {
		t.Fatalf("forceWakeupForArm(%s) = true, want false", benchstat.ArmTracked)
	}
	// And false is the value applyForceWakeup declines to write, so the object
	// is untouched rather than rewritten with the value it already holds. A nil
	// module is safe precisely because the false case returns before using it.
	if err := applyForceWakeup(nil, false); err != nil {
		t.Errorf("applyForceWakeup(_, false) = %v, want nil: false must be the untouched path", err)
	}
}

func TestArmTracksCgroup(t *testing.T) {
	for _, tc := range []struct {
		arm  string
		want bool
	}{
		{benchstat.ArmOff, false},
		{benchstat.ArmLoaded, false},
		{benchstat.ArmAttachedUntracked, false},
		{benchstat.ArmTracked, true},
		{benchstat.ArmDecoded, true},
		{benchstat.ArmTrackedForceWake, true},
	} {
		if got := armTracksCgroup(tc.arm); got != tc.want {
			t.Errorf("armTracksCgroup(%s) = %v, want %v", tc.arm, got, tc.want)
		}
	}
}

// A3F must differ from A3 in the notification policy and in nothing else this
// harness controls. Stated as an equality between the two arms on every other
// axis, so that a future arm-shaped difference has to be added here first.
func TestForceWakeArmDiffersFromTrackedOnlyInWakeup(t *testing.T) {
	if armTracksCgroup(benchstat.ArmTrackedForceWake) != armTracksCgroup(benchstat.ArmTracked) {
		t.Error("A3F and A3 disagree about tracking the workload cgroup; they must not")
	}
	// Decoding is A4's difference, and A3F is built from A3.
	if benchstat.ArmTrackedForceWake == benchstat.ArmDecoded {
		t.Error("A3F must not be the decoding arm")
	}
	if forceWakeupForArm(benchstat.ArmTrackedForceWake) == forceWakeupForArm(benchstat.ArmTracked) {
		t.Error("A3F and A3 load the same notification policy; the experiment would compare nothing")
	}
}

// --- the object declares what the loader writes --------------------------------

// The tunable exists, is read-only, is the width Config writes, and ships
// disabled.
//
// Read from the ELF symbol table for the reason rodata.go gives at length: a
// DATASEC offset is zero in an unlinked object, so the symbol table is the only
// place the real offset lives.
func TestObjectDeclaresTheForceWakeupTunable(t *testing.T) {
	obj := objectOrSkip(t)

	f, err := elf.Open(obj)
	if err != nil {
		t.Fatalf("opening %s: %v", obj, err)
	}
	defer f.Close()

	syms, err := f.Symbols()
	if err != nil {
		t.Fatalf("reading the symbol table of %s: %v", obj, err)
	}

	var sym *elf.Symbol
	for i := range syms {
		if syms[i].Name == RODataForceWakeup {
			sym = &syms[i]
			break
		}
	}
	if sym == nil {
		t.Fatalf("%s declares no symbol named %q; Config.RingbufForceWakeup would be silently ignored",
			obj, RODataForceWakeup)
	}

	sec := f.Sections[sym.Section]
	if sec.Name != ".rodata" {
		t.Errorf("%s lives in %s, not .rodata: libbpf would not freeze it and the verifier could not "+
			"fold it, so A3 would pay for a runtime load it never used to", RODataForceWakeup, sec.Name)
	}
	if sym.Size != 8 {
		t.Errorf("%s is %d bytes, want 8 to match the __u64 the loader writes", RODataForceWakeup, sym.Size)
	}

	data, err := sec.Data()
	if err != nil {
		t.Fatalf("reading %s: %v", sec.Name, err)
	}
	if sym.Value+8 > uint64(len(data)) {
		t.Fatalf("%s lies at offset %d of a %d-byte section", RODataForceWakeup, sym.Value, len(data))
	}
	if got := f.ByteOrder.Uint64(data[sym.Value : sym.Value+8]); got != 0 {
		t.Errorf("%s ships as %d, want 0: every arm would force a wakeup", RODataForceWakeup, got)
	}
}

// The ABI version global must still be readable beside the new one. rodata.go
// warns that a reader trusting raw DATASEC offsets "stops being right the
// moment a second read-only global is added" — this is that moment, and the
// check is that the loader's own reader was already right.
func TestABIVersionStillReadableAlongsideTheTunable(t *testing.T) {
	obj := objectOrSkip(t)

	got, err := readOnlyU32FromObject(obj, "allseer_abi_version")
	if err != nil {
		t.Fatalf("reading allseer_abi_version from %s: %v", obj, err)
	}
	if got == 0 {
		t.Fatal("allseer_abi_version read as 0; the second .rodata global displaced it")
	}
	if err := checkABIVersion(obj, got); err != nil {
		t.Errorf("checkABIVersion against the object's own version: %v", err)
	}
}

// --- the record the experiment produces ----------------------------------------

// The forced-wakeup arm has to be identifiable in the session file. A run recorded
// under A3's name would be pooled with A3's pairs and the experiment would
// silently average the two configurations together.
func TestForceWakeArmIsDistinguishableInARecord(t *testing.T) {
	if benchstat.ArmTrackedForceWake == benchstat.ArmTracked {
		t.Fatal("the two arms share a name")
	}
	for _, a := range benchstat.Arms() {
		if a == benchstat.ArmTrackedForceWake {
			t.Errorf("%s is an acceptance arm; it must be opt-in", benchstat.ArmTrackedForceWake)
		}
	}
	var known bool
	for _, a := range benchstat.KnownArms() {
		if a == benchstat.ArmTrackedForceWake {
			known = true
		}
	}
	if !known {
		t.Errorf("%s is not in KnownArms(); the scheduler would refuse it", benchstat.ArmTrackedForceWake)
	}
}
