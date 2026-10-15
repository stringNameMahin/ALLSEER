package telemetry

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stringNameMahin/ALLSEER/internal/telemetry/abi"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
)

// allAttached is every program reported as loaded and attached.
func allAttached() []ProbeInfo {
	descs := AllProbes()
	out := make([]ProbeInfo, 0, len(descs))
	for _, d := range descs {
		out = append(out, ProbeInfo{
			Name:     d.Name,
			Family:   d.Family,
			Loaded:   true,
			Attached: true,
		})
	}
	return out
}

// withDetached marks the named programs as loaded but not attached.
func withDetached(probes []ProbeInfo, names ...string) []ProbeInfo {
	drop := make(map[string]bool, len(names))
	for _, n := range names {
		drop[n] = true
	}
	out := make([]ProbeInfo, len(probes))
	copy(out, probes)
	for i := range out {
		if drop[out[i].Name] {
			out[i].Attached = false
			out[i].Error = "deliberately not attached"
		}
	}
	return out
}

func containsEntry(entries []string, want string) bool {
	for _, e := range entries {
		if e == want {
			return true
		}
	}
	return false
}

func contains(kinds []capability.Kind, want capability.Kind) bool {
	for _, k := range kinds {
		if k == want {
			return true
		}
	}
	return false
}

// The table has to name every program the loader can attach. A program missing
// from it is a probe whose capabilities never reach the catalog, which is the
// silent half of the failure this reporting exists to prevent.
func TestProbeTableNamesEveryAttachableProgram(t *testing.T) {
	want := append([]string{
		ProgProcExec, ProgProcExit,
		ProgOpenatEnter, ProgOpenatExit,
		ProgConnectEnter, ProgConnectExit,
		ProgFileOpen,
	}, ProgPrivPairs()...)

	got := make(map[string]bool)
	for _, d := range AllProbes() {
		if got[d.Name] {
			t.Errorf("program %q appears twice in the table", d.Name)
		}
		got[d.Name] = true
	}

	if len(got) != len(want) {
		t.Errorf("table has %d programs, the loader names %d", len(got), len(want))
	}
	for _, name := range want {
		if !got[name] {
			t.Errorf("program %q is attachable but absent from the table", name)
		}
	}
}

// Twenty-nine programs, confirmed independently from the compiled object's
// symbol table in every audit of this repository: the twenty-eight tracepoint
// programs and the fentry hook on security_file_open.
func TestProbeTableIsTwentyNinePrograms(t *testing.T) {
	if n := len(AllProbes()); n != 29 {
		t.Errorf("AllProbes() = %d programs, want 29", n)
	}
}

// Sixteen degradation units, never twenty-nine. Two sched singletons, thirteen
// enter/exit pairs and one fentry singleton.
func TestProbeFamiliesAreSixteenUnits(t *testing.T) {
	families := AllProbeFamilies()
	if len(families) != 16 {
		t.Fatalf("AllProbeFamilies() = %d units, want 16", len(families))
	}

	singletons, pairs := 0, 0
	for _, f := range families {
		switch len(f.Programs) {
		case 1:
			singletons++
		case 2:
			pairs++
		default:
			t.Errorf("family %q has %d programs, want 1 or 2", f.Name, len(f.Programs))
		}
	}
	if singletons != 3 {
		t.Errorf("%d singleton families, want 3", singletons)
	}
	if pairs != 13 {
		t.Errorf("%d paired families, want 13", pairs)
	}
}

// proc_exec and proc_exit are the attribution floor, and reporting has to say
// so: M7's fail-closed requirement reads this flag and nothing else.
func TestFloorIsProcExecAndProcExitOnly(t *testing.T) {
	for _, f := range AllProbeFamilies() {
		wantFloor := f.Name == FamilyProcExec || f.Name == FamilyProcExit
		if f.Floor != wantFloor {
			t.Errorf("family %q Floor = %v, want %v", f.Name, f.Floor, wantFloor)
		}
	}
}

// A privilege family observes the kind its own syscall decodes to, not all four
// a PRIV_CHANGE record could carry. Reporting the union per family would claim
// priv.capset is observable on a host carrying only the setuid pair.
func TestPrivilegeFamilyReportsOnlyItsOwnKind(t *testing.T) {
	byName := make(map[string]ProbeFamily)
	for _, f := range AllProbeFamilies() {
		byName[f.Name] = f
	}

	cases := []struct {
		family string
		want   capability.Kind
	}{
		{PrivFamilyFor("setuid"), capability.KindPrivSetuid},
		{PrivFamilyFor("setgroups"), capability.KindPrivSetuid},
		{PrivFamilyFor("capset"), capability.KindPrivCapSet},
		{PrivFamilyFor("unshare"), capability.KindPrivNamespace},
		{PrivFamilyFor("setns"), capability.KindPrivNamespace},
		{PrivFamilyFor("seccomp"), capability.KindPrivSeccomp},
	}

	for _, tc := range cases {
		f, ok := byName[tc.family]
		if !ok {
			t.Errorf("family %q is missing", tc.family)
			continue
		}
		if len(f.Capabilities) != 1 || f.Capabilities[0] != tc.want {
			t.Errorf("family %q observes %v, want exactly [%s]", tc.family, f.Capabilities, tc.want)
		}
	}

	// The union is what the event type advertises, and it is wider than any one
	// family. That is the whole reason this is computed per family.
	if n := len(CapabilitiesFor(abi.EvtPrivChange)); n != 4 {
		t.Fatalf("CapabilitiesFor(EvtPrivChange) = %d kinds, want 4", n)
	}
}

// An entry-side program emits nothing, so it contributes no capability of its
// own. Its family still does, through the exit side.
func TestEntrySideProgramsEmitNothing(t *testing.T) {
	for _, d := range AllProbes() {
		isEntry := d.Name == ProgOpenatEnter || d.Name == ProgConnectEnter ||
			(len(d.Name) > 11 && d.Name[:11] == "priv_enter_")
		if isEntry && d.Emits != abi.EvtUnknown {
			t.Errorf("%s emits %s, want EvtUnknown", d.Name, d.Emits)
		}
		if !isEntry && d.Emits == abi.EvtUnknown {
			t.Errorf("%s emits nothing, but it is not an entry-side program", d.Name)
		}
	}
}

// The whole set attached observes everything the object can emit, and nothing
// is reported as a gap.
func TestFullAttachHasNoGap(t *testing.T) {
	cov := ComputeCoverage(allAttached())

	if cov.Degraded {
		t.Error("a fully attached set reports Degraded")
	}
	if !cov.FloorIntact {
		t.Error("a fully attached set reports the floor broken")
	}
	if len(cov.Unobservable) != 0 {
		t.Errorf("Unobservable = %v, want empty", cov.Unobservable)
	}
	for _, want := range []capability.Kind{
		capability.KindProcessExec, capability.KindProcessExit,
		capability.KindFileRead, capability.KindFileWrite, capability.KindFileCreate,
		capability.KindNetConnect, capability.KindIPCUnixSock,
		capability.KindPrivSetuid, capability.KindPrivCapSet,
		capability.KindPrivNamespace, capability.KindPrivSeccomp,
	} {
		if !contains(cov.Observable, want) {
			t.Errorf("%s is not observable with every probe attached", want)
		}
	}
}

// The property the family is the unit for. Dropping one half of a pair leaves
// the other emitting nothing, so the family must contribute no capability at
// all rather than half of one.
func TestHalfAPairObservesNothing(t *testing.T) {
	files := []capability.Kind{
		capability.KindFileRead, capability.KindFileWrite, capability.KindFileCreate}

	cases := []struct {
		name string
		// drop takes the family's own half and every other family that
		// observes the same kinds, so what is asserted is the pair's own
		// contribution rather than the union of the object's.
		drop []string
		lost []capability.Kind
	}{
		{"openat exit missing", []string{ProgOpenatExit, ProgFileOpen}, files},
		{"openat entry missing", []string{ProgOpenatEnter, ProgFileOpen}, files},
		{"connect entry missing", []string{ProgConnectEnter}, []capability.Kind{
			capability.KindNetConnect, capability.KindIPCUnixSock}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cov := ComputeCoverage(withDetached(allAttached(), tc.drop...))

			if !cov.Degraded {
				t.Error("a partially attached family does not report Degraded")
			}
			for _, k := range tc.lost {
				if contains(cov.Observable, k) {
					t.Errorf("%s is reported observable with %v unattached", k, tc.drop)
				}
				if !contains(cov.Unobservable, k) {
					t.Errorf("%s is not reported as a gap with %v unattached", k, tc.drop)
				}
			}
		})
	}
}

// The fentry hook is what makes an incomplete openat pair survivable: the kinds
// stay observable because every open still reaches security_file_open. What is
// lost is the openat entry point itself - the return value, the dirfd and the
// opens that failed during path resolution - and coverage has to say so rather
// than report the kinds as whole.
func TestFileOpenKeepsOpensObservableWhenTheOpenatPairIsIncomplete(t *testing.T) {
	cov := ComputeCoverage(withDetached(allAttached(), ProgOpenatExit))

	if !cov.Degraded {
		t.Error("an incomplete openat family does not report Degraded")
	}
	var openat FamilyCoverage
	for _, f := range cov.Families {
		if f.Name == FamilyOpenat {
			openat = f
		}
	}
	if openat.Complete || len(openat.Missing) != 1 {
		t.Errorf("openat family = %+v, want incomplete with one missing program", openat)
	}

	for _, k := range []capability.Kind{
		capability.KindFileRead, capability.KindFileWrite, capability.KindFileCreate} {
		if !contains(cov.Observable, k) {
			t.Errorf("%s is not observable although security_file_open is attached", k)
		}
		if contains(cov.Unobservable, k) {
			t.Errorf("%s is reported as a gap although security_file_open is attached", k)
		}
		// The entry point is still watched, by the hook rather than by the
		// pair. What an incomplete pair costs is the openat return value and
		// the opens that failed before a file existed, and the incomplete
		// family above is what reports that.
		if gap := gapFor(cov, k); gap != nil && containsEntry(gap.Missing, "openat") {
			t.Errorf("%s reports openat unwatched although the hook covers it: %+v", k, gap)
		}
	}
}

// With everything attached, an open is watched at every entry point the catalog
// declares for it. The read and mmap entry points of fs.read stay unwatched and
// are reported so: ALLSEER observes the open that reached a file, not each
// later use of the descriptor.
func TestEveryOpenEntryPointIsWatchedWhenFullyAttached(t *testing.T) {
	cov := ComputeCoverage(allAttached())

	for _, k := range []capability.Kind{
		capability.KindFileRead, capability.KindFileWrite, capability.KindFileCreate} {
		gap := gapFor(cov, k)
		if gap == nil {
			continue
		}
		for _, entry := range []string{"open", "openat", "openat2", "creat", "io_uring"} {
			if containsEntry(gap.Missing, entry) {
				t.Errorf("%s reports %s unwatched with every probe attached: %+v", k, entry, gap)
			}
		}
	}

	read := gapFor(cov, capability.KindFileRead)
	if read == nil || !containsEntry(read.Missing, "read") || !containsEntry(read.Missing, "mmap") {
		t.Errorf("fs.read does not report read and mmap as unwatched: %+v", read)
	}
}

// Exactly one program may be dropped at load time, and it is the fentry hook.
// Anything else in this list would mean a tracepoint program could vanish
// without the floor check or a family noticing.
func TestOptionalProgramsIsTheFentryHookOnly(t *testing.T) {
	opt := OptionalPrograms()
	if len(opt) != 1 || opt[0] != ProgFileOpen {
		t.Fatalf("OptionalPrograms() = %v, want only %s", opt, ProgFileOpen)
	}
	for _, d := range AllProbes() {
		if d.Optional && d.Type != probeTypeFentry {
			t.Errorf("%s is optional and is a %s, not an fentry program", d.Name, d.Type)
		}
	}
}

// The degradation the hook is optional for: a kernel that cannot load it keeps
// the openat pair, so opens stay observable through openat and the entry points
// only the hook reaches are reported unwatched rather than quietly lost.
func TestWithoutTheHookOnlyOpenatIsWatched(t *testing.T) {
	cov := ComputeCoverage(withDetached(allAttached(), ProgFileOpen))

	for _, k := range []capability.Kind{
		capability.KindFileRead, capability.KindFileWrite, capability.KindFileCreate} {
		if !contains(cov.Observable, k) {
			t.Errorf("%s is not observable with the openat pair attached", k)
		}
		gap := gapFor(cov, k)
		if gap == nil {
			t.Fatalf("%s reports no entry-point gap without the hook", k)
		}
		if !containsEntry(gap.Observed, "openat") {
			t.Errorf("%s does not report openat watched: %+v", k, gap)
		}
		for _, entry := range []string{"openat2", "io_uring"} {
			if !containsEntry(gap.Missing, entry) {
				t.Errorf("%s does not report %s unwatched without the hook: %+v", k, entry, gap)
			}
		}
	}
}

// The fixable gaps are reported apart from the permanent ones, because an
// operator can only act on the first kind.
func TestDegradedEntryPointsSeparatesFixableFromByDesign(t *testing.T) {
	if lost := ComputeCoverage(allAttached()).DegradedEntryPoints(); len(lost) != 0 {
		t.Errorf("a fully attached load reports lost entry points: %+v", lost)
	}

	lost := ComputeCoverage(withDetached(allAttached(), ProgFileOpen)).DegradedEntryPoints()
	gap := func(k capability.Kind) *EntryPointGap {
		for i := range lost {
			if lost[i].Kind == k {
				return &lost[i]
			}
		}
		return nil
	}
	read := gap(capability.KindFileRead)
	if read == nil {
		t.Fatalf("fs.read reports no lost entry points without the hook: %+v", lost)
	}
	for _, entry := range []string{"openat2", "io_uring"} {
		if !containsEntry(read.Missing, entry) {
			t.Errorf("fs.read does not report %s lost: %+v", read, entry)
		}
	}
	// Watched at no attachment, so not a loss: it is how this build works.
	for _, entry := range []string{"read", "mmap"} {
		if containsEntry(read.Missing, entry) {
			t.Errorf("fs.read reports %s as lost, but no probe ever watches it: %+v", entry, read)
		}
	}
}

func gapFor(cov Coverage, k capability.Kind) *EntryPointGap {
	for i := range cov.EntryPoints {
		if cov.EntryPoints[i].Kind == k {
			return &cov.EntryPoints[i]
		}
	}
	return nil
}

// Dropping one privilege family must not take the other ten with it, and must
// not leave its own kind reported as observable when no other family covers it.
func TestOnePrivilegeFamilyDegradesAlone(t *testing.T) {
	cov := ComputeCoverage(withDetached(allAttached(),
		"priv_enter_capset", "priv_exit_capset"))

	if contains(cov.Observable, capability.KindPrivCapSet) {
		t.Error("priv.capset is observable with the capset pair unattached")
	}
	if !contains(cov.Unobservable, capability.KindPrivCapSet) {
		t.Error("priv.capset is not reported as a gap")
	}
	// setuid is covered by seven other families, so it survives.
	if !contains(cov.Observable, capability.KindPrivSetuid) {
		t.Error("priv.setuid stopped being observable when capset was dropped")
	}
	if !contains(cov.Observable, capability.KindPrivSeccomp) {
		t.Error("priv.seccomp stopped being observable when capset was dropped")
	}
}

// A kind no program in this object emits is a build property, not a
// degradation. Conflating the two would make an unfinished probe look like a
// load failure and the reverse.
func TestUnsupportedIsNotReportedAsAGap(t *testing.T) {
	cov := ComputeCoverage(allAttached())

	if len(cov.Unsupported) == 0 {
		t.Fatal("no unsupported kinds, but this object has no unlink or chmod probe")
	}
	for _, k := range cov.Unsupported {
		if contains(cov.Observable, k) {
			t.Errorf("%s is both unsupported and observable", k)
		}
		if contains(cov.Unobservable, k) {
			t.Errorf("%s is reported as a degradation gap, but nothing emits it", k)
		}
	}
	if !contains(cov.Unsupported, capability.KindFileDelete) {
		t.Error("fs.delete has no probe in this object and should be unsupported")
	}
}

// Every known kind lands in exactly one of the three buckets, so a reader
// cannot find a capability missing from the report entirely.
func TestEveryKnownKindIsAccountedFor(t *testing.T) {
	cov := ComputeCoverage(withDetached(allAttached(), ProgConnectExit))

	seen := make(map[capability.Kind]int)
	for _, set := range [][]capability.Kind{cov.Observable, cov.Unobservable, cov.Unsupported} {
		for _, k := range set {
			seen[k]++
		}
	}
	for _, k := range capability.AllKinds() {
		if seen[k] != 1 {
			t.Errorf("%s appears in %d buckets, want exactly 1", k, seen[k])
		}
	}
}

// Losing the floor is not a degraded session to continue quietly. It is the
// case M7 must refuse to govern on, and the report has to make it findable.
func TestFloorBreachIsReported(t *testing.T) {
	for _, prog := range []string{ProgProcExec, ProgProcExit} {
		cov := ComputeCoverage(withDetached(allAttached(), prog))
		if cov.FloorIntact {
			t.Errorf("FloorIntact is true with %s unattached", prog)
		}
		if !cov.Degraded {
			t.Errorf("Degraded is false with %s unattached", prog)
		}
	}

	// A non-floor family failing must not be mistaken for a floor breach.
	cov := ComputeCoverage(withDetached(allAttached(), ProgOpenatExit))
	if !cov.FloorIntact {
		t.Error("dropping openat reports the attribution floor broken")
	}
}

// The end of the chain: what attached decides what the catalog admits is
// observable.
func TestApplySetsObservableOnCatalog(t *testing.T) {
	cat := capability.NewCatalog()
	if cat.Observable(capability.KindProcessExec) {
		t.Fatal("a fresh catalog reports process.exec observable")
	}

	ComputeCoverage(withDetached(allAttached(), ProgOpenatExit, ProgFileOpen)).Apply(cat)

	if !cat.Observable(capability.KindProcessExec) {
		t.Error("process.exec is not observable after Apply")
	}
	if cat.Observable(capability.KindFileRead) {
		t.Error("fs.read is observable after Apply, with no open probe attached")
	}
}

// A grant nothing watches reads as governance and enforces nothing. Naming
// those grants is what lets the daemon refuse rather than proceed quietly.
func TestGrantGapNamesUngovernedGrants(t *testing.T) {
	cov := ComputeCoverage(withDetached(allAttached(), ProgConnectEnter))

	granted := []capability.Kind{
		capability.KindProcessExec,
		capability.KindNetConnect,
		capability.KindFileDelete,
	}
	gap := cov.GrantGap(granted)

	if contains(gap, capability.KindProcessExec) {
		t.Error("process.exec is observable but reported as a gap")
	}
	if !contains(gap, capability.KindNetConnect) {
		t.Error("net.connect was granted and is unobservable, but is not in the gap")
	}
	if !contains(gap, capability.KindFileDelete) {
		t.Error("fs.delete has no probe at all, but is not in the gap")
	}

	if len(ComputeCoverage(allAttached()).GrantGap(
		[]capability.Kind{capability.KindProcessExec})) != 0 {
		t.Error("a fully observable grant produced a gap")
	}
}

// The report travels to the audit record and to a bug report, so it has to
// survive a round trip and keep the fields a later reader needs.
func TestCoverageRoundTripsThroughJSON(t *testing.T) {
	cov := ComputeCoverage(withDetached(allAttached(), ProgProcExit, ProgOpenatExit))

	raw, err := json.Marshal(cov)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Coverage
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if back.Degraded != cov.Degraded || back.FloorIntact != cov.FloorIntact {
		t.Error("degradation flags did not survive the round trip")
	}
	if len(back.Unobservable) != len(cov.Unobservable) {
		t.Errorf("Unobservable = %d kinds after round trip, want %d",
			len(back.Unobservable), len(cov.Unobservable))
	}
	if len(back.Probes) != 29 {
		t.Errorf("Probes = %d after round trip, want 29", len(back.Probes))
	}

	var missing []string
	for _, f := range back.Families {
		if !f.Complete {
			missing = append(missing, f.Missing...)
		}
	}
	if len(missing) != 2 {
		t.Errorf("round trip reports %d missing programs, want 2: %v", len(missing), missing)
	}
}

// A caller that reports only the probes it tried still gets an honest answer
// about the rest, rather than silently full coverage.
func TestAbsentProbesCountAsUnattached(t *testing.T) {
	cov := ComputeCoverage([]ProbeInfo{
		{Name: ProgProcExec, Family: FamilyProcExec, Loaded: true, Attached: true},
		{Name: ProgProcExit, Family: FamilyProcExit, Loaded: true, Attached: true},
	})

	if !cov.Degraded {
		t.Error("a report naming two probes claims an undegraded object")
	}
	if !cov.FloorIntact {
		t.Error("both floor programs attached, but the floor reports broken")
	}
	if contains(cov.Observable, capability.KindFileRead) {
		t.Error("fs.read is observable though no openat probe was reported")
	}
	if !contains(cov.Observable, capability.KindProcessExec) {
		t.Error("process.exec was attached but is not observable")
	}
}

// Attach points are what a reader matches against the kernel's tracepoint list,
// so a duplicate or an empty one makes the report unusable as a diagnostic.
func TestAttachPointsAreUniqueAndNamed(t *testing.T) {
	seen := make(map[string]string)
	for _, d := range AllProbes() {
		switch {
		case d.AttachPoint == "":
			t.Errorf("%s has no attach point", d.Name)
		case d.Type != probeTypeTracepoint && d.Type != probeTypeFentry:
			t.Errorf("%s has type %q, want tracepoint or fentry", d.Name, d.Type)
		}
		if other, dup := seen[d.AttachPoint]; dup {
			t.Errorf("%s and %s share attach point %q", other, d.Name, d.AttachPoint)
		}
		seen[d.AttachPoint] = d.Name
	}
}

// The bug report is what a user pastes into an issue, so the facts a maintainer
// needs have to be in the text and not only in the struct.
func TestBugReportNamesTheGapAndItsCause(t *testing.T) {
	probes := withDetached(allAttached(), ProgOpenatExit)
	for i := range probes {
		if probes[i].Name == ProgOpenatExit {
			probes[i].Error = "telemetry: attaching \"openat_exit\": permission denied"
		}
	}
	report := ComputeCoverage(probes).BugReport()

	for _, want := range []string{
		"degraded:     true",
		"floor intact: true",
		FamilyOpenat,
		ProgOpenatExit,
		"permission denied",
		string(capability.KindFileRead),
	} {
		if !strings.Contains(report, want) {
			t.Errorf("bug report omits %q\n\n%s", want, report)
		}
	}
}

// A floor breach is the case that must not read like an ordinary degradation.
func TestBugReportFlagsAFloorBreach(t *testing.T) {
	report := ComputeCoverage(withDetached(allAttached(), ProgProcExit)).BugReport()

	if !strings.Contains(report, "floor intact: false") {
		t.Errorf("bug report does not report the floor broken\n\n%s", report)
	}
	if !strings.Contains(report, "[FLOOR]") {
		t.Errorf("bug report does not mark the floor family\n\n%s", report)
	}
}

// A healthy load must not read as a problem.
func TestBugReportOnAHealthyLoadReportsNoFailures(t *testing.T) {
	report := ComputeCoverage(allAttached()).BugReport()

	if !strings.Contains(report, "All 16 probe families attached.") {
		t.Errorf("healthy report does not say so\n\n%s", report)
	}
	if strings.Contains(report, "Attach failures:") {
		t.Errorf("healthy report lists attach failures\n\n%s", report)
	}
	if strings.Contains(report, "this load does not") {
		t.Errorf("healthy report claims a degradation gap\n\n%s", report)
	}
	// Unsupported kinds are a build property and belong in every report.
	if !strings.Contains(report, "no probe in this build observes") {
		t.Errorf("healthy report omits the unsupported section\n\n%s", report)
	}
}
