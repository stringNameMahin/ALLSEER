package synth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stringNameMahin/ALLSEER/internal/telemetry"
	"github.com/stringNameMahin/ALLSEER/internal/telemetry/abi"
	"github.com/stringNameMahin/ALLSEER/internal/telemetry/resolve"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// What these tests are about is that a synthetic event is indistinguishable
// from a decoded one. The decoder has its own tests and the replay source has
// its own; the claim that is unproven until here is that this package adds
// nothing to what those two already decide, and that what it *does* add —
// identity, sequence, the enrichment M6 will produce — is deterministic and
// stated by the caller rather than invented.
//
// Nothing in this file needs root, a kernel, libbpf, cgroup v2 or a compiled
// eBPF object, which is the property that makes a generator worth having.

const session = "s-synth"

// proc is the identity most specs below run under: an ordinary governed build
// process, one generation below the session root.
func proc() Proc {
	return Proc{
		PID: 4101, TID: 4101, PPID: 4100,
		UID: 1000, GID: 1000,
		Comm:       "go",
		CgroupID:   9001,
		StartTime:  88_120_000,
		Executable: "/usr/local/go/bin/go",
	}
}

func gen(t *testing.T) *Generator {
	t.Helper()
	g, err := New(Config{SessionID: session, Process: proc()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

// next builds one event and fails the test if it cannot.
func next(t *testing.T, g *Generator, s Spec) event.Event {
	t.Helper()
	e, err := g.Next(s)
	if err != nil {
		t.Fatalf("Next(%s): %v", s.Type, err)
	}
	return e
}

// openSpec is a successful read of a resolved path, the most ordinary event in
// any stream.
func openSpec(path string) Spec {
	return Spec{
		Type: abi.EvtFileOpen,
		Ret:  3,
		File: &File{Path: "go.mod", ResolvedPath: path, Inode: 525301, Device: 2049},
	}
}

// --- construction --------------------------------------------------------------

// A generator with no session produces events nothing can attribute:
// session.Dispatcher refuses them with ErrEventUnidentified and the validator
// has no envelope to reach. Refused at construction rather than discovered on a
// stream that has already been written to disk.
func TestNewRefusesAnEmptySessionID(t *testing.T) {
	if _, err := New(Config{}); !errors.Is(err, ErrNoSessionID) {
		t.Fatalf("New with no session ID: err = %v, want ErrNoSessionID", err)
	}
}

func TestNewFillsTheClockDefaults(t *testing.T) {
	g := gen(t)
	e := next(t, g, openSpec("/home/dev/project/go.mod"))

	if e.KernelTimestamp != DefaultStartTimestamp {
		t.Errorf("first KernelTimestamp = %d, want DefaultStartTimestamp (%d)",
			e.KernelTimestamp, DefaultStartTimestamp)
	}
	second := next(t, g, openSpec("/home/dev/project/main.go"))
	if got := second.KernelTimestamp - e.KernelTimestamp; got != DefaultInterval {
		t.Errorf("step = %d ns, want DefaultInterval (%d)", got, DefaultInterval)
	}
}

// --- determinism ---------------------------------------------------------------

// The property the whole package is for. A benchmark compared against itself
// and a corpus reviewed as a diff both need the same specs to produce the same
// bytes, on every run and in every process.
func TestGenerationIsDeterministic(t *testing.T) {
	specs := []Spec{
		{Type: abi.EvtProcExec, Exec: &Exec{Filename: "/usr/bin/git", Argv: []string{"git", "commit"}}},
		openSpec("/home/dev/project/go.mod"),
		{Type: abi.EvtNetConnect, Net: &Net{
			Family: AFInet, Protocol: IPProtoTCP, SockType: SockStream,
			DestAddr: netip.MustParseAddr("203.0.113.10"), DestPort: 443,
			Hostname: "proxy.golang.org",
		}},
		{Type: abi.EvtProcExit},
	}

	stream := func() []byte {
		g, err := New(Config{SessionID: session, Process: proc()})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		var buf bytes.Buffer
		if err := g.WriteStream(&buf, specs...); err != nil {
			t.Fatalf("WriteStream: %v", err)
		}
		return buf.Bytes()
	}

	first, second := stream(), stream()
	if !bytes.Equal(first, second) {
		t.Fatalf("two runs of the same specs produced different streams:\n%s\n---\n%s", first, second)
	}
	if len(first) == 0 {
		t.Fatal("the stream is empty")
	}
}

// Determinism has to hold for the record layer on its own, because that is what
// a decoder benchmark measures and what a fixture of raw bytes would be built
// from.
func TestRecordIsAPureFunction(t *testing.T) {
	s := openSpec("/home/dev/project/go.mod")
	s.Proc = ptr(proc())

	a, err := Record(s, 12345)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	b, err := Record(s, 12345)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Error("the same spec and timestamp produced different bytes")
	}

	c, err := Record(s, 12346)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if bytes.Equal(a, c) {
		t.Error("a different timestamp produced identical bytes")
	}
}

// --- the record is the ABI's record --------------------------------------------

// The size is asserted against the generated constant and against the literal
// the header declares. Against the constant because a header change must move
// this package with it; against 856 because a generator that silently agreed
// with a *changed* constant would prove nothing about the layout the committed
// probes write.
func TestRecordIsTheSizeTheABIDeclares(t *testing.T) {
	raw, err := Record(openSpec("/tmp/x"), 1)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	if len(raw) != abi.RecordSize {
		t.Errorf("record is %d bytes, want abi.RecordSize (%d)", len(raw), abi.RecordSize)
	}
	if len(raw) != 856 {
		t.Errorf("record is %d bytes, want 856; sizeof(struct allseer_event) is part of the "+
			"kernel/user contract and this issue does not change it", len(raw))
	}
	if EventSize != abi.RecordSize {
		t.Errorf("EventSize = %d, want abi.RecordSize (%d)", EventSize, abi.RecordSize)
	}
	if EventSize != telemetry.NewDecoder().EventSize() {
		t.Errorf("EventSize = %d, and the decoder expects %d; the generator would produce records "+
			"the collector's own decoder refuses", EventSize, telemetry.NewDecoder().EventSize())
	}
}

// Every record carries this build's ABI version, because the decoder compares
// it before it believes any other field. A generator that left it zero would
// produce nothing but ErrABIVersionMismatch.
func TestRecordCarriesThisBuildsABIVersion(t *testing.T) {
	raw, err := Record(openSpec("/tmp/x"), 1)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	rec, err := abi.DecodeRecord(raw)
	if err != nil {
		t.Fatalf("DecodeRecord: %v", err)
	}
	if rec.Version != abi.ABIVersion {
		t.Errorf("record version = %d, want %d", rec.Version, abi.ABIVersion)
	}
}

// The claim this package rests on: what Next returns is what the collector's
// own decoder makes of the same bytes, plus identity and enrichment and nothing
// else. Asserted by decoding the record independently and comparing field by
// field, so a judgment added here later — a capability chosen, a domain filled
// in, an errno named — fails rather than being reviewed for.
func TestGeneratedEventIsWhatTheDecoderProduces(t *testing.T) {
	s := Spec{
		Type: abi.EvtFileOpen,
		Ret:  -2,
		File: &File{
			Path: "id_rsa", ResolvedPath: "/home/dev/.ssh/id_rsa",
			Flags: 0, Mode: 0o600, Inode: 4242, Device: 2049, Bytes: 17,
		},
	}
	s.Proc = ptr(proc())

	g := gen(t)
	got := next(t, g, s)

	raw, err := Record(s, got.KernelTimestamp)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	want, err := telemetry.NewDecoder().Decode(raw)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if got.Capability != want.Capability || got.Domain != want.Domain {
		t.Errorf("capability/domain = %q/%q, decoder says %q/%q",
			got.Capability, got.Domain, want.Capability, want.Domain)
	}
	if !reflect.DeepEqual(got.Result, want.Result) {
		t.Errorf("Result = %+v, decoder says %+v", got.Result, want.Result)
	}
	if got.KernelTimestamp != want.KernelTimestamp {
		t.Errorf("KernelTimestamp = %d, decoder says %d", got.KernelTimestamp, want.KernelTimestamp)
	}

	// Process identity, with the two enrichment fields removed: those are the
	// generator's to add and the decoder has no source for them.
	gotProc := got.Process
	gotProc.Executable, gotProc.AncestryDepth = "", 0
	if !reflect.DeepEqual(gotProc, want.Process) {
		t.Errorf("Process = %+v, decoder says %+v", gotProc, want.Process)
	}

	// Payload, with the resolved path removed for the same reason.
	gotFile := *got.File
	gotFile.ResolvedPath = ""
	if !reflect.DeepEqual(gotFile, *want.File) {
		t.Errorf("File = %+v, decoder says %+v", gotFile, *want.File)
	}
}

// The generator does not decide what an open exercised; the flags do, in the
// decoder. If this table ever has to be maintained here as well, the second
// decoder this package refuses to be has arrived.
func TestOpenFlagsDecideTheCapability(t *testing.T) {
	const (
		oWrOnly = 0x1
		oRdWr   = 0x2
		oCreat  = 0x40
	)

	cases := []struct {
		flags uint32
		want  capability.Kind
	}{
		{0, capability.KindFileRead},
		{oWrOnly, capability.KindFileWrite},
		{oRdWr, capability.KindFileWrite},
		{oCreat | oWrOnly, capability.KindFileCreate},
	}

	g := gen(t)
	for _, c := range cases {
		e := next(t, g, Spec{
			Type: abi.EvtFileOpen,
			Ret:  3,
			File: &File{Path: "f", ResolvedPath: "/home/dev/project/f", Flags: c.flags},
		})
		if e.Capability != c.want {
			t.Errorf("flags %#x produced %q, want %q", c.flags, e.Capability, c.want)
		}
		if domain, _ := capability.DomainOf(c.want); e.Domain != domain {
			t.Errorf("flags %#x produced domain %q, want %q", c.flags, e.Domain, domain)
		}
	}
}

// A failed syscall is a governance signal in its own right, and a stream that
// could only carry successes would be unable to express the case the corpus
// cares most about: an agent repeatedly failing to open credential material.
func TestFailedSyscallCarriesTheErrno(t *testing.T) {
	g := gen(t)
	e := next(t, g, Spec{
		Type: abi.EvtFileOpen,
		Ret:  -2,
		File: &File{Path: "id_rsa", ResolvedPath: "/home/dev/.ssh/id_rsa"},
	})

	if e.Result.Succeeded {
		t.Error("a negative return decoded as a success")
	}
	if e.Result.ReturnCode != -2 {
		t.Errorf("ReturnCode = %d, want -2", e.Result.ReturnCode)
	}
	if e.Result.Errno != "ENOENT" {
		t.Errorf("Errno = %q, want ENOENT", e.Result.Errno)
	}
}

// The record carries no syscall identifier, so naming one would be a guess in a
// field kept for forensics. Pinned here because a generator is exactly where
// somebody would be tempted to fill it in: the spec knows it meant an openat.
func TestSyscallIsLeftEmpty(t *testing.T) {
	g := gen(t)
	e := next(t, g, openSpec("/home/dev/project/go.mod"))
	if e.Syscall != "" {
		t.Errorf("Syscall = %q; the record carries no syscall identifier", e.Syscall)
	}
}

// (uid_t)-1 is the kernel's "leave this unchanged" marker in the setres*id
// family. It reaches the record as 0xFFFFFFFF and has to come back as -1, or a
// privilege event means something else.
func TestIdentityBoundaryValuesSurviveTheRoundTrip(t *testing.T) {
	g := gen(t)
	e := next(t, g, Spec{
		Type: abi.EvtProcExit,
		Proc: &Proc{PID: math.MaxInt32, TID: -1, PPID: 1, UID: -1, GID: -1, Comm: "sh"},
	})

	if e.Process.PID != math.MaxInt32 {
		t.Errorf("PID = %d, want %d", e.Process.PID, math.MaxInt32)
	}
	for name, got := range map[string]int32{"TID": e.Process.TID, "UID": e.Process.UID, "GID": e.Process.GID} {
		if got != -1 {
			t.Errorf("%s = %d, want -1; the marker must survive as itself", name, got)
		}
	}
}

// --- the stream ----------------------------------------------------------------

// Sequence is dense and 1-based, timestamps increase, and the ID follows the
// same "<session>/<sequence>" form replay synthesizes for a record that omits
// one — so a generated stream and a replayed one identify events identically.
func TestStreamIsDenseMonotonicAndIdentified(t *testing.T) {
	g := gen(t)

	specs := make([]Spec, 12)
	for i := range specs {
		specs[i] = openSpec("/home/dev/project/go.mod")
	}
	events, err := g.Generate(specs...)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(events) != len(specs) {
		t.Fatalf("generated %d events from %d specs", len(events), len(specs))
	}

	for i, e := range events {
		if e.SessionID != session {
			t.Errorf("event %d: SessionID = %q, want %q", i, e.SessionID, session)
		}
		if want := uint64(i + 1); e.Sequence != want {
			t.Errorf("event %d: Sequence = %d, want %d", i, e.Sequence, want)
		}
		if want := session + "/" + strconv.FormatUint(e.Sequence, 10); e.ID != want {
			t.Errorf("event %d: ID = %q, want %q", i, e.ID, want)
		}
		if i > 0 && e.KernelTimestamp <= events[i-1].KernelTimestamp {
			t.Errorf("event %d: KernelTimestamp %d does not increase on %d",
				i, e.KernelTimestamp, events[i-1].KernelTimestamp)
		}
		if e.Dropped != 0 {
			t.Errorf("event %d: reports %d dropped records in a clean stream", i, e.Dropped)
		}
	}
}

// Loss is the case the replay corpus states a rule for: the gap and the counter
// have to agree, or every fail-closed test built on the stream is vacuous. Here
// they agree by construction rather than by the author remembering to.
func TestDroppedAdvancesSequenceAndClockTogether(t *testing.T) {
	g := gen(t)

	first := next(t, g, openSpec("/home/dev/project/go.mod"))
	after := next(t, g, Spec{
		Type:    abi.EvtFileOpen,
		Ret:     3,
		Dropped: 24,
		File:    &File{Path: "main.go", ResolvedPath: "/home/dev/project/main.go"},
	})

	if after.Dropped != 24 {
		t.Errorf("Dropped = %d, want 24", after.Dropped)
	}
	if gap := after.Sequence - first.Sequence; gap != 25 {
		t.Errorf("sequence advanced by %d over 24 lost records, want 25", gap)
	}
	if steps := (after.KernelTimestamp - first.KernelTimestamp) / DefaultInterval; steps != 25 {
		t.Errorf("clock advanced by %d steps, want 25; the lost records took time as well as "+
			"sequence numbers", steps)
	}

	// The next event resumes dense numbering from where the hole left off.
	third := next(t, g, openSpec("/home/dev/project/go.sum"))
	if third.Sequence != after.Sequence+1 {
		t.Errorf("Sequence after the hole = %d, want %d", third.Sequence, after.Sequence+1)
	}
}

// A spec the record layer or the decoder refuses must not consume a sequence
// number. Otherwise a caller that recovers from an error ships a stream with a
// hole it never asked for, which reads as ring buffer loss.
func TestARefusedSpecDoesNotAdvanceTheStream(t *testing.T) {
	g := gen(t)
	first := next(t, g, openSpec("/home/dev/project/go.mod"))

	if _, err := g.Next(Spec{Type: abi.EvtFileOpen}); err == nil {
		t.Fatal("a file event with no payload was accepted")
	}
	if _, err := g.Next(Spec{Type: abi.EvtUnknown}); err == nil {
		t.Fatal("ALLSEER_EVT_UNKNOWN was accepted")
	}

	second := next(t, g, openSpec("/home/dev/project/main.go"))
	if second.Sequence != first.Sequence+1 {
		t.Errorf("Sequence = %d after two refusals, want %d; a refused spec left a hole",
			second.Sequence, first.Sequence+1)
	}
}

// The per-spec identity overrides the configured default, which is what lets
// one stream carry a process tree.
func TestSpecIdentityOverridesTheDefault(t *testing.T) {
	g := gen(t)

	inherited := next(t, g, openSpec("/home/dev/project/go.mod"))
	if inherited.Process.PID != proc().PID || inherited.Process.Executable != proc().Executable {
		t.Errorf("Process = %+v, want the configured default", inherited.Process)
	}

	child := next(t, g, Spec{
		Type: abi.EvtProcExec,
		Proc: &Proc{
			PID: 4180, TID: 4180, PPID: 4101, UID: 1000, GID: 1000, Comm: "compile",
			CgroupID: 9001, StartTime: 88_500_000,
			Executable: "/usr/local/go/pkg/tool/compile", AncestryDepth: 1,
		},
		Exec: &Exec{Filename: "/usr/local/go/pkg/tool/compile"},
	})
	if child.Process.PID != 4180 || child.Process.AncestryDepth != 1 {
		t.Errorf("Process = %+v, want the spec's identity at depth 1", child.Process)
	}
	if inherited.Process.AncestryDepth != 0 {
		t.Error("the spec's identity leaked into an earlier event")
	}
}

// WallClock is left zero unless the caller states the boot offset, because the
// offset strategy is an open decision and a synthesized wall time reads as
// observed.
func TestWallClockIsZeroUnlessTheBootTimeIsStated(t *testing.T) {
	g := gen(t)
	e := next(t, g, openSpec("/home/dev/project/go.mod"))
	if !e.WallClock.IsZero() {
		t.Errorf("WallClock = %v with no boot time configured", e.WallClock)
	}

	boot := time.Date(2026, 3, 2, 10, 15, 0, 0, time.UTC)
	dated, err := New(Config{SessionID: session, Process: proc(), BootWallClock: boot})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	first := next(t, dated, openSpec("/home/dev/project/go.mod"))
	second := next(t, dated, openSpec("/home/dev/project/main.go"))

	if want := boot.Add(time.Duration(first.KernelTimestamp)); !first.WallClock.Equal(want) {
		t.Errorf("WallClock = %v, want %v", first.WallClock, want)
	}
	if got := second.WallClock.Sub(first.WallClock); got != time.Duration(DefaultInterval) {
		t.Errorf("wall clock advanced %v between events, want %v", got, time.Duration(DefaultInterval))
	}
}

// A caller that reuses one Spec across a stream must not end up with every
// event pointing at the same backing array.
func TestEnvKeysAreNotSharedWithTheSpec(t *testing.T) {
	keys := []string{"PATH", "HOME"}
	g := gen(t)
	e := next(t, g, Spec{
		Type: abi.EvtProcExec,
		Exec: &Exec{Filename: "/usr/bin/git", EnvKeys: keys},
	})

	keys[0] = "AWS_SECRET_ACCESS_KEY"
	if e.Exec.EnvKeys[0] != "PATH" {
		t.Errorf("EnvKeys[0] = %q; the event shares the caller's slice", e.Exec.EnvKeys[0])
	}
}

// --- the observation ------------------------------------------------------------

// The observation is the resolver's answer, not a second one written here. The
// validator reads it, so an observation that disagreed with the payload would
// be a grant matched against something that did not happen.
func TestObservationComesFromTheResolver(t *testing.T) {
	g := gen(t)
	events, err := g.Generate(
		openSpec("/home/dev/project/go.mod"),
		Spec{Type: abi.EvtProcExec, Exec: &Exec{
			Filename: "/usr/bin/git", Argv: []string{"git", "commit", "-am", "wip"},
			Interpreter: "/bin/sh",
		}},
		Spec{Type: abi.EvtNetConnect, Net: &Net{
			Family: AFInet, Protocol: IPProtoTCP, SockType: SockStream,
			DestAddr: netip.MustParseAddr("203.0.113.10"), DestPort: 443,
			Hostname: "proxy.golang.org",
		}},
	)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	for i := range events {
		want, err := resolve.Observe(&events[i])
		if err != nil {
			t.Fatalf("event %d: Observe: %v", i, err)
		}
		if !reflect.DeepEqual(events[i].Observation, want) {
			t.Errorf("event %d: Observation = %+v, resolver says %+v", i, events[i].Observation, want)
		}
	}

	if got := events[0].Observation.Target; got != "/home/dev/project/go.mod" {
		t.Errorf("file target = %q, want the resolved path", got)
	}
	if got := events[2].Observation.Target; got != "proxy.golang.org:443" {
		t.Errorf("network target = %q, want the correlated host and port", got)
	}
}

// An unresolved path is a legitimate thing to generate and must stay
// unevaluable: resolve.Observe never falls back to the raw syscall path,
// because matching a pre-resolution path is the symlink escape the whole path
// story exists to prevent.
func TestAnUnresolvedPathProducesAnUnevaluableTarget(t *testing.T) {
	g := gen(t)
	e := next(t, g, Spec{
		Type: abi.EvtFileOpen,
		Ret:  3,
		File: &File{Path: "../../etc/shadow"},
	})

	if e.File.Path != "../../etc/shadow" {
		t.Errorf("Path = %q, want the path as the process passed it", e.File.Path)
	}
	if e.Observation.Target != "" {
		t.Errorf("Target = %q; an unresolved path must not reach selector matching",
			e.Observation.Target)
	}
}

// An uncorrelated destination is the case that matters for network grants: it
// must be reported as uncorrelated rather than assumed equivalent to a granted
// host, or skipping DNS is the cheapest way past a network grant.
func TestAnUncorrelatedDestinationSaysSo(t *testing.T) {
	g := gen(t)
	e := next(t, g, Spec{
		Type: abi.EvtNetConnect,
		Net: &Net{
			Family: AFInet, Protocol: IPProtoTCP, SockType: SockStream,
			DestAddr: netip.MustParseAddr("198.51.100.7"), DestPort: 443,
		},
	})

	if e.Network.Hostname != "" {
		t.Errorf("Hostname = %q, want empty", e.Network.Hostname)
	}
	if got := e.Observation.Attributes[capability.AttrHostnameCorrelated]; got != "false" {
		t.Errorf("%s = %q, want \"false\"", capability.AttrHostnameCorrelated, got)
	}
	if got := e.Observation.Target; got != "198.51.100.7:443" {
		t.Errorf("Target = %q, want the address and port", got)
	}
}

// --- the network vocabulary -----------------------------------------------------

// The constants this package offers and the names decode.go renders are two
// tables of the same Linux values, which is how a synthetic AF_INET quietly
// becomes something else. Compared through the decoder so they cannot drift
// apart unnoticed.
func TestNetworkVocabularyMatchesTheDecoder(t *testing.T) {
	families := []struct {
		family uint16
		want   string
	}{
		{AFUnspec, "AF_UNSPEC"},
		{AFUnix, "AF_UNIX"},
		{AFInet, "AF_INET"},
		{AFInet6, "AF_INET6"},
	}
	protocols := []struct {
		proto uint16
		want  string
	}{
		{IPProtoTCP, "tcp"},
		{IPProtoUDP, "udp"},
	}
	sockTypes := []struct {
		sock uint16
		want string
	}{
		{SockStream, "SOCK_STREAM"},
		{SockDgram, "SOCK_DGRAM"},
		{SockRaw, "SOCK_RAW"},
		{SockSeqpacket, "SOCK_SEQPACKET"},
	}

	g := gen(t)
	for _, f := range families {
		e := next(t, g, Spec{Type: abi.EvtNetConnect, Net: &Net{Family: f.family}})
		if e.Network.AddressFamily != f.want {
			t.Errorf("family %d decoded as %q, want %q", f.family, e.Network.AddressFamily, f.want)
		}
	}
	for _, p := range protocols {
		e := next(t, g, Spec{Type: abi.EvtNetConnect, Net: &Net{Family: AFInet, Protocol: p.proto}})
		if e.Network.Protocol != p.want {
			t.Errorf("protocol %d decoded as %q, want %q", p.proto, e.Network.Protocol, p.want)
		}
	}
	for _, s := range sockTypes {
		e := next(t, g, Spec{Type: abi.EvtNetConnect, Net: &Net{Family: AFInet, SockType: s.sock}})
		if e.Network.SocketType != s.want {
			t.Errorf("socket type %d decoded as %q, want %q", s.sock, e.Network.SocketType, s.want)
		}
	}
}

// The family decides how many of the sixteen bytes mean anything, so an address
// has to come back as itself. A v4-mapped v6 address stays mapped, matching the
// decoder, which keeps the audit record showing what the socket reported.
func TestAddressesRoundTripUnderTheirFamily(t *testing.T) {
	cases := []struct {
		family uint16
		addr   string
		want   string
	}{
		{AFInet, "203.0.113.10", "203.0.113.10"},
		{AFInet6, "2001:db8::1", "2001:db8::1"},
		{AFInet6, "::ffff:203.0.113.10", "::ffff:203.0.113.10"},
	}

	g := gen(t)
	for _, c := range cases {
		e := next(t, g, Spec{Type: abi.EvtNetConnect, Net: &Net{
			Family: c.family, DestAddr: netip.MustParseAddr(c.addr), DestPort: 443,
		}})
		if e.Network.DestAddr != c.want {
			t.Errorf("%s under family %d decoded as %q, want %q",
				c.addr, c.family, e.Network.DestAddr, c.want)
		}
	}
}

// --- refusals -------------------------------------------------------------------

// Everything a caller can get wrong about a spec, and the reason each is a
// refusal rather than a repair: in every case the record would say something
// other than what the spec said, and a fixture that quietly differs from its
// own description is worse than no fixture.
func TestSpecRefusals(t *testing.T) {
	longPath := "/" + strings.Repeat("a", abi.PathMax)
	longArg := strings.Repeat("x", abi.ArgLen)

	cases := []struct {
		name string
		spec Spec
		want error
	}{
		{"file type with no payload", Spec{Type: abi.EvtFileOpen}, ErrPayloadMismatch},
		{"exec type with no payload", Spec{Type: abi.EvtProcExec}, ErrPayloadMismatch},
		{"net type with no payload", Spec{Type: abi.EvtNetConnect}, ErrPayloadMismatch},
		{"two payloads", Spec{
			Type: abi.EvtFileOpen,
			File: &File{Path: "a"},
			Net:  &Net{Family: AFInet},
		}, ErrPayloadMismatch},
		{"payload on a type with no union member", Spec{
			Type: abi.EvtProcExit,
			File: &File{Path: "a"},
		}, ErrPayloadMismatch},
		{"new_path on something that is not a rename", Spec{
			Type: abi.EvtFileChmod,
			File: &File{Path: "a", NewPath: "b"},
		}, ErrPayloadMismatch},
		{"bytes on a connect", Spec{
			Type: abi.EvtNetConnect,
			Net:  &Net{Family: AFInet, Bytes: 4096},
		}, ErrPayloadMismatch},
		{"path longer than the field", Spec{
			Type: abi.EvtFileOpen,
			File: &File{Path: longPath},
		}, ErrValueTooLong},
		{"comm longer than the field", Spec{
			Type: abi.EvtProcExit,
			Proc: &Proc{Comm: strings.Repeat("c", abi.CommLen)},
		}, ErrValueTooLong},
		{"argument longer than the field", Spec{
			Type: abi.EvtProcExec,
			Exec: &Exec{Filename: "/usr/bin/git", Argv: []string{longArg}},
		}, ErrValueTooLong},
		{"NUL inside a path", Spec{
			Type: abi.EvtFileOpen,
			File: &File{Path: "/etc/pass\x00wd"},
		}, ErrEmbeddedNUL},
		{"more arguments than the record holds", Spec{
			Type: abi.EvtProcExec,
			Exec: &Exec{Filename: "/usr/bin/git", Argv: make([]string, abi.ArgvMax+1)},
		}, ErrTooManyArgs},
		{"v6 address under AF_INET", Spec{
			Type: abi.EvtNetConnect,
			Net:  &Net{Family: AFInet, DestAddr: netip.MustParseAddr("2001:db8::1")},
		}, ErrAddressFamily},
		{"v4 address under AF_INET6", Spec{
			Type: abi.EvtNetConnect,
			Net:  &Net{Family: AFInet6, DestAddr: netip.MustParseAddr("203.0.113.10")},
		}, ErrAddressFamily},
		{"address under a family that carries none", Spec{
			Type: abi.EvtNetConnect,
			Net:  &Net{Family: AFUnix, DestAddr: netip.MustParseAddr("203.0.113.10")},
		}, ErrAddressFamily},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := gen(t)
			if _, err := g.Next(c.spec); !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
			// The same refusal, from the record layer on its own.
			if _, err := Record(c.spec, 1); !errors.Is(err, c.want) {
				t.Fatalf("Record: err = %v, want %v", err, c.want)
			}
		})
	}
}

// The refusals that belong to the decoder are surfaced from the decoder rather
// than restated here. A generator with its own opinion about which event types
// are decodable is a second opinion that can disagree with the one on the hot
// path.
func TestDecoderRefusalsAreSurfacedUnchanged(t *testing.T) {
	cases := []struct {
		name string
		typ  abi.EventType
		want error
	}{
		{"unset type", abi.EvtUnknown, telemetry.ErrUnsetEventType},
		{"undecided privilege mapping", abi.EvtPrivChange, telemetry.ErrUndecidedMapping},
		{"type outside this build's enum", abi.EventType(99), telemetry.ErrUnknownEventType},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := gen(t)
			if _, err := g.Next(Spec{Type: c.typ}); !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
			// The record itself is well-formed: it is the meaning that is
			// refused, not the bytes.
			raw, err := Record(Spec{Type: c.typ}, 1)
			if err != nil {
				t.Fatalf("Record: %v", err)
			}
			if len(raw) != abi.RecordSize {
				t.Fatalf("record is %d bytes, want %d", len(raw), abi.RecordSize)
			}
		})
	}
}

// --- the stream format ------------------------------------------------------------

// One JSON object per line and nothing else. The blank lines and comments the
// reader tolerates are for hand-written fixtures, and this is a machine-produced
// stream.
func TestWriteStreamIsOneEventPerLine(t *testing.T) {
	g := gen(t)
	var buf bytes.Buffer
	if err := g.WriteStream(&buf, openSpec("/a"), openSpec("/b"), openSpec("/c")); err != nil {
		t.Fatalf("WriteStream: %v", err)
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("wrote %d lines for 3 events", len(lines))
	}
	for i, line := range lines {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "//") {
			t.Errorf("line %d is a comment or blank: %q", i, line)
		}
		var e event.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("line %d does not parse as an event: %v", i, err)
		}
		if e.Sequence != uint64(i+1) {
			t.Errorf("line %d carries sequence %d", i, e.Sequence)
		}
	}
}

// A stream that failed to build must not reach the writer half-written. A
// truncated recording is the one thing the replay source cannot tell apart from
// a complete one.
func TestWriteStreamRefusesBeforeWritingAnything(t *testing.T) {
	g := gen(t)
	var buf bytes.Buffer
	err := g.WriteStream(&buf, openSpec("/a"), Spec{Type: abi.EvtFileOpen})
	if err == nil {
		t.Fatal("WriteStream accepted a spec with no payload")
	}
	if !errors.Is(err, ErrPayloadMismatch) {
		t.Errorf("err = %v, want ErrPayloadMismatch", err)
	}
	if buf.Len() != 0 {
		t.Errorf("wrote %d bytes before failing:\n%s", buf.Len(), buf.String())
	}
	if !strings.Contains(err.Error(), "spec 1") {
		t.Errorf("err = %v; it does not name the spec that failed", err)
	}
}

// --- through the replay source ------------------------------------------------------

// The integration the whole design turns on: a generated stream is read back by
// the replay source, and what comes out the other side is what went in. Nothing
// downstream can tell a generated source from a recorded one, which is what
// makes the generator usable everywhere a recording is.
func TestGeneratedStreamReplaysVerbatim(t *testing.T) {
	specs := []Spec{
		{Type: abi.EvtProcExec, Exec: &Exec{Filename: "/usr/local/go/bin/go", Argv: []string{"go", "build"}}},
		openSpec("/home/dev/project/go.mod"),
		{Type: abi.EvtFileOpen, Ret: -2, Dropped: 24, File: &File{
			Path: "id_rsa", ResolvedPath: "/home/dev/.ssh/id_rsa",
		}},
		{Type: abi.EvtNetConnect, Net: &Net{
			Family: AFInet, Protocol: IPProtoTCP, SockType: SockStream,
			DestAddr: netip.MustParseAddr("203.0.113.10"), DestPort: 443,
			Hostname: "proxy.golang.org",
		}},
		{Type: abi.EvtProcExit},
	}

	// Two generators over the same config, because a Generator is stateful and
	// the reference stream and the replayed one must be the same stream.
	want, err := gen(t).Generate(specs...)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	src, err := gen(t).Source(specs...)
	if err != nil {
		t.Fatalf("Source: %v", err)
	}
	if err := src.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = src.Close() }()

	var got []event.Event
	for e := range src.Events() {
		got = append(got, e)
	}
	if err := src.Err(); err != nil {
		t.Fatalf("the replay source ended with: %v", err)
	}

	if len(got) != len(want) {
		t.Fatalf("replayed %d events, generated %d", len(got), len(want))
	}
	for i := range want {
		if !reflect.DeepEqual(got[i], want[i]) {
			t.Errorf("event %d differs after a round trip:\n got %+v\nwant %+v", i, got[i], want[i])
		}
	}

	// The loss the third spec declared survives as both halves of the evidence:
	// the counter the record carries and the discontinuity in the numbering.
	stats := src.Stats()
	if stats.EventsReceived != uint64(len(specs)) {
		t.Errorf("EventsReceived = %d, want %d", stats.EventsReceived, len(specs))
	}
	if stats.DroppedEvents != 24 {
		t.Errorf("DroppedEvents = %d, want 24", stats.DroppedEvents)
	}
	if stats.DecodeErrors != 0 {
		t.Errorf("DecodeErrors = %d; a generated stream must parse", stats.DecodeErrors)
	}
	if got := src.SequenceGaps(); got != 1 {
		t.Errorf("SequenceGaps = %d, want 1", got)
	}
}

// A clean stream has no gaps, which is the other half of the claim above: the
// gap detector reports what the stream says rather than something the generator
// leaves behind.
func TestACleanGeneratedStreamReportsNoLoss(t *testing.T) {
	specs := make([]Spec, 8)
	for i := range specs {
		specs[i] = openSpec("/home/dev/project/go.mod")
	}

	src, err := gen(t).Source(specs...)
	if err != nil {
		t.Fatalf("Source: %v", err)
	}
	if err := src.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = src.Close() }()

	n := 0
	for range src.Events() {
		n++
	}
	if n != len(specs) {
		t.Fatalf("delivered %d events, want %d", n, len(specs))
	}
	if got := src.SequenceGaps(); got != 0 {
		t.Errorf("SequenceGaps = %d in a dense stream", got)
	}
	if got := src.Stats().DroppedEvents; got != 0 {
		t.Errorf("DroppedEvents = %d in a clean stream", got)
	}
}

// Source satisfies the interface everything downstream consumes. Asserted
// rather than assumed, because the value of this package is entirely in that
// nothing downstream can tell.
func TestSourceIsAnEventSource(t *testing.T) {
	generated, err := gen(t).Source(openSpec("/a"), openSpec("/b"))
	if err != nil {
		t.Fatalf("Source: %v", err)
	}

	// Consumed only through the interface, which is how every stage downstream
	// of telemetry sees it.
	var src event.Source = generated
	defer func() { _ = src.Close() }()

	if err := src.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	n := 0
	for range src.Events() {
		n++
	}
	if n != 2 {
		t.Fatalf("delivered %d events through event.Source, want 2", n)
	}
	if got := src.Stats().EventsReceived; got != 2 {
		t.Errorf("Stats().EventsReceived = %d, want 2", got)
	}
}

func ptr[T any](v T) *T { return &v }
