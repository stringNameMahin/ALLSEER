//go:build linux && ebpf

package telemetry

// End-to-end tests for the loader.
//
// These are the first tests in the repository that need a kernel. They are
// behind the same `linux && ebpf` tag as the code they exercise, so
// `go test ./...` on any host is unaffected; `make test-ebpf` runs them.
//
// Everything that needs the bpf() syscall needs privilege, and the tests say so
// rather than passing vacuously: each one skips with the precise reason when it
// cannot run, so a green run on an unprivileged host cannot be mistaken for
// evidence that the loader works.

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stringNameMahin/ALLSEER/internal/telemetry/abi"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skipf("loading BPF needs privilege; running as uid %d. Re-run with: "+
			"sudo -E env PATH=$PATH CGO_LDFLAGS=\"$(pkg-config --libs libbpf)\" go test -tags ebpf -count=1 ./internal/telemetry/",
			os.Geteuid())
	}
}

// currentCgroupID returns the cgroup v2 ID of the calling process, which is
// what bpf_get_current_cgroup_id() reports for it.
//
// The ID is the inode number of the cgroup's directory in the unified
// hierarchy. That equivalence is what makes the filter map usable from user
// space at all: the kernel side has a 64-bit number and no name, and this is
// the only way the two are connected.
func currentCgroupID(t *testing.T) uint64 {
	t.Helper()

	root, err := requireCgroupV2()
	if err != nil {
		t.Skipf("no cgroup2 hierarchy: %v", err)
	}

	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatalf("reading /proc/self/cgroup: %v", err)
	}
	var rel string
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		// The unified hierarchy is the "0::<path>" line.
		if after, ok := strings.CutPrefix(line, "0::"); ok {
			rel = after
			break
		}
	}
	if rel == "" {
		t.Skip("this process is not in a cgroup v2 hierarchy")
	}

	fi, err := os.Stat(filepath.Join(root, rel))
	if err != nil {
		t.Fatalf("stat cgroup %s: %v", rel, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("stat did not yield a syscall.Stat_t")
	}
	return st.Ino
}

// trackedKV encodes one tracked_cgroups entry the way allseer_maps.h declares
// it: an allseer_cgroup_id_t key and a one-byte allseer_tracked_t value whose
// content means nothing. The value is 1 rather than 0 only so that a reader of
// a map dump can tell a written entry from zeroed memory; the probe never looks
// at it.
func trackedKV(id uint64) (key, value []byte) {
	key = binary.NativeEndian.AppendUint64(nil, id)
	return key, []byte{1}
}

// The lifecycle rules the interface documents, none of which need a kernel.
func TestLoaderLifecycleWithoutLoading(t *testing.T) {
	ctx := context.Background()
	l := NewLoader(Config{}, nil)

	if err := l.DeleteMap(ctx, MapTrackedCgroups, make([]byte, 8)); !errors.Is(err, ErrNotLoaded) {
		t.Errorf("DeleteMap before Load = %v, want ErrNotLoaded", err)
	}
	if _, err := l.ReadCounter(ctx, MapRingbufDrops); !errors.Is(err, ErrNotLoaded) {
		t.Errorf("ReadCounter before Load = %v, want ErrNotLoaded", err)
	}
	if err := l.Attach(ctx, ProgProcExec); !errors.Is(err, ErrNotLoaded) {
		t.Errorf("Attach before Load = %v, want ErrNotLoaded", err)
	}
	if _, err := l.RingBuffer(ctx, MapEvents); !errors.Is(err, ErrNotLoaded) {
		t.Errorf("RingBuffer before Load = %v, want ErrNotLoaded", err)
	}
	if err := l.UpdateMap(ctx, MapTrackedCgroups, make([]byte, 8), []byte{1}); !errors.Is(err, ErrNotLoaded) {
		t.Errorf("UpdateMap before Load = %v, want ErrNotLoaded", err)
	}

	// DetachAll and Close are documented idempotent, including before Load.
	if err := l.DetachAll(ctx); err != nil {
		t.Errorf("DetachAll on an unloaded loader = %v, want nil", err)
	}
	if err := l.Close(); err != nil {
		t.Errorf("Close on an unloaded loader = %v, want nil", err)
	}
	if err := l.Close(); err != nil {
		t.Errorf("second Close = %v, want nil", err)
	}
	if err := l.Attach(ctx, ProgProcExec); !errors.Is(err, ErrClosed) {
		t.Errorf("Attach after Close = %v, want ErrClosed", err)
	}
	if err := l.DeleteMap(ctx, MapTrackedCgroups, make([]byte, 8)); !errors.Is(err, ErrClosed) {
		t.Errorf("DeleteMap after Close = %v, want ErrClosed", err)
	}
	if _, err := l.ReadCounter(ctx, MapRingbufDrops); !errors.Is(err, ErrClosed) {
		t.Errorf("ReadCounter after Close = %v, want ErrClosed", err)
	}
}

// A bad ring buffer size must be refused before anything is opened, so this
// needs neither privilege nor a compiled object.
func TestLoadRefusesAnInvalidRingBufferSize(t *testing.T) {
	obj := objectOrSkip(t)
	l := NewLoader(Config{RingBufferSize: 3 * os.Getpagesize()}, nil)
	defer l.Close()

	err := l.Load(context.Background(), obj)
	if !errors.Is(err, ErrRingBufferSize) {
		t.Fatalf("Load with a non-power-of-two ring buffer = %v, want ErrRingBufferSize", err)
	}
}

// Layout drift must stop the load, not the first event. A decoder claiming a
// different record size stands in for an object compiled from a changed header.
type wrongSizeDecoder struct{ Decoder }

func (wrongSizeDecoder) EventSize() int { return abi.RecordSize + 8 }

func TestLoadRefusesLayoutDrift(t *testing.T) {
	obj := objectOrSkip(t)
	l := NewLoader(Config{}, wrongSizeDecoder{NewDecoder()})
	defer l.Close()

	err := l.Load(context.Background(), obj)
	if !errors.Is(err, ErrLayoutDrift) {
		t.Fatalf("Load with a mismatched decoder = %v, want ErrLayoutDrift", err)
	}
}

// The version the object was compiled against must stop the load too, and it
// must stop it for a reason the size check cannot see: the fixture is the real
// object with four bytes changed, so its record layout still matches exactly.
//
// Needs the compiled object and not privilege. Load refuses before it opens
// anything, which is the property under test.
func TestLoadRefusesABIVersionDrift(t *testing.T) {
	l := NewLoader(Config{}, nil)
	defer l.Close()

	err := l.Load(context.Background(), objectWithABIVersion(t, abi.ABIVersion+1))
	if !errors.Is(err, ErrABIVersionDrift) {
		t.Fatalf("Load with a mismatched ABI version = %v, want ErrABIVersionDrift", err)
	}
}

// An object whose version cannot be read is refused rather than treated as
// version zero. The fixture is the real object with the symbol renamed, which
// is what an object built from a source that dropped the global — or a
// different program altogether — looks like to the check, and it reaches the
// version check because everything the earlier checks look at is intact.
func TestLoadRefusesAnObjectWithNoABIVersion(t *testing.T) {
	l := NewLoader(Config{}, nil)
	defer l.Close()

	err := l.Load(context.Background(), objectWithoutABIVersion(t))
	if !errors.Is(err, ErrNoObjectGlobal) {
		t.Fatalf("Load with no version global = %v, want ErrNoObjectGlobal", err)
	}
	if errors.Is(err, ErrABIVersionDrift) {
		t.Error("a missing global was reported as a version disagreement")
	}
}

// The ordering claim, made as an assertion rather than left to a reading of
// Load: a version mismatch is found before any program is attached, and before
// any object exists to attach one to.
//
// Attach returning ErrNotLoaded is the strongest form of that available from
// outside — it means the refused Load left no module behind, so there was never
// anything an attach could have run against. The module field is checked too,
// because a loader in this package can see it and "no module" is the fact the
// ordering rests on.
//
// Deliberately not a root test. If this needed privilege it would skip on the
// hosts most likely to be running a stale object, which is the case it exists
// for.
func TestABIVersionIsCheckedBeforeAnyProgramIsAttached(t *testing.T) {
	ctx := context.Background()
	l := NewLoader(Config{}, nil)
	defer l.Close()

	if err := l.Load(ctx, objectWithABIVersion(t, abi.ABIVersion+1)); !errors.Is(err, ErrABIVersionDrift) {
		t.Fatalf("Load = %v, want ErrABIVersionDrift", err)
	}

	l.mu.Lock()
	module := l.module
	links := len(l.links)
	l.mu.Unlock()
	if module != nil {
		t.Error("a refused Load left a loaded object behind")
	}
	if links != 0 {
		t.Errorf("a refused Load left %d links attached", links)
	}

	for _, prog := range []string{ProgProcExec, ProgProcExit, ProgOpenatEnter, ProgOpenatExit,
		ProgConnectEnter, ProgConnectExit} {
		if err := l.Attach(ctx, prog); !errors.Is(err, ErrNotLoaded) {
			t.Errorf("Attach(%s) after a refused Load = %v, want ErrNotLoaded", prog, err)
		}
	}
}

// The size check and the version check are independent, and each has to refuse
// on its own. Neither standing in for the other is the whole reason both exist:
// a layout that changed size is caught by one, and a layout that kept its size
// and changed meaning only by the other.
func TestLayoutAndABIVersionChecksAreIndependent(t *testing.T) {
	obj := objectOrSkip(t)

	// The real object: version wrong, layout right.
	if err := checkRecordLayout(objectWithABIVersion(t, abi.ABIVersion+1), NewDecoder().EventSize()); err != nil {
		t.Errorf("the size check refused an object whose only fault is its version: %v", err)
	}
	// The real object with a decoder claiming a different size: layout wrong,
	// version right.
	if err := checkABIVersion(obj, abi.ABIVersion); err != nil {
		t.Errorf("the version check refused the object the size check is about to refuse: %v", err)
	}
	l := NewLoader(Config{}, wrongSizeDecoder{NewDecoder()})
	defer l.Close()
	if err := l.Load(context.Background(), obj); !errors.Is(err, ErrLayoutDrift) {
		t.Fatalf("Load = %v, want ErrLayoutDrift — the version check must not mask it", err)
	}
}

// loadAndAttach brings a loader up to the point where events would flow, with
// every probe in the object attached, and registers teardown. Shared by the
// runtime tests below.
//
// Both programs, not just the one a given test is about. The object is one
// object with one ring buffer, so a test that attaches only proc_exec is
// testing a configuration the collector will never run; and the exec/exit
// pairing property cannot be observed at all unless both are on the same
// stream.
//
// The openat pair is deliberately *not* attached here, and that is a change
// from "every probe in the object". openat is among the busiest syscalls on a
// Linux host and this process's cgroup is the one these tests track, so
// attaching it would put every open the Go runtime performs onto the same ring
// the exec assertions read from — including the subtest that requires the drop
// counter to still be zero. The open probes have their own file, which attaches
// what each of its tests is about; the one test that needs all four on one
// stream says so.
func loadAndAttach(t *testing.T) (*BPFLoader, <-chan []byte) {
	t.Helper()
	return loadAndAttachPrograms(t, ProgProcExec, ProgProcExit)
}

// loadAndAttachPrograms brings a loader up with a named set of programs
// attached and a reader on the ring buffer, and registers teardown.
func loadAndAttachPrograms(t *testing.T, progs ...string) (*BPFLoader, <-chan []byte) {
	t.Helper()
	requireRoot(t)
	obj := objectOrSkip(t)

	ctx := context.Background()
	l := NewLoader(Config{ObjectPath: obj, RingBufferSize: 1 << 22}, nil)
	t.Cleanup(func() {
		if err := l.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	if err := l.Load(ctx, obj); err != nil {
		t.Fatalf("Load: %v", err)
	}
	records, err := l.RingBuffer(ctx, MapEvents)
	if err != nil {
		t.Fatalf("RingBuffer: %v", err)
	}
	for _, prog := range progs {
		if err := l.Attach(ctx, prog); err != nil {
			t.Fatalf("Attach %s: %v", prog, err)
		}
	}
	return l, records
}

// execMarker copies /bin/true to a uniquely named path and runs it, so the exec
// this test causes can be told apart from every other exec on a live machine by
// its filename alone.
func execMarker(t *testing.T, name string) (path string, pid int) {
	t.Helper()

	src, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Skipf("no /bin/true to copy: %v", err)
	}
	path = filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, src, 0o755); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}

	cmd := exec.Command(path)
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting %s: %v", path, err)
	}
	pid = cmd.Process.Pid
	if err := cmd.Wait(); err != nil {
		t.Fatalf("running %s: %v", path, err)
	}
	return path, pid
}

// collect drains records for a bounded time, decoding each one, and returns
// every exec event whose filename matches.
//
// Both layers are exercised on purpose. abi.DecodeRecord is what proves the
// bytes have the shape the ABI declares — the version field in particular,
// which pkg/event.Event has nowhere to carry. NewDecoder().Decode is what
// proves the loader's raw stream is what the rest of the system consumes.
func collect(t *testing.T, records <-chan []byte, want string, d time.Duration) []decoded {
	t.Helper()

	dec := NewDecoder()
	deadline := time.After(d)
	var found []decoded

	for {
		select {
		case raw, ok := <-records:
			if !ok {
				return found
			}
			rec, err := abi.DecodeRecord(raw)
			if err != nil {
				t.Errorf("abi.DecodeRecord on a %d-byte record: %v", len(raw), err)
				continue
			}
			ev, err := dec.Decode(raw)
			if err != nil {
				// A truncated path on some unrelated exec is not this test's
				// business; the decoder refusing it is documented behaviour.
				t.Logf("decoder refused a record: %v", err)
				continue
			}
			if ev.Exec != nil && ev.Exec.Filename == want {
				found = append(found, decoded{raw: rec, event: ev})
			}
		case <-deadline:
			return found
		}
	}
}

type decoded struct {
	raw   abi.Event
	event *event.Event
}

// collectForPID drains records for a bounded time and returns every event
// attributed to one process, in arrival order.
//
// collect above matches on the exec payload's filename, which is the only field
// that tells one machine's execs apart. An exit record has no payload at all —
// internal/telemetry/decode.go: "No union member is designated for an exit, so
// none is read" — so the PID is the only handle there is, and a PID is enough
// here because the process in question was forked by this test and reaped
// before the drain begins.
func collectForPID(t *testing.T, records <-chan []byte, pid int, d time.Duration) []decoded {
	t.Helper()

	dec := NewDecoder()
	deadline := time.After(d)
	var found []decoded

	for {
		select {
		case raw, ok := <-records:
			if !ok {
				return found
			}
			rec, err := abi.DecodeRecord(raw)
			if err != nil {
				t.Errorf("abi.DecodeRecord on a %d-byte record: %v", len(raw), err)
				continue
			}
			ev, err := dec.Decode(raw)
			if err != nil {
				// Some unrelated process on this host tripping a documented
				// refusal is not this test's business.
				t.Logf("decoder refused a record: %v", err)
				continue
			}
			if int(ev.Process.PID) == pid {
				found = append(found, decoded{raw: rec, event: ev})
			}
		case <-deadline:
			return found
		}
	}
}

// firstOfKind returns the first collected event exercising a capability.
func firstOfKind(evs []decoded, k capability.Kind) (decoded, bool) {
	for _, e := range evs {
		if e.event.Capability == k {
			return e, true
		}
	}
	return decoded{}, false
}

func TestRuntimeExecEventReachesUserspace(t *testing.T) {
	l, records := loadAndAttach(t)
	ctx := context.Background()

	cgroupID := currentCgroupID(t)
	key, value := trackedKV(cgroupID)
	if err := l.UpdateMap(ctx, MapTrackedCgroups, key, value); err != nil {
		t.Fatalf("UpdateMap: %v", err)
	}

	path, pid := execMarker(t, "allseer-exec-probe")
	found := collect(t, records, path, 3*time.Second)
	if len(found) == 0 {
		t.Fatalf("no exec event for %s reached user space", path)
	}
	got := found[0]

	t.Run("event type", func(t *testing.T) {
		if abi.EventType(got.raw.Type) != abi.EvtProcExec {
			t.Errorf("type = %s, want %s", abi.EventType(got.raw.Type), abi.EvtProcExec)
		}
		if got.event.Capability != capability.KindProcessExec {
			t.Errorf("capability = %s, want %s", got.event.Capability, capability.KindProcessExec)
		}
	})

	t.Run("ABI version", func(t *testing.T) {
		if got.raw.Version != abi.ABIVersion {
			t.Errorf("version = %d, want %d", got.raw.Version, abi.ABIVersion)
		}
	})

	t.Run("process identity", func(t *testing.T) {
		if int(got.event.Process.PID) != pid {
			t.Errorf("pid = %d, want %d", got.event.Process.PID, pid)
		}
		if int(got.event.Process.PPID) != os.Getpid() {
			t.Errorf("ppid = %d, want this process %d", got.event.Process.PPID, os.Getpid())
		}
		if int(got.event.Process.UID) != os.Geteuid() {
			t.Errorf("uid = %d, want %d", got.event.Process.UID, os.Geteuid())
		}
		if got.event.Process.StartTime == 0 {
			t.Error("start_time is zero; (pid, start_time) cannot disambiguate a recycled pid")
		}
		// comm is the new image's, truncated to ALLSEER_COMM_LEN-1.
		want := "allseer-exec-probe"
		if len(want) > abi.CommLen-1 {
			want = want[:abi.CommLen-1]
		}
		if got.event.Process.Comm != want {
			t.Errorf("comm = %q, want %q", got.event.Process.Comm, want)
		}
	})

	t.Run("executable filename", func(t *testing.T) {
		if got.event.Exec.Filename != path {
			t.Errorf("filename = %q, want %q", got.event.Exec.Filename, path)
		}
	})

	t.Run("cgroup id", func(t *testing.T) {
		if got.event.Process.CgroupID != cgroupID {
			t.Errorf("cgroup_id = %d, want %d", got.event.Process.CgroupID, cgroupID)
		}
	})

	t.Run("no drops were counted", func(t *testing.T) {
		// The third leg of the distinction TestRuntimeRingBufferDropsAreCounted
		// draws: a record that reached user space is not a loss, and the
		// counter must not have moved for it.
		n, err := l.ReadCounter(ctx, MapRingbufDrops)
		if err != nil {
			t.Fatalf("ReadCounter: %v", err)
		}
		if n != 0 {
			t.Errorf("%d drop(s) counted on a run whose records all arrived", n)
		}
	})

	t.Run("kernel timestamp", func(t *testing.T) {
		if got.event.KernelTimestamp == 0 {
			t.Error("kernel timestamp is zero")
		}
	})

	t.Run("result", func(t *testing.T) {
		// sched_process_exec fires only after a successful exec, so the probe
		// writes ret = 0 and the decoder must read that as success.
		if !got.event.Result.Succeeded || got.event.Result.ReturnCode != 0 {
			t.Errorf("result = %+v, want a zero success", got.event.Result)
		}
	})

	t.Run("detach closes the stream", func(t *testing.T) {
		if err := l.DetachAll(ctx); err != nil {
			t.Fatalf("DetachAll: %v", err)
		}
		select {
		case _, ok := <-records:
			for ok {
				_, ok = <-records
			}
		case <-time.After(2 * time.Second):
			t.Error("record channel did not close after DetachAll")
		}
		if err := l.DetachAll(ctx); err != nil {
			t.Errorf("second DetachAll = %v, want nil", err)
		}
	})
}

// The filter is the whole reason the map exists. With the probe attached and a
// cgroup that is *not* this one in the map, an exec here must produce nothing.
//
// A cgroup ID that is deliberately not ours, rather than an empty map: an empty
// map proves only that a lookup on nothing misses, which a probe that always
// returned would also satisfy.
func TestRuntimeUntrackedCgroupProducesNoEvent(t *testing.T) {
	l, records := loadAndAttach(t)
	ctx := context.Background()

	mine := currentCgroupID(t)
	other := mine ^ 0xDEADBEEF // certainly not a cgroup this process is in
	key, value := trackedKV(other)
	if err := l.UpdateMap(ctx, MapTrackedCgroups, key, value); err != nil {
		t.Fatalf("UpdateMap: %v", err)
	}

	path, _ := execMarker(t, "allseer-untracked-probe")
	if found := collect(t, records, path, 2*time.Second); len(found) != 0 {
		t.Fatalf("exec in an untracked cgroup produced %d event(s); the kernel filter did not hold", len(found))
	}

	// And the same exec is reported once the cgroup is added, which is what
	// makes the negative result above evidence of filtering rather than of a
	// probe that never fires.
	key, value = trackedKV(mine)
	if err := l.UpdateMap(ctx, MapTrackedCgroups, key, value); err != nil {
		t.Fatalf("UpdateMap: %v", err)
	}
	path, _ = execMarker(t, "allseer-tracked-probe")
	if found := collect(t, records, path, 3*time.Second); len(found) == 0 {
		t.Fatal("exec in a tracked cgroup produced no event, so the negative case above proves nothing")
	}
}

func TestUpdateMapRefusesWrongWidths(t *testing.T) {
	requireRoot(t)
	obj := objectOrSkip(t)

	ctx := context.Background()
	l := NewLoader(Config{ObjectPath: obj}, nil)
	defer l.Close()
	if err := l.Load(ctx, obj); err != nil {
		t.Fatalf("Load: %v", err)
	}

	for _, tc := range []struct {
		name       string
		key, value []byte
	}{
		{"short key", make([]byte, 4), []byte{1}},
		{"long key", make([]byte, 16), []byte{1}},
		{"short value", make([]byte, 8), nil},
		{"long value", make([]byte, 8), []byte{1, 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := l.UpdateMap(ctx, MapTrackedCgroups, tc.key, tc.value)
			if !errors.Is(err, ErrMapValueSize) {
				t.Fatalf("UpdateMap = %v, want ErrMapValueSize", err)
			}
		})
	}

	if err := l.UpdateMap(ctx, "no_such_map", make([]byte, 8), []byte{1}); err == nil {
		t.Error("UpdateMap on an unknown map succeeded")
	}
}

// Deleting an entry is how a session stops being watched, so the widths are
// checked the same way UpdateMap's are and for the same reason: a truncated
// cgroup ID names a different cgroup, and here that means un-tracking a session
// that is still running while leaving the one that ended tracked.
func TestDeleteMapRefusesWrongKeyWidthAndUnknownMaps(t *testing.T) {
	requireRoot(t)
	obj := objectOrSkip(t)

	ctx := context.Background()
	l := NewLoader(Config{ObjectPath: obj}, nil)
	defer l.Close()
	if err := l.Load(ctx, obj); err != nil {
		t.Fatalf("Load: %v", err)
	}

	for _, tc := range []struct {
		name string
		key  []byte
	}{
		{"empty key", nil},
		{"short key", make([]byte, 4)},
		{"long key", make([]byte, 16)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := l.DeleteMap(ctx, MapTrackedCgroups, tc.key); !errors.Is(err, ErrMapValueSize) {
				t.Fatalf("DeleteMap = %v, want ErrMapValueSize", err)
			}
		})
	}

	if err := l.DeleteMap(ctx, "no_such_map", make([]byte, 8)); err == nil {
		t.Error("DeleteMap on an unknown map succeeded")
	}

	// A key the map does not hold is its own finding, not a failure and not a
	// success. See ErrMapKeyNotFound.
	key, _ := trackedKV(0xA11CE)
	if err := l.DeleteMap(ctx, MapTrackedCgroups, key); !errors.Is(err, ErrMapKeyNotFound) {
		t.Errorf("DeleteMap on an absent key = %v, want ErrMapKeyNotFound", err)
	}
}

// ReadCounter refuses a map that is not the shape it reads, because the name is
// a string and nothing else can tell.
func TestReadCounterRefusesMapsThatAreNotCounters(t *testing.T) {
	requireRoot(t)
	obj := objectOrSkip(t)

	ctx := context.Background()
	l := NewLoader(Config{ObjectPath: obj}, nil)
	defer l.Close()
	if err := l.Load(ctx, obj); err != nil {
		t.Fatalf("Load: %v", err)
	}

	for _, name := range []string{MapTrackedCgroups, MapEvents} {
		if _, err := l.ReadCounter(ctx, name); !errors.Is(err, ErrNotACounter) {
			t.Errorf("ReadCounter(%q) = %v, want ErrNotACounter", name, err)
		}
	}
	if _, err := l.ReadCounter(ctx, "no_such_map"); err == nil {
		t.Error("ReadCounter on an unknown map succeeded")
	}
}

// The tracked-to-untracked transition, which is what DeleteMap exists for.
//
// Three legs, and all three are needed. An exec that is reported proves the
// probe fires at all; the same exec unreported after the delete proves the
// entry is gone from the kernel's view and not merely from Go's; and the second
// delete proves the loader can tell "already removed" from "removal failed",
// which is the distinction a collector detaching a session twice depends on.
func TestRuntimeDeleteMapUntracksACgroup(t *testing.T) {
	l, records := loadAndAttach(t)
	ctx := context.Background()

	cgroupID := currentCgroupID(t)
	key, value := trackedKV(cgroupID)
	if err := l.UpdateMap(ctx, MapTrackedCgroups, key, value); err != nil {
		t.Fatalf("UpdateMap: %v", err)
	}

	path, _ := execMarker(t, "allseer-delete-tracked")
	if found := collect(t, records, path, 3*time.Second); len(found) == 0 {
		t.Fatal("exec in a tracked cgroup produced no event, so the negative case below proves nothing")
	}

	if err := l.DeleteMap(ctx, MapTrackedCgroups, key); err != nil {
		t.Fatalf("DeleteMap: %v", err)
	}

	path, _ = execMarker(t, "allseer-delete-untracked")
	if found := collect(t, records, path, 2*time.Second); len(found) != 0 {
		t.Fatalf("exec after the cgroup was deleted produced %d event(s); the entry is still in the kernel", len(found))
	}

	if err := l.DeleteMap(ctx, MapTrackedCgroups, key); !errors.Is(err, ErrMapKeyNotFound) {
		t.Errorf("second DeleteMap = %v, want ErrMapKeyNotFound", err)
	}
}

// execBurst runs /bin/true n times, which is n execs in this process's cgroup.
//
// The marker trick execMarker uses is deliberately not used here: this needs
// volume rather than identifiable records, and nothing is draining the ring for
// them to be identified in.
func execBurst(t *testing.T, n int) {
	t.Helper()
	for range n {
		if err := exec.Command("/bin/true").Run(); err != nil {
			t.Fatalf("running /bin/true: %v", err)
		}
	}
}

// Ring buffer loss is counted in the kernel, and the three things that look
// alike from user space are told apart.
//
// The loader is brought up with the smallest ring buffer the kernel will create
// and, deliberately, no reader: RingBuffer is never called, so nothing drains
// what the probe submits. One page holds four 856-byte records and then the
// ring is full for good, which is the only way to produce a reservation failure
// on demand — a full ring on a healthy host is a race nobody can lose reliably.
//
// The three legs are the distinction allseer_maps.h draws:
//
//   - filtered. Execs with an empty filter map. The probe returns before it
//     reserves anything, so nothing is lost and the counter must stay at zero.
//     A counter that moved here would be counting the design working.
//   - emitted. Covered by TestRuntimeExecEventReachesUserspace, which asserts
//     the counter is still zero after a record has gone all the way through.
//   - lost. Execs in a tracked cgroup with the ring already full.
func TestRuntimeRingBufferDropsAreCounted(t *testing.T) {
	requireRoot(t)
	obj := objectOrSkip(t)
	ctx := context.Background()

	l := NewLoader(Config{ObjectPath: obj, RingBufferSize: os.Getpagesize()}, nil)
	t.Cleanup(func() {
		if err := l.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	if err := l.Load(ctx, obj); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := l.Attach(ctx, ProgProcExec); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	// A freshly loaded object has lost nothing.
	if n, err := l.ReadCounter(ctx, MapRingbufDrops); err != nil {
		t.Fatalf("ReadCounter: %v", err)
	} else if n != 0 {
		t.Fatalf("a freshly loaded object reports %d drops, want 0", n)
	}

	// Filtered: nothing is tracked, so nothing is reserved and nothing is lost.
	execBurst(t, 64)
	if n, err := l.ReadCounter(ctx, MapRingbufDrops); err != nil {
		t.Fatalf("ReadCounter: %v", err)
	} else if n != 0 {
		t.Fatalf("%d exec(s) the cgroup filter rejected were counted as %d drop(s); "+
			"a filtered event is not a lost one", 64, n)
	}

	// Lost: tracked, with a one-page ring nobody is draining.
	key, value := trackedKV(currentCgroupID(t))
	if err := l.UpdateMap(ctx, MapTrackedCgroups, key, value); err != nil {
		t.Fatalf("UpdateMap: %v", err)
	}

	const burst = 256
	execBurst(t, burst)

	dropped, err := l.ReadCounter(ctx, MapRingbufDrops)
	if err != nil {
		t.Fatalf("ReadCounter: %v", err)
	}
	if dropped == 0 {
		t.Fatalf("%d execs into a %d-byte ring buffer nobody is draining produced 0 counted drops; "+
			"the loss is happening and is not being recorded", burst, os.Getpagesize())
	}
	// The ring holds four records, so all but a handful of the burst had
	// nowhere to go. An exact number would be asserting that nothing else on
	// this host execs in this cgroup, which is not true of a machine running
	// tests.
	if dropped > burst*2 {
		t.Errorf("counted %d drops from a burst of %d; the counter is not counting records", dropped, burst)
	}
	t.Logf("burst of %d execs into a %d-byte ring: %d records counted as lost",
		burst, os.Getpagesize(), dropped)

	// Monotonic and never reset by a read: a second read cannot report less.
	again, err := l.ReadCounter(ctx, MapRingbufDrops)
	if err != nil {
		t.Fatalf("ReadCounter: %v", err)
	}
	if again < dropped {
		t.Errorf("a second read reports %d after %d; reading the counter must not reset it", again, dropped)
	}
}

// --- the exit probe ----------------------------------------------------------

// An exit reaches user space, decodes as process.exit, and names the process
// that ended.
//
// The identity assertions are the point rather than the arrival. An exit record
// carries no payload, so everything it is worth is in struct allseer_proc: if
// the PID were the reporting thread's rather than the group leader's, or the
// start time were read after the task had been torn down, the record would
// still arrive and still decode and would attribute the death of one process to
// another.
func TestRuntimeExitEventReachesUserspace(t *testing.T) {
	l, records := loadAndAttach(t)
	ctx := context.Background()

	cgroupID := currentCgroupID(t)
	key, value := trackedKV(cgroupID)
	if err := l.UpdateMap(ctx, MapTrackedCgroups, key, value); err != nil {
		t.Fatalf("UpdateMap: %v", err)
	}

	_, pid := execMarker(t, "allseer-exit-probe")
	evs := collectForPID(t, records, pid, 3*time.Second)

	got, ok := firstOfKind(evs, capability.KindProcessExit)
	if !ok {
		t.Fatalf("no process.exit event for pid %d reached user space; collected %d event(s) for it", pid, len(evs))
	}

	t.Run("event type", func(t *testing.T) {
		if abi.EventType(got.raw.Type) != abi.EvtProcExit {
			t.Errorf("type = %s, want %s", abi.EventType(got.raw.Type), abi.EvtProcExit)
		}
		if got.event.Domain != capability.DomainProcess {
			t.Errorf("domain = %s, want %s", got.event.Domain, capability.DomainProcess)
		}
	})

	t.Run("ABI version", func(t *testing.T) {
		if got.raw.Version != abi.ABIVersion {
			t.Errorf("version = %d, want %d", got.raw.Version, abi.ABIVersion)
		}
	})

	t.Run("process identity", func(t *testing.T) {
		if int(got.event.Process.PID) != pid {
			t.Errorf("pid = %d, want %d", got.event.Process.PID, pid)
		}
		// The probe emits only on the thread group leader, so these must agree.
		// A record where they differ is a per-thread exit that got through.
		if got.event.Process.TID != got.event.Process.PID {
			t.Errorf("tid = %d and pid = %d differ, so this record is a thread's exit, not a process's",
				got.event.Process.TID, got.event.Process.PID)
		}
		if int(got.event.Process.PPID) != os.Getpid() {
			t.Errorf("ppid = %d, want this process %d", got.event.Process.PPID, os.Getpid())
		}
		if got.event.Process.StartTime == 0 {
			t.Error("start_time is zero; (pid, start_time) cannot disambiguate a recycled pid")
		}
		if got.event.Process.CgroupID != cgroupID {
			t.Errorf("cgroup_id = %d, want %d", got.event.Process.CgroupID, cgroupID)
		}
	})

	t.Run("no payload is claimed", func(t *testing.T) {
		// decode.go designates no union member for an exit. An event carrying
		// one would mean the decoder read the union for a type that declares
		// nothing in it.
		if got.event.Exec != nil || got.event.File != nil ||
			got.event.Network != nil || got.event.Privil != nil {
			t.Error("an exit event carries a payload; no union member is designated for one")
		}
	})

	t.Run("result", func(t *testing.T) {
		// ret is written 0 for this issue. See the TODO at the foot of
		// bpf/allseer.bpf.c: the exit status needs a field of its own, and
		// `ret` is defined as a syscall return.
		if !got.event.Result.Succeeded || got.event.Result.ReturnCode != 0 {
			t.Errorf("result = %+v, want a zero success", got.event.Result)
		}
	})
}

// exec and exit for one process agree on (PID, StartTime), and arrive in that
// order.
//
// This is the property the exit probe exists to make observable and the one
// nothing could assert before it. event.Process.StartTime is documented as
// making "(PID, StartTime) unique for a boot", and telemetry.ProcessTracker is
// keyed on exactly that pair — Track on one event, Untrack on the other. If the
// two probes disagreed about either half, a tracker would register a process
// under one key and try to retire it under another, and the PID would never be
// released. Ordering matters for the same reason: an Untrack that arrived first
// would retire a key before it was ever created.
func TestRuntimeExecAndExitAgreeOnProcessIdentity(t *testing.T) {
	l, records := loadAndAttach(t)
	ctx := context.Background()

	key, value := trackedKV(currentCgroupID(t))
	if err := l.UpdateMap(ctx, MapTrackedCgroups, key, value); err != nil {
		t.Fatalf("UpdateMap: %v", err)
	}

	path, pid := execMarker(t, "allseer-exec-exit-pair")
	evs := collectForPID(t, records, pid, 3*time.Second)

	execEv, ok := firstOfKind(evs, capability.KindProcessExec)
	if !ok {
		t.Fatalf("no process.exec event for pid %d; collected %d event(s)", pid, len(evs))
	}
	exitEv, ok := firstOfKind(evs, capability.KindProcessExit)
	if !ok {
		t.Fatalf("no process.exit event for pid %d; collected %d event(s)", pid, len(evs))
	}

	// The exec record is the one that names the binary, which is what confirms
	// both records belong to the process this test started rather than to a PID
	// that happened to match.
	if execEv.event.Exec == nil || execEv.event.Exec.Filename != path {
		t.Fatalf("the exec event for pid %d is not this test's marker: %+v", pid, execEv.event.Exec)
	}

	if execEv.event.Process.PID != exitEv.event.Process.PID {
		t.Errorf("pid: exec says %d, exit says %d", execEv.event.Process.PID, exitEv.event.Process.PID)
	}
	if execEv.event.Process.StartTime != exitEv.event.Process.StartTime {
		t.Errorf("start_time: exec says %d, exit says %d — exec does not replace the task_struct, "+
			"so these must be the same value and a tracker keyed on the pair cannot work if they are not",
			execEv.event.Process.StartTime, exitEv.event.Process.StartTime)
	}
	if execEv.event.KernelTimestamp >= exitEv.event.KernelTimestamp {
		t.Errorf("exec timestamp %d is not before exit timestamp %d",
			execEv.event.KernelTimestamp, exitEv.event.KernelTimestamp)
	}
}

// The per-probe filter obligation, proven for the exit probe rather than
// inherited from the exec one.
//
// internal/telemetry states the standing requirement: "the filter is per-probe
// rather than a property of the object, so every tracepoint added after this
// one has to perform the same lookup or it silently reports on cgroups nobody
// declared." A probe that skipped the lookup would pass every other test in
// this file.
//
// It also proves something about the kernel that no amount of reading the C can
// settle: that bpf_get_current_cgroup_id() still answers with the process's
// cgroup when the tracepoint fires from do_exit. If the task were already
// dissociated, every exit would miss the filter and the positive leg below
// would find nothing.
func TestRuntimeUntrackedCgroupProducesNoExitEvent(t *testing.T) {
	l, records := loadAndAttach(t)
	ctx := context.Background()

	mine := currentCgroupID(t)
	other := mine ^ 0xDEADBEEF // certainly not a cgroup this process is in
	key, value := trackedKV(other)
	if err := l.UpdateMap(ctx, MapTrackedCgroups, key, value); err != nil {
		t.Fatalf("UpdateMap: %v", err)
	}

	_, pid := execMarker(t, "allseer-exit-untracked")
	if evs := collectForPID(t, records, pid, 2*time.Second); len(evs) != 0 {
		t.Fatalf("a process in an untracked cgroup produced %d event(s); the kernel filter did not hold", len(evs))
	}

	// And the same thing is reported once the cgroup is tracked, which is what
	// makes the negative result above evidence of filtering rather than of a
	// probe that never fires.
	key, value = trackedKV(mine)
	if err := l.UpdateMap(ctx, MapTrackedCgroups, key, value); err != nil {
		t.Fatalf("UpdateMap: %v", err)
	}
	_, pid = execMarker(t, "allseer-exit-tracked")
	evs := collectForPID(t, records, pid, 3*time.Second)
	if _, ok := firstOfKind(evs, capability.KindProcessExit); !ok {
		t.Fatal("a process in a tracked cgroup produced no exit event, so the negative case above proves nothing")
	}
}

// The exit probe carries the drop-counting obligation too.
//
// Only proc_exit is attached, so every counted drop is a record that probe
// wanted to emit. Attaching both would prove that the object counts drops,
// which TestRuntimeRingBufferDropsAreCounted already proves, and would leave
// open whether the new probe contributes at all — a probe that omitted
// count_ringbuf_drop() would be invisible behind the exec probe's counting.
func TestRuntimeExitProbeCountsItsOwnDrops(t *testing.T) {
	requireRoot(t)
	obj := objectOrSkip(t)
	ctx := context.Background()

	l := NewLoader(Config{ObjectPath: obj, RingBufferSize: os.Getpagesize()}, nil)
	t.Cleanup(func() {
		if err := l.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	if err := l.Load(ctx, obj); err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Deliberately only the exit probe, and deliberately no RingBuffer call:
	// nothing drains the one-page ring, so it fills after four records and
	// every exit after that is lost.
	if err := l.Attach(ctx, ProgProcExit); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	if n, err := l.ReadCounter(ctx, MapRingbufDrops); err != nil {
		t.Fatalf("ReadCounter: %v", err)
	} else if n != 0 {
		t.Fatalf("a freshly loaded object reports %d drops, want 0", n)
	}

	// Filtered: nothing tracked, so nothing is reserved and nothing is lost.
	execBurst(t, 64)
	if n, err := l.ReadCounter(ctx, MapRingbufDrops); err != nil {
		t.Fatalf("ReadCounter: %v", err)
	} else if n != 0 {
		t.Fatalf("64 exits the cgroup filter rejected were counted as %d drop(s); "+
			"a filtered event is not a lost one", n)
	}

	key, value := trackedKV(currentCgroupID(t))
	if err := l.UpdateMap(ctx, MapTrackedCgroups, key, value); err != nil {
		t.Fatalf("UpdateMap: %v", err)
	}

	const burst = 256
	execBurst(t, burst)

	dropped, err := l.ReadCounter(ctx, MapRingbufDrops)
	if err != nil {
		t.Fatalf("ReadCounter: %v", err)
	}
	if dropped == 0 {
		t.Fatalf("%d exits into a %d-byte ring buffer nobody is draining produced 0 counted drops; "+
			"proc_exit is losing records without calling count_ringbuf_drop()", burst, os.Getpagesize())
	}
	if dropped > burst*2 {
		t.Errorf("counted %d drops from a burst of %d; the counter is not counting records", dropped, burst)
	}
	t.Logf("burst of %d exits into a %d-byte ring, exit probe only: %d records counted as lost",
		burst, os.Getpagesize(), dropped)
}

// Both programs attach at once, and DetachAll takes both down.
//
// The first time the loader has held more than one link. Attach is per name, so
// ErrAlreadyAttached must still be per name and not per object; DetachAll is
// documented to detach "every attached program", and a shutdown that dropped
// one link and left the other would leave a probe writing into a ring buffer
// whose reader has gone.
func TestRuntimeBothProbesAttachAndDetachTogether(t *testing.T) {
	requireRoot(t)
	obj := objectOrSkip(t)
	ctx := context.Background()

	l := NewLoader(Config{ObjectPath: obj, RingBufferSize: 1 << 22}, nil)
	t.Cleanup(func() {
		if err := l.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	if err := l.Load(ctx, obj); err != nil {
		t.Fatalf("Load: %v", err)
	}
	records, err := l.RingBuffer(ctx, MapEvents)
	if err != nil {
		t.Fatalf("RingBuffer: %v", err)
	}

	for _, prog := range []string{ProgProcExec, ProgProcExit} {
		if err := l.Attach(ctx, prog); err != nil {
			t.Fatalf("Attach %s: %v", prog, err)
		}
	}
	// Per name, not per object: attaching one twice is still refused while the
	// other stays attached.
	for _, prog := range []string{ProgProcExec, ProgProcExit} {
		if err := l.Attach(ctx, prog); !errors.Is(err, ErrAlreadyAttached) {
			t.Errorf("second Attach %s = %v, want ErrAlreadyAttached", prog, err)
		}
	}

	// Both are really running: one process yields one event from each.
	key, value := trackedKV(currentCgroupID(t))
	if err := l.UpdateMap(ctx, MapTrackedCgroups, key, value); err != nil {
		t.Fatalf("UpdateMap: %v", err)
	}
	_, pid := execMarker(t, "allseer-both-probes")
	evs := collectForPID(t, records, pid, 3*time.Second)
	if _, ok := firstOfKind(evs, capability.KindProcessExec); !ok {
		t.Error("no exec event with both probes attached")
	}
	if _, ok := firstOfKind(evs, capability.KindProcessExit); !ok {
		t.Error("no exit event with both probes attached")
	}

	if err := l.DetachAll(ctx); err != nil {
		t.Fatalf("DetachAll: %v", err)
	}
	select {
	case _, ok := <-records:
		for ok {
			_, ok = <-records
		}
	case <-time.After(2 * time.Second):
		t.Error("record channel did not close after DetachAll")
	}

	// Both links are gone, so both names are attachable again. A DetachAll that
	// had dropped only one would refuse the one it kept.
	for _, prog := range []string{ProgProcExec, ProgProcExit} {
		if err := l.Attach(ctx, prog); err != nil {
			t.Errorf("Attach %s after DetachAll = %v; the link was not released", prog, err)
		}
	}
}

func TestAttachRefusesTwiceAndUnknownPrograms(t *testing.T) {
	requireRoot(t)
	obj := objectOrSkip(t)

	ctx := context.Background()
	l := NewLoader(Config{ObjectPath: obj}, nil)
	defer l.Close()
	if err := l.Load(ctx, obj); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := l.Load(ctx, obj); !errors.Is(err, ErrAlreadyLoaded) {
		t.Errorf("second Load = %v, want ErrAlreadyLoaded", err)
	}
	if err := l.Attach(ctx, ProgProcExec); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if err := l.Attach(ctx, ProgProcExec); !errors.Is(err, ErrAlreadyAttached) {
		t.Errorf("second Attach = %v, want ErrAlreadyAttached", err)
	}
	if err := l.Attach(ctx, "no_such_program"); err == nil {
		t.Error("Attach on an unknown program succeeded")
	}

	if _, err := l.RingBuffer(ctx, MapEvents); err != nil {
		t.Fatalf("RingBuffer: %v", err)
	}
	if _, err := l.RingBuffer(ctx, MapEvents); !errors.Is(err, ErrRingBufferExists) {
		t.Errorf("second RingBuffer = %v, want ErrRingBufferExists", err)
	}
}
