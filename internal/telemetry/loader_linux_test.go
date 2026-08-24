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

// loadAndAttach brings a loader up to the point where events would flow, and
// registers teardown. Shared by the runtime tests below.
func loadAndAttach(t *testing.T) (*BPFLoader, <-chan []byte) {
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
	if err := l.Attach(ctx, ProgProcExec); err != nil {
		t.Fatalf("Attach: %v", err)
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
