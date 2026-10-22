//go:build linux && ebpf

package telemetry

// Runtime tests for leaving out the families a kernel refuses.

import (
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// refusedObject copies obj with each named program's first instruction made
// an exit, which the kernel refuses: R0 is read before it is set.
func refusedObject(t *testing.T, obj string, progs ...string) string {
	t.Helper()
	b, err := os.ReadFile(obj)
	if err != nil {
		t.Fatal(err)
	}
	f, err := elf.NewFile(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range progs {
		var d ProbeDescriptor
		for _, p := range AllProbes() {
			if p.Name == name {
				d = p
			}
		}
		if d.Name == "" {
			t.Fatalf("no program %s", name)
		}
		sec := f.Section(d.Type + "/" + d.AttachPoint)
		if sec == nil {
			t.Fatalf("no section for %s", name)
		}
		// Were the instruction relocated, libbpf would refuse the patched
		// program instead of the verifier, which is the same outcome.
		copy(b[sec.Offset:], []byte{0x95, 0, 0, 0, 0, 0, 0, 0})
	}
	out := filepath.Join(t.TempDir(), "refused.bpf.o")
	if err := os.WriteFile(out, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return out
}

// A kernel that refuses a pair and a hook governs with the rest, and the
// report names both families and why.
func TestRuntimeARefusedFamilyIsLeftOut(t *testing.T) {
	requireRoot(t)
	obj := refusedObject(t, objectOrSkip(t), ProgConnectExit, ProgFileOpen)
	ctx := context.Background()
	l := NewLoader(Config{ObjectPath: obj, RingBufferSize: 1 << 22}, nil)
	t.Cleanup(func() { _ = l.Close() })
	if err := l.Load(ctx, obj); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// The whole pair goes, though only its exit was refused.
	gone := map[string]bool{ProgConnectEnter: true, ProgConnectExit: true, ProgFileOpen: true}
	for _, p := range l.Probes() {
		switch {
		case gone[p.Name]:
			if p.Loaded || !strings.Contains(p.Error, "refused the "+p.Family+" family") {
				t.Errorf("%s = %+v, want left out with its family named", p.Name, p)
			}
			if err := l.Attach(ctx, p.Name); err == nil {
				t.Errorf("%s attached though it was left out", p.Name)
			}
		case !p.Loaded:
			t.Errorf("%s was left out though its family loads: %s", p.Name, p.Error)
		default:
			if err := l.Attach(ctx, p.Name); err != nil {
				t.Errorf("Attach %s: %v", p.Name, err)
			}
		}
	}
	cov := l.Coverage()
	report := cov.BugReport()
	if !cov.Degraded || !cov.FloorIntact {
		t.Errorf("degraded %v floor %v, want degraded with the floor intact:\n%s", cov.Degraded, cov.FloorIntact, report)
	}
	for _, f := range []string{FamilyConnect, FamilyFileOpen} {
		if !strings.Contains(report, "refused the "+f+" family") {
			t.Errorf("the report does not say why %s is missing:\n%s", f, report)
		}
	}
}

// The floor is not a family to leave out: without it nothing is attributed.
func TestRuntimeARefusedFloorFailsTheLoad(t *testing.T) {
	requireRoot(t)
	obj := refusedObject(t, objectOrSkip(t), ProgProcExec)
	ctx := context.Background()
	l := NewLoader(Config{ObjectPath: obj, RingBufferSize: 1 << 22}, nil)
	t.Cleanup(func() { _ = l.Close() })
	if err := l.Load(ctx, obj); err == nil {
		t.Fatal("an object whose proc_exec the kernel refuses loaded")
	}
	if err := l.Attach(ctx, ProgProcExit); err == nil {
		t.Error("a program attached after the load failed")
	}
}

// Refusing both families behind net.connect is not a gap to govern with: the
// collector refuses to start, and says which kind went dark.
func TestRuntimeARefusedCoreKindFailsTheStart(t *testing.T) {
	requireRoot(t)
	obj := refusedObject(t, objectOrSkip(t), ProgConnectExit, ProgSocketConnect)
	c, err := NewBPFCollector(Config{ObjectPath: obj, RingBufferSize: 1 << 22})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	err = c.Start(context.Background())
	if !errors.Is(err, ErrCoreUnobservable) || !strings.Contains(err.Error(), "[net.connect]") {
		t.Fatalf("Start = %v, want ErrCoreUnobservable naming net.connect", err)
	}
	if !strings.Contains(err.Error(), "refused the "+FamilyConnect+" family") ||
		!strings.Contains(err.Error(), "refused the "+FamilySocketConnect+" family") {
		t.Errorf("the refusal does not say why both families are missing:\n%v", err)
	}
}
