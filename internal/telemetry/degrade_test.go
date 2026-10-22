package telemetry

import (
	"errors"
	"fmt"
	"math/bits"
	"math/rand/v2"
	"slices"
	"sort"
	"strings"
	"syscall"
	"testing"
)

// fakeKernel refuses any load that includes a refused family, and every
// load when the floor is broken. Load number failAt fails with failErr
// instead, as memory pressure or a signal would.
type fakeKernel struct {
	refused     map[string]bool
	floorBroken bool
	failAt      int
	failErr     error
	loads       int
	last        map[string]bool // the families left out of the last load that succeeded
}

func (k *fakeKernel) load(out map[string]bool) error {
	k.loads++
	if k.loads == k.failAt {
		return k.failErr
	}
	if k.floorBroken {
		return fmt.Errorf("refused the floor: %w", syscall.EACCES)
	}
	var in []string
	for f := range k.refused {
		if !out[f] {
			in = append(in, f)
		}
	}
	if len(in) > 0 {
		sort.Strings(in)
		return fmt.Errorf("refused %s: %w", strings.Join(in, " "), syscall.EACCES)
	}
	k.last = out
	return nil
}

func families(n int) []string {
	var out []string
	for i := range n {
		out = append(out, fmt.Sprintf("f%02d", i))
	}
	return out
}

func keys(m map[string]error) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestDegradeFamiliesLeavesOutExactlyTheRefused(t *testing.T) {
	all := families(18)
	for _, refused := range [][]string{
		{"f07"}, {"f00"}, {"f17"}, {"f00", "f17"}, {"f03", "f04", "f11"}, all,
	} {
		k := &fakeKernel{refused: map[string]bool{}}
		for _, f := range refused {
			k.refused[f] = true
		}
		first := k.load(nil)
		why, err := degradeFamilies(all, first, k.load)
		if err != nil {
			t.Fatalf("%v: %v", refused, err)
		}
		if got := keys(why); !slices.Equal(got, refused) {
			t.Errorf("left out %v, want %v", got, refused)
		}
		for _, f := range refused {
			if e := why[f]; e == nil || e.Error() != "refused "+f+": permission denied" {
				t.Errorf("%s left out for %v, want the load that isolated it", f, e)
			}
		}
		// The last load is the one the caller keeps: everything but these.
		if len(k.last) != len(refused) {
			t.Errorf("%v: the kept load left out %v", refused, k.last)
		}
	}
}

// About log2(n) loads per refused family, not n.
func TestDegradeFamiliesBisects(t *testing.T) {
	k := &fakeKernel{refused: map[string]bool{"f09": true}}
	if _, err := degradeFamilies(families(18), syscall.EACCES, k.load); err != nil {
		t.Fatal(err)
	}
	if k.loads > 6 {
		t.Errorf("%d loads to find one refused family of 18, want at most 6", k.loads)
	}
}

// Nothing loads without every family: the floor or a map is refused, and the
// first error is the reason, not a later one.
func TestDegradeFamiliesRefusesWhenTheFloorFails(t *testing.T) {
	first := fmt.Errorf("the whole object was refused: %w", syscall.EINVAL)
	for _, n := range []int{0, 1, 18} {
		k := &fakeKernel{floorBroken: true}
		why, err := degradeFamilies(families(n), first, k.load)
		if !errors.Is(err, first) || why != nil {
			t.Errorf("%d families: %v, %v; want the first error", n, why, err)
		}
		// One bisection shows it, not one per family.
		if want := bits.Len(uint(n)); k.loads > want {
			t.Errorf("%d families: %d loads to find the floor refused, want at most %d", n, k.loads, want)
		}
	}
}

func TestDegradeFamiliesOnRandomRefusals(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	all := families(18)
	for range 500 {
		k := &fakeKernel{refused: map[string]bool{}}
		var want []string
		for _, f := range all {
			if r.IntN(5) == 0 {
				k.refused[f] = true
				want = append(want, f)
			}
		}
		if len(want) == 0 {
			continue
		}
		why, err := degradeFamilies(all, syscall.EACCES, k.load)
		if err != nil || !slices.Equal(keys(why), want) {
			t.Fatalf("refused %v: left out %v, %v", want, keys(why), err)
		}
	}
}

// A load that fails for a reason other than a refusal says nothing about
// which family is at fault. Nothing is left out and the start fails with it,
// whether it is the first load or one during the search.
func TestDegradeFamiliesFailsOnErrorsThatAreNotRefusals(t *testing.T) {
	transient := []error{
		fmt.Errorf("failed to load BPF object: %w", syscall.ENOMEM),
		fmt.Errorf("failed to load BPF object: %w", syscall.EAGAIN),
		fmt.Errorf("failed to load BPF object: %w", syscall.EINTR),
		errors.New("telemetry: reopening BPF object: no such file or directory"),
	}
	for _, e := range transient {
		k := &fakeKernel{refused: map[string]bool{"f07": true}}
		if why, err := degradeFamilies(families(18), e, k.load); err != e || why != nil || k.loads != 0 {
			t.Errorf("first load failed with %q: left out %v, %v after %d loads; want that error and no loads",
				e, keys(why), err, k.loads)
		}
		// Every load of the search, including the one that confirms it.
		for at := 1; ; at++ {
			k := &fakeKernel{refused: map[string]bool{"f07": true}, failAt: at, failErr: e}
			why, err := degradeFamilies(families(18), syscall.EACCES, k.load)
			if k.loads < at {
				break
			}
			if err != e || why != nil {
				t.Errorf("load %d failed with %q: left out %v, %v; want that error and nothing left out",
					at, e, keys(why), err)
			}
		}
	}
}

func TestOnlyKernelRefusalsDegrade(t *testing.T) {
	for _, c := range []struct {
		err  error
		want bool
	}{
		{fmt.Errorf("failed to load BPF object: %w", syscall.EACCES), true},
		{fmt.Errorf("failed to load BPF object: %w", syscall.EINVAL), true},
		{fmt.Errorf("failed to load BPF object: %w", syscall.ESRCH), true},
		{fmt.Errorf("failed to load BPF object: %w", syscall.E2BIG), true},
		{fmt.Errorf("failed to load BPF object: %w", syscall.Errno(524)), true},
		{fmt.Errorf("failed to load BPF object: %w", syscall.ENOMEM), false},
		{fmt.Errorf("failed to load BPF object: %w", syscall.EAGAIN), false},
		{fmt.Errorf("failed to load BPF object: %w", syscall.EINTR), false},
		{fmt.Errorf("failed to load BPF object: %w", syscall.EBUSY), false},
		{errors.New("refused"), false},
		{nil, false},
	} {
		if got := refusal(c.err); got != c.want {
			t.Errorf("refusal(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}
