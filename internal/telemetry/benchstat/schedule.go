package benchstat

// The two parts of the probe-overhead harness that decide what runs, in what
// order, and whether a run is admissible at all.
//
// They live here, beside the statistics, for the reason the package doc gives
// about the statistics themselves: they are the parts most likely to be wrong
// in a way nobody notices, and here they are unit-testable on any machine with
// no root, no kernel, no libbpf and no hours of measurement. Both of them
// replace an implementation that failed silently — one produced the same
// "shuffle" for every replicate, the other treated a cache it could not read as
// a cache it had read and found empty — and a silent failure in either one
// produces a session that looks exactly like a good session and means nothing.

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// --- the arm ordering ---------------------------------------------------------

// ArmOrder returns the order in which arms run in one replicate of a session.
//
// Every replicate of a session gets a different permutation, every permutation
// holds every arm exactly once, and the whole schedule is reproducible from the
// session seed alone. That combination is what keeps the treatment from being
// confounded with position: a build measured first in its replicate pays for a
// page cache and a thermal state that the fifth build does not, and on the host
// this was designed against that difference is larger than the effect being
// measured.
//
// # Why this is not a shell one-liner
//
// It was one, and it did not shuffle. The orchestrator used
//
//	printf '%s\n' "${ARMS[@]}" | shuf --random-source=<(yes "$SEED-$rep")
//
// on the reasonable-looking theory that a different replicate makes a different
// seed string and therefore a different permutation. GNU shuf draws a
// permutation of five items from a *single byte* at the head of its random
// source — measurably: changing byte 1 of the source changes the permutation
// and changing any of bytes 2 through 40 does not. `yes "$SEED-$rep"` puts the
// only part that varies with the replicate after a constant multi-character
// prefix, so every replicate of a session was handed the same first byte and
// returned the same permutation. Five replicates of the recorded session ran
// A4, A2, A0, A3, A1, in that order, every time.
//
// No string arrangement fixes that. Even `yes "$rep-$SEED"` would have had a
// one-byte seeding surface and would have collided for every pair of
// replicates sharing a leading digit. The mechanism has to change, which means
// the permutation has to be drawn by something that consumes a full 64 bits of
// state per draw — and once that is true, it may as well be somewhere it can
// be tested.
//
// The returned slice is freshly allocated; arms is never modified.
func ArmOrder(seed int64, replicate int, arms []string) ([]string, error) {
	if len(arms) == 0 {
		return nil, errors.New("benchstat: no arms to order")
	}
	if replicate < 1 {
		return nil, fmt.Errorf("benchstat: replicate %d is not a replicate number (they start at 1)", replicate)
	}

	known := map[string]bool{}
	for _, a := range KnownArms() {
		known[a] = true
	}
	seen := map[string]bool{}
	for _, a := range arms {
		if !known[a] {
			return nil, fmt.Errorf("benchstat: %q is not one of %v", a, KnownArms())
		}
		if seen[a] {
			// Rejected rather than deduplicated. An arm named twice would run
			// twice in one replicate and overwrite its own pairing key, so the
			// analysis would silently compare one of the two runs and discard
			// the other with no record that it had.
			return nil, fmt.Errorf("benchstat: arm %q is listed more than once", a)
		}
		seen[a] = true
	}

	out := make([]string, len(arms))
	copy(out, arms)

	// Fisher-Yates, written out rather than delegated to rand.Shuffle, because
	// a session has to stay reproducible from its recorded seed for longer than
	// any promise the standard library makes about which algorithm Shuffle uses
	// to consume its generator. Pinning both the generator and the shuffle here
	// makes reproducibility a property of this file.
	r := newArmRNG(seed, replicate)
	for i := len(out) - 1; i > 0; i-- {
		j := r.below(uint64(i + 1))
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// armRNG is splitmix64: a 64-bit state, a fixed odd increment, and a finalizer
// with full avalanche.
//
// Chosen because it is four lines, has no dependencies, is completely specified
// by those four lines, and — the property the previous implementation lacked —
// two states differing by one produce unrelated output.
type armRNG struct{ state uint64 }

// newArmRNG derives a replicate's generator from the session seed.
//
// The replicate is folded into the state through the mixing function rather
// than concatenated onto the seed as text. That is the whole correction: the
// shell's version varied a byte the consumer never read, and this one varies
// all 64 bits of the state that every draw depends on.
func newArmRNG(seed int64, replicate int) *armRNG {
	st := mix64(uint64(seed)) ^ mix64(uint64(replicate)+goldenGamma)
	return &armRNG{state: mix64(st)}
}

const goldenGamma = 0x9E3779B97F4A7C15

func (r *armRNG) next() uint64 {
	r.state += goldenGamma
	return mix64(r.state)
}

// below returns a uniform value in [0, n) with no modulo bias.
//
// The bias a bare `next() % n` introduces is small for five arms and is still
// not worth carrying: it would make some permutations systematically more
// likely than others, which is the same class of defect as the one this file
// exists to fix, just quieter.
func (r *armRNG) below(n uint64) uint64 {
	if n == 0 {
		return 0
	}
	// threshold is 2^64 mod n, computed in 64-bit arithmetic. Draws below it
	// come from the short final block of the range and are rejected.
	threshold := -n % n
	for {
		if v := r.next(); v >= threshold {
			return v % n
		}
	}
}

// mix64 is the splitmix64 finalizer.
func mix64(x uint64) uint64 {
	x ^= x >> 30
	x *= 0xBF58476D1CE4E5B9
	x ^= x >> 27
	x *= 0x94D049BB133111EB
	x ^= x >> 31
	return x
}

// --- the cold-cache guard -------------------------------------------------------

// ErrCacheNotCold is returned when a run's GOCACHE cannot be shown to be an
// existing, readable, empty directory.
//
// One error for every way the check can fail, because the runner's response to
// all of them is the same: refuse the run. The wrapped cause carries which one
// it was, for whoever has to fix it.
var ErrCacheNotCold = errors.New("benchstat: the GOCACHE for this run could not be verified empty")

// VerifyColdCache reports whether dir is an existing, readable, empty
// directory, and refuses everything else.
//
// # Why this fails closed
//
// The primary workload is `go build ./...` against a cache that was empty when
// the run started, and the wall clock it produces is meaningless if it was not.
// The previous check was
//
//	if entries, err := os.ReadDir(cfg.goCache); err == nil && len(entries) > 0 {
//
// which recorded a non-empty cache as a note on the record and built anyway,
// and — the worse half — took any error from ReadDir as permission to proceed.
// A missing directory, an unreadable one, a path that turned out to be a file:
// each of them skipped the body and left the run looking exactly like a
// verified cold one.
//
// That is the failure mode this whole harness is built to avoid, because it is
// invisible downstream. A warm run emits the same schema, the same fields and
// the same event counts as a cold one; only its wall clock is an order of
// magnitude too low, and a low wall clock on a treatment arm reads as low
// overhead. Refusing a run costs one run. Accepting one corrupts a session that
// took hours, and corrupts it in the direction of a pass.
func VerifyColdCache(dir string) error {
	if dir == "" {
		return fmt.Errorf("%w: no GOCACHE path was supplied for a cold-build run", ErrCacheNotCold)
	}

	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("%w: %s could not be inspected: %w", ErrCacheNotCold, dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: %s is not a directory (mode %s)", ErrCacheNotCold, dir, info.Mode())
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("%w: %s could not be listed: %w", ErrCacheNotCold, dir, err)
	}
	if len(entries) > 0 {
		return fmt.Errorf("%w: %s already holds %d entr%s (%s): the build would not be cold",
			ErrCacheNotCold, dir, len(entries), plural(len(entries), "y", "ies"), sampleNames(entries))
	}
	return nil
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// sampleNames names a few entries, so the failure says what was in the way
// rather than only that something was.
func sampleNames(entries []os.DirEntry) string {
	const max = 3
	names := make([]string, 0, max)
	for i, e := range entries {
		if i == max {
			names = append(names, "...")
			break
		}
		names = append(names, e.Name())
	}
	return strings.Join(names, ", ")
}
