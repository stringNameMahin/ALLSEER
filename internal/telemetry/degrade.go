package telemetry

import (
	"errors"
	"syscall"
)

// errnoENOTSUPP is the kernel's internal "not supported", which reaches user
// space from BPF program loads although it has no name there.
const errnoENOTSUPP = syscall.Errno(524)

// refusal reports whether a load error is the kernel refusing a program, which
// leaving its family out can cure: the verifier rejecting it, a helper or
// program type the kernel lacks, a function missing from kernel BTF. Memory
// pressure, a signal, or an error that is not an errno at all says nothing
// about which family is at fault, so it must fail the load rather than drop a
// healthy family for the life of the daemon.
func refusal(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	switch errno {
	case syscall.EACCES, syscall.EPERM, syscall.EINVAL, syscall.E2BIG, syscall.ESRCH, syscall.ENOENT,
		syscall.EOPNOTSUPP, errnoENOTSUPP:
		return true
	}
	return false
}

// degradeFamilies finds the probe families to leave out so that the rest of
// the object loads, after loading every family failed with first.
//
// load tries the object with the named families left out. Families are
// independent units: the verifier judges each program alone, so a refused
// family is found by bisecting the families not yet left out, in order, and
// a kernel refusing k of n costs about k*log2(n) loads. When the object fails
// with every family left out, what fails is the floor or a map, nothing can
// govern, and first is returned as the reason. Only refusals degrade: when
// first or any later load fails for another reason, that error is returned
// and nothing is left out.
//
// The result maps each family left out to the error of the load that
// isolated it.
func degradeFamilies(families []string, first error, load func(out map[string]bool) error) (map[string]error, error) {
	if !refusal(first) {
		return nil, first
	}
	out := map[string]bool{}
	why := map[string]error{}
	failing := first
	for range families {
		var rest []string
		for _, f := range families {
			if !out[f] {
				rest = append(rest, f)
			}
		}
		// rest[:k] in, rest[k:] out. k = len(rest) failed with failing; find
		// the smallest k that fails.
		lo, hi, hiErr := 0, len(rest), failing
		for lo < hi {
			mid := (lo + hi) / 2
			if err := load(withOut(out, rest[mid:])); err != nil {
				if !refusal(err) {
					return nil, err
				}
				hi, hiErr = mid, err
			} else {
				lo = mid + 1
			}
		}
		if lo == 0 {
			return nil, first
		}
		f := rest[lo-1]
		out[f], why[f] = true, hiErr
		if failing = load(out); failing == nil {
			return why, nil
		}
		if !refusal(failing) {
			return nil, failing
		}
	}
	return nil, first
}

func withOut(out map[string]bool, more []string) map[string]bool {
	u := make(map[string]bool, len(out)+len(more))
	for f := range out {
		u[f] = true
	}
	for _, f := range more {
		u[f] = true
	}
	return u
}
