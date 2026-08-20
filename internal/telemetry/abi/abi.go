// Package abi is the Go view of the kernel/user ABI declared in
// bpf/include/allseer_event.h.
//
// Almost everything here is generated. layout_gen.go holds the sizes, offsets,
// struct mirrors, and decode functions derived from the header by
// internal/telemetry/abigen; this file holds the small amount that is not
// derived from a C declaration and therefore cannot be generated.
//
// # What this package is for
//
// It is the boundary where kernel bytes become Go values, and nothing more. It
// deliberately does **not** import pkg/event or pkg/capability, and it produces
// no event.Event. Turning a decoded record into the system's vocabulary — which
// allseer_event_type corresponds to which capability.Kind, what an unresolved
// path means, how a truncated string is reported — is the decoder's job, and
// the decoder is a separate milestone issue. Keeping the split means this
// package can be regenerated from a changed header without touching any code
// that makes a judgment.
//
// # Why it is generated
//
// The header's own preamble states the failure mode: "A mismatch does not
// produce a clean error; it produces plausible garbage that flows straight into
// governance decisions." A hand-written Go mirror is a duplicate of the layout,
// duplicates drift, and this particular drift corrupts the evidence every
// downstream conclusion rests on while looking entirely healthy.
//
//go:generate go run github.com/stringNameMahin/ALLSEER/internal/telemetry/abigen/cmd/abigen -header ../../../bpf/include/allseer_event.h -out layout_gen.go -package abi
package abi

import "bytes"

// CString converts a NUL-padded fixed-size character array to a Go string, and
// reports whether it was terminated.
//
// The second return value is the point. The header caps every path at
// ALLSEER_PATH_MAX because "eBPF stack space is limited to 512 bytes and the
// verifier rejects unbounded copies", and it states the consequence directly:
// "The user-space enricher must treat truncation as an enrichment failure,
// never as a complete path."
//
// An array with no NUL in it is exactly that case. Returning the bytes as a
// string with no signal would let a truncated path be matched against a grant
// as though it were the whole path — and a prefix that matches a granted glob
// while the real path does not is the cheapest possible way past a selector.
// So truncation is reported here, at the only place that can still see it, and
// what to do about it is decided by the caller.
func CString(b []byte) (s string, terminated bool) {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i]), true
	}
	return string(b), false
}
