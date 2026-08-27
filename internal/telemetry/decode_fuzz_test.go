package telemetry

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/stringNameMahin/ALLSEER/internal/telemetry/abi"
	"github.com/stringNameMahin/ALLSEER/internal/telemetry/resolve"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// FuzzDecode is the interpretation half of the trust boundary.
//
// # Why this exists when abi already has a fuzz target
//
// abi.FuzzDecodeRecord covers the layout half: for any input, DecodeRecord
// either errors or returns a record, and never panics or reads out of bounds.
// It asserts nothing about meaning, because the generated layer has none — it
// deliberately imports neither pkg/event nor pkg/capability.
//
// Every property below is about meaning, and none of them can be stated one
// level down:
//
//   - An accepted record yields a capability the M1 catalog knows, whose domain
//     is the catalog's rather than a second opinion.
//   - It yields exactly the payload that domain requires, and none from another
//     domain. That is the allOf rule in the event JSON schema, asserted here
//     against the code that has to satisfy it.
//   - No string in the event contains a NUL byte, and none was produced from a
//     field that had no terminator. A path that filled its field is the
//     truncation the header forbids treating as complete, and this is the last
//     place it is visible.
//   - Nothing that needs session state, a boot offset, or a resolver is filled
//     in. A decoder that invented an ID, a wall clock, or a resolved path would
//     be manufacturing evidence, and it would still pass the layout fuzzer.
//   - The event is consumable by the stage that follows it: resolve.Observe
//     accepts it and never panics on it.
//
// The M5 issue asks for a fuzz target over "malformed, truncated, and oversized
// records" for Decoder.Decode specifically. This is that target; the seeds
// cover all three shapes plus the type and string mutations only this layer can
// reject.
func FuzzDecode(f *testing.F) {
	// Sizes: exact, short, long, empty. The generated layer refuses three of
	// the four, and the fourth is the only shape the rest of the properties
	// apply to.
	f.Add(make([]byte, abi.RecordSize))
	f.Add(make([]byte, 0))
	f.Add(make([]byte, abi.RecordSize-1))
	f.Add(make([]byte, abi.RecordSize+1))
	f.Add(bytes.Repeat([]byte{0xFF}, abi.RecordSize))

	// One well-formed record per accepted event type, so the fuzzer starts from
	// inputs that reach the payload decoders rather than only from ones that
	// bounce off the type switch.
	for _, typ := range abi.AllEventTypes() {
		raw := newRecord(typ)
		putStr(raw, abi.OffsetEventProc+abi.OffsetProcComm, "node")
		putI32(raw, abi.OffsetEventRet, -2)
		put32(raw, offFileFlags, 0x241)
		putStr(raw, offFilePath, "/home/dev/project/src/index.js")
		putStr(raw, offFileNewPath, "/etc/cron.d/job")
		put32(raw, offExecArgc, 3)
		putStr(raw, offExecFilename, "/usr/bin/git")
		putStr(raw, offArgv(0), "git")
		put16(raw, offNetFamily, 2)
		put16(raw, offNetProtocol, 6)
		put16(raw, offNetDport, 443)
		f.Add(raw)
	}

	// A type outside the enum: the loaded object being newer than this binary.
	f.Add(newRecord(abi.EventType(math.MaxUint32)))

	// A well-formed record of a declared type carrying a version this build does
	// not decode. newRecord stamps the right one, so this is the one place that
	// overwrites it. The zeroed and 0xFF-filled seeds above already cover the
	// two extreme versions; this one is the near miss, which is the shape an
	// actual ABI bump produces.
	wrongVersion := newRecord(abi.EvtProcExec)
	put32(wrongVersion, abi.OffsetEventVersion, abi.ABIVersion+1)
	f.Add(wrongVersion)

	// Strings that filled their fields. The case the header names, and the one
	// this layer is the last to be able to see.
	truncated := newRecord(abi.EvtProcExec)
	fill(truncated, offExecFilename, abi.PathMax)
	fill(truncated, offArgv(0), abi.ArgLen)
	fill(truncated, abi.OffsetEventProc+abi.OffsetProcComm, abi.CommLen)
	put32(truncated, offExecArgc, math.MaxUint32)
	f.Add(truncated)

	d := NewDecoder()

	f.Fuzz(func(t *testing.T, raw []byte) {
		e, err := d.Decode(raw)

		if err != nil {
			if e != nil {
				t.Fatal("an error was returned alongside an event; a caller checking only one of " +
					"the two would act on a record the decoder could not interpret")
			}
			if len(raw) == abi.RecordSize && readType(raw).IsKnown() {
				// Refusing a correctly sized record of a declared type is
				// allowed — three conditions do it — but each has a sentinel,
				// and an error outside that set means something was refused for
				// a reason nobody wrote down.
				if !isDeclaredRefusal(err) {
					t.Fatalf("a well-formed record was refused without a documented sentinel: %v", err)
				}
			}
			return
		}

		if len(raw) != abi.RecordSize {
			t.Fatalf("accepted a %d-byte record; only %d is valid", len(raw), abi.RecordSize)
		}

		// --- the vocabulary --------------------------------------------------

		if err := capability.ValidateKind(e.Capability); err != nil {
			t.Fatalf("decoded to a capability the catalog does not know: %v", err)
		}
		domain, known := capability.DomainOf(e.Capability)
		if !known || e.Domain != domain {
			t.Fatalf("Domain = %q but the catalog says %q for %q", e.Domain, domain, e.Capability)
		}
		typ := readType(raw)
		if !containsKind(CapabilitiesFor(typ), e.Capability) {
			t.Fatalf("%s decoded to %q, which CapabilitiesFor does not advertise for it", typ, e.Capability)
		}

		// --- the payload -----------------------------------------------------

		set := 0
		for _, present := range []bool{e.File != nil, e.Network != nil, e.Exec != nil, e.Privil != nil} {
			if present {
				set++
			}
		}
		if set > 1 {
			t.Fatalf("%d payloads on one event", set)
		}
		switch e.Domain {
		case capability.DomainFilesystem:
			if e.File == nil {
				t.Fatal("filesystem event with no file payload")
			}
		case capability.DomainNetwork:
			if e.Network == nil {
				t.Fatal("network event with no network payload")
			}
		}
		// A privilege payload appears on exactly one type and on no other. The
		// inverse — a privilege event with no payload — is not asserted here,
		// because privPayload always returns a struct: which of its fields are
		// filled is decided by fields_present, not by whether the pointer is
		// set.
		if e.Privil != nil && e.Domain != capability.DomainPrivilege {
			t.Fatalf("a privilege payload rode on a %s event", e.Domain)
		}
		if e.Domain == capability.DomainPrivilege && e.Privil == nil {
			t.Fatal("a privilege event carried no privilege payload")
		}

		// --- strings ---------------------------------------------------------
		//
		// A NUL inside a decoded string would mean a fixed-size field was read
		// past its terminator, which is how one field's bytes end up appended
		// to another's.
		for _, s := range stringsOf(e) {
			if strings.ContainsRune(s, 0) {
				t.Fatalf("a decoded string contains a NUL byte: %q", s)
			}
		}

		// --- what must stay empty ---------------------------------------------

		if e.ID != "" || e.SessionID != "" || e.Sequence != 0 || !e.WallClock.IsZero() || e.Dropped != 0 {
			t.Fatalf("the decoder filled a field that needs session state or a measured clock: %+v", e)
		}
		if e.Syscall != "" {
			t.Fatalf("Syscall = %q; the record carries no syscall identifier", e.Syscall)
		}
		if !reflect.DeepEqual(e.Observation, capability.Observation{}) {
			t.Fatalf("Observation = %+v; resolution runs after enrichment", e.Observation)
		}
		if e.File != nil && e.File.ResolvedPath != "" {
			t.Fatalf("ResolvedPath = %q; the decoder must not resolve paths", e.File.ResolvedPath)
		}
		if e.Network != nil && e.Network.Hostname != "" {
			t.Fatalf("Hostname = %q; the decoder must not correlate", e.Network.Hostname)
		}
		if e.Process.Executable != "" || e.Process.AncestryDepth != 0 {
			t.Fatalf("the decoder filled an enrichment field on Process: %+v", e.Process)
		}
		if e.Exec != nil && (e.Exec.Interpreter != "" || e.Exec.BinaryHash != "" || e.Exec.EnvKeys != nil) {
			t.Fatalf("the decoder filled an enrichment field on Exec: %+v", *e.Exec)
		}

		// --- the result ------------------------------------------------------

		if e.Result.Succeeded != (e.Result.ReturnCode >= 0) {
			t.Fatalf("Result = %+v: a negative return is a failure", e.Result)
		}
		if e.Result.Succeeded && e.Result.Errno != "" {
			t.Fatalf("a successful call carries errno %q", e.Result.Errno)
		}

		// --- determinism -----------------------------------------------------

		again, err := d.Decode(raw)
		if err != nil {
			t.Fatalf("second decode of the same bytes failed: %v", err)
		}
		if !reflect.DeepEqual(e, again) {
			t.Fatal("decoding is not deterministic")
		}

		// --- and the stage that follows ---------------------------------------
		//
		// Whatever the bytes were, the event must be something the next stage
		// can evaluate rather than something it panics on. Observe returns an
		// error for kinds outside the catalog, which the assertions above have
		// already excluded, so an error here is a genuine inconsistency.
		if _, err := resolve.Observe(e); err != nil {
			t.Fatalf("a decoded event could not be resolved to an observation: %v", err)
		}
	})
}

// readType reads the event type out of a raw record, for the fuzz properties
// that need to know what the input claimed to be. Native endian, like the
// decoder: the probe writes these bytes on the machine that reads them.
func readType(raw []byte) abi.EventType {
	return abi.EventType(binary.NativeEndian.Uint32(raw[abi.OffsetEventType:]))
}

// isDeclaredRefusal reports whether an error is one of the four documented
// reasons a correctly sized record of a declared type is refused.
func isDeclaredRefusal(err error) bool {
	for _, sentinel := range []error{
		ErrABIVersionMismatch, ErrUnsetEventType, ErrUnsetPrivOp, ErrUnknownPrivOp, ErrTruncatedString,
	} {
		if errors.Is(err, sentinel) {
			return true
		}
	}
	return false
}

func containsKind(ks []capability.Kind, k capability.Kind) bool {
	for _, candidate := range ks {
		if candidate == k {
			return true
		}
	}
	return false
}

// stringsOf collects every string the decoder produced, so one property can be
// asserted over all of them at once.
func stringsOf(e *event.Event) []string {
	out := []string{e.Process.Comm, string(e.Capability), string(e.Domain), e.Result.Errno}
	if e.File != nil {
		out = append(out, e.File.Path, e.File.NewPath)
	}
	if e.Network != nil {
		out = append(out, e.Network.Protocol, e.Network.SourceAddr, e.Network.DestAddr,
			e.Network.AddressFamily, e.Network.SocketType)
	}
	if e.Exec != nil {
		out = append(out, e.Exec.Filename)
		out = append(out, e.Exec.Argv...)
	}
	return out
}
