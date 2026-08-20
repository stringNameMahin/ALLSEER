package replay

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stringNameMahin/ALLSEER/pkg/capability"
)

// fixtureDir is the committed corpus described in its own README.
const fixtureDir = "../../../test/testdata/replay"

// fixtures enumerates the seed corpus with the properties each one is committed
// to hold. These are asserted rather than described so that a fixture edited
// into an inconsistent state, whether a resequenced stream or a drop counter
// that no longer matches its gap, fails loudly instead of quietly changing what
// every downstream test is measuring.
var fixtures = []struct {
	name string
	file string

	sessionID string
	events    int

	// wantGaps is the number of sequence discontinuities the recording carries.
	// Non-zero only for fixtures that are about telemetry loss.
	wantGaps uint64

	// wantDropped is the total the recording's own Dropped counters report.
	wantDropped uint64
}{
	{
		name:      "go-build",
		file:      "go-build.jsonl",
		sessionID: "s-gobuild",
		events:    13,
		// A clean capture. If this ever reports loss, the fixture has been
		// edited and the benign baseline is no longer benign.
		wantGaps:    0,
		wantDropped: 0,
	},
	{
		name:        "npm-install",
		file:        "npm-install.jsonl",
		sessionID:   "s-npm",
		events:      10,
		wantGaps:    1,
		wantDropped: 24,
	},
	{
		name:        "git-operation",
		file:        "git-operation.jsonl",
		sessionID:   "s-git",
		events:      10,
		wantGaps:    0,
		wantDropped: 0,
	},
	{
		// The sequence recording. Clean, because the claim it supports is about
		// the *relationship* between two events: a hole in this stream would
		// mean the detector could be reasoning across records it never saw, and
		// that is a separate concern with its own fixture.
		name:        "credential-egress",
		file:        "credential-egress.jsonl",
		sessionID:   "s-exfil",
		events:      10,
		wantGaps:    0,
		wantDropped: 0,
	},
}

// The sequence fixture is only useful if it still contains the near-misses it
// was written around. Asserted here, beside the other structural claims, so a
// well-meaning edit that "tidied" the failed read or re-graded the /etc/passwd
// event fails in the corpus rather than silently weakening a detector test one
// package away.
func TestCredentialEgressFixtureKeepsItsNearMisses(t *testing.T) {
	s := Open(filepath.Join(fixtureDir, "credential-egress.jsonl"))
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = s.Close() }()

	got := map[string]struct {
		kind      capability.Kind
		target    string
		succeeded bool
	}{}
	for _, e := range drain(t, s) {
		got[e.ID] = struct {
			kind      capability.Kind
			target    string
			succeeded bool
		}{e.Capability, e.Observation.Target, e.Result.Succeeded}
	}

	for _, c := range []struct {
		id        string
		kind      capability.Kind
		target    string
		succeeded bool
		why       string
	}{
		{"ex-003", capability.KindFileRead, "/home/dev/.aws/credentials", true,
			"the only qualifying antecedent in the stream"},
		{"ex-004", capability.KindFileRead, "/etc/passwd", true,
			"a medium-graded read that must not qualify"},
		{"ex-005", capability.KindFileRead, "/home/dev/.ssh/id_ed25519", false,
			"a critical-graded read that failed and so must not qualify"},
		{"ex-006", capability.KindNetDNS, "registry.npmjs.org", true,
			"a lookup, which is not egress"},
		{"ex-007", capability.KindNetConnect, "registry.npmjs.org:443", true,
			"granted egress, where the sequence is reported and charges nothing"},
		{"ex-009", capability.KindNetConnect, "198.51.100.77:8443", true,
			"the uncorrelated egress the detector moves across a policy boundary"},
	} {
		e, ok := got[c.id]
		if !ok {
			t.Errorf("%s is gone from the fixture; it was %s", c.id, c.why)
			continue
		}
		if e.kind != c.kind || e.target != c.target || e.succeeded != c.succeeded {
			t.Errorf("%s is now %s on %q (succeeded=%v), want %s on %q (succeeded=%v): it is %s",
				c.id, e.kind, e.target, e.succeeded, c.kind, c.target, c.succeeded, c.why)
		}
	}
}

func TestFixturesAreWellFormed(t *testing.T) {
	for _, f := range fixtures {
		t.Run(f.name, func(t *testing.T) {
			s := Open(filepath.Join(fixtureDir, f.file))
			if err := s.Start(context.Background()); err != nil {
				t.Fatalf("Start: %v", err)
			}
			defer func() { _ = s.Close() }()

			got := drain(t, s)

			// A parse failure anywhere in the stream is fatal by default, so a
			// non-nil Err means the fixture contains malformed JSON.
			if err := s.Err(); err != nil {
				t.Fatalf("fixture failed to parse: %v", err)
			}
			if len(got) != f.events {
				t.Errorf("delivered %d events, want %d", len(got), f.events)
			}

			var lastSeq, lastTS uint64
			for i, e := range got {
				if e.SessionID != f.sessionID {
					t.Errorf("event %d (%s): SessionID = %q, want %q",
						i, e.ID, e.SessionID, f.sessionID)
				}
				if e.ID == "" {
					t.Errorf("event %d: empty ID; every event must be independently interpretable", i)
				}

				// Sequence must advance. A fixture that repeats or rewinds a
				// sequence number breaks the ordering the pipeline relies on.
				if i > 0 && e.Sequence <= lastSeq {
					t.Errorf("event %d (%s): Sequence %d does not advance past %d",
						i, e.ID, e.Sequence, lastSeq)
				}
				lastSeq = e.Sequence

				// Timestamps are monotonic in a real capture. The replay source
				// delivers in file order and never sorts, so a fixture whose
				// order disagrees with its timestamps is a fixture bug.
				if i > 0 && e.KernelTimestamp < lastTS {
					t.Errorf("event %d (%s): KernelTimestamp %d goes backwards from %d",
						i, e.ID, e.KernelTimestamp, lastTS)
				}
				lastTS = e.KernelTimestamp

				// The capability must be in the catalog. A fixture referencing
				// an unknown Kind would exercise a validator path that cannot
				// occur in production, since the envelope parser rejects them.
				if err := capability.ValidateKind(e.Capability); err != nil {
					t.Errorf("event %d (%s): %v", i, e.ID, err)
				}

				// Domain is denormalized alongside Capability and the two must
				// agree, on the event and on its observation.
				if want, ok := capability.DomainOf(e.Capability); ok && e.Domain != want {
					t.Errorf("event %d (%s): Domain = %q but capability %q is in domain %q",
						i, e.ID, e.Domain, e.Capability, want)
				}
				if e.Observation.Kind != e.Capability {
					t.Errorf("event %d (%s): Observation.Kind = %q, event Capability = %q",
						i, e.ID, e.Observation.Kind, e.Capability)
				}
				if e.Observation.Target == "" {
					t.Errorf("event %d (%s): empty Observation.Target; downstream stages match on it",
						i, e.ID)
				}
			}

			if got, want := s.SequenceGaps(), f.wantGaps; got != want {
				t.Errorf("SequenceGaps() = %d, want %d", got, want)
			}
			if got, want := s.Stats().DroppedEvents, f.wantDropped; got != want {
				t.Errorf("Stats().DroppedEvents = %d, want %d", got, want)
			}
			if got, want := s.Stats().EventsReceived, uint64(f.events); got != want {
				t.Errorf("Stats().EventsReceived = %d, want %d", got, want)
			}
		})
	}
}

// A recording that lost records must replay as a recording that lost records.
// This is asserted on its own because every fail-closed test downstream depends
// on it: if replay ever renumbered a gap away, those tests would still pass
// while testing nothing.
func TestNpmFixturePreservesLoss(t *testing.T) {
	s := Open(filepath.Join(fixtureDir, "npm-install.jsonl"))
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = s.Close() }()

	var beforeGap, afterGap uint64
	for _, e := range drain(t, s) {
		if e.ID == "np-006" {
			beforeGap = e.Sequence
		}
		if e.ID == "np-031" {
			afterGap = e.Sequence
			if e.Dropped != 24 {
				t.Errorf("np-031 Dropped = %d, want 24 carried on the event itself", e.Dropped)
			}
		}
	}

	if beforeGap != 6 || afterGap != 31 {
		t.Errorf("sequence around the gap = %d then %d, want 6 then 31", beforeGap, afterGap)
	}
}

// The uncorrelated connection in the npm fixture is the reason that fixture
// exists. If correlation were ever assumed rather than observed, the easiest
// way to evade a network grant would be to skip DNS.
func TestNpmFixtureHasUncorrelatedConnection(t *testing.T) {
	s := Open(filepath.Join(fixtureDir, "npm-install.jsonl"))
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = s.Close() }()

	var correlated, uncorrelated int
	for _, e := range drain(t, s) {
		if e.Capability != capability.KindNetConnect || e.Network == nil {
			continue
		}
		if e.Network.Hostname == "" {
			uncorrelated++
		} else {
			correlated++
		}
	}

	if correlated == 0 {
		t.Error("fixture has no correlated connection; the matching case is untested")
	}
	if uncorrelated == 0 {
		t.Error("fixture has no uncorrelated connection; the evasion case is untested")
	}
}

func BenchmarkReplayFixture(b *testing.B) {
	path := filepath.Join(fixtureDir, "go-build.jsonl")

	for b.Loop() {
		s := Open(path)
		if err := s.Start(context.Background()); err != nil {
			b.Fatalf("Start: %v", err)
		}
		for range s.Events() {
		}
		_ = s.Close()
	}
}
