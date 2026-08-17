package validator

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stringNameMahin/ALLSEER/internal/telemetry/replay"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

func TestObservationOfPrefersTheRecordedObservation(t *testing.T) {
	// The recorded observation is what the collector concluded at the time.
	// Re-deriving it from the payload would let a replayed session be validated
	// against different facts than the live one was, so a populated observation
	// wins even when the payload disagrees.
	e := &event.Event{
		Capability: capability.KindFileWrite,
		File:       &event.FilePayload{ResolvedPath: "/ws/from-payload.go"},
		Observation: capability.Observation{
			Kind:   capability.KindFileWrite,
			Domain: capability.DomainFilesystem,
			Target: "/ws/as-recorded.go",
		},
	}

	obs, err := ObservationOf(e)
	if err != nil {
		t.Fatalf("ObservationOf: %v", err)
	}
	if obs.Target != "/ws/as-recorded.go" {
		t.Errorf("Target = %q, want the recorded observation", obs.Target)
	}
}

func TestObservationOfDerivesWhenAbsent(t *testing.T) {
	e := &event.Event{
		Capability: capability.KindFileWrite,
		File:       &event.FilePayload{ResolvedPath: "/ws/main.go"},
	}

	obs, err := ObservationOf(e)
	if err != nil {
		t.Fatalf("ObservationOf: %v", err)
	}
	if obs.Target != "/ws/main.go" || obs.Kind != capability.KindFileWrite {
		t.Errorf("observation = %+v, want one derived from the payload", obs)
	}
}

func TestMatchEvent(t *testing.T) {
	m := NewMatcher()
	grant := capability.Grant{
		Kind:     capability.KindFileWrite,
		Domain:   capability.DomainFilesystem,
		Selector: capability.Selector{PathPatterns: []string{"/ws/**"}},
	}

	inside := &event.Event{
		Capability: capability.KindFileWrite,
		File:       &event.FilePayload{ResolvedPath: "/ws/src/main.go"},
	}
	check(t, m.MatchEvent(grant, inside), wantMatch)

	outside := &event.Event{
		Capability: capability.KindFileWrite,
		File:       &event.FilePayload{ResolvedPath: "/etc/passwd"},
	}
	check(t, m.MatchEvent(grant, outside), wantMismatch)

	// The path could not be resolved, so the operation's target is unknown.
	truncated := &event.Event{
		Capability: capability.KindFileWrite,
		File:       &event.FilePayload{Path: "src/main.go"},
	}
	check(t, m.MatchEvent(grant, truncated), wantUnevaluable)
}

// TestMatchEventUnresolvableIsNeverAMatch is the property that makes the bridge
// safe to put in front of the matcher.
//
// The dangerous shape is a Kind-only grant — no selector at all — against an
// event that could not be resolved. An empty observation would satisfy such a
// grant and the operation would read as expected behavior, so an unresolvable
// event has to stop at the bridge rather than arrive as a blank observation.
func TestMatchEventUnresolvableIsNeverAMatch(t *testing.T) {
	m := NewMatcher()

	unconstrained := capability.Grant{Kind: capability.KindFileWrite}
	events := []*event.Event{
		nil,
		{Capability: capability.KindFileWrite}, // no payload at all
		{Capability: capability.Kind("fs.teleport")}, // not in the catalog
		{Capability: capability.KindNetConnect},      // no network payload
		{Capability: capability.KindProcessExec},     // no exec payload
	}

	for _, e := range events {
		got := m.MatchEvent(unconstrained, e)
		if got.Matched {
			t.Errorf("an unresolvable event matched an unconstrained grant: %q", got.Reason)
		}
		if !got.Unevaluable {
			t.Errorf("an unresolvable event was reported as a mismatch: %q", got.Reason)
		}
	}
}

// TestMatchEventFromReplay is the end-to-end path this feature exists to open:
// a recorded stream off an event.Source reaches the matcher without anything in
// between reaching into a payload struct.
func TestMatchEventFromReplay(t *testing.T) {
	src := replay.New(replay.Config{
		Path: filepath.FromSlash("../../test/testdata/replay/git-operation.jsonl"),
	})
	defer src.Close()

	if err := src.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}

	// What a git-operation envelope would plausibly grant: reads and writes
	// inside the project, denying nothing here.
	grants := []capability.Grant{
		{
			Kind:     capability.KindFileRead,
			Selector: capability.Selector{PathPatterns: []string{"/home/dev/project/**"}},
		},
		{
			Kind:     capability.KindFileWrite,
			Selector: capability.Selector{PathPatterns: []string{"/home/dev/project/**"}},
		},
	}

	m := NewMatcher()
	var covered, uncovered, unevaluated int
	for e := range src.Events() {
		for _, g := range grants {
			if g.Kind != e.Capability {
				continue
			}
			switch r := m.MatchEvent(g, &e); {
			case r.Matched:
				covered++
			case r.Unevaluable:
				unevaluated++
			default:
				uncovered++
			}
		}
	}
	if err := src.Err(); err != nil {
		t.Fatalf("replay: %v", err)
	}

	if covered == 0 {
		t.Error("no recorded event was covered by the workspace grants; the bridge is not delivering targets")
	}
	// The fixture deliberately includes a read of /home/dev/.ssh/id_rsa, which
	// is outside the project and must show up as uncovered rather than as
	// something the matcher could not evaluate.
	if uncovered == 0 {
		t.Error("the out-of-workspace read in the fixture was not reported as uncovered")
	}
	if unevaluated != 0 {
		t.Errorf("%d recorded events could not be evaluated; the fixture resolves every path", unevaluated)
	}
}
