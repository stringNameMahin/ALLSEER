package resolve

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stringNameMahin/ALLSEER/internal/telemetry/replay"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// The replay fixtures were hand-authored before this package existed, and each
// record carries the observation its author expected the collector to produce.
// That makes them an independent statement of the intended conventions, and
// running the resolver against them is the closest thing available to a test
// against a real capture.
var fixtures = []string{
	"../../../test/testdata/replay/go-build.jsonl",
	"../../../test/testdata/replay/npm-install.jsonl",
	"../../../test/testdata/replay/git-operation.jsonl",
}

func loadFixture(t *testing.T, path string) []event.Event {
	t.Helper()

	src := replay.New(replay.Config{Path: filepath.FromSlash(path)})
	defer src.Close()

	if err := src.Start(context.Background()); err != nil {
		t.Fatalf("start %s: %v", path, err)
	}

	var events []event.Event
	for e := range src.Events() {
		events = append(events, e)
	}
	if err := src.Err(); err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if len(events) == 0 {
		t.Fatalf("%s produced no events", path)
	}
	return events
}

// TestResolverAgreesWithFixtures checks the resolver against every recorded
// observation.
//
// Kind, Domain, and Target must match exactly: those are the fields selector
// matching reads, and a disagreement means the resolver and the corpus describe
// different operations. Attributes are checked as a subset -- every attribute
// the fixture records must be reproduced with the same value -- because the
// fixtures were written by hand and are not uniform about which optional
// attributes they include. Producing more detail than a fixture bothered to
// write down is not a regression; producing different detail is.
func TestResolverAgreesWithFixtures(t *testing.T) {
	for _, path := range fixtures {
		t.Run(filepath.Base(path), func(t *testing.T) {
			for _, e := range loadFixture(t, path) {
				if e.Observation.Kind == "" {
					continue // no recorded expectation to check against
				}

				got, err := Observe(&e)
				if err != nil {
					t.Errorf("%s: Observe: %v", e.ID, err)
					continue
				}

				want := e.Observation
				if got.Kind != want.Kind {
					t.Errorf("%s: Kind = %q, fixture says %q", e.ID, got.Kind, want.Kind)
				}
				if got.Domain != want.Domain {
					t.Errorf("%s: Domain = %q, fixture says %q", e.ID, got.Domain, want.Domain)
				}
				if got.Target != want.Target {
					t.Errorf("%s: Target = %q, fixture says %q", e.ID, got.Target, want.Target)
				}
				for k, v := range want.Attributes {
					if got.Attributes[k] != v {
						t.Errorf("%s: attribute %q = %q, fixture says %q", e.ID, k, got.Attributes[k], v)
					}
				}
			}
		})
	}
}

// TestFixturesCoverTheResolvedDomains guards the test above from silently
// checking less than it appears to: it is only meaningful while the corpus
// still exercises each branch of the resolver.
func TestFixturesCoverTheResolvedDomains(t *testing.T) {
	seen := map[string]bool{}
	for _, path := range fixtures {
		for _, e := range loadFixture(t, path) {
			if e.File != nil && e.File.NewPath != "" {
				seen["rename"] = true
			}
			if e.Network != nil {
				seen["network"] = true
			}
			if e.Exec != nil {
				seen["exec"] = true
			}
			if e.File != nil {
				seen["file"] = true
			}
		}
	}

	for _, want := range []string{"file", "rename", "network", "exec"} {
		if !seen[want] {
			t.Errorf("the replay corpus no longer exercises %s resolution", want)
		}
	}
}
