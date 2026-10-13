package telemetry

import (
	"errors"
	"testing"
)

func TestTrackerDepthFollowsParents(t *testing.T) {
	tr := NewProcTracker()
	tr.TrackRoot("s1", 100)

	if d := tr.Observe("s1", 100, 1000, 1); d != 0 {
		t.Fatalf("root depth = %d, want 0", d)
	}
	if d := tr.Observe("s1", 101, 1100, 100); d != 1 {
		t.Fatalf("child depth = %d, want 1", d)
	}
	if d := tr.Observe("s1", 102, 1200, 101); d != 2 {
		t.Fatalf("grandchild depth = %d, want 2", d)
	}
	if got := tr.Descendants("s1"); len(got) != 3 {
		t.Fatalf("Descendants = %v, want 3 processes", got)
	}
}

// A recycled PID is a different process. The stranger reusing the number must
// not inherit the old process's session or depth.
func TestTrackerPIDReuseIsNotMisattributed(t *testing.T) {
	tr := NewProcTracker()
	tr.TrackRoot("s1", 200)
	tr.Observe("s1", 200, 10, 1)
	tr.Observe("s1", 201, 20, 200)
	if err := tr.Untrack(201, 20); err != nil {
		t.Fatal(err)
	}

	if sid, ok := tr.SessionFor(201, 99); ok {
		t.Fatalf("reused pid 201 with a new start time is attributed to %q", sid)
	}
	if d := tr.Depth(201, 20); d != -1 {
		t.Fatalf("exited process still has depth %d", d)
	}

	// The old parent's PID is reused outside the session. A child of the new
	// holder seen in another session must not chain to s1's tree.
	tr.Untrack(200, 10)
	tr.Observe("s2", 200, 50, 1)
	if d := tr.Observe("s2", 300, 60, 200); d != 2 {
		t.Fatalf("child of the new pid-200 holder has depth %d, want 2 (depth 1 parent)", d)
	}
	if sid, _ := tr.SessionFor(300, 60); sid != "s2" {
		t.Fatalf("child attributed to %q, want s2", sid)
	}
}

func TestTrackerRefusesCrossSessionOwnership(t *testing.T) {
	tr := NewProcTracker()
	if err := tr.Track("a", 1, 1); err != nil {
		t.Fatal(err)
	}
	if err := tr.Track("b", 1, 1); !errors.Is(err, ErrProcessTracked) {
		t.Fatalf("Track by a second session = %v, want ErrProcessTracked", err)
	}
}

func TestTrackerForgetSession(t *testing.T) {
	tr := NewProcTracker()
	tr.TrackRoot("s", 5)
	tr.Observe("s", 5, 1, 1)
	tr.TrackRoot("s", 6)
	tr.ForgetSession("s")
	if got := tr.Descendants("s"); len(got) != 0 {
		t.Fatalf("Descendants after ForgetSession = %v", got)
	}
	if d := tr.Observe("other", 6, 2, 1); d != 1 {
		t.Fatalf("a forgotten pending root leaked into another session: depth %d", d)
	}
}
