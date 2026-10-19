package ece

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The schema documents max_duration as a duration string. The Go encoding has
// to write that form, or a sealed envelope fails its own published contract.
func TestMaxDurationIsADurationString(t *testing.T) {
	b, err := json.Marshal(Constraints{MaxDuration: 30 * time.Minute, MaxProcesses: 4})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(b); !strings.Contains(got, `"max_duration":"30m0s"`) || !strings.Contains(got, `"max_processes":4`) {
		t.Fatalf("encoded constraints = %s", got)
	}
	if b, _ := json.Marshal(Constraints{WorkspaceRoot: "/w"}); strings.Contains(string(b), "max_duration") {
		t.Errorf("an unset duration was written: %s", b)
	}

	var c Constraints
	if err := json.Unmarshal([]byte(`{"max_duration":"1h30m","max_file_writes":7}`), &c); err != nil {
		t.Fatal(err)
	}
	if c.MaxDuration != 90*time.Minute || c.MaxFileWrites != 7 {
		t.Errorf("decoded %+v", c)
	}
	for _, bad := range []string{`{"max_duration":"soon"}`, `{"max_duration":3600000000000}`} {
		if err := json.Unmarshal([]byte(bad), &c); err == nil {
			t.Errorf("%s decoded without error", bad)
		}
	}
}

// The published example is what an operator copies. It has to parse.
func TestThePublishedExampleParses(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "api", "schema", "examples", "ece.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	var env Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		t.Fatalf("the published example does not parse: %v", err)
	}
	if env.Constraints.MaxDuration != 30*time.Minute {
		t.Errorf("max_duration = %v, want 30m", env.Constraints.MaxDuration)
	}
	again, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	var back Envelope
	if err := json.Unmarshal(again, &back); err != nil || back.Constraints != env.Constraints {
		t.Errorf("round trip: %v, %+v", err, back.Constraints)
	}
}
