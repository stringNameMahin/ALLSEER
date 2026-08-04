package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Exit codes are part of the CLI's contract with scripts and CI, so they are
// asserted rather than checked by hand. In particular a corrupt recording must
// exit non-zero: a truncated capture that exits 0 reads as a complete session
// to whatever consumed it.
func TestRunExitCodes(t *testing.T) {
	fixtures := filepath.Join("..", "..", "test", "testdata", "replay")

	corrupt := filepath.Join(t.TempDir(), "corrupt.jsonl")
	const corruptStream = `{"id":"a","session_id":"s","sequence":1,"capability":"fs.read","domain":"filesystem"}
this line is not json
`
	if err := os.WriteFile(corrupt, []byte(corruptStream), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	tests := []struct {
		name string
		args []string
		want int
	}{
		{"no arguments", nil, 2},
		{"unknown command", []string{"bogus"}, 2},
		{"help", []string{"help"}, 0},
		{"help flag", []string{"--help"}, 0},
		{"version", []string{"version"}, 0},
		{"capabilities", []string{"capabilities"}, 0},
		{"capabilities json", []string{"capabilities", "-json"}, 0},
		{"capabilities unknown domain", []string{"capabilities", "-domain", "nope"}, 2},
		{"replay without a file", []string{"replay"}, 2},
		{"replay missing file", []string{"replay", "does-not-exist.jsonl"}, 1},
		{"replay clean fixture", []string{"replay", "-quiet", filepath.Join(fixtures, "go-build.jsonl")}, 0},
		{"replay json output", []string{"replay", "-json", "-quiet", filepath.Join(fixtures, "go-build.jsonl")}, 0},
		// A recording that lost records is still a valid recording; the loss is
		// reported in the summary, not as a failure.
		{"replay lossy fixture", []string{"replay", "-quiet", filepath.Join(fixtures, "npm-install.jsonl")}, 0},
		// A corrupt recording is not.
		{"replay corrupt stream", []string{"replay", "-quiet", corrupt}, 1},
		{"replay corrupt stream skipping", []string{"replay", "-quiet", "-skip-malformed", corrupt}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := run(tt.args); got != tt.want {
				t.Errorf("run(%q) = %d, want %d", tt.args, got, tt.want)
			}
		})
	}
}

// Help is generated from the dispatch table so that it cannot advertise a
// command the binary does not have.
func TestEveryAdvertisedCommandDispatches(t *testing.T) {
	for _, c := range commands() {
		if c.name == "" {
			t.Error("command with empty name")
		}
		if c.summary == "" {
			t.Errorf("command %q has no summary", c.name)
		}
		if c.run == nil {
			t.Errorf("command %q is advertised but has no implementation", c.name)
		}
	}
}

func TestTruncateElidesMiddle(t *testing.T) {
	tests := []struct {
		in   string
		max  int
		want string
	}{
		{"short", 20, "short"},
		{"exactly-twenty-chr!!", 20, "exactly-twenty-chr!!"},
		// Both ends survive: for a path the leading directories and the file
		// name are each more informative than the middle.
		{"/home/dev/project/internal/middleware/ratelimit/limiter_test.go", 30, "/home/dev/pro...miter_test.go"},
	}

	for _, tt := range tests {
		got := truncate(tt.in, tt.max)
		if got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.in, tt.max, got, tt.want)
		}
		if len(got) > tt.max {
			t.Errorf("truncate(%q, %d) returned %d chars, exceeding max", tt.in, tt.max, len(got))
		}
	}
}
