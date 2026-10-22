package e2e

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stringNameMahin/ALLSEER/pkg/ece"
)

// A path past the old 256-byte field, inside the workspace, arrived truncated,
// scored as unverifiable and asked for approval, which enforce turns into a
// kill. pnpm's node_modules/.pnpm and Bazel output trees reach that length in
// ordinary builds. A build that writes and reads deep in its own tree now
// finishes, and every decision about the file is an allow.
func TestLongPathsInTheWorkspaceDoNotStopTheAgent(t *testing.T) {
	d := startDaemon(t, "enforce")
	ws := workspace(t)
	rel := strings.Join([]string{strings.Repeat("d", 190), strings.Repeat("e", 190), strings.Repeat("f", 190)}, "/")
	if n := len(ws) + len(rel) + len("/deep.txt") + 1; n <= 256 || n >= 1024 {
		t.Fatalf("the path is %d bytes; this test needs one between 256 and 1023", n)
	}
	r := shim(t, d.socket, ws, "", script(t, fmt.Sprintf(
		"set -e\nmkdir -p %s\np=\"$PWD/%s/deep.txt\"\nprintf x > \"$p\"\ncat \"$p\" >/dev/null\n", rel, rel)))
	sid := r.sessionID(t)
	if code := r.wait(t, 60*time.Second); code != 0 {
		t.Fatalf("the agent exited %d under enforce:\n%s\ndecisions other than allow:\n%s", code, r.stderr.String(), d.explain())
	}

	seen := 0
	for _, dec := range d.decisions(t, sid) {
		if !strings.Contains(target(dec), "deep.txt") {
			continue
		}
		seen++
		if dec.Action != ece.ActionAllow {
			t.Errorf("%s on %q: %s by %s, risk %.0f; want allow", dec.Verdict, target(dec), dec.Action,
				dec.MatchedRule, dec.Risk.Score)
		}
	}
	if seen == 0 {
		t.Fatalf("no decision names the deep file; decisions other than allow:\n%s", d.explain())
	}
}
