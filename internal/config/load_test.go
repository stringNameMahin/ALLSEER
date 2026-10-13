package config

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stringNameMahin/ALLSEER/internal/policy"
)

func TestDefaultsAreValidAndSafe(t *testing.T) {
	c := Defaults()
	if f := Fatal(Validate(c)); len(f) != 0 {
		t.Fatalf("defaults have fatal issues: %+v", f)
	}
	if c.Policy.DefaultMode != policy.ModeMonitor || !c.Envelope.RequireApproval || !c.Telemetry.FailClosedOnDrop {
		t.Fatalf("defaults are not the safe values: %+v", c)
	}
	if c.Policy.ApprovalTimeoutAction != "deny" {
		t.Fatalf("approval timeout action = %q, want deny", c.Policy.ApprovalTimeoutAction)
	}
}

func TestLoadOverlaysAndRefusesUnknownKeys(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.yaml")
	if err := os.WriteFile(good, []byte("daemon:\n  socket_path: /tmp/x.sock\npolicy:\n  default_mode: enforce\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := FileLoader{}.Load(context.Background(), good)
	if err != nil {
		t.Fatal(err)
	}
	if c.Daemon.SocketPath != "/tmp/x.sock" || c.Policy.DefaultMode != policy.ModeEnforce {
		t.Fatalf("overlay not applied: %+v", c.Daemon)
	}
	if c.Audit.Path == "" || !c.Envelope.RequireApproval {
		t.Fatal("unset fields lost their defaults")
	}

	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("policy:\n  defualt_mode: monitor\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (FileLoader{}).Load(context.Background(), bad); err == nil {
		t.Fatal("a misspelled key was accepted")
	}

	empty := filepath.Join(dir, "empty.yaml")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (FileLoader{}).Load(context.Background(), empty); err != nil {
		t.Fatalf("empty file: %v", err)
	}
}

func TestValidateRefusesUnsafeValues(t *testing.T) {
	c := Defaults()
	c.Policy.DefaultMode = "lenient"
	c.Audit.Path = ""
	c.Policy.ApprovalTimeoutAction = "maybe"
	if got := len(Fatal(Validate(c))); got != 3 {
		t.Fatalf("fatal issues = %d, want 3: %+v", got, Validate(c))
	}
}

func TestRestrictOnlyTightens(t *testing.T) {
	cases := []struct{ cfg, req, want policy.Mode }{
		{policy.ModeEnforce, policy.ModeMonitor, policy.ModeEnforce},
		{policy.ModeMonitor, policy.ModeEnforce, policy.ModeEnforce},
		{policy.ModeInteractive, "", policy.ModeInteractive},
		{policy.ModeWarn, "bogus", policy.ModeWarn},
	}
	for _, c := range cases {
		if got := Restrict(c.cfg, c.req); got != c.want {
			t.Errorf("Restrict(%s, %s) = %s, want %s", c.cfg, c.req, got, c.want)
		}
	}
}
