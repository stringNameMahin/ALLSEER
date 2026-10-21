package config

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stringNameMahin/ALLSEER/internal/policy"
)

func TestDefaultsAreValidAndSafe(t *testing.T) {
	c := Defaults()
	if f := Fatal(Validate(c)); len(f) != 0 {
		t.Fatalf("defaults have fatal issues: %+v", f)
	}
	if c.Policy.DefaultMode != policy.ModeInteractive || !c.Envelope.RequireApproval || !c.Telemetry.FailClosedOnDrop {
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

// A field that parses and then does nothing is worse than a missing one: the
// operator who sets drop_privileges has every reason to believe it happened.
func TestUnimplementedSettingsAreReported(t *testing.T) {
	cases := []struct {
		name  string
		set   func(*Config)
		field string
		fatal bool
	}{
		{"privilege drop", func(c *Config) { c.Daemon.DropPrivileges = true }, "daemon.drop_privileges", true},
		{"run as user", func(c *Config) { c.Daemon.RunAsUser = "allseer" }, "daemon.run_as_user", true},
		{"dns correlation", func(c *Config) { c.Telemetry.EnableDNSCorrelation = true }, "telemetry.enable_dns_correlation", false},
		{"binary hashing", func(c *Config) { c.Telemetry.EnableBinaryHashing = true }, "telemetry.enable_binary_hashing", false},
		{"audit retention", func(c *Config) { c.Audit.RetentionDays = 90 }, "audit.retention_days", false},
		{"llm analyzer", func(c *Config) { c.Intent.Analyzer = "hybrid" }, "intent.analyzer", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := Defaults()
			c.set(cfg)
			var got *Issue
			for _, i := range Validate(cfg) {
				if i.Field == c.field {
					cp := i
					got = &cp
				}
			}
			if got == nil {
				t.Fatalf("%s set but no issue reported for %s", c.name, c.field)
			}
			if got.Fatal != c.fatal {
				t.Errorf("%s: fatal = %v, want %v (%s)", c.field, got.Fatal, c.fatal, got.Message)
			}
			if !strings.Contains(got.Message, "not implemented") {
				t.Errorf("%s: message does not say it is unimplemented: %q", c.field, got.Message)
			}
		})
	}
}

// The logging settings are honoured, so a valid value reports nothing and an
// unusable one refuses startup rather than falling back to stderr.
func TestLoggingSettingsAreValidated(t *testing.T) {
	for _, set := range []func(*Config){
		func(c *Config) { c.Logging.Level = "debug" },
		func(c *Config) { c.Logging.Format = "json" },
		func(c *Config) { c.Logging.Output = "/var/log/allseer/allseerd.log" },
		func(c *Config) { c.Logging.Output = "stdout" },
		func(c *Config) { c.Logging.AddSource = true },
	} {
		cfg := Defaults()
		set(cfg)
		for _, i := range Validate(cfg) {
			if strings.HasPrefix(i.Field, "logging.") {
				t.Errorf("a valid logging setting reported %s: %s", i.Field, i.Message)
			}
		}
	}
	for field, set := range map[string]func(*Config){
		"logging.level":  func(c *Config) { c.Logging.Level = "verbose" },
		"logging.format": func(c *Config) { c.Logging.Format = "xml" },
		"logging.output": func(c *Config) { c.Logging.Output = "allseerd.log" },
	} {
		cfg := Defaults()
		set(cfg)
		fatal := false
		for _, i := range Validate(cfg) {
			fatal = fatal || (i.Field == field && i.Fatal)
		}
		if !fatal {
			t.Errorf("an unusable %s was not refused", field)
		}
	}
}

// The built-in defaults must describe what the daemon does, so starting with
// no configuration file at all reports nothing.
func TestDefaultsReportNoIssues(t *testing.T) {
	if issues := Validate(Defaults()); len(issues) != 0 {
		for _, i := range issues {
			t.Errorf("default config reports %s: %s (fatal %v)", i.Field, i.Message, i.Fatal)
		}
	}
}

// The shipped example is what a deployment starts from, so it has to load.
func TestExampleConfigLoadsAndReportsNothingFatal(t *testing.T) {
	c, err := FileLoader{}.Load(context.Background(), "../../configs/allseerd.example.yaml")
	if err != nil {
		t.Fatalf("loading the shipped example: %v", err)
	}
	for _, i := range Validate(c) {
		if i.Fatal {
			t.Errorf("the shipped example is fatal at %s: %s", i.Field, i.Message)
		} else {
			t.Logf("example warns at %s: %s", i.Field, i.Message)
		}
	}
}

// Rotation is on by default and bounded; switching it off is allowed and said
// out loud, and a negative bound is refused.
func TestAuditRotationSettings(t *testing.T) {
	c := Defaults()
	if c.Audit.MaxSizeMB <= 0 || c.Audit.MaxFiles <= 0 {
		t.Fatalf("defaults rotate at %d MB keeping %d files, want both bounded", c.Audit.MaxSizeMB, c.Audit.MaxFiles)
	}
	for _, i := range Validate(c) {
		if i.Field == "audit.max_size_mb" {
			t.Errorf("default rotation reports %+v", i)
		}
	}

	c.Audit.MaxSizeMB = 0
	warned := false
	for _, i := range Validate(c) {
		warned = warned || (i.Field == "audit.max_size_mb" && !i.Fatal)
	}
	if !warned {
		t.Error("rotation switched off without a warning")
	}

	c.Audit.MaxSizeMB, c.Audit.MaxFiles = 100, -1
	if len(Fatal(Validate(c))) == 0 {
		t.Error("a negative max_files was accepted")
	}
}
