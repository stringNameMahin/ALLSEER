package config

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/stringNameMahin/ALLSEER/internal/logging"
	"github.com/stringNameMahin/ALLSEER/internal/policy"
	"github.com/stringNameMahin/ALLSEER/internal/telemetry"
)

// Defaults returns the configuration a daemon runs with when nothing is
// configured. Every security-relevant value is the safe one: monitor mode,
// approval required, fail closed on telemetry loss.
func Defaults() *Config {
	return &Config{
		Daemon: DaemonConfig{
			SocketPath: "/run/allseer/allseerd.sock",
			// Authorization is by SO_PEERCRED per request, not by file mode, so
			// any local user may connect and govern their own processes.
			SocketMode:            0o666,
			StateDir:              "/var/lib/allseer",
			MaxConcurrentSessions: 8,
			ShutdownGrace:         30 * time.Second,
		},
		Telemetry: telemetry.Config{
			ObjectPath:       "/usr/lib/allseer/allseer.bpf.o",
			RingBufferSize:   8 << 20,
			EventChannelSize: 16384,
			FailClosedOnDrop: true,
		},
		Intent: IntentConfig{
			Analyzer:        "rules",
			Timeout:         20 * time.Second,
			FallbackToRules: true,
		},
		Envelope: EnvelopeConfig{
			RequireApproval: true,
			DefaultTTL:      time.Hour,
			MaxGrants:       64,
		},
		Risk: RiskConfig{
			SensitivityPath: "/etc/allseer/sensitivity.yaml",
		},
		Policy: PolicyConfig{
			RuleSetPath:           "/etc/allseer/rules.yaml",
			DefaultMode:           policy.ModeMonitor,
			ApprovalTimeout:       5 * time.Minute,
			ApprovalTimeoutAction: "deny",
		},
		Audit: AuditConfig{
			Path:            "/var/lib/allseer/audit.jsonl",
			Format:          "jsonl",
			RecordAllEvents: true,
			SyncWrites:      false,
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "text",
			Output: "stderr",
		},
	}
}

// FileLoader loads YAML configuration over the defaults.
type FileLoader struct{}

var _ Loader = FileLoader{}

// Load reads path over Defaults. An empty path returns the defaults. Unknown
// keys are refused, so a misspelled security setting cannot silently fall back
// to a default.
func (FileLoader) Load(_ context.Context, path string) (*Config, error) {
	c := Defaults()
	if path == "" {
		return c, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("config: %s: %w", path, err)
	}
	return c, nil
}

// Validate reports problems with c. Fatal issues must refuse startup.
func (FileLoader) Validate(c *Config) []Issue { return Validate(c) }

// Validate reports problems with c.
func Validate(c *Config) []Issue {
	var out []Issue
	fatal := func(field, format string, a ...any) {
		out = append(out, Issue{Field: field, Message: fmt.Sprintf(format, a...), Fatal: true})
	}
	warn := func(field, format string, a ...any) {
		out = append(out, Issue{Field: field, Message: fmt.Sprintf(format, a...)})
	}

	if !filepath.IsAbs(c.Daemon.SocketPath) {
		fatal("daemon.socket_path", "must be absolute, got %q", c.Daemon.SocketPath)
	}
	if c.Daemon.SocketMode > 0o777 {
		fatal("daemon.socket_mode", "%o is not a permission mode", c.Daemon.SocketMode)
	}
	if c.Daemon.MaxConcurrentSessions <= 0 {
		fatal("daemon.max_concurrent_sessions", "must be positive")
	}
	if c.Telemetry.ObjectPath == "" {
		fatal("telemetry.object_path", "is required")
	}
	if !ValidMode(c.Policy.DefaultMode) {
		fatal("policy.default_mode", "unknown mode %q", c.Policy.DefaultMode)
	}
	if c.Policy.RuleSetPath == "" {
		fatal("policy.rule_set_path", "is required")
	}
	switch c.Policy.ApprovalTimeoutAction {
	case "deny":
	case "allow":
		warn("policy.approval_timeout_action", "allow on timeout lets an unattended agent continue past every approval request")
	default:
		fatal("policy.approval_timeout_action", "must be deny or allow, got %q", c.Policy.ApprovalTimeoutAction)
	}
	if c.Policy.ApprovalTimeout <= 0 {
		fatal("policy.approval_timeout", "must be positive")
	}
	if c.Audit.Path == "" {
		fatal("audit.path", "is required: a daemon must not govern without an audit trail")
	}
	if _, err := logging.ParseLevel(c.Logging.Level); err != nil {
		fatal("logging.level", "%v", err)
	}
	if err := logging.CheckFormat(c.Logging.Format); err != nil {
		fatal("logging.format", "%v", err)
	}
	if err := logging.CheckOutput(c.Logging.Output); err != nil {
		fatal("logging.output", "%v", err)
	}
	if !c.Telemetry.FailClosedOnDrop {
		warn("telemetry.fail_closed_on_drop", "disabled: sessions continue across telemetry gaps")
	}
	if !c.Envelope.RequireApproval {
		warn("envelope.require_approval", "disabled: envelopes are sealed without a human reading them")
	}
	if c.Envelope.AutoApproveBelowRisk > 0 {
		warn("envelope.auto_approve_below_risk", "set: some envelopes are approved without a human")
	}
	out = append(out, unimplemented(c)...)
	return out
}

// unimplemented reports settings this build accepts and does not act on.
//
// A configuration field that parses and then does nothing is worse than a
// missing one. The operator who writes drop_privileges: true has every reason
// to believe the daemon drops privileges, and nothing in the log or the status
// output would tell them otherwise. Each of these is reported with what the
// build actually does instead, so the gap is visible at startup rather than
// after an incident.
//
// Security-relevant settings are fatal when they are switched on: silently
// running with less protection than the file asks for is the failure this
// function exists to prevent. The rest warn, because the daemon's behaviour is
// still correct, just not configurable yet.
func unimplemented(c *Config) []Issue {
	var out []Issue
	ignored := func(field, what string) {
		out = append(out, Issue{Field: field, Message: "not implemented in this build: " + what})
	}
	refuse := func(field, what string) {
		out = append(out, Issue{Field: field, Message: "not implemented in this build: " + what, Fatal: true})
	}

	if c.Daemon.DropPrivileges {
		refuse("daemon.drop_privileges",
			"the daemon stays root for its lifetime; unset this or do not rely on it")
	}
	if c.Daemon.RunAsUser != "" {
		refuse("daemon.run_as_user", "privilege dropping is not implemented, so this user is never switched to")
	}
	if c.Intent.EnableSanitizer {
		refuse("intent.enable_sanitizer",
			"no prompt-injection sanitizer exists; prompts reach the analyzer unfiltered")
	}
	if c.Telemetry.EnableDNSCorrelation {
		ignored("telemetry.enable_dns_correlation",
			"no DNS correlator exists, so hostname grants cannot match and connections reach policy by address")
	}
	if c.Telemetry.EnableBinaryHashing {
		ignored("telemetry.enable_binary_hashing", "executables are not hashed")
	}
	if c.Audit.MaxSizeMB > 0 || c.Audit.RetentionDays > 0 {
		ignored("audit.max_size_mb", "the audit log is never rotated or pruned; it grows without bound")
	}
	if c.Intent.Analyzer == "llm" || c.Intent.Analyzer == "hybrid" {
		ignored("intent.analyzer",
			"only the deterministic rule analyzer is built, and it is what runs whatever this says")
	}
	return out
}

// Fatal returns the fatal subset of issues.
func Fatal(issues []Issue) []Issue {
	var out []Issue
	for _, i := range issues {
		if i.Fatal {
			out = append(out, i)
		}
	}
	return out
}

// ModeRank orders enforcement modes from least to most restrictive.
func ModeRank(m policy.Mode) int {
	switch m {
	case policy.ModeMonitor:
		return 0
	case policy.ModeWarn:
		return 1
	case policy.ModeInteractive:
		return 2
	case policy.ModeEnforce:
		return 3
	}
	return -1
}

// ValidMode reports whether m is a known mode.
func ValidMode(m policy.Mode) bool { return ModeRank(m) >= 0 }

// Restrict returns the stricter of the configured and requested modes. A
// request can tighten governance but never loosen it.
func Restrict(configured, requested policy.Mode) policy.Mode {
	if ModeRank(requested) > ModeRank(configured) {
		return requested
	}
	return configured
}
