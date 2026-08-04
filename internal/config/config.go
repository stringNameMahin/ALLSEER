// Package config defines ALLSEER's configuration surface.
//
// Configuration is layered: defaults, then file, then environment, then command
// line, with later layers overriding earlier ones. That ordering is
// conventional; one rule here is not. Security-relevant settings may only be
// restricted by later layers, never relaxed. An environment variable must not
// be able to downgrade a system configured for enforce mode into monitor mode,
// because the environment is what a compromised agent is best positioned to
// influence.
//
// Configuration is validated once at load and immutable thereafter. Policy
// rules hot-reload; configuration does not.
package config

import (
	"context"
	"time"

	"github.com/stringNameMahin/ALLSEER/internal/policy"
	"github.com/stringNameMahin/ALLSEER/internal/telemetry"
)

// Config is the complete daemon configuration.
type Config struct {
	Daemon    DaemonConfig     `json:"daemon" yaml:"daemon"`
	Telemetry telemetry.Config `json:"telemetry" yaml:"telemetry"`
	Intent    IntentConfig     `json:"intent" yaml:"intent"`
	Envelope  EnvelopeConfig   `json:"envelope" yaml:"envelope"`
	Risk      RiskConfig       `json:"risk" yaml:"risk"`
	Policy    PolicyConfig     `json:"policy" yaml:"policy"`
	Audit     AuditConfig      `json:"audit" yaml:"audit"`
	Logging   LoggingConfig    `json:"logging" yaml:"logging"`
}

// DaemonConfig configures the daemon process.
type DaemonConfig struct {
	// SocketPath is the control socket the CLI and shim connect to. Its
	// permissions are a security boundary: anyone who can write to it can
	// create sessions and therefore define what an agent is allowed to do.
	SocketPath string `json:"socket_path" yaml:"socket_path"`

	// SocketMode is the Unix permission bits for the socket.
	SocketMode uint32 `json:"socket_mode" yaml:"socket_mode"`

	// StateDir holds persistent state: sessions, envelopes, audit logs.
	StateDir string `json:"state_dir" yaml:"state_dir"`

	MaxConcurrentSessions int           `json:"max_concurrent_sessions" yaml:"max_concurrent_sessions"`
	ShutdownGrace         time.Duration `json:"shutdown_grace" yaml:"shutdown_grace"`

	// DropPrivileges lowers privileges after eBPF programs are loaded. Loading
	// needs CAP_BPF and CAP_SYS_ADMIN; steady-state operation does not, and
	// keeping them is a standing risk for nothing.
	DropPrivileges bool `json:"drop_privileges" yaml:"drop_privileges"`

	// RunAsUser is the user to drop to when DropPrivileges is set.
	RunAsUser string `json:"run_as_user,omitempty" yaml:"run_as_user,omitempty"`
}

// IntentConfig configures intent analysis.
type IntentConfig struct {
	// Analyzer selects the implementation: "rules", "llm", or "hybrid".
	Analyzer string `json:"analyzer" yaml:"analyzer"`

	// LLM configures the model-backed analyzer.
	LLM LLMConfig `json:"llm" yaml:"llm"`

	// Timeout bounds analysis. Analysis happens before the agent starts, so a
	// slow analyzer delays task start rather than any syscall.
	Timeout time.Duration `json:"timeout" yaml:"timeout"`

	// FallbackToRules uses the rule analyzer when the LLM is unavailable. When
	// false, LLM failure blocks the session: safer, less usable.
	FallbackToRules bool `json:"fallback_to_rules" yaml:"fallback_to_rules"`

	// EnableSanitizer runs prompt-injection detection before analysis.
	EnableSanitizer bool `json:"enable_sanitizer" yaml:"enable_sanitizer"`
}

// LLMConfig configures the model-backed analyzer.
type LLMConfig struct {
	// Provider is the API provider. Currently "anthropic".
	Provider string `json:"provider" yaml:"provider"`

	// Model is the model identifier.
	Model string `json:"model" yaml:"model"`

	// APIKeyEnv names the environment variable holding the key. The key itself
	// is never stored in configuration, so a config file can be committed and
	// shared without leaking credentials.
	APIKeyEnv string `json:"api_key_env" yaml:"api_key_env"`

	// BaseURL overrides the API endpoint.
	BaseURL string `json:"base_url,omitempty" yaml:"base_url,omitempty"`

	MaxTokens  int           `json:"max_tokens" yaml:"max_tokens"`
	Timeout    time.Duration `json:"timeout" yaml:"timeout"`
	MaxRetries int           `json:"max_retries" yaml:"max_retries"`
}

// EnvelopeConfig configures ECE generation.
type EnvelopeConfig struct {
	// ProfileDir holds profile definitions.
	ProfileDir string `json:"profile_dir" yaml:"profile_dir"`

	// RequireApproval demands human sign-off before any envelope takes effect.
	RequireApproval bool `json:"require_approval" yaml:"require_approval"`

	// AutoApproveBelowRisk skips approval when the envelope's aggregate risk is
	// below this threshold. A usability concession, and the setting most likely
	// to quietly disable the human-in-the-loop guarantee.
	AutoApproveBelowRisk float64 `json:"auto_approve_below_risk" yaml:"auto_approve_below_risk"`

	DefaultTTL time.Duration `json:"default_ttl" yaml:"default_ttl"`
	MaxGrants  int           `json:"max_grants" yaml:"max_grants"`
}

// RiskConfig configures risk scoring.
type RiskConfig struct {
	// EnabledScorers selects active scorers by name. Empty means all.
	EnabledScorers []string `json:"enabled_scorers" yaml:"enabled_scorers"`

	// ScorerWeights overrides individual scorer weights, so tuning does not
	// require a rebuild.
	ScorerWeights map[string]float64 `json:"scorer_weights,omitempty" yaml:"scorer_weights,omitempty"`

	// SensitivePaths and SensitiveHosts add deployment-specific locations on top
	// of the built-in set.
	SensitivePaths []string `json:"sensitive_paths,omitempty" yaml:"sensitive_paths,omitempty"`
	SensitiveHosts []string `json:"sensitive_hosts,omitempty" yaml:"sensitive_hosts,omitempty"`

	// Thresholds map risk scores to levels.
	Thresholds map[string]float64 `json:"thresholds,omitempty" yaml:"thresholds,omitempty"`

	// EnableBaseline turns on behavioral baseline learning.
	EnableBaseline bool `json:"enable_baseline" yaml:"enable_baseline"`
}

// PolicyConfig configures the policy engine.
type PolicyConfig struct {
	// RuleSetPath is the active rule set file.
	RuleSetPath string `json:"rule_set_path" yaml:"rule_set_path"`

	// DefaultMode is the enforcement posture when a session does not specify
	// one. Defaults to monitor: a system that starts out blocking will be
	// uninstalled before it is trusted.
	DefaultMode policy.Mode `json:"default_mode" yaml:"default_mode"`

	// HotReload watches the rule set file for changes.
	HotReload bool `json:"hot_reload" yaml:"hot_reload"`

	// ApprovalTimeout bounds how long to wait for a human answer.
	ApprovalTimeout time.Duration `json:"approval_timeout" yaml:"approval_timeout"`

	// ApprovalTimeoutAction is applied when no one answers in time.
	ApprovalTimeoutAction string `json:"approval_timeout_action" yaml:"approval_timeout_action"`
}

// AuditConfig configures decision recording.
type AuditConfig struct {
	Path string `json:"path" yaml:"path"`

	// Format is "jsonl" or "cbor".
	Format string `json:"format" yaml:"format"`

	// RecordAllEvents logs every event, not just violations. Expensive, and
	// necessary for research analysis and replay-based development.
	RecordAllEvents bool `json:"record_all_events" yaml:"record_all_events"`

	MaxSizeMB     int `json:"max_size_mb" yaml:"max_size_mb"`
	RetentionDays int `json:"retention_days" yaml:"retention_days"`

	// SyncWrites forces fsync per record. Slower, but without it a crash loses
	// exactly the records most likely to matter.
	SyncWrites bool `json:"sync_writes" yaml:"sync_writes"`
}

// LoggingConfig configures diagnostic output.
type LoggingConfig struct {
	// Level is "debug", "info", "warn", or "error".
	Level string `json:"level" yaml:"level"`

	// Format is "json" or "text".
	Format string `json:"format" yaml:"format"`

	// Output is "stdout", "stderr", or a file path.
	Output string `json:"output" yaml:"output"`

	// AddSource includes file and line in log records.
	AddSource bool `json:"add_source" yaml:"add_source"`
}

// Loader reads and validates configuration.
type Loader interface {
	// Load builds the effective configuration from all layers.
	Load(ctx context.Context, path string) (*Config, error)

	// Validate checks a configuration for correctness and internal consistency.
	Validate(c *Config) []Issue
}

// Issue is a configuration problem.
type Issue struct {
	// Field is the dotted path to the offending setting.
	Field string `json:"field"`

	// Message explains the problem.
	Message string `json:"message"`

	// Fatal reports whether this prevents startup. Non-fatal issues are
	// warnings: a permissive-but-valid setting should be surfaced loudly
	// without refusing to start.
	Fatal bool `json:"fatal"`
}

// TODO(config): provide Defaults(). Every default has to be the safe choice:
// monitor mode, approval required, fail-closed on telemetry loss. See
// configs/allseerd.example.yaml for the intended values.
// TODO(config): implement layered loading with the restrict-only override rule
// for security-relevant fields.
// TODO(config): enumerate which fields are security-relevant and therefore
// restrict-only. That list is itself a security control and belongs in docs/,
// not only in code.
// TODO(config): add `allseerctl config validate` so misconfiguration is caught
// before a session depends on it.
// TODO(config): decide the config file format. YAML is friendlier to write;
// JSON needs no extra dependency. Leaning YAML, accepting one dependency.
