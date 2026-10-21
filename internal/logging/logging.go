// Package logging builds the daemon's diagnostic logger.
//
// This is for diagnostics only: what the daemon is doing and whether it is
// healthy. It is not the audit trail. Governance decisions go to the audit sink
// in pkg/decision, which has different requirements around durability,
// completeness, and tamper evidence. Conflating the two produces an audit trail
// that can be silenced by a log level, which is not an audit trail.
//
// The logger is a plain *slog.Logger. What this package controls is its
// handler: every record passes through a redacting handler before it is
// written, so no call site has to remember which values are sensitive. That
// boundary is the reason the package exists, and wrapping slog in an interface
// of its own would add nothing to it.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
)

// Options selects how and where diagnostics are written. It mirrors
// config.LoggingConfig; config validates with the checks below, so this
// package does not import config.
type Options struct {
	// Level is debug, info, warn or error. Empty is info.
	Level string

	// Format is text or json. Empty is text.
	Format string

	// Output is stderr, stdout or an absolute file path. Empty is stderr.
	Output string

	// AddSource includes the file and line of the call site.
	AddSource bool
}

// FileMode is the permission a log file is created with. Diagnostics carry
// paths, users and session identifiers, so they are not world-readable. An
// existing file keeps its mode, as the audit log does.
const FileMode os.FileMode = 0o600

// ParseLevel reads a configured level.
func ParseLevel(s string) (slog.Level, error) {
	switch s {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("logging: unknown level %q; want debug, info, warn or error", s)
}

// CheckFormat reports whether s is a format this build writes.
func CheckFormat(s string) error {
	switch s {
	case "", "text", "json":
		return nil
	}
	return fmt.Errorf("logging: unknown format %q; want text or json", s)
}

// CheckOutput reports whether s names a usable destination. A relative path
// is refused: the daemon's working directory is not something an operator
// chose, so the file would land somewhere nobody looks.
func CheckOutput(s string) error {
	switch s {
	case "", "stderr", "stdout":
		return nil
	}
	if !filepath.IsAbs(s) {
		return fmt.Errorf("logging: output %q must be stderr, stdout or an absolute path", s)
	}
	return nil
}

// New builds a redacting logger. The Closer releases the log file, and does
// nothing when the output is a stream.
func New(o Options, stdout, stderr io.Writer) (*slog.Logger, io.Closer, error) {
	level, err := ParseLevel(o.Level)
	if err != nil {
		return nil, nil, err
	}
	if err := CheckFormat(o.Format); err != nil {
		return nil, nil, err
	}
	if err := CheckOutput(o.Output); err != nil {
		return nil, nil, err
	}

	var w io.Writer
	var c io.Closer = nopCloser{}
	switch o.Output {
	case "", "stderr":
		w = stderr
	case "stdout":
		w = stdout
	default:
		f, err := os.OpenFile(o.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, FileMode)
		if err != nil {
			return nil, nil, fmt.Errorf("logging: opening %s: %w", o.Output, err)
		}
		w, c = f, f
	}

	ho := &slog.HandlerOptions{Level: level, AddSource: o.AddSource}
	var h slog.Handler = slog.NewTextHandler(w, ho)
	if o.Format == "json" {
		h = slog.NewJSONHandler(w, ho)
	}
	return slog.New(NewRedactingHandler(h, DefaultRedactor())), c, nil
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

// TODO(logging): add sampling for high-frequency debug records. Per-event debug
// logging becomes a performance problem of its own at realistic event rates.
// TODO(logging): decide whether to emit OpenTelemetry traces. Valuable for
// latency analysis, but a substantial dependency for a project trying to keep
// them at zero.
// TODO(logging): change the level at runtime. slog.LevelVar makes it cheap; it
// needs a control RPC, and none exists yet.
