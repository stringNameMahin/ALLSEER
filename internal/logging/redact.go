package logging

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"
)

// Redacted replaces a value, or the part of one, that must not be logged.
const Redacted = "[REDACTED]"

// Redactor removes or masks sensitive data before it is logged.
//
// An agent's command line may contain a token, and an error string may quote
// a URL with a password in it. Redaction is applied at the handler so no
// individual call site has to remember.
type Redactor interface {
	// Redact returns a safe version of a value for a given field name.
	Redact(field string, value any) any

	// ShouldRedact reports whether a field is dropped whole.
	ShouldRedact(field string) bool
}

// Rules is the redaction the daemon applies. Fields whose names say they hold
// a secret are dropped whole, and every string that reaches the log is scrubbed
// of credential shapes.
//
// Paths are deliberately left alone, home directories included. A denied read
// of a credential file is reported by its path, and a log that hid the path
// would hide the finding.
type Rules struct{}

var _ Redactor = Rules{}

// DefaultRedactor returns the rules the daemon logs with.
func DefaultRedactor() Redactor { return Rules{} }

// sensitiveNames match anywhere in a field name once separators are removed,
// so api_key, apiKey and API-KEY are all caught.
var sensitiveNames = []string{
	"password", "passwd", "secret", "token", "apikey", "accesskey", "privatekey",
	"authorization", "cookie", "credential", "prompt",
}

// sensitiveWords match one whole segment of a field name. They are too short
// to match as substrings: "env" would catch every "environment_ok".
var sensitiveWords = map[string]bool{"env": true, "environ": true, "auth": true}

// ShouldRedact implements Redactor.
func (Rules) ShouldRedact(field string) bool {
	f := strings.ToLower(field)
	compact := strings.NewReplacer("_", "", "-", "", ".", "", " ", "").Replace(f)
	for _, n := range sensitiveNames {
		if strings.Contains(compact, n) {
			return true
		}
	}
	for _, w := range strings.FieldsFunc(f, func(r rune) bool {
		return r == '_' || r == '-' || r == '.' || r == ' '
	}) {
		if sensitiveWords[w] {
			return true
		}
	}
	return false
}

// Redact implements Redactor. Strings, errors and Stringers are scrubbed;
// anything else is scrubbed through its JSON form and replaced by that form
// only when something had to be removed, so clean values keep their shape.
func (r Rules) Redact(field string, value any) any {
	if r.ShouldRedact(field) {
		return Redacted
	}
	switch v := value.(type) {
	case nil, bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64,
		float32, float64, time.Time, time.Duration:
		return value
	case string:
		return Scrub(v)
	case []byte:
		if s := Scrub(string(v)); s != string(v) {
			return s
		}
		return value
	case error:
		if s := Scrub(v.Error()); s != v.Error() {
			return s
		}
		return value
	case fmt.Stringer:
		if s := Scrub(v.String()); s != v.String() {
			return s
		}
		return value
	}
	raw, err := json.Marshal(value)
	if err != nil {
		// Not representable as JSON, so check what a text handler would print.
		text := fmt.Sprintf("%+v", value)
		if s := Scrub(text); s != text {
			return s
		}
		return value
	}
	if s := Scrub(string(raw)); s != string(raw) {
		return s
	}
	return value
}

// pattern is one credential shape and what replaces it.
type pattern struct {
	re   *regexp.Regexp
	repl string
}

// The secret-bearing key names a key=value or --flag value pair is matched on.
const secretKey = `(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|credentials?)`

// secretPair is such a key and its separator, up to where the value starts.
const secretPair = `[a-z0-9_.-]*` + secretKey + `[a-z0-9_.-]*["']?\s*[=:]\s*`

// patterns are applied in order. The structural ones come first, so a token
// inside an Authorization header is removed with its header, not left as a
// header with a token-shaped hole.
var patterns = []pattern{
	// PEM private keys, through the END line or the end of the string.
	{regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)`), Redacted},
	// A password in a URL: scheme://user:password@host.
	{regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://[^\s/:@]+:)[^\s/@]+@`), "${1}" + Redacted + "@"},
	// An Authorization header, whatever its scheme.
	{regexp.MustCompile(`(?i)(authorization["']?\s*[:=]\s*["']?(?:(?:basic|bearer|digest|token|negotiate)\s+)?)[^\s"',;]+`), "${1}" + Redacted},
	// A bearer token outside a header.
	{regexp.MustCompile(`(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{16,}`), "${1}" + Redacted},
	// --password hunter2, --api-key=abc. The flag has to start a word, so a
	// path such as /home/dev/my-token-file is not read as one.
	{regexp.MustCompile(`(?i)(^|[\s"'])(--?[a-z0-9-]*` + secretKey + `[a-z0-9-]*[ =])[^\s"']+`), "${1}${2}" + Redacted},
	// password=hunter2, "token": "abc", ?api_key=x. The key may not follow a
	// path character, so "open /home/dev/.git-credentials: permission denied"
	// keeps its reason.
	// A quoted value keeps its quotes, so a scrubbed JSON fragment still reads
	// as JSON.
	{regexp.MustCompile(`(?i)(^|[^\w./-])(` + secretPair + `)"[^"]*"`), `${1}${2}"` + Redacted + `"`},
	{regexp.MustCompile(`(?i)(^|[^\w./-])(` + secretPair + `)'[^']*'`), `${1}${2}'` + Redacted + `'`},
	{regexp.MustCompile(`(?i)(^|[^\w./-])(` + secretPair + `)[^\s"',;&]+`), "${1}${2}" + Redacted},
	// Token formats recognisable on their own.
	{regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{16}\b`), Redacted},
	{regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b`), Redacted},
	{regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}\b`), Redacted},
	{regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}\b`), Redacted},
	{regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}\b`), Redacted},
	{regexp.MustCompile(`\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}\b`), Redacted},
	{regexp.MustCompile(`\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b`), Redacted},
	{regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`), Redacted},
	{regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`), Redacted},
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`), Redacted},
}

// Scrub removes credential shapes from s.
func Scrub(s string) string {
	for _, p := range patterns {
		s = p.re.ReplaceAllString(s, p.repl)
	}
	return s
}

// RedactingHandler applies a Redactor to every record before passing it on.
type RedactingHandler struct {
	next slog.Handler
	r    Redactor
}

var _ slog.Handler = (*RedactingHandler)(nil)

// NewRedactingHandler wraps next.
func NewRedactingHandler(next slog.Handler, r Redactor) *RedactingHandler {
	return &RedactingHandler{next: next, r: r}
}

// Enabled implements slog.Handler.
func (h *RedactingHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.next.Enabled(ctx, l)
}

// Handle implements slog.Handler. The message is redacted too: a call site
// that formats a value into its message has not escaped the boundary.
func (h *RedactingHandler) Handle(ctx context.Context, rec slog.Record) error {
	msg := fmt.Sprint(h.r.Redact(slog.MessageKey, rec.Message))
	out := slog.NewRecord(rec.Time, rec.Level, msg, rec.PC)
	rec.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(h.attr(a))
		return true
	})
	return h.next.Handle(ctx, out)
}

// WithAttrs implements slog.Handler. Attributes bound once are redacted once.
func (h *RedactingHandler) WithAttrs(as []slog.Attr) slog.Handler {
	out := make([]slog.Attr, len(as))
	for i, a := range as {
		out[i] = h.attr(a)
	}
	return &RedactingHandler{next: h.next.WithAttrs(out), r: h.r}
}

// WithGroup implements slog.Handler.
func (h *RedactingHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return &RedactingHandler{next: h.next.WithGroup(name), r: h.r}
}

func (h *RedactingHandler) attr(a slog.Attr) slog.Attr {
	v := a.Value.Resolve()
	if h.r.ShouldRedact(a.Key) {
		return slog.String(a.Key, Redacted)
	}
	switch v.Kind() {
	case slog.KindGroup:
		group := v.Group()
		out := make([]slog.Attr, len(group))
		for i, g := range group {
			out[i] = h.attr(g)
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(out...)}
	case slog.KindString:
		return slog.Any(a.Key, h.r.Redact(a.Key, v.String()))
	case slog.KindAny:
		return slog.Any(a.Key, h.r.Redact(a.Key, v.Any()))
	}
	return slog.Attr{Key: a.Key, Value: v}
}
