package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

// Each case holds a secret, and the secret must not survive.
func TestScrubRemovesCredentialShapes(t *testing.T) {
	cases := []struct{ name, in, secret, keep string }{
		{"pem key", "key: -----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjE\n-----END OPENSSH PRIVATE KEY----- done",
			"b3BlbnNzaC1rZXktdjE", "done"},
		{"unterminated pem", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA", "MIIEowIBAAKCAQEA", ""},
		{"url password", "fetching https://dev:hunter2@git.example.com/r.git", "hunter2", "https://dev:[REDACTED]@git.example.com/r.git"},
		{"auth header bearer", "Authorization: Bearer abc.def.ghi", "abc.def.ghi", "Authorization: Bearer [REDACTED]"},
		{"auth header token", `curl -H 'Authorization: token q1w2e3r4t5'`, "q1w2e3r4t5", "curl -H"},
		{"bare bearer", "sent bearer 0123456789abcdefXYZ upstream", "0123456789abcdefXYZ", "upstream"},
		{"flag space", "tool --password hunter2 --verbose", "hunter2", "--verbose"},
		{"flag equals", "tool --api-key=s3cr3tvalue", "s3cr3tvalue", "--api-key="},
		{"key equals", "connecting with password=hunter2 now", "hunter2", "now"},
		{"json key", `{"token":"abc123","user":"dev"}`, "abc123", `{"token":"[REDACTED]","user":"dev"}`},
		{"yaml key", "api_key: 'xyz789'", "xyz789", "api_key: '[REDACTED]'"},
		{"query", "GET /cb?access_key=AK123&x=1", "AK123", "&x=1"},
		{"aws", "id AKIAIOSFODNN7EXAMPLE used", "AKIAIOSFODNN7EXAMPLE", "used"},
		{"github", "ghp_" + strings.Repeat("a1B2", 9), "ghp_a1B2", ""},
		{"github pat", "github_pat_11ABCDEFG0123456789_abcdefghijklmnop", "11ABCDEFG", ""},
		{"gitlab", "glpat-abcdefghij0123456789", "glpat-abcdef", ""},
		{"slack", "xoxb-1234567890-abcdefghij", "xoxb-12345", ""},
		{"anthropic", "sk-ant-api03-abcdefghijklmnopqrstuvwxyz012345", "abcdefghijklmnop", ""},
		{"stripe", "sk_live_abcdefghijklmnop1234", "sk_live_abc", ""},
		{"google", "AIza" + strings.Repeat("x", 35), "AIzaxxx", ""},
		{"npm", "npm_" + strings.Repeat("A", 36), "npm_AAA", ""},
		{"jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N", "eyJzdWIiOiIx", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Scrub(c.in)
			if strings.Contains(got, c.secret) {
				t.Errorf("Scrub(%q) = %q still holds %q", c.in, got, c.secret)
			}
			if !strings.Contains(got, Redacted) {
				t.Errorf("Scrub(%q) = %q does not mark what it removed", c.in, got)
			}
			if c.keep != "" && !strings.Contains(got, c.keep) {
				t.Errorf("Scrub(%q) = %q lost %q, which is not secret", c.in, got, c.keep)
			}
		})
	}
}

// What the daemon actually logs has to come through unchanged. A redactor that
// hid paths or identifiers would hide the findings the log is for.
func TestScrubLeavesDiagnosticsAlone(t *testing.T) {
	for _, s := range []string{
		"/home/dev/.ssh/id_rsa",
		`fs.read on "/home/dev/.aws/credentials"`,
		"open /home/dev/.git-credentials: permission denied",
		"/home/dev/my-token-file x",
		"/run/secrets/db_password",
		"s-20261019t111300-eafef3eb",
		"apr-s-20261019t111310-3a5af6c1-2",
		"sha256:5a19cf8f010e89cb509aa0308f480eadd805afa47979f9ecc1c145b8cd380299",
		"203.0.113.9:443",
		"terminated: block in enforce mode, with no human to ask",
		"verdict explicitly_denied, risk 100 (critical), rule envelope-explicit-denial",
		"the token was refused by the server",
		"disk-usage-0123456789abcdefghijklmnop",
		"approval apr-1 denied by dev: too broad",
	} {
		if got := Scrub(s); got != s {
			t.Errorf("Scrub(%q) = %q; a diagnostic was altered", s, got)
		}
	}
}

func TestFieldNamesThatHoldSecrets(t *testing.T) {
	r := Rules{}
	for _, f := range []string{"password", "api_key", "apiKey", "API-KEY", "auth_token", "Authorization",
		"cookie", "prompt", "raw_prompt", "env", "agent.env", "auth", "client_secret", "credentials"} {
		if !r.ShouldRedact(f) {
			t.Errorf("ShouldRedact(%q) = false", f)
		}
	}
	for _, f := range []string{"session", "decision", "path", "err", "summary", "reason", "author",
		"environment_ok", "probe", "owner", "uid", "detail"} {
		if r.ShouldRedact(f) {
			t.Errorf("ShouldRedact(%q) = true; an ordinary field was dropped", f)
		}
	}
}

type secretStringer struct{}

func (secretStringer) String() string { return "dial https://u:pw12345@host" }

type logValuer struct{}

func (logValuer) LogValue() slog.Value { return slog.StringValue("password=fromvaluer") }

// One record exercising every place a value can sit: the message, a string,
// an error, a Stringer, a group, a struct, a LogValuer, and attributes bound
// with With. None of the secrets may reach the output.
func TestHandlerRedactsEveryValueKind(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(NewRedactingHandler(slog.NewJSONHandler(&buf, nil), Rules{}))
	log = log.With("bound_token", "boundsecret", "bound_url", "https://u:boundpw@h")

	type creds struct {
		User     string `json:"user"`
		Password string `json:"password"`
	}
	type clean struct {
		N    int    `json:"n"`
		Path string `json:"path"`
	}
	log.WithGroup("g").Info("retrying with password=msgsecret",
		"password", "fieldsecret",
		"err", errors.New("fetch https://u:errpw@h failed"),
		"path", "/home/dev/.ssh/id_rsa",
		"nested", slog.Group("inner", "token", "groupsecret", "url", "https://u:grouppw@h"),
		"stringer", secretStringer{},
		"creds", creds{User: "dev", Password: "structsecret"},
		"clean", clean{N: 3, Path: "/w"},
		"valuer", logValuer{},
		"n", 7,
		// A secret is not always a string, and a group named like one goes
		// whole.
		"session_token", 424242,
		slog.Group("env", "PATH", "/opt/envsecretpath"),
	)

	out := buf.String()
	for _, secret := range []string{"msgsecret", "fieldsecret", "errpw", "groupsecret", "grouppw",
		"pw12345", "structsecret", "fromvaluer", "boundsecret", "boundpw", "424242", "envsecretpath"} {
		if strings.Contains(out, secret) {
			t.Errorf("%q reached the log:\n%s", secret, out)
		}
	}

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("output is not one JSON record: %v\n%s", err, out)
	}
	g, _ := rec["g"].(map[string]any)
	if g == nil {
		t.Fatalf("group g lost: %s", out)
	}
	if g["path"] != "/home/dev/.ssh/id_rsa" || g["n"] != float64(7) {
		t.Errorf("ordinary values changed: path %v n %v", g["path"], g["n"])
	}
	// A clean struct keeps its shape; only one that held a secret is replaced.
	if c, ok := g["clean"].(map[string]any); !ok || c["path"] != "/w" {
		t.Errorf("a clean struct was rewritten: %#v", g["clean"])
	}
	if rec["bound_token"] != Redacted {
		t.Errorf("a bound secret field = %v", rec["bound_token"])
	}
}

func TestHandlerKeepsLevelFilteringAndGroups(t *testing.T) {
	var buf bytes.Buffer
	h := NewRedactingHandler(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}), Rules{})
	if h.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("the wrapped handler's level was not honoured")
	}
	if h.WithGroup("") != h {
		t.Error("an empty group did not return the same handler")
	}
}
