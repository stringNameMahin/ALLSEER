package logging

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLevelsFormatsAndStreams(t *testing.T) {
	var out, errs bytes.Buffer

	log, c, err := New(Options{Level: "warn"}, &out, &errs)
	if err != nil {
		t.Fatal(err)
	}
	log.Info("quiet")
	log.Warn("loud", "k", "v")
	_ = c.Close()
	if strings.Contains(errs.String(), "quiet") || !strings.Contains(errs.String(), "loud") {
		t.Errorf("warn level wrote %q", errs.String())
	}
	if out.Len() != 0 {
		t.Errorf("stderr output wrote to stdout: %q", out.String())
	}
	if !strings.Contains(errs.String(), "level=WARN") {
		t.Errorf("default format is not text: %q", errs.String())
	}

	out.Reset()
	log, _, err = New(Options{Level: "debug", Format: "json", Output: "stdout", AddSource: true}, &out, &errs)
	if err != nil {
		t.Fatal(err)
	}
	log.Debug("detail", "token", "abc")
	var rec map[string]any
	if err := json.Unmarshal(out.Bytes(), &rec); err != nil {
		t.Fatalf("json format wrote %q: %v", out.String(), err)
	}
	if rec["msg"] != "detail" || rec["token"] != Redacted || rec["source"] == nil {
		t.Errorf("record = %v; want the debug message, a redacted token and a source", rec)
	}
}

// A log file is created private and appended to, never truncated.
func TestFileOutputIsPrivateAndAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allseerd.log")
	for _, msg := range []string{"first", "second"} {
		log, c, err := New(Options{Output: path}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		log.Info(msg)
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "first") || !strings.Contains(string(b), "second") {
		t.Errorf("log file = %q, want both runs", b)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != FileMode {
		t.Errorf("log file mode = %o, want %o", fi.Mode().Perm(), FileMode)
	}
}

func TestBadOptionsAreRefused(t *testing.T) {
	for _, o := range []Options{
		{Level: "verbose"},
		{Format: "xml"},
		{Output: "logs/allseerd.log"},
		{Output: filepath.Join(t.TempDir(), "missing", "allseerd.log")},
	} {
		if _, _, err := New(o, nil, nil); err == nil {
			t.Errorf("New(%+v) succeeded", o)
		}
	}
}
