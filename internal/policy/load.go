package policy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

// Loading is where a rule set stops being a file and starts being policy, and
// the whole job here is to make that transition loud when it should not happen.
//
// Bad policy fails quietly by nature. A rule with a misspelled condition key
// still parses, still loads, and still never fires; nothing errors, nothing
// logs, and the protection the operator believed they configured simply is not
// there. That is the same failure the ECE linter exists to catch on the
// envelope side, and it gets the same answer: refuse at admission, while a
// human is looking.
//
// So this loader is deliberately strict in four ways, each covering a defect
// that is otherwise invisible at runtime:
//
//   - Unknown fields are rejected. A typo in a condition key is not a rule that
//     matches slightly differently; it is a rule missing a constraint its
//     author wrote, which means it matches *more* than intended.
//   - "enabled" must be written out. Go's zero value for a bool is false, so a
//     rule that omits the field is silently inert -- the one field whose default
//     silently removes a rule from the policy.
//   - A second YAML document is an error, rather than a quietly ignored half of
//     the file.
//   - The result is admitted through the same checks the engine applies, so a
//     rule set that loads is a rule set that runs.
//
// YAML stays inside this file. The evaluator knows nothing about the format the
// rules arrived in, which is what keeps its semantics testable without a
// dependency and lets a future JSON or programmatic source feed the same
// engine.

// ErrNoRules reports a file that parsed but contained no rule set at all -- an
// empty file, or one holding only comments. It is an error rather than an empty
// policy because a daemon starting with an empty rule set would fall through to
// the default action on every event, which looks like a working system.
var ErrNoRules = errors.New("policy: rule set file is empty")

// FileLoader reads rule sets from the filesystem. It implements Loader.
//
// Stateless: the zero value is usable and safe for concurrent use.
type FileLoader struct{}

var _ Loader = FileLoader{}

// NewLoader returns a filesystem rule set loader.
func NewLoader() FileLoader { return FileLoader{} }

// Load reads and validates a rule set.
//
// A returned rule set is guaranteed to be one NewEngine accepts: validation
// here is the engine's own admission check, not a second implementation of it.
// Any error means no rule set, never a partial one -- a caller that fell back to
// "whatever loaded" would be running a policy nobody wrote.
func (FileLoader) Load(_ context.Context, path string) (*RuleSet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("policy: open rule set: %w", err)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("policy: read rule set %s: %w", path, err)
	}
	return parseRuleSet(data, path)
}

// Watch is not implemented. Nil is the interface's documented answer for a
// loader that cannot watch, and a caller must read it as "no hot reload" rather
// than as "nothing has changed yet".
//
// TODO(policy): implement watching. It needs a decision first -- fsnotify is a
// second dependency, and polling a mtime is dependency-free but has a window in
// which a half-written file is readable. Whichever wins, a reload must go
// through Load so a bad file is rejected before it reaches the engine.
func (FileLoader) Watch(_ context.Context, _ string) (<-chan *RuleSet, error) {
	return nil, nil
}

// parseRuleSet decodes and validates rule set bytes. Separate from Load so the
// strictness can be tested against literals rather than fixture files.
func parseRuleSet(data []byte, source string) (*RuleSet, error) {
	var rs RuleSet

	dec := yaml.NewDecoder(bytes.NewReader(data))
	// The single most valuable line in this file. Without it, "violaton_types"
	// parses cleanly and produces a rule with one fewer condition than its
	// author wrote -- a rule that matches more, silently.
	dec.KnownFields(true)

	if err := dec.Decode(&rs); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%w: %s", ErrNoRules, source)
		}
		return nil, fmt.Errorf("policy: parse rule set %s: %w", source, err)
	}

	// A second document would be silently ignored, and a file whose second half
	// does nothing is a trap for whoever appends to it.
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return nil, fmt.Errorf("policy: parse rule set %s: %w", source, err)
		}
		return nil, fmt.Errorf("policy: rule set %s contains more than one YAML document; only the first would be used", source)
	}

	if err := requireExplicitEnabled(data, source); err != nil {
		return nil, err
	}

	// Admission is the engine's, called rather than reimplemented: a rule set
	// this loader accepts and NewEngine then rejects would be a bug that only
	// surfaces at daemon start.
	if _, err := compile(rs.Rules, rs.DefaultAction); err != nil {
		return nil, fmt.Errorf("%w (in %s)", err, source)
	}

	return &rs, nil
}

// requireExplicitEnabled rejects a rule that does not write out its enabled
// field.
//
// Rule.Enabled is a plain bool, so the decoded value cannot distinguish
// "enabled: false" from a rule that never mentioned it -- and the two mean
// opposite things to a reviewer. A rule written to block kernel tampering that
// forgot one line is not a conservative default; it is a hole with a
// description above it.
//
// The presence check runs as a second, deliberately minimal decode rather than
// by shadowing Rule with a pointer-typed copy. A copy would have to be kept in
// step with Rule field by field, and the field it forgot would be the one that
// stopped being validated.
func requireExplicitEnabled(data []byte, source string) error {
	var probe struct {
		Rules []struct {
			ID      string `yaml:"id"`
			Enabled *bool  `yaml:"enabled"`
		} `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &probe); err != nil {
		// The strict decode above already reported anything malformed, so a
		// failure here means the two decodes disagree, which is worth saying
		// plainly rather than ignoring.
		return fmt.Errorf("policy: re-reading rule set %s: %w", source, err)
	}

	for i, r := range probe.Rules {
		if r.Enabled != nil {
			continue
		}
		name := r.ID
		if name == "" {
			name = fmt.Sprintf("#%d", i)
		}
		return fmt.Errorf("policy: rule %q in %s does not set enabled; write it out, "+
			"since an omitted enabled is a rule silently absent from the policy", name, source)
	}
	return nil
}
