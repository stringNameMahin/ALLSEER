package risk

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/stringNameMahin/ALLSEER/internal/validator"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
)

// This file is the first security *knowledge* in the risk engine — the first
// place ALLSEER asserts that some resource matters more than another, rather
// than deriving everything from what the envelope declared and the validator
// concluded.
//
// That makes it different in kind from score.go, and it is arranged
// accordingly.
//
// # The list is data, and it lives in configs/
//
// Not in Go source. The project has already drawn this line once: the policy
// rule set is YAML in configs/ because it is the file an operator edits, while
// the capability table is Go because it is a closed enum tied to code. A
// sensitivity list is the former — what counts as sensitive is deployment
// specific, which is exactly why SensitivityOracle is an interface separate
// from Scorer. A list compiled into a scorer would be a security claim nobody
// could review, override, or diff.
//
// # An empty list is not the neutral option
//
// Shipping defaults asserts "these locations should be considered sensitive".
// Shipping nothing asserts "no location is", which is also an assertion and a
// false one. There is no abstention available, so the defaults are shipped and
// every entry carries a written reason. See configs/sensitivity.default.yaml.
//
// # Unknown is a third state, and it is load-bearing
//
// PathSensitivity returns SensitivityUnknown for a path no entry covers. That
// is not SeverityInfo. "We have never heard of this file" and "we looked at
// this file and it is unremarkable" are different findings, and collapsing them
// would make the list's silence indistinguishable from its approval — which is
// how a list becomes the single thing standing between a credential read and a
// warning, with everything it has not been taught about silently safe.
//
// # The list may only raise
//
// Nothing here can lower a score. Grades map to non-negative points, the lowest
// two map to zero, and there is no negative contribution to configure. A list
// that could lower a score would make "add a path here" a way to launder
// access, and would make a missing entry indistinguishable from a deliberate
// exemption.
//
// # An unusable pattern refuses the file
//
// Loading fails closed. A sensitivity entry whose pattern cannot match anything
// protects nothing and does it silently, which is the same failure
// validator.EnvelopeLinter exists to catch on the envelope side and gets the
// same answer: refuse at admission, while a human is looking.

// SensitivityUnknown is what an oracle reports for a resource it has no
// knowledge of.
//
// It is the empty capability.Severity, deliberately: the empty value is not a
// member of the severity vocabulary, so a caller that forgets to handle it
// cannot accidentally read it as SeverityInfo. This is the same device
// decision.Level uses for an unscored event, where "" is not a member of
// decision.AllLevels.
const SensitivityUnknown capability.Severity = ""

// KnownSensitivity reports whether s is a grade an oracle actually assigned, as
// opposed to the absence of knowledge.
func KnownSensitivity(s capability.Severity) bool { return severityRank(s) >= 0 }

// --- the list ---------------------------------------------------------------------

// SensitivityList is a reviewable set of graded resource patterns.
//
// The YAML shape of configs/sensitivity.default.yaml. Kept as a distinct type
// from the oracle so the file can be loaded, linted, and printed without
// standing up matching, the same split internal/policy makes between RuleSet
// and RuleEngine.
type SensitivityList struct {
	Name        string `yaml:"name" json:"name"`
	Version     string `yaml:"version" json:"version"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`

	Paths []SensitivityEntry `yaml:"paths" json:"paths"`
}

// SensitivityEntry grades a set of path patterns, with the reason written down.
type SensitivityEntry struct {
	Patterns []string `yaml:"patterns" json:"patterns"`

	// Sensitivity is the grade. One of the five capability.Severity values;
	// SensitivityUnknown is not writable, because an entry that declares a
	// resource unknown is an entry that says nothing.
	Sensitivity capability.Severity `yaml:"sensitivity" json:"sensitivity"`

	// Reason is why this location is consequential, and it is required.
	//
	// Required rather than encouraged because this file is where the project's
	// security claims live, and a claim nobody can review is a claim nobody
	// will remove when it turns out to be wrong. It is carried into the audit
	// record on the factor's evidence, so the answer to "why did this score
	// go up" is the sentence its author wrote rather than a pattern.
	Reason string `yaml:"reason" json:"reason"`
}

// ErrNoSensitivityEntries reports a file that parsed but graded nothing.
//
// An error rather than an empty list, for the reason the package comment gives:
// an empty list is the claim that nothing is sensitive, and a daemon that
// started with one would silently score every credential read as ordinary.
var ErrNoSensitivityEntries = errors.New("risk: sensitivity list contains no entries")

// LoadSensitivityList reads a sensitivity list from disk.
//
// Any error means no list at all, never a partial one. A caller that fell back
// to "whatever parsed" would be running with a security claim nobody wrote.
func LoadSensitivityList(path string) (*SensitivityList, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("risk: read sensitivity list: %w", err)
	}
	return ParseSensitivityList(data, path)
}

// ParseSensitivityList decodes and validates list bytes.
//
// Separate from LoadSensitivityList so the strictness can be exercised against
// literals rather than fixture files, which is how internal/policy's loader is
// tested and for the same reason.
func ParseSensitivityList(data []byte, source string) (*SensitivityList, error) {
	var list SensitivityList

	dec := yaml.NewDecoder(bytes.NewReader(data))
	// A misspelled key here is an entry missing the field its author wrote.
	// "sensitivty: critical" would decode to the empty grade and be rejected
	// below, but "reasn:" would decode to an entry with no reason — and the
	// point of rejecting unknown fields is that neither reaches a human as a
	// puzzle about why their list behaves differently than it reads.
	dec.KnownFields(true)

	if err := dec.Decode(&list); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%w: %s", ErrNoSensitivityEntries, source)
		}
		return nil, fmt.Errorf("risk: parse sensitivity list %s: %w", source, err)
	}

	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return nil, fmt.Errorf("risk: parse sensitivity list %s: %w", source, err)
		}
		return nil, fmt.Errorf("risk: sensitivity list %s contains more than one YAML document; "+
			"only the first would be used", source)
	}

	if err := validateSensitivityList(&list, source); err != nil {
		return nil, err
	}
	return &list, nil
}

// validateSensitivityList is the admission check, and it fails closed.
//
// Every rejection here covers a defect that is otherwise invisible at runtime:
// an entry with an unusable pattern matches nothing, an entry with an unknown
// grade contributes nothing, and an entry with no reason cannot be reviewed.
// All three produce a list that loads, runs, and protects less than its author
// believes — the specific failure this project refuses to let happen quietly.
func validateSensitivityList(list *SensitivityList, source string) error {
	if len(list.Paths) == 0 {
		return fmt.Errorf("%w: %s", ErrNoSensitivityEntries, source)
	}

	for i, e := range list.Paths {
		where := fmt.Sprintf("entry #%d in %s", i, source)

		if len(e.Patterns) == 0 {
			return fmt.Errorf("risk: %s has no patterns", where)
		}
		if e.Sensitivity == SensitivityUnknown {
			return fmt.Errorf("risk: %s does not set sensitivity; write it out, since an entry "+
				"that grades nothing is an entry that says nothing", where)
		}
		if !KnownSensitivity(e.Sensitivity) {
			return fmt.Errorf("risk: %s has unknown sensitivity %q; want one of info, low, medium, high, critical",
				where, e.Sensitivity)
		}
		if e.Reason == "" {
			return fmt.Errorf("risk: %s has no reason; every entry in a sensitivity list is a security "+
				"claim, and a claim nobody can review is a claim nobody will remove", where)
		}

		for _, p := range e.Patterns {
			// Called, not reimplemented. An entry here has to mean exactly what
			// an identically written grant means, or the list would protect a
			// different set of files than an operator reading it expects.
			if err := validator.ValidatePattern(p); err != nil {
				return fmt.Errorf("risk: %s: %w; an unusable pattern matches nothing, "+
					"so the list is refused rather than silently protecting less than it reads", where, err)
			}
		}
	}
	return nil
}

// --- the oracle -------------------------------------------------------------------

// PathOracle implements SensitivityOracle over a configured path list.
//
// It rates paths and nothing else. HostSensitivity and ExecutableSensitivity
// are implemented — the whole interface is, rather than three-quarters of it —
// and both report SensitivityUnknown for everything, which is the truthful
// answer for a build with no host or executable list. See their comments: the
// alternative, returning SeverityInfo, would be a fabricated "this is fine" for
// every destination the agent connects to.
//
// # Shape, and why it is flat
//
// The list's entries are flattened into one validator.PatternSet with the
// grade and reason held in slices parallel to it. Two properties come from
// that, and both matter on a path that runs for every governed syscall:
//
//   - The patterns are ordered by grade, highest first, so the *first* match is
//     the highest-grade match. Precedence is decided by construction rather
//     than by scanning every entry and comparing.
//   - The observed path is segmented once per lookup rather than once per
//     pattern. Scanning forty patterns through validator.MatchPath re-validates
//     every pattern and re-splits the same path forty times, which measured at
//     8.7 µs and 183 allocations per event against a whole-pipeline budget of
//     2.5 µs. Through a compiled set it is one allocation.
//
// Immutable after construction and safe for concurrent use.
type PathOracle struct {
	set *validator.PatternSet

	// grades and reasons are parallel to set, in the same highest-grade-first
	// order. Slices rather than a struct per pattern because the scan reads
	// only the index the set returns.
	grades  []capability.Severity
	reasons []string

	list *SensitivityList
}

var _ SensitivityOracle = (*PathOracle)(nil)

// NewPathOracle builds an oracle from a validated list.
//
// The list is re-validated rather than trusted, because a caller can construct
// a SensitivityList programmatically without going through the loader and the
// admission rule has to hold either way.
func NewPathOracle(list *SensitivityList) (*PathOracle, error) {
	if list == nil {
		return nil, errors.New("risk: sensitivity list is required")
	}
	if err := validateSensitivityList(list, "the supplied list"); err != nil {
		return nil, err
	}

	// Highest grade first, ties broken by declaration order. Stable, so a list
	// loaded twice produces one oracle: the reason a matched entry names is
	// carried into the audit record, and a record whose explanation depends on
	// an unstable sort is not reproducible.
	ordered := make([]int, len(list.Paths))
	for i := range ordered {
		ordered[i] = i
	}
	sort.SliceStable(ordered, func(a, b int) bool {
		return severityRank(list.Paths[ordered[a]].Sensitivity) >
			severityRank(list.Paths[ordered[b]].Sensitivity)
	})

	var (
		patterns []string
		grades   []capability.Severity
		reasons  []string
	)
	for _, idx := range ordered {
		e := list.Paths[idx]
		for _, p := range e.Patterns {
			patterns = append(patterns, p)
			grades = append(grades, e.Sensitivity)
			reasons = append(reasons, e.Reason)
		}
	}

	// Compiled through the validator, so a pattern here means exactly what the
	// same pattern means in a grant. CompilePatterns runs ValidatePattern
	// again; the duplication is deliberate, since a set that accepted what
	// validateSensitivityList rejected would be a disagreement nobody could see.
	set, err := validator.CompilePatterns(patterns)
	if err != nil {
		return nil, fmt.Errorf("risk: compiling sensitivity patterns: %w", err)
	}

	return &PathOracle{set: set, grades: grades, reasons: reasons, list: list}, nil
}

// LoadPathOracle reads a list from disk and builds an oracle from it.
func LoadPathOracle(path string) (*PathOracle, error) {
	list, err := LoadSensitivityList(path)
	if err != nil {
		return nil, err
	}
	return NewPathOracle(list)
}

// List returns the list this oracle was built from, for reporting.
func (o *PathOracle) List() *SensitivityList { return o.list }

// PathSensitivity rates a filesystem path.
//
// Returns SensitivityUnknown when nothing covers the path, and — importantly —
// also when the path is not in the resolved form the matcher requires.
// validator.MatchPath refuses an unresolved path rather than guessing, so an
// unresolved path is one this oracle genuinely cannot rate. Reporting it as
// unrated is the same refusal the validator makes about coverage, and for the
// same reason: a truncated or relative path must never be the cheapest way to
// look unremarkable.
//
// Highest grade wins when several entries match. A narrower entry added later
// can therefore only raise a path's grade.
func (o *PathOracle) PathSensitivity(path string) capability.Severity {
	grade, _ := o.PathSensitivityReason(path)
	return grade
}

// PathSensitivityReason returns the grade and the written reason for a path.
//
// The reason is what reaches the audit record, so that "why did this score go
// up" is answered by the sentence the list's author wrote rather than by a
// glob the reader has to interpret.
func (o *PathOracle) PathSensitivityReason(path string) (capability.Severity, string) {
	if o == nil || path == "" {
		return SensitivityUnknown, ""
	}
	// The first match is the highest-grade match, because the set was built in
	// that order. No comparison happens here.
	i := o.set.MatchIndex(path)
	if i < 0 {
		return SensitivityUnknown, ""
	}
	return o.grades[i], o.reasons[i]
}

// HostSensitivity rates a network destination, and this build cannot.
//
// It reports SensitivityUnknown for every host, which is the truth: no host
// list exists and no scorer consumes one yet. The interface is implemented in
// full rather than left out so that a caller cannot mistake a missing method
// for a missing risk — and the answer is explicitly unknown rather than
// SeverityInfo, because "not rated" and "rated harmless" are the distinction
// this whole file exists to keep, and returning the latter would assert that
// every destination an agent connects to is fine.
//
// TODO(risk): host sensitivity needs its own list and its own vocabulary —
// validator.ValidateHostPattern and MatchHost are the matching half and already
// exist. It is deliberately not added here because no scorer reads it yet, and
// configuration nothing consumes is configuration that lies about what it does.
// It arrives with novel_network_destination.
func (o *PathOracle) HostSensitivity(_ string) capability.Severity {
	return SensitivityUnknown
}

// ExecutableSensitivity rates a binary, and this build cannot.
//
// Unknown for the same reason as HostSensitivity, and the gap is worth naming
// because the module doc calls it out specifically: curl, ssh, and a shell mean
// something different from a compiler in an agent context, and nothing here
// knows that yet.
//
// TODO(risk): executable sensitivity arrives with the privilege_change and
// exfiltration_pattern scorers, which are the ones that would read it.
func (o *PathOracle) ExecutableSensitivity(_ string) capability.Severity {
	return SensitivityUnknown
}

// TODO(risk): prefilter the scan. This was deferred on the grounds that scoring
// one unrated path costs 982 ns against a 2.5 µs pipeline, which is
// proportionate — and that reasoning no longer covers the whole picture.
// CredentialEgressScorer calls PathSensitivity once per retained successful
// read when it evaluates an egress event, so the same lookup runs up to 256
// times for one syscall: 340 µs at the engine level, 120 µs end to end (see the
// measurements in sequence.go). The cheap next step is unchanged — a
// required-literal-segment index, since every pattern in the shipped list has
// at least one literal segment (".ssh", "shadow", "environ") and a path whose
// segment set contains none of them cannot match that pattern at all, with the
// extension-shaped patterns (/**/*.pem) falling into a small always-check
// residue. Still not built here, because it belongs to this file's own
// milestone rather than to the detector's, but it now has a measurement behind
// it rather than a guess.

// severityRank orders grades. Local to this file rather than shared with
// score.go's point table, because ordering and weighting are different
// questions: two grades could carry the same points (info and low both do)
// while still being ordered.
func severityRank(s capability.Severity) int {
	switch s {
	case capability.SeverityInfo:
		return 0
	case capability.SeverityLow:
		return 1
	case capability.SeverityMedium:
		return 2
	case capability.SeverityHigh:
		return 3
	case capability.SeverityCritical:
		return 4
	default:
		return -1
	}
}
