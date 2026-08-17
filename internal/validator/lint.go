package validator

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
)

// Envelope admission is the mirror image of the rest of this package. Validate
// asks whether an observation is covered by the envelope; linting asks whether
// the envelope can be evaluated at all — before a human approves it, and before
// a single event arrives.
//
// It lives beside the matcher rather than in internal/envelope for one reason:
// the lint has to agree with matching exactly. Every rule below is a statement
// about what this package's matchers will do with a pattern, and it is enforced
// by calling the same functions they call. A linter maintained anywhere else
// would drift, and the drift would be invisible: a pattern accepted at approval
// time and rejected by the matcher matches nothing at all. Co-location also
// keeps admission available to a daemon loading an envelope from a store, which
// has no business importing the generator.
//
// The severity scale is not decoration; it encodes the one asymmetry that
// matters. An unparseable pattern in a *grant* grants nothing, which is
// fail-closed: the session produces false positives, a human sees them, and
// nothing is silently permitted. The same pattern in a *denial* denies nothing,
// and that failure is invisible everywhere — no error, no event, no audit line,
// just a prohibition that was never in force. So:
//
//   - Critical, and blocking: a defect that leaves an entry unable to match
//     anything it was written to match, in a denial. Plus an unknown Kind on
//     either side, which the closed-enum decision already places here.
//   - High: a grant that silently covers more than its text suggests.
//   - Medium: a grant that matches nothing, or a denial wider than it reads.
//   - Low: an ambiguity a reader should resolve, whose direction depends on the
//     filesystem or on how the document is read rather than on the matcher.
//
// Only critical refuses admission. Everything else is reported for a human to
// weigh, because a linter that blocks on judgment calls is a linter operators
// route around. See docs/grant-precedence.md §5 and docs/path-matching.md §5.

// EnvelopeLinter implements ece.Validator over this package's selector
// semantics.
//
// Stateless: the zero value is usable and safe for concurrent use.
type EnvelopeLinter struct{}

var _ ece.Validator = EnvelopeLinter{}

// NewEnvelopeLinter returns a linter for envelope admission.
func NewEnvelopeLinter() EnvelopeLinter { return EnvelopeLinter{} }

// Validate reports every selector-level problem in an envelope.
//
// A nil envelope is an error rather than an issue, for the same reason
// Validate's inputs are: a caller with no envelope has a wiring bug, not a
// governance finding. An envelope with no problems returns no issues and no
// error; callers must consult BlockingIssues rather than treating any issue as
// grounds for refusal.
func (EnvelopeLinter) Validate(_ context.Context, env *ece.Envelope) ([]ece.Issue, error) {
	if env == nil {
		return nil, ErrNoEnvelope
	}
	return LintEnvelope(env), nil
}

// LintEnvelope is Validate as a free function, so admission can be exercised
// without constructing a linter.
//
// Issues are returned in document order — constraints, then grants, then
// denials — because that is the order a reviewer reads the envelope in.
func LintEnvelope(env *ece.Envelope) []ece.Issue {
	var issues []ece.Issue

	issues = append(issues, lintWorkspaceRoot(env.Constraints.WorkspaceRoot)...)
	for i := range env.Grants {
		issues = append(issues, lintEntry(env.Grants[i], roleGrant, fmt.Sprintf("grants[%d]", i))...)
	}
	for i := range env.Denials {
		issues = append(issues, lintEntry(env.Denials[i], roleDenial, fmt.Sprintf("denials[%d]", i))...)
	}
	return issues
}

// BlockingIssues returns the subset of issues that must refuse admission.
//
// Exported so the rule lives in one place. Sealing, the approval CLI, and a
// daemon loading an envelope from disk all need the same answer, and three call
// sites each deciding for themselves which severities are fatal is how one of
// them ends up admitting an envelope the others would reject.
func BlockingIssues(issues []ece.Issue) []ece.Issue {
	var out []ece.Issue
	for _, i := range issues {
		if i.Severity == capability.SeverityCritical {
			out = append(out, i)
		}
	}
	return out
}

// entryRole distinguishes a grant from a denial. It decides severity
// throughout: the same defect fails closed in a grant and open in a denial.
type entryRole string

const (
	roleGrant  entryRole = "grant"
	roleDenial entryRole = "denial"
)

// unmatchable is the severity of a value that can never match anything.
func (r entryRole) unmatchable() capability.Severity {
	if r == roleDenial {
		return capability.SeverityCritical
	}
	return capability.SeverityMedium
}

// effect states what an unmatchable value costs, in the terms a reviewer needs.
func (r entryRole) effect() string {
	if r == roleDenial {
		return "this denial can never match, so it protects nothing"
	}
	return "this pattern can never match, so the grant is narrower than it reads"
}

// overbroad is the severity of a dimension the matcher ignores. A grant that
// covers more than its text suggests is the serious direction; a denial that
// does is merely imprecise.
func (r entryRole) overbroad() capability.Severity {
	if r == roleDenial {
		return capability.SeverityMedium
	}
	return capability.SeverityHigh
}

// Selector dimension names, spelled as they appear in the ECE schema so an
// Issue.Field is a JSON path a reviewer can follow into the document.
const (
	dimPaths       = "path_patterns"
	dimHosts       = "hosts"
	dimPorts       = "ports"
	dimProtocols   = "protocols"
	dimExecutables = "executables"
	dimArgs        = "arg_patterns"
)

// lintEntry checks one grant or denial.
func lintEntry(g capability.Grant, role entryRole, field string) []ece.Issue {
	if err := capability.ValidateKind(g.Kind); err != nil {
		// Nothing further is checkable: without a known Kind there is no domain,
		// and without a domain there is no telling which selector dimensions the
		// matcher would even read. Critical on both sides, because an entry the
		// matcher never compares against anything is as absent as a missing one,
		// and the closed-enum decision already places this check at admission.
		return []ece.Issue{{
			Severity:   capability.SeverityCritical,
			Field:      field + ".kind",
			Message:    fmt.Sprintf("%v; no observation carries this kind, so the %s is never compared against anything", err, role),
			Suggestion: "use a kind from the capability catalog; allseerctl capabilities lists them",
		}}
	}
	domain, _ := capability.DomainOf(g.Kind)

	var issues []ece.Issue

	// The matcher reads the domain from the catalog, never from this field, so a
	// disagreement changes no verdict. It still misleads every human who reads
	// the envelope, which is the only reason the field exists.
	if g.Domain != domain {
		issues = append(issues, ece.Issue{
			Severity:   capability.SeverityLow,
			Field:      field + ".domain",
			Message:    fmt.Sprintf("domain %q disagrees with the catalog, which places %s in %q; matching uses the catalog", g.Domain, g.Kind, domain),
			Suggestion: fmt.Sprintf("set domain to %q", domain),
		})
	}

	sel := g.Selector
	applicable := applicableDimensions(domain)
	populated := populatedDimensions(sel)

	// A dimension the matcher does not read for this domain is not a narrowing.
	// An fs.write grant carrying hosts and no path patterns reads as scoped and
	// covers the whole filesystem.
	for _, dim := range populated {
		if slices.Contains(applicable, dim) {
			continue
		}
		issues = append(issues, ece.Issue{
			Severity: role.overbroad(),
			Field:    field + ".selector." + dim,
			Message: fmt.Sprintf("%s does not apply to %s capabilities, which are matched on %s; the matcher ignores it, so this %s is wider than it reads",
				dim, domain, strings.Join(applicable, ", "), role),
			Suggestion: fmt.Sprintf("remove %s, or narrow the %s with %s", dim, role, strings.Join(applicable, " or ")),
		})
	}

	// Only the dimensions matching actually consults are worth validating: a
	// malformed pattern in a dimension nobody reads is already reported above,
	// and reporting it twice would bury the finding that matters.
	for _, dim := range applicable {
		at := field + ".selector." + dim
		switch dim {
		case dimPaths:
			issues = append(issues, lintPathPatterns(sel.PathPatterns, at, role)...)
		case dimExecutables:
			issues = append(issues, lintPathPatterns(sel.Executables, at, role)...)
		case dimHosts:
			issues = append(issues, lintHostPatterns(sel.Hosts, at, role)...)
		case dimPorts:
			issues = append(issues, lintPorts(sel.Ports, at, role)...)
		case dimProtocols:
			issues = append(issues, lintStrings(sel.Protocols, at, "protocol", role)...)
		case dimArgs:
			// Nothing beyond emptiness is checked here. ArgPatterns is a
			// readability convenience and never a security boundary, and the
			// matcher applies it forgivingly on purpose; inventing a syntax to
			// enforce would imply a guarantee this dimension does not make.
			issues = append(issues, lintStrings(sel.ArgPatterns, at, "argument pattern", role)...)
		}
	}

	issues = append(issues, lintMaxCount(sel.MaxCount, field+".selector.max_count", role)...)

	// An unbounded grant is the most common envelope-quality failure there is,
	// and the one the whole system is least able to compensate for. Reported,
	// never blocked: whether an unbounded grant is acceptable is what
	// envelope.Limits.AllowUnboundedSelectors exists to decide, and that is an
	// operator's call rather than a linter's.
	if role == roleGrant && len(populated) == 0 && narrowable(domain) {
		issues = append(issues, ece.Issue{
			Severity:   capability.SeverityMedium,
			Field:      field + ".selector",
			Message:    fmt.Sprintf("%s is granted with no selector, so it covers every %s operation", g.Kind, domain),
			Suggestion: fmt.Sprintf("narrow the grant with %s", strings.Join(applicable, " or ")),
		})
	}

	return issues
}

// applicableDimensions reports the selector dimensions SelectorMatcher reads
// for a domain. It must track matcher.go's dispatch exactly; a dimension
// missing here would be reported as ignored while the matcher honors it.
func applicableDimensions(d capability.Domain) []string {
	switch d {
	case capability.DomainFilesystem:
		return []string{dimPaths}
	case capability.DomainNetwork:
		return []string{dimHosts, dimPorts, dimProtocols}
	case capability.DomainProcess:
		return []string{dimExecutables, dimArgs}
	default:
		// Privilege, IPC, and kernel capabilities have no selector dimension of
		// their own, except that the resource is sometimes named by a path — a
		// unix socket, a loaded module — and the matcher honors PathPatterns
		// when a grant sets them.
		return []string{dimPaths}
	}
}

// narrowable reports whether a domain has a selector dimension an envelope
// author is expected to use. A priv.setuid grant with no selector is not an
// oversight; there is nothing to narrow it with.
func narrowable(d capability.Domain) bool {
	switch d {
	case capability.DomainFilesystem, capability.DomainNetwork, capability.DomainProcess:
		return true
	}
	return false
}

// populatedDimensions reports which selector dimensions carry values, in schema
// order.
func populatedDimensions(s capability.Selector) []string {
	var out []string
	if len(s.PathPatterns) > 0 {
		out = append(out, dimPaths)
	}
	if len(s.Hosts) > 0 {
		out = append(out, dimHosts)
	}
	if len(s.Ports) > 0 {
		out = append(out, dimPorts)
	}
	if len(s.Protocols) > 0 {
		out = append(out, dimProtocols)
	}
	if len(s.Executables) > 0 {
		out = append(out, dimExecutables)
	}
	if len(s.ArgPatterns) > 0 {
		out = append(out, dimArgs)
	}
	return out
}

// lintPathPatterns checks a path-shaped dimension: PathPatterns or Executables,
// both of which reach GlobPathMatcher and so answer to ValidatePattern.
func lintPathPatterns(patterns []string, field string, role entryRole) []ece.Issue {
	var issues []ece.Issue
	for i, p := range patterns {
		at := fmt.Sprintf("%s[%d]", field, i)
		if err := ValidatePattern(p); err != nil {
			issues = append(issues, ece.Issue{
				Severity:   role.unmatchable(),
				Field:      at,
				Message:    fmt.Sprintf("%v; %s", err, role.effect()),
				Suggestion: "write an absolute path pattern with no . or .. segments; ** must stand alone as a whole segment",
			})
			// An unparseable pattern has no ambiguity worth reporting on top.
			continue
		}
		issues = append(issues, lintPathAmbiguity(p, at, role)...)
	}
	return issues
}

// lintPathAmbiguity reports patterns whose bytes may not be the bytes the
// kernel will present. Matching is byte-exact by design — it has to agree with
// the kernel about file identity — so these are resolved by a human at approval
// time or not at all. See docs/path-matching.md §5.
func lintPathAmbiguity(pattern, field string, role entryRole) []ece.Issue {
	var issues []ece.Issue

	if !isASCII(pattern) {
		// Reported on both sides, and the reason differs. In a denial a
		// homoglyph or a differently normalized name fails to cover the file it
		// was written for. In a grant it is worse than useless in the other
		// direction: a reviewer reads a Cyrillic "package.json" as the real one
		// and approves a grant for a file that does not exist.
		severity := capability.SeverityLow
		if role == roleDenial {
			severity = capability.SeverityMedium
		}
		issues = append(issues, ece.Issue{
			Severity:   severity,
			Field:      field,
			Message:    fmt.Sprintf("pattern %q contains non-ASCII bytes; matching is byte-exact, so a different Unicode normalization or a homoglyph is a different path", pattern),
			Suggestion: "restrict selector patterns to ASCII, or confirm the exact bytes with whoever wrote the pattern",
		})
	}

	// Case is reported for denials only. A grant written in the wrong case
	// covers nothing and shows up immediately as false positives; a denial
	// written in the wrong case is evadable by changing case on a
	// case-insensitive filesystem, and nothing in the log would look wrong.
	// Reporting both would put an issue on nearly every real envelope, and a
	// linter nobody reads protects nothing either.
	if role == roleDenial && hasUpperASCII(pattern) {
		issues = append(issues, ece.Issue{
			Severity:   capability.SeverityLow,
			Field:      field,
			Message:    fmt.Sprintf("pattern %q is case-sensitive; on a case-insensitive filesystem the denial is evaded by changing case", pattern),
			Suggestion: "add the other spellings, or confirm the target filesystem is case-sensitive",
		})
	}

	return issues
}

// lintHostPatterns checks Selector.Hosts.
//
// No ambiguity checks accompany it: ValidateHostPattern already rejects
// non-ASCII names outright, and host comparison folds case, so neither
// limitation path matching carries applies here.
func lintHostPatterns(hosts []string, field string, role entryRole) []ece.Issue {
	var issues []ece.Issue
	for i, h := range hosts {
		if err := ValidateHostPattern(h); err != nil {
			issues = append(issues, ece.Issue{
				Severity:   role.unmatchable(),
				Field:      fmt.Sprintf("%s[%d]", field, i),
				Message:    fmt.Sprintf("%v; %s", err, role.effect()),
				Suggestion: "use a hostname, a wildcard domain (*.example.com), a literal address, or a CIDR block",
			})
		}
	}
	return issues
}

// lintPorts checks Selector.Ports.
//
// An empty list means any port, so the only failure here is a list that is
// non-empty and unsatisfiable. Zero is included: as an observed destination it
// means the probe had nothing to report, never that a connection was made to
// port zero.
func lintPorts(ports []int, field string, role entryRole) []ece.Issue {
	var issues []ece.Issue
	for i, p := range ports {
		if !IsValidPort(p) {
			issues = append(issues, ece.Issue{
				Severity:   role.unmatchable(),
				Field:      fmt.Sprintf("%s[%d]", field, i),
				Message:    fmt.Sprintf("port %d is outside 1-65535 and can never be observed; %s", p, role.effect()),
				Suggestion: "remove the port, or leave ports empty to mean any port",
			})
		}
	}
	return issues
}

// lintStrings reports empty entries in a list matched by literal comparison.
func lintStrings(values []string, field, label string, role entryRole) []ece.Issue {
	var issues []ece.Issue
	for i, v := range values {
		if strings.TrimSpace(v) == "" {
			issues = append(issues, ece.Issue{
				Severity:   role.unmatchable(),
				Field:      fmt.Sprintf("%s[%d]", field, i),
				Message:    fmt.Sprintf("%s entry is empty and matches nothing; %s", label, role.effect()),
				Suggestion: fmt.Sprintf("remove the entry, or leave the list empty to place no %s constraint", label),
			})
		}
	}
	return issues
}

// lintMaxCount checks Selector.MaxCount.
//
// A negative value reads as "none allowed" and behaves as unlimited, since
// budgetExhausted treats anything at or below zero as unbounded. On a denial
// the field is not read at all: denials are never charged a budget, so a denial
// written as "deny the first three" denies all of them.
func lintMaxCount(max int, field string, role entryRole) []ece.Issue {
	switch {
	case max < 0:
		return []ece.Issue{{
			Severity:   capability.SeverityLow,
			Field:      field,
			Message:    fmt.Sprintf("max_count %d is negative and is treated as unlimited, not as zero uses", max),
			Suggestion: "omit max_count for no limit, or set a positive budget",
		}}
	case max > 0 && role == roleDenial:
		return []ece.Issue{{
			Severity:   capability.SeverityLow,
			Field:      field,
			Message:    fmt.Sprintf("max_count %d has no effect on a denial; denials are never charged a budget, so every matching operation is denied", max),
			Suggestion: "remove max_count from the denial",
		}}
	}
	return nil
}

// lintWorkspaceRoot checks Constraints.WorkspaceRoot.
//
// Not a selector, but the same admission problem: the root reaches
// PathMatcher.WithinRoot, which refuses anything unresolved. An unusable root
// therefore reports every uncovered filesystem operation as a workspace escape,
// which is a false-positive source rather than a protection gap — hence medium
// and non-blocking.
func lintWorkspaceRoot(root string) []ece.Issue {
	if root == "" {
		// No root is a coherent choice: workspace escape is simply not reported.
		return nil
	}
	if IsResolved(root) {
		return nil
	}
	return []ece.Issue{{
		Severity:   capability.SeverityMedium,
		Field:      "constraints.workspace_root",
		Message:    fmt.Sprintf("workspace root %q is not a resolved absolute path; containment cannot be evaluated against it, so every uncovered filesystem operation reports a workspace escape", root),
		Suggestion: "record the workspace root as an absolute path with no . or .. segments",
	}}
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7f {
			return false
		}
	}
	return true
}

func hasUpperASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			return true
		}
	}
	return false
}
