package risk

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/stringNameMahin/ALLSEER/internal/validator"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// --- fixtures ---------------------------------------------------------------------

func defaultListPath() string {
	return filepath.Join("..", "..", "configs", "sensitivity.default.yaml")
}

func defaultOracle(t *testing.T) *ResourceOracle {
	t.Helper()
	o, err := LoadResourceOracle(defaultListPath())
	if err != nil {
		t.Fatalf("loading the shipped sensitivity list: %v", err)
	}
	return o
}

// listYAML builds a minimal well-formed list around the entries given, so a
// rejection test exercises exactly one defect at a time.
func listYAML(entries string) []byte {
	return []byte("name: t\nversion: \"1\"\npaths:\n" + entries)
}

func oracleFrom(t *testing.T, entries string) *ResourceOracle {
	t.Helper()
	list, err := ParseSensitivityList(listYAML(entries), "test")
	if err != nil {
		t.Fatalf("ParseSensitivityList: %v", err)
	}
	o, err := NewResourceOracle(list)
	if err != nil {
		t.Fatalf("NewResourceOracle: %v", err)
	}
	return o
}

func engineWith(t *testing.T, o SensitivityOracle) *BaselineEngine {
	t.Helper()
	e, err := NewEngineWithOracle(o)
	if err != nil {
		t.Fatalf("NewEngineWithOracle: %v", err)
	}
	return e
}

func scoreWith(t *testing.T, e *BaselineEngine, req ScoreRequest) *decision.RiskAssessment {
	t.Helper()
	a, err := e.Score(context.Background(), req)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	return a
}

// departure is the shape most of these tests score: an ungranted read, so the
// sensitivity factor is charged rather than merely reported.
func departure(kind capability.Kind, target string) ScoreRequest {
	return ScoreRequest{
		Event:      fileEvent(kind, target),
		Validation: result(decision.VerdictOutsideEnvelope, viol(validator.ViolationUngrantedCapability, capability.SeverityMedium)),
		Envelope:   envelope(),
		History:    history().withSeen(kind, target),
	}
}

// observedEvent builds an event carrying only a resolved observation, so a
// non-filesystem capability can be scored without inventing a payload struct
// the resolver would have to interpret.
func observedEvent(kind capability.Kind, target string) *event.Event {
	domain, _ := capability.DomainOf(kind)
	return &event.Event{
		ID:          "e-obs",
		SessionID:   "s-1",
		Capability:  kind,
		Domain:      domain,
		Observation: capability.Observation{Kind: kind, Domain: domain, Target: target},
	}
}

func sensitivityOf(a *decision.RiskAssessment) (grade, dimension string, points float64, present bool) {
	f := factor(a, FactorSensitivePath)
	if f == nil {
		return "", "", 0, false
	}
	return f.Evidence[EvidenceSensitivity], f.Evidence[EvidenceDimension], f.Weight, true
}

// --- the shipped list ---------------------------------------------------------------

// The defaults ALLSEER ships are a security claim the project owns, so the file
// it ships is loaded and exercised rather than assumed good. A list that failed
// its own admission check would be a claim nobody could act on.
func TestShippedSensitivityListLoads(t *testing.T) {
	list, err := LoadSensitivityList(defaultListPath())
	if err != nil {
		t.Fatalf("the shipped list does not load: %v", err)
	}
	if len(list.Paths) == 0 {
		t.Fatal("the shipped list grades nothing")
	}

	// Loading already enforces these, so this is the assertion that the
	// enforcement is really running against the real file rather than only
	// against literals in a rejection table.
	for i, e := range list.Paths {
		if e.Reason == "" {
			t.Errorf("entry #%d ships without a reason", i)
		}
		if !KnownSensitivity(e.Sensitivity) {
			t.Errorf("entry #%d ships grade %q, which is not a grade", i, e.Sensitivity)
		}
		for _, p := range e.Patterns {
			if err := validator.ValidatePattern(p); err != nil {
				t.Errorf("entry #%d ships an unusable pattern: %v", i, err)
			}
		}
		// The vocabulary the file documents: absolute patterns, `/**/...` for
		// home-relative locations rather than a tilde the loader cannot expand.
		for _, p := range e.Patterns {
			if strings.Contains(p, "~") {
				t.Errorf("entry #%d uses %q; the matcher has no home directory to expand", i, p)
			}
		}
	}

	// Every grade the model prices should be represented, or a level of the
	// scale ships untested against real data.
	seen := map[capability.Severity]bool{}
	for _, e := range list.Paths {
		seen[e.Sensitivity] = true
	}
	for _, g := range []capability.Severity{
		capability.SeverityInfo, capability.SeverityLow, capability.SeverityMedium,
		capability.SeverityHigh, capability.SeverityCritical,
	} {
		if !seen[g] {
			t.Errorf("the shipped list has no %q entry", g)
		}
	}
}

// The ratings the project is actually claiming, checked one path at a time.
// This table is the reviewable form of the security claim: changing a grade
// here should require changing this test, deliberately.
func TestShippedSensitivityRatings(t *testing.T) {
	o := defaultOracle(t)

	cases := []struct {
		path string
		want capability.Severity
		note string
	}{
		// The case that motivated the feature.
		{"/home/dev/.ssh/id_rsa", capability.SeverityCritical, "a private key the agent cannot rotate"},
		{"/root/.ssh/id_ed25519", capability.SeverityCritical, "home is not assumed to be /home"},
		{"/etc/shadow", capability.SeverityCritical, "password hashes"},
		{"/etc/sudoers.d/90-agent", capability.SeverityCritical, "escalation surface"},
		{"/home/dev/.aws/credentials", capability.SeverityCritical, "long-lived cloud keys"},
		{"/home/dev/.gnupg/private-keys-v1.d/x.key", capability.SeverityCritical, "signing keys"},
		{"/srv/certs/server.pem", capability.SeverityCritical, "identified by format, not location"},

		// The rest of an SSH directory is high rather than critical: it
		// enumerates rather than authenticates.
		{"/home/dev/.ssh/known_hosts", capability.SeverityHigh, ""},
		{"/home/dev/webapp/.env", capability.SeverityHigh, "inside a workspace, still a token store"},
		{"/home/dev/.npmrc", capability.SeverityHigh, "publish tokens"},
		{"/proc/4021/environ", capability.SeverityHigh, "another process's environment"},

		{"/etc/passwd", capability.SeverityMedium, "read constantly by ordinary tooling"},
		{"/home/dev/.bash_history", capability.SeverityMedium, ""},

		{"/etc/resolv.conf", capability.SeverityLow, "reading is unremarkable; writing redirects"},

		// Explicitly rated unremarkable — the distinction the module refuses to
		// collapse. These are NOT unknown.
		{"/usr/include/stdio.h", capability.SeverityInfo, "ordinary build traffic"},
		{"/usr/share/doc/README", capability.SeverityInfo, ""},
		{"/etc/ssl/certs/ca-certificates.crt", capability.SeverityInfo, "public trust store"},

		// Genuinely unknown: the list has never heard of these.
		{"/home/dev/project/internal/parser/parse.go", SensitivityUnknown, "workspace source"},
		{"/home/dev/.cache/go-build/a3/a3f19c2e", SensitivityUnknown, "build cache"},
		{"/usr/local/go/src/fmt/print.go", SensitivityUnknown, "a toolchain the list does not know"},
	}

	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			got, reason := o.PathSensitivityReason(c.path)
			if got != c.want {
				t.Errorf("PathSensitivity(%q) = %q, want %q (%s)", c.path, got, c.want, c.note)
			}
			if KnownSensitivity(got) && reason == "" {
				t.Errorf("%q was rated %q with no reason to show a reader", c.path, got)
			}
			if !KnownSensitivity(got) && reason != "" {
				t.Errorf("%q is unrated but carries a reason %q", c.path, reason)
			}
		})
	}
}

// Highest grade wins, so a narrower entry can only ever raise a path. The
// shipped list depends on this: `/**/.ssh/id_*` is critical and `/**/.ssh/**`
// is high, and both match a private key.
func TestHighestGradeWins(t *testing.T) {
	o := oracleFrom(t, `
  - patterns: [/ws/**]
    sensitivity: low
    reason: broad
  - patterns: [/ws/secrets/**]
    sensitivity: critical
    reason: narrow
`)
	if got := o.PathSensitivity("/ws/secrets/key"); got != capability.SeverityCritical {
		t.Errorf("got %q, want the narrower critical entry to win", got)
	}
	if got := o.PathSensitivity("/ws/main.go"); got != capability.SeverityLow {
		t.Errorf("got %q, want low", got)
	}

	// Declaration order must not decide it, so the same two entries reversed
	// reach the same answer.
	rev := oracleFrom(t, `
  - patterns: [/ws/secrets/**]
    sensitivity: critical
    reason: narrow
  - patterns: [/ws/**]
    sensitivity: low
    reason: broad
`)
	if got := rev.PathSensitivity("/ws/secrets/key"); got != capability.SeverityCritical {
		t.Errorf("got %q with the entries reversed, want critical either way", got)
	}
}

// --- unknown is a third state -------------------------------------------------------

// The property the whole file is arranged around: an unrated resource must be
// distinguishable from a resource rated unremarkable, and neither may be read
// as "fine".
func TestUnknownIsNotTheSameAsNotSensitive(t *testing.T) {
	o := defaultOracle(t)
	e := engineWith(t, o)

	unknown := scoreWith(t, e, departure(capability.KindFileRead, "/home/dev/project/main.go"))
	rated := scoreWith(t, e, departure(capability.KindFileRead, "/usr/include/stdio.h"))

	ug, _, upts, uok := sensitivityOf(unknown)
	rg, _, rpts, rok := sensitivityOf(rated)

	if !uok || !rok {
		t.Fatal("an engine built with an oracle produced no sensitive_path factor")
	}
	if ug != SensitivityUnknownLabel {
		t.Errorf("an unlisted path reported %q, want %q", ug, SensitivityUnknownLabel)
	}
	if rg != string(capability.SeverityInfo) {
		t.Errorf("a path rated info reported %q", rg)
	}
	if ug == rg {
		t.Error("unrated and rated-unremarkable are indistinguishable in the record")
	}

	// They contribute the same points — zero — which is exactly why the record
	// has to carry the distinction the score cannot.
	if upts != 0 || rpts != 0 {
		t.Errorf("points: unknown %v, info %v; both must be 0", upts, rpts)
	}
	if unknown.Score != rated.Score {
		t.Errorf("scores diverged (%v vs %v); neither grade may move a score", unknown.Score, rated.Score)
	}
}

// An engine with no oracle emits no factor at all. Three states, all
// distinguishable: nobody asked, asked and unknown, asked and rated.
func TestNoOracleMeansNobodyAsked(t *testing.T) {
	plain := score(t, departure(capability.KindFileRead, "/home/dev/.ssh/id_rsa"))
	if _, _, _, ok := sensitivityOf(plain); ok {
		t.Error("an engine built without an oracle produced a sensitive_path factor")
	}

	e := engineWith(t, defaultOracle(t))
	withOracle := scoreWith(t, e, departure(capability.KindFileRead, "/home/dev/.ssh/id_rsa"))
	g, _, pts, ok := sensitivityOf(withOracle)
	if !ok {
		t.Fatal("an engine built with an oracle produced no factor")
	}
	if g != string(capability.SeverityCritical) || pts != 25 {
		t.Errorf("got %q at %v points, want critical at 25", g, pts)
	}
	if withOracle.Score <= plain.Score {
		t.Errorf("sensitivity did not raise the score: %v with, %v without", withOracle.Score, plain.Score)
	}
}

// Every dimension the oracle interface declares is consulted, and the two this
// build cannot answer say so by name rather than by omission or by a
// reassuring zero.
func TestEveryOracleDimensionIsConsulted(t *testing.T) {
	e := engineWith(t, defaultOracle(t))

	// Each domain reports through the factor that owns it. The network domain
	// moved to sensitive_host when host ratings arrived, which is the shape the
	// executable dimension will take when it gets a list of its own: a
	// dimension with knowledge behind it gets its own factor, and the ones
	// without knowledge stay on sensitive_path saying "unrated".
	cases := []struct {
		name       string
		kind       capability.Kind
		target     string
		wantFactor string
		wantDim    string
		wantGr     string
	}{
		{"filesystem rates the path", capability.KindFileRead, "/etc/shadow",
			FactorSensitivePath, DimensionPath, string(capability.SeverityCritical)},
		{"network rates the destination", capability.KindNetConnect, "169.254.169.254:80",
			FactorSensitiveHost, DimensionHost, string(capability.SeverityCritical)},
		{"network says unknown for a host it has never heard of", capability.KindNetConnect, "evil.example:443",
			FactorSensitiveHost, DimensionHost, SensitivityUnknownLabel},
		{"process is unrated in this build", capability.KindProcessExec, "/bin/sh",
			FactorSensitivePath, DimensionExecutable, SensitivityUnknownLabel},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := scoreWith(t, e, ScoreRequest{
				Event:      observedEvent(c.kind, c.target),
				Validation: result(decision.VerdictOutsideEnvelope, viol(validator.ViolationUngrantedCapability, capability.SeverityMedium)),
				Envelope:   envelope(),
				History:    history().withSeen(c.kind, c.target),
			})

			f := factor(a, c.wantFactor)
			if f == nil {
				t.Fatalf("no %s factor; factors were %v", c.wantFactor, names(a))
			}
			if got := f.Evidence[EvidenceDimension]; got != c.wantDim {
				t.Errorf("dimension = %q, want %q", got, c.wantDim)
			}
			if got := f.Evidence[EvidenceSensitivity]; got != c.wantGr {
				t.Errorf("sensitivity = %q, want %q", got, c.wantGr)
			}

			// Exactly one of the two resource factors speaks per event. Both
			// would make an operator read two lines to learn one thing, and
			// would leave a sentence about paths on an event that touched none.
			other := FactorSensitivePath
			if c.wantFactor == FactorSensitivePath {
				other = FactorSensitiveHost
			}
			if factor(a, other) != nil {
				t.Errorf("%s also reported on a %s event", other, c.kind)
			}
		})
	}

	// The one dimension still without a list of its own answers explicitly
	// unknown when asked directly, so the interface is implemented rather than
	// two-thirds implemented.
	o := defaultOracle(t)
	if got := o.ExecutableSensitivity("/usr/bin/curl"); got != SensitivityUnknown {
		t.Errorf("ExecutableSensitivity = %q, want unknown", got)
	}
	if KnownSensitivity(o.ExecutableSensitivity("/anything")) {
		t.Error("an unrated executable reported as a known grade")
	}
}

// A capability in a domain no oracle method covers says "unrated" rather than
// implying a lookup happened and came back clean.
func TestDomainsWithNoOracleMethodAreUnrated(t *testing.T) {
	e := engineWith(t, defaultOracle(t))
	a := scoreWith(t, e, ScoreRequest{
		Event:      observedEvent(capability.KindKernelBPFLoad, "bpf-program"),
		Validation: result(decision.VerdictOutsideEnvelope, viol(validator.ViolationUngrantedCapability, capability.SeverityCritical)),
		Envelope:   envelope(),
		History:    history(),
	})
	g, dim, pts, ok := sensitivityOf(a)
	if !ok {
		t.Fatal("no sensitive_path factor")
	}
	if dim != DimensionUnrated || g != SensitivityUnknownLabel || pts != 0 {
		t.Errorf("got %q/%q at %v, want unrated/unknown at 0", dim, g, pts)
	}
}

// An unresolvable event has no target to rate, and that is unknown rather than
// unremarkable — the same refusal the validator makes about coverage.
func TestAnUnresolvableEventIsUnrated(t *testing.T) {
	e := engineWith(t, defaultOracle(t))
	a := scoreWith(t, e, ScoreRequest{
		Event:      unresolvableEvent(),
		Validation: result(decision.VerdictIndeterminate, viol(validator.ViolationUnresolvable, capability.SeverityMedium)),
		Envelope:   envelope(),
		History:    history(),
	})
	g, _, pts, ok := sensitivityOf(a)
	if !ok {
		t.Fatal("no sensitive_path factor")
	}
	if g != SensitivityUnknownLabel || pts != 0 {
		t.Errorf("got %q at %v points, want unknown at 0", g, pts)
	}

	// Directly: the oracle refuses a path the matcher would refuse, rather than
	// reporting it unremarkable.
	o := defaultOracle(t)
	for _, p := range []string{"", "relative/path", "/etc/../etc/shadow", "not/absolute/.ssh/id_rsa"} {
		if got := o.PathSensitivity(p); got != SensitivityUnknown {
			t.Errorf("PathSensitivity(%q) = %q, want unknown", p, got)
		}
	}
}

// --- grading ---------------------------------------------------------------------------

// The full price list, one grade at a time. info and low are zero on purpose:
// they say something to a reader and nothing to a score.
func TestEverySensitivityGradeIsPriced(t *testing.T) {
	cases := []struct {
		grade  capability.Severity
		points float64
	}{
		{capability.SeverityInfo, 0},
		{capability.SeverityLow, 0},
		{capability.SeverityMedium, 8},
		{capability.SeverityHigh, 15},
		{capability.SeverityCritical, 25},
	}

	for _, c := range cases {
		t.Run(string(c.grade), func(t *testing.T) {
			o := oracleFrom(t, "  - patterns: [/graded/**]\n    sensitivity: "+string(c.grade)+
				"\n    reason: a reason written down\n")
			e := engineWith(t, o)

			a := scoreWith(t, e, departure(capability.KindFileRead, "/graded/x"))
			_, _, pts, ok := sensitivityOf(a)
			if !ok {
				t.Fatal("no sensitive_path factor")
			}
			if pts != c.points {
				t.Errorf("%q contributed %v points, want %v", c.grade, pts, c.points)
			}

			// The score moves by exactly the factor's weight and nothing else,
			// which is what keeps the model checkable by hand.
			base := score(t, departure(capability.KindFileRead, "/graded/x"))
			if a.Score-base.Score != c.points {
				t.Errorf("score moved by %v, want %v", a.Score-base.Score, c.points)
			}

			// Never negative. A list may only raise.
			if pts < 0 {
				t.Errorf("%q contributed a negative %v", c.grade, pts)
			}
		})
	}
}

// The written reason reaches the audit record, so "why did this score go up" is
// answered by the sentence its author wrote.
func TestTheReasonReachesTheRecord(t *testing.T) {
	const reason = "a credential granting access to other hosts that the agent cannot rotate"
	o := oracleFrom(t, "  - patterns: [/graded/**]\n    sensitivity: critical\n    reason: "+reason+"\n")
	e := engineWith(t, o)

	a := scoreWith(t, e, departure(capability.KindFileRead, "/graded/key"))
	f := factor(a, FactorSensitivePath)
	if f == nil {
		t.Fatal("no sensitive_path factor")
	}
	if f.Evidence[EvidenceReason] != reason {
		t.Errorf("reason = %q, want the list's own sentence", f.Evidence[EvidenceReason])
	}
	if f.Evidence[EvidenceTarget] != "/graded/key" {
		t.Errorf("target = %q, want the path that was rated", f.Evidence[EvidenceTarget])
	}
}

// A grade this build cannot read is an unknown quantity, not a harmless one —
// the same rule severityPointsFor applies to an unrecognized violation
// severity. Reachable only through a third-party oracle, since the loader
// refuses such a grade in a file.
func TestAnUnrecognizedGradeIsNotHarmless(t *testing.T) {
	e := engineWith(t, fixedOracle{grade: capability.Severity("severe")})
	a := scoreWith(t, e, departure(capability.KindFileRead, "/anything"))

	g, _, pts, ok := sensitivityOf(a)
	if !ok {
		t.Fatal("no sensitive_path factor")
	}
	if pts != sensitivityPoints[capability.SeverityMedium] {
		t.Errorf("an unrecognized grade contributed %v, want the medium fallback %v",
			pts, sensitivityPoints[capability.SeverityMedium])
	}
	// Reported verbatim rather than flattened to "unknown": the oracle did say
	// something, and a record that hid which word it used would make the
	// mismatch impossible to find.
	if g != "severe" {
		t.Errorf("sensitivity = %q, want the oracle's own word recorded", g)
	}
	if g == SensitivityUnknownLabel {
		t.Error("a grade the oracle did assign was reported as unknown")
	}
}

type fixedOracle struct{ grade capability.Severity }

func (o fixedOracle) PathSensitivity(string) capability.Severity       { return o.grade }
func (o fixedOracle) HostSensitivity(string) capability.Severity       { return o.grade }
func (o fixedOracle) ExecutableSensitivity(string) capability.Severity { return o.grade }

// --- interaction with the rest of the model ------------------------------------------------

// Sensitivity stacks additively with the factors that were already there, and
// changes none of them. In particular it must not alter the severity the
// validator assigned, which the violation_severity factor reports verbatim.
func TestSensitivityStacksWithoutDisturbingTheOthers(t *testing.T) {
	e := engineWith(t, defaultOracle(t))

	const key = "/home/dev/.ssh/id_rsa"
	esc := viol(validator.ViolationWorkspaceEscape, capability.SeverityHigh)
	esc.Expected, esc.Observed = "within "+ws, key

	req := ScoreRequest{
		Event: fileEvent(capability.KindFileRead, key),
		Validation: result(decision.VerdictGrantExceeded,
			viol(validator.ViolationSelectorMismatch, capability.SeverityMedium), esc),
		Envelope: envelope(),
		History:  history().withViolations(3),
	}

	plain := score(t, req)
	rated := scoreWith(t, e, req)

	// 25 grant_exceeded + 15 escape severity + 10 escape + 5 novel + 3 prior.
	if plain.Score != 58 {
		t.Fatalf("baseline score = %v, want 58", plain.Score)
	}
	// The same, plus 25 for a critical resource.
	if rated.Score != 83 {
		t.Errorf("score = %v, want 83 (factors %+v)", rated.Score, rated.Factors)
	}

	// Every other factor is untouched, weight for weight. This is the "do not
	// modify Violation.Severity" rule checked from the outside: had sensitivity
	// been folded into severity, violation_severity would have moved.
	for _, name := range []string{FactorVerdict, FactorViolationSeverity, FactorWorkspaceEscape, FactorNovelTarget, FactorViolationHistory} {
		a, b := factor(plain, name), factor(rated, name)
		if a == nil || b == nil {
			t.Fatalf("%s missing from one of the assessments", name)
		}
		if !reflect.DeepEqual(*a, *b) {
			t.Errorf("%s changed when sensitivity was added:\n without %+v\n with    %+v", name, *a, *b)
		}
	}

	// And the ordering an operator reads the factor list in.
	want := []string{
		FactorVerdict, FactorViolationSeverity, FactorSensitivePath,
		FactorWorkspaceEscape, FactorNovelTarget, FactorViolationHistory, FactorEvidenceBasis,
	}
	if got := names(rated); !reflect.DeepEqual(got, want) {
		t.Errorf("factors = %v, want %v", got, want)
	}

	// Confidence is unchanged: sensitivity is a finding about the resource, not
	// one of the model's three evidence inputs about the event.
	if rated.Confidence != plain.Confidence {
		t.Errorf("confidence moved from %v to %v", plain.Confidence, rated.Confidence)
	}
}

// A covered event still scores exactly zero, and the grade is still reported.
//
// The invariant is load-bearing — LevelNone has to keep meaning "nothing
// departed" — but a grant over credential material is worth seeing in an audit,
// so the finding survives with the points withheld and the reason why stated.
func TestACoveredEventKeepsItsZeroButNotItsSilence(t *testing.T) {
	e := engineWith(t, defaultOracle(t))

	a := scoreWith(t, e, ScoreRequest{
		Event:      fileEvent(capability.KindFileRead, "/home/dev/.ssh/id_rsa"),
		Validation: result(decision.VerdictWithinEnvelope),
		Envelope:   envelope(),
		History:    history().withViolations(9),
	})

	if a.Score != 0 || a.Level != decision.LevelNone {
		t.Errorf("a covered read of a private key scored %v (%q), want 0 / none", a.Score, a.Level)
	}

	f := factor(a, FactorSensitivePath)
	if f == nil {
		t.Fatal("the grade was not reported at all")
	}
	if f.Evidence[EvidenceSensitivity] != string(capability.SeverityCritical) {
		t.Errorf("sensitivity = %q, want critical to be reported even uncharged",
			f.Evidence[EvidenceSensitivity])
	}
	if f.Weight != 0 {
		t.Errorf("weight = %v, want 0 for an operation the envelope covered", f.Weight)
	}
	if f.Evidence[EvidenceNotCharged] == "" {
		t.Error("the points were withheld without saying why")
	}
}

// Clamping still holds with the oracle-backed factors in play. The ceiling is
// 190: the unrated engine's 110, plus 25 for sensitive_path, 30 for
// credential_access_egress, and 25 for sensitive_host, all three of which
// arrive with an oracle. It is asserted as an exact number so that adding a
// scorer is a deliberate act — the scale is clamped rather than rescaled
// precisely so a new factor cannot silently move every existing score, and this
// is where that stays true.
//
// The declared ceiling is not reachable, and deliberately overstates: a single
// event has either a path or a destination, never both, so sensitive_path and
// sensitive_host cannot contribute together. Summing the declared weights is
// still the right check, because Weight() is each scorer's own promise about
// what it can contribute and the clamp has to hold against the sum of the
// promises rather than against a case analysis of which co-occur.
func TestSensitivityDoesNotEscapeTheScale(t *testing.T) {
	e := engineWith(t, defaultOracle(t))

	var ceiling float64
	for _, s := range e.Scorers() {
		ceiling += s.Weight()
	}
	if ceiling != 190 {
		t.Errorf("scorer ceiling = %v, want 190", ceiling)
	}

	esc := viol(validator.ViolationWorkspaceEscape, capability.SeverityHigh)
	a := scoreWith(t, e, ScoreRequest{
		Event: fileEvent(capability.KindFileDelete, "/etc/shadow"),
		Validation: result(decision.VerdictExplicitlyDenied,
			viol(validator.ViolationExplicitDenial, capability.SeverityCritical), esc),
		Envelope: envelope(),
		History:  history().withViolations(40),
	})
	if a.Score != ScoreMax {
		t.Errorf("Score = %v, want it clamped to %v", a.Score, ScoreMax)
	}
	if a.Level != decision.LevelCritical {
		t.Errorf("Level = %q, want critical", a.Level)
	}
}

// Repeated scoring against one oracle produces one answer, including the order
// of the entry scan — which is a sort over a map-free slice precisely so it
// cannot depend on iteration order.
func TestSensitivityScoringIsDeterministic(t *testing.T) {
	e := engineWith(t, defaultOracle(t))
	req := departure(capability.KindFileRead, "/home/dev/.ssh/id_rsa")

	first := scoreWith(t, e, req)
	for i := 0; i < 50; i++ {
		fresh := engineWith(t, defaultOracle(t))
		if got := scoreWith(t, fresh, req); !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d diverged\n got %+v\nwant %+v", i, got, first)
		}
	}
}

// --- admission: unusable entries fail closed ------------------------------------------------

// Every rejection covers a defect that would otherwise produce a list that
// loads, runs, and protects less than its author believes.
func TestSensitivityListRejections(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "relative pattern",
			yaml: "  - patterns: [\"**/.ssh/**\"]\n    sensitivity: critical\n    reason: r\n",
			want: "not absolute",
		},
		{
			name: "** mixed into a segment",
			yaml: "  - patterns: [/home/**dev/**]\n    sensitivity: high\n    reason: r\n",
			want: "whole segment",
		},
		{
			name: "empty pattern",
			yaml: "  - patterns: [\"\"]\n    sensitivity: high\n    reason: r\n",
			want: "empty",
		},
		{
			name: "relative segment",
			yaml: "  - patterns: [/home/../etc/shadow]\n    sensitivity: high\n    reason: r\n",
			want: "relative segment",
		},
		{
			name: "no patterns",
			yaml: "  - patterns: []\n    sensitivity: high\n    reason: r\n",
			want: "no patterns",
		},
		{
			name: "no sensitivity",
			yaml: "  - patterns: [/etc/shadow]\n    reason: r\n",
			want: "does not set sensitivity",
		},
		{
			name: "unknown sensitivity",
			yaml: "  - patterns: [/etc/shadow]\n    sensitivity: severe\n    reason: r\n",
			want: "unknown sensitivity",
		},
		{
			name: "no reason",
			yaml: "  - patterns: [/etc/shadow]\n    sensitivity: critical\n",
			want: "no reason",
		},
		{
			name: "empty reason",
			yaml: "  - patterns: [/etc/shadow]\n    sensitivity: critical\n    reason: \"\"\n",
			want: "no reason",
		},
		{
			name: "misspelled field",
			yaml: "  - patterns: [/etc/shadow]\n    sensitivty: critical\n    reason: r\n",
			want: "field sensitivty not found",
		},
		{
			name: "one bad pattern among good ones refuses the file",
			yaml: "  - patterns: [/etc/shadow, \"bad**pattern\"]\n    sensitivity: critical\n    reason: r\n",
			want: "not absolute",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseSensitivityList(listYAML(c.yaml), "test")
			if err == nil {
				t.Fatalf("accepted %s", c.name)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %v, want it to mention %q", err, c.want)
			}
		})
	}

	// Whole-file rejections.
	for _, c := range []struct{ name, body, want string }{
		{"empty file", "", "no entries"},
		{"comments only", "# nothing here\n", "no entries"},
		{"no paths key", "name: t\nversion: \"1\"\n", "no entries"},
		{"unknown top-level field", "name: t\nrules: []\npaths: []\n", "field rules not found"},
		{"malformed yaml", "paths: [\n", "parse sensitivity list"},
		{"second document", "name: t\npaths:\n  - patterns: [/etc/shadow]\n    sensitivity: critical\n    reason: r\n---\nname: other\n", "more than one YAML document"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseSensitivityList([]byte(c.body), "test")
			if err == nil {
				t.Fatalf("accepted %s", c.name)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %v, want it to mention %q", err, c.want)
			}
		})
	}

	// A missing file is an error, not an empty list.
	if _, err := LoadSensitivityList(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Error("a missing sensitivity list loaded successfully")
	}
}

// The oracle re-validates rather than trusting a programmatically built list,
// since the admission rule has to hold whether or not the loader was involved.
func TestOracleRefusesAnUnvalidatedList(t *testing.T) {
	_, err := NewResourceOracle(&SensitivityList{
		Paths: []SensitivityEntry{{Patterns: []string{"**/.ssh/**"}, Sensitivity: capability.SeverityCritical, Reason: "r"}},
	})
	if err == nil {
		t.Fatal("the oracle accepted an unusable pattern that the loader would refuse")
	}
	if !strings.Contains(err.Error(), "not absolute") {
		t.Errorf("error = %v, want the pattern named", err)
	}

	if _, err := NewResourceOracle(nil); err == nil {
		t.Error("the oracle accepted a nil list")
	}
}

// A nil oracle is refused rather than defaulted away, because an engine that
// looks configured and rates nothing is the failure this file exists to
// prevent.
func TestEngineRefusesANilOracle(t *testing.T) {
	if _, err := NewEngineWithOracle(nil); err == nil {
		t.Fatal("NewEngineWithOracle accepted a nil oracle")
	}

	// The same refusal one layer down, for a hand-assembled scorer set.
	if _, err := (SensitivePathScorer{}).Evaluate(context.Background(), ScoreRequest{
		Event:      fileEvent(capability.KindFileRead, "/etc/shadow"),
		Validation: result(decision.VerdictOutsideEnvelope),
	}); err == nil {
		t.Error("a scorer with no oracle produced a factor")
	}

	// And a nil *ResourceOracle reads as knowing nothing rather than panicking,
	// which is what session.MemoryState's nil handling established as the house
	// rule for absent state.
	var nilOracle *ResourceOracle
	if got := nilOracle.PathSensitivity("/etc/shadow"); got != SensitivityUnknown {
		t.Errorf("a nil oracle reported %q, want unknown", got)
	}
}

// The scorer metadata has to keep matching what it produces, the same check the
// standard set gets.
func TestSensitiveScorerAgreesWithItsMetadata(t *testing.T) {
	s := NewSensitivePathScorer(defaultOracle(t))
	if s.Name() != FactorSensitivePath {
		t.Errorf("Name = %q", s.Name())
	}
	if s.Weight() != 25 {
		t.Errorf("Weight = %v, want 25", s.Weight())
	}

	f, err := s.Evaluate(context.Background(), departure(capability.KindFileRead, "/etc/shadow"))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if f == nil {
		t.Fatal("no factor")
	}
	if f.Name != s.Name() || f.Weight > s.Weight() || f.Description == "" {
		t.Errorf("factor %+v disagrees with its scorer", *f)
	}
	if _, err := s.Evaluate(context.Background(), ScoreRequest{Event: fileEvent(capability.KindFileRead, "/x")}); err == nil {
		t.Error("the scorer evaluated a request with no validation behind it")
	}
}

// --- benchmark ----------------------------------------------------------------------------

// The path that matters: an ordinary file the list has never heard of. The
// unknown answer must not cost an allocation, since it is what an oracle says
// about almost every event.
func BenchmarkScoreWithOracleUnrated(b *testing.B) {
	o, err := LoadResourceOracle(defaultListPath())
	if err != nil {
		b.Fatal(err)
	}
	e, err := NewEngineWithOracle(o)
	if err != nil {
		b.Fatal(err)
	}
	req := ScoreRequest{
		Event:      fileEvent(capability.KindFileWrite, ws+"/main.go"),
		Validation: result(decision.VerdictWithinEnvelope),
		Envelope:   envelope(),
		History:    history(),
	}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := e.Score(ctx, req); err != nil {
			b.Fatal(err)
		}
	}
}

// The expensive answer: a rated critical path, which scans to a match and
// builds evidence carrying the reason.
func BenchmarkScoreWithOracleRated(b *testing.B) {
	o, err := LoadResourceOracle(defaultListPath())
	if err != nil {
		b.Fatal(err)
	}
	e, err := NewEngineWithOracle(o)
	if err != nil {
		b.Fatal(err)
	}
	req := departure(capability.KindFileRead, "/home/dev/.ssh/id_rsa")
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := e.Score(ctx, req); err != nil {
			b.Fatal(err)
		}
	}
}
