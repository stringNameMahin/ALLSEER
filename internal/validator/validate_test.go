package validator

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stringNameMahin/ALLSEER/internal/telemetry/replay"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// --- helpers ----------------------------------------------------------------

// fakeState is a SessionState with fixed answers. The validator reads counters
// and never advances them, so a struct of constants is a complete stand-in.
type fakeState struct {
	grantUse map[int]int
	writes   int
	sent     int64
	procs    int
	seconds  float64
	seen     map[string]bool
}

func (s fakeState) GrantUseCount(i int) int { return s.grantUse[i] }
func (s fakeState) FileWriteCount() int     { return s.writes }
func (s fakeState) NetworkBytesSent() int64 { return s.sent }
func (s fakeState) ProcessCount() int       { return s.procs }
func (s fakeState) ElapsedSeconds() float64 { return s.seconds }
func (s fakeState) SeenTargets(k capability.Kind, target string) bool {
	return s.seen[string(k)+"|"+target]
}

var _ SessionState = fakeState{}

func fileEvent(kind capability.Kind, resolved string) *event.Event {
	return &event.Event{
		ID:         "e-1",
		Capability: kind,
		Domain:     capability.DomainFilesystem,
		File:       &event.FilePayload{ResolvedPath: resolved},
	}
}

func netEvent(host, addr string, port int) *event.Event {
	return &event.Event{
		ID:         "e-net",
		Capability: capability.KindNetConnect,
		Domain:     capability.DomainNetwork,
		Network: &event.NetworkPayload{
			Protocol: "tcp", Hostname: host, DestAddr: addr, DestPort: port,
		},
	}
}

func envelope(grants, denials []capability.Grant) *ece.Envelope {
	return &ece.Envelope{
		SchemaVersion: ece.SchemaVersion,
		ID:            "env-1",
		SessionID:     "s-1",
		Grants:        grants,
		Denials:       denials,
		DefaultAction: ece.ActionWarn,
		Sealed:        true,
	}
}

func pathGrantOf(kind capability.Kind, patterns ...string) capability.Grant {
	return capability.Grant{
		Kind:     kind,
		Domain:   capability.DomainFilesystem,
		Selector: capability.Selector{PathPatterns: patterns},
	}
}

func validate(t *testing.T, env *ece.Envelope, e *event.Event, st SessionState) *Result {
	t.Helper()

	res, err := NewValidator().Validate(context.Background(), ValidateRequest{
		Envelope: env, Event: e, State: st,
	})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res == nil {
		t.Fatal("Validate returned a nil result with no error")
	}
	if res.Verdict == "" {
		t.Fatal("Verdict is empty; a result with no verdict reads as nothing at all")
	}
	if len(res.Reasoning) == 0 {
		t.Error("Reasoning is empty; the verdict reaches the audit log unexplained")
	}
	return res
}

func hasViolation(res *Result, vt ViolationType) bool {
	for _, v := range res.Violations {
		if v.Type == vt {
			return true
		}
	}
	return false
}

// --- the core verdicts ------------------------------------------------------

func TestValidateWithinEnvelope(t *testing.T) {
	env := envelope([]capability.Grant{pathGrantOf(capability.KindFileWrite, "/ws/**")}, nil)

	res := validate(t, env, fileEvent(capability.KindFileWrite, "/ws/src/main.go"), nil)

	if res.Verdict != decision.VerdictWithinEnvelope {
		t.Errorf("Verdict = %q, want within_envelope", res.Verdict)
	}
	if res.MatchedGrant == nil {
		t.Error("MatchedGrant is nil; the audit log cannot say which grant covered this")
	}
	if len(res.Violations) != 0 {
		t.Errorf("Violations = %v, want none", res.Violations)
	}
	if res.MatchedDenial != nil {
		t.Error("MatchedDenial is set on a permitted operation")
	}
}

// TestValidateUngrantedVersusMisTargeted keeps the two findings apart. "The
// agent used a capability nobody expected" and "the agent used an expected
// capability on the wrong thing" are different stories, and collapsing them
// loses the more informative one.
func TestValidateUngrantedVersusMisTargeted(t *testing.T) {
	env := envelope([]capability.Grant{pathGrantOf(capability.KindFileRead, "/ws/**")}, nil)

	// fs.read is granted, but not for this path.
	misTargeted := validate(t, env, fileEvent(capability.KindFileRead, "/etc/passwd"), nil)
	if misTargeted.Verdict != decision.VerdictGrantExceeded {
		t.Errorf("Verdict = %q, want grant_exceeded", misTargeted.Verdict)
	}
	if !hasViolation(misTargeted, ViolationSelectorMismatch) {
		t.Error("no selector_mismatch violation")
	}
	if hasViolation(misTargeted, ViolationUngrantedCapability) {
		t.Error("a mis-targeted grant was reported as an ungranted capability")
	}

	// fs.write appears in no grant at all.
	ungranted := validate(t, env, fileEvent(capability.KindFileWrite, "/ws/src/main.go"), nil)
	if ungranted.Verdict != decision.VerdictOutsideEnvelope {
		t.Errorf("Verdict = %q, want outside_envelope", ungranted.Verdict)
	}
	if !hasViolation(ungranted, ViolationUngrantedCapability) {
		t.Error("no ungranted_capability violation")
	}
	if hasViolation(ungranted, ViolationSelectorMismatch) {
		t.Error("an ungranted capability was reported as a selector mismatch")
	}
}

func TestValidateExplicitDenial(t *testing.T) {
	env := envelope(
		[]capability.Grant{pathGrantOf(capability.KindFileWrite, "/ws/**")},
		[]capability.Grant{pathGrantOf(capability.KindFileWrite, "/ws/.git/**")},
	)

	res := validate(t, env, fileEvent(capability.KindFileWrite, "/ws/.git/config"), nil)

	if res.Verdict != decision.VerdictExplicitlyDenied {
		t.Errorf("Verdict = %q, want explicitly_denied", res.Verdict)
	}
	if res.MatchedDenial == nil {
		t.Fatal("MatchedDenial is nil on a denied operation")
	}
	// A denied result must never carry a matched grant: downstream reads
	// MatchedGrant as "what covered this", and a covered denial is a
	// contradiction.
	if res.MatchedGrant != nil {
		t.Error("MatchedGrant is set on a denied operation")
	}
	if !hasViolation(res, ViolationExplicitDenial) {
		t.Error("no explicit_denial violation")
	}
}

// TestValidateDenialOverridesMoreSpecificGrant is the precedence rule at its
// sharpest: the grant is as narrow as a grant gets and the denial as broad as
// one gets, and the denial still wins.
func TestValidateDenialOverridesMoreSpecificGrant(t *testing.T) {
	env := envelope(
		[]capability.Grant{pathGrantOf(capability.KindFileWrite, "/ws/.git/config")},
		[]capability.Grant{pathGrantOf(capability.KindFileWrite, "/**")},
	)

	res := validate(t, env, fileEvent(capability.KindFileWrite, "/ws/.git/config"), nil)

	if res.Verdict != decision.VerdictExplicitlyDenied {
		t.Errorf("Verdict = %q, want explicitly_denied; specificity must not defeat a denial", res.Verdict)
	}
}

func TestValidateMostSpecificGrantIsReported(t *testing.T) {
	env := envelope([]capability.Grant{
		pathGrantOf(capability.KindFileWrite, "/**"),
		pathGrantOf(capability.KindFileWrite, "/ws/**"),
		pathGrantOf(capability.KindFileWrite, "/ws/src/*.go"),
	}, nil)

	res := validate(t, env, fileEvent(capability.KindFileWrite, "/ws/src/main.go"), nil)

	if res.Verdict != decision.VerdictWithinEnvelope {
		t.Fatalf("Verdict = %q", res.Verdict)
	}
	if got := res.MatchedGrant.Selector.PathPatterns[0]; got != "/ws/src/*.go" {
		t.Errorf("MatchedGrant = %q, want the most specific grant", got)
	}
}

// --- unevaluable ------------------------------------------------------------

func TestValidateUnresolvableObservation(t *testing.T) {
	env := envelope([]capability.Grant{pathGrantOf(capability.KindFileWrite, "/ws/**")}, nil)

	// Enrichment failed: the resolved path is empty, so the target is unknown.
	e := &event.Event{
		Capability: capability.KindFileWrite,
		File:       &event.FilePayload{Path: "src/main.go"},
	}
	res := validate(t, env, e, nil)

	if res.Verdict != decision.VerdictIndeterminate {
		t.Errorf("Verdict = %q, want indeterminate", res.Verdict)
	}
	if !hasViolation(res, ViolationUnresolvable) {
		t.Error("no unresolvable violation")
	}
	if hasViolation(res, ViolationSelectorMismatch) {
		t.Error("an unevaluable observation was reported as a selector mismatch")
	}
	if res.MatchedGrant != nil {
		t.Error("MatchedGrant is set on an indeterminate result")
	}
}

// TestValidateUnevaluableDenialBlocksAGrant is the subtle one, and the reason
// denials are evaluated before grants rather than alongside them.
//
// A grant plainly covers the operation, but a denial of the same capability
// could not be evaluated. Answering "within envelope" would mean the cheapest
// way past a denial is to make its target unresolvable.
func TestValidateUnevaluableDenialBlocksAGrant(t *testing.T) {
	env := envelope(
		[]capability.Grant{{
			Kind:     capability.KindNetConnect,
			Domain:   capability.DomainNetwork,
			Selector: capability.Selector{Hosts: []string{"10.0.0.0/8"}},
		}},
		[]capability.Grant{{
			Kind:     capability.KindNetConnect,
			Domain:   capability.DomainNetwork,
			Selector: capability.Selector{Hosts: []string{"exfil.example.com"}},
		}},
	)

	// The address is inside the granted block, so the grant matches. The denial
	// names a host whose correlation is missing, so it cannot be ruled out.
	res := validate(t, env, netEvent("", "10.1.2.3", 443), nil)

	if res.Verdict != decision.VerdictIndeterminate {
		t.Fatalf("Verdict = %q, want indeterminate; an uncheckable denial was dismissed", res.Verdict)
	}
	if res.MatchedGrant != nil {
		t.Error("MatchedGrant is set although the denial could not be ruled out")
	}
	if !hasViolation(res, ViolationUnresolvable) {
		t.Error("no unresolvable violation")
	}
}

// TestValidateCorrelationMissingIsNamed checks that the reason a network
// observation could not be evaluated survives into the violation. "We could not
// tell" and "we could not tell because DNS correlation failed" are the same
// verdict and different findings for whoever reads the log.
func TestValidateCorrelationMissingIsNamed(t *testing.T) {
	env := envelope([]capability.Grant{{
		Kind:     capability.KindNetConnect,
		Domain:   capability.DomainNetwork,
		Selector: capability.Selector{Hosts: []string{"api.github.com"}},
	}}, nil)

	res := validate(t, env, netEvent("", "140.82.121.5", 443), nil)

	if res.Verdict != decision.VerdictIndeterminate {
		t.Fatalf("Verdict = %q, want indeterminate", res.Verdict)
	}
	var detail string
	for _, v := range res.Violations {
		if v.Type == ViolationUnresolvable {
			detail = v.Detail
		}
	}
	if !strings.Contains(detail, "correlation") {
		t.Errorf("violation detail = %q, want it to name the correlation failure", detail)
	}
}

// TestValidateCorrelatedNetworkStillConcludes guards the test above from
// passing for the wrong reason: when correlation succeeded, the same shapes
// must produce ordinary verdicts rather than indeterminate.
func TestValidateCorrelatedNetworkStillConcludes(t *testing.T) {
	env := envelope([]capability.Grant{{
		Kind:     capability.KindNetConnect,
		Domain:   capability.DomainNetwork,
		Selector: capability.Selector{Hosts: []string{"api.github.com"}, Ports: []int{443}},
	}}, nil)

	within := validate(t, env, netEvent("api.github.com", "140.82.121.5", 443), nil)
	if within.Verdict != decision.VerdictWithinEnvelope {
		t.Errorf("Verdict = %q, want within_envelope", within.Verdict)
	}

	elsewhere := validate(t, env, netEvent("evil.example.com", "1.2.3.4", 443), nil)
	if elsewhere.Verdict != decision.VerdictGrantExceeded {
		t.Errorf("Verdict = %q, want grant_exceeded", elsewhere.Verdict)
	}
}

func TestValidateUnresolvableEvents(t *testing.T) {
	env := envelope([]capability.Grant{{Kind: capability.KindFileWrite}}, nil)

	tests := []struct {
		name string
		e    *event.Event
	}{
		{"no payload", &event.Event{Capability: capability.KindFileWrite}},
		{"unknown capability", &event.Event{Capability: capability.Kind("fs.teleport")}},
		{"network event without payload", &event.Event{Capability: capability.KindNetConnect}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := validate(t, env, tt.e, nil)

			// The grant here is unconstrained, so a blank observation would
			// have satisfied it. Nothing uninterpretable may read as expected.
			if res.Verdict != decision.VerdictIndeterminate {
				t.Errorf("Verdict = %q, want indeterminate", res.Verdict)
			}
			if !hasViolation(res, ViolationUnresolvable) {
				t.Error("no unresolvable violation")
			}
		})
	}
}

// --- workspace escape -------------------------------------------------------

// TestValidateWorkspaceEscapeIsDistinct is the milestone's explicit
// requirement: leaving the workspace is reported as its own violation, not
// folded into the selector mismatch that accompanies it.
func TestValidateWorkspaceEscapeIsDistinct(t *testing.T) {
	// Granted narrower than the workspace, so "outside the grant" and "outside
	// the workspace" are separable.
	env := envelope([]capability.Grant{pathGrantOf(capability.KindFileRead, "/ws/src/**")}, nil)
	env.Constraints.WorkspaceRoot = "/ws"

	escaped := validate(t, env, fileEvent(capability.KindFileRead, "/home/dev/.ssh/id_rsa"), nil)
	if !hasViolation(escaped, ViolationWorkspaceEscape) {
		t.Error("no workspace_escape violation for a read outside the root")
	}
	if !hasViolation(escaped, ViolationSelectorMismatch) {
		t.Error("the selector mismatch was replaced by the escape rather than accompanying it")
	}

	// Inside the workspace, outside the granted glob: a mismatch and nothing
	// more. This is the pair the milestone says must not be conflated --
	// editing the wrong source file is not the same event as writing to /etc.
	inside := validate(t, env, fileEvent(capability.KindFileRead, "/ws/docs/notes.md"), nil)
	if !hasViolation(inside, ViolationSelectorMismatch) {
		t.Error("no selector_mismatch violation inside the workspace")
	}
	if hasViolation(inside, ViolationWorkspaceEscape) {
		t.Error("a file inside the workspace was reported as an escape")
	}

	// A sibling directory sharing the root's name prefix is not inside it,
	// which is the containment bug this check exists to avoid.
	sibling := validate(t, env, fileEvent(capability.KindFileRead, "/wsx/file"), nil)
	if !hasViolation(sibling, ViolationWorkspaceEscape) {
		t.Error("/wsx was treated as inside /ws")
	}
}

func TestValidateWorkspaceEscapeNotReportedWhenGranted(t *testing.T) {
	// A grant that deliberately reaches outside the workspace -- a module cache,
	// a toolchain -- is authorized. Flagging it would make the signal useless in
	// exactly the sessions where it matters.
	env := envelope([]capability.Grant{
		pathGrantOf(capability.KindFileRead, "/ws/**", "/home/dev/.cache/go-build/**"),
	}, nil)
	env.Constraints.WorkspaceRoot = "/ws"

	res := validate(t, env, fileEvent(capability.KindFileRead, "/home/dev/.cache/go-build/ab/cd"), nil)
	if res.Verdict != decision.VerdictWithinEnvelope {
		t.Fatalf("Verdict = %q, want within_envelope", res.Verdict)
	}
	if hasViolation(res, ViolationWorkspaceEscape) {
		t.Error("an explicitly granted path outside the workspace was reported as an escape")
	}
}

func TestValidateWorkspaceEscapeNeedsAResolvedPath(t *testing.T) {
	env := envelope([]capability.Grant{pathGrantOf(capability.KindFileRead, "/ws/**")}, nil)
	env.Constraints.WorkspaceRoot = "/ws"

	e := &event.Event{Capability: capability.KindFileRead, File: &event.FilePayload{Path: "../etc/passwd"}}
	res := validate(t, env, e, nil)

	if hasViolation(res, ViolationWorkspaceEscape) {
		t.Error("an unresolved path was declared a workspace escape; that is inventing evidence")
	}
	if res.Verdict != decision.VerdictIndeterminate {
		t.Errorf("Verdict = %q, want indeterminate", res.Verdict)
	}

	// The same rule where nothing was even evaluated: the capability is
	// ungranted, so no grant was consulted and no grant reported itself
	// unevaluable, yet the target is still unknown. An unknown path cannot be
	// said to have left anywhere.
	ungranted := validate(t, env,
		&event.Event{Capability: capability.KindFileWrite, File: &event.FilePayload{Path: "relative"}}, nil)
	if ungranted.Verdict != decision.VerdictOutsideEnvelope {
		t.Errorf("Verdict = %q, want outside_envelope", ungranted.Verdict)
	}
	if hasViolation(ungranted, ViolationWorkspaceEscape) {
		t.Error("an ungranted capability with an unresolved target was declared a workspace escape")
	}
}

// --- budgets and expiry -----------------------------------------------------

func TestValidateMaxCount(t *testing.T) {
	grant := capability.Grant{
		Kind:     capability.KindFileWrite,
		Domain:   capability.DomainFilesystem,
		Selector: capability.Selector{PathPatterns: []string{"/ws/**"}, MaxCount: 3},
	}
	env := envelope([]capability.Grant{grant}, nil)
	e := fileEvent(capability.KindFileWrite, "/ws/main.go")

	under := validate(t, env, e, fakeState{grantUse: map[int]int{0: 2}})
	if under.Verdict != decision.VerdictWithinEnvelope {
		t.Errorf("Verdict = %q with budget remaining, want within_envelope", under.Verdict)
	}

	// Three uses recorded against a limit of three: this would be the fourth.
	spent := validate(t, env, e, fakeState{grantUse: map[int]int{0: 3}})
	if spent.Verdict != decision.VerdictGrantExceeded {
		t.Errorf("Verdict = %q with the budget spent, want grant_exceeded", spent.Verdict)
	}
	if !hasViolation(spent, ViolationCountExceeded) {
		t.Error("no count_exceeded violation")
	}
	if spent.MatchedGrant == nil {
		t.Error("MatchedGrant is nil; the exhausted grant must still be named")
	}

	// Without session state there is no history, so nothing has been spent.
	stateless := validate(t, env, e, nil)
	if stateless.Verdict != decision.VerdictWithinEnvelope {
		t.Errorf("Verdict = %q without session state, want within_envelope", stateless.Verdict)
	}
}

// TestValidateMaxCountChargesTheWinningGrant: the counter charged is the one
// belonging to the grant precedence selected, which is why precedence has to
// run before the budget check.
func TestValidateMaxCountChargesTheWinningGrant(t *testing.T) {
	env := envelope([]capability.Grant{
		{ // 0: broad, unlimited
			Kind:     capability.KindFileWrite,
			Selector: capability.Selector{PathPatterns: []string{"/ws/**"}},
		},
		{ // 1: narrow, exhausted
			Kind:     capability.KindFileWrite,
			Selector: capability.Selector{PathPatterns: []string{"/ws/src/*.go"}, MaxCount: 1},
		},
	}, nil)

	res := validate(t, env, fileEvent(capability.KindFileWrite, "/ws/src/main.go"),
		fakeState{grantUse: map[int]int{1: 1}})

	if res.Verdict != decision.VerdictGrantExceeded {
		t.Errorf("Verdict = %q, want grant_exceeded; the exhausted narrow grant is the one that applies", res.Verdict)
	}
}

// TestValidateSessionConstraintOnAGrantedOperation covers the verdict that
// only exists for operations that were individually fine: the write that takes
// the session past its budget is granted, and is still the moment something
// went wrong.
func TestValidateSessionConstraintOnAGrantedOperation(t *testing.T) {
	env := envelope([]capability.Grant{pathGrantOf(capability.KindFileWrite, "/ws/**")}, nil)
	env.Constraints.MaxFileWrites = 100

	e := fileEvent(capability.KindFileWrite, "/ws/main.go")

	under := validate(t, env, e, fakeState{writes: 99})
	if under.Verdict != decision.VerdictWithinEnvelope {
		t.Errorf("Verdict = %q at 99 of 100 writes, want within_envelope", under.Verdict)
	}

	// 100 recorded against a limit of 100: this write is the one past.
	over := validate(t, env, e, fakeState{writes: 100})
	if over.Verdict != decision.VerdictConstraintViolation {
		t.Errorf("Verdict = %q at the limit, want constraint_violation", over.Verdict)
	}
	if !hasViolation(over, ViolationConstraintExceeded) {
		t.Error("no constraint_exceeded violation")
	}
	if over.MatchedGrant == nil {
		t.Error("MatchedGrant is nil; the operation was granted and the grant must still be named")
	}
}

// TestValidateSessionConstraintOnlyAppliesToItsDimension: an exhausted egress
// budget must not start flagging file reads, or every subsequent event in the
// session becomes a violation of something it never touched.
func TestValidateSessionConstraintOnlyAppliesToItsDimension(t *testing.T) {
	env := envelope([]capability.Grant{
		pathGrantOf(capability.KindFileRead, "/ws/**"),
		pathGrantOf(capability.KindFileWrite, "/ws/**"),
	}, nil)
	env.Constraints.MaxNetworkBytes = 1024
	env.Constraints.MaxFileWrites = 10

	spent := fakeState{sent: 1 << 20, writes: 2}

	read := validate(t, env, fileEvent(capability.KindFileRead, "/ws/main.go"), spent)
	if read.Verdict != decision.VerdictWithinEnvelope {
		t.Errorf("Verdict = %q for a read under an exhausted egress budget, want within_envelope", read.Verdict)
	}

	// A read is not a write either, so the write budget does not apply to it.
	env.Constraints.MaxFileWrites = 1
	read = validate(t, env, fileEvent(capability.KindFileRead, "/ws/main.go"), fakeState{writes: 5})
	if read.Verdict != decision.VerdictWithinEnvelope {
		t.Errorf("Verdict = %q for a read under an exhausted write budget, want within_envelope", read.Verdict)
	}
	write := validate(t, env, fileEvent(capability.KindFileWrite, "/ws/main.go"), fakeState{writes: 5})
	if write.Verdict != decision.VerdictConstraintViolation {
		t.Errorf("Verdict = %q for a write under an exhausted write budget, want constraint_violation", write.Verdict)
	}
}

func TestValidateSessionDurationAppliesToEveryObservation(t *testing.T) {
	env := envelope([]capability.Grant{pathGrantOf(capability.KindFileRead, "/ws/**")}, nil)
	env.Constraints.MaxDuration = time.Minute

	// Past the deadline nothing the session does is still within the time it
	// was granted, whatever dimension the event exercises.
	res := validate(t, env, fileEvent(capability.KindFileRead, "/ws/main.go"), fakeState{seconds: 120})
	if res.Verdict != decision.VerdictConstraintViolation {
		t.Errorf("Verdict = %q past the duration limit, want constraint_violation", res.Verdict)
	}
}

func TestValidateSessionConstraintPerDimension(t *testing.T) {
	execEvent := &event.Event{
		Capability: capability.KindProcessExec,
		Exec:       &event.ExecPayload{Filename: "/usr/bin/git", Argv: []string{"git", "status"}},
	}

	t.Run("process count", func(t *testing.T) {
		env := envelope([]capability.Grant{{Kind: capability.KindProcessExec}}, nil)
		env.Constraints.MaxProcesses = 5

		under := validate(t, env, execEvent, fakeState{procs: 4})
		if under.Verdict != decision.VerdictWithinEnvelope {
			t.Errorf("Verdict = %q under the process budget, want within_envelope", under.Verdict)
		}
		over := validate(t, env, execEvent, fakeState{procs: 5})
		if over.Verdict != decision.VerdictConstraintViolation {
			t.Errorf("Verdict = %q at the process budget, want constraint_violation", over.Verdict)
		}
	})

	t.Run("network bytes", func(t *testing.T) {
		env := envelope([]capability.Grant{{Kind: capability.KindNetConnect}}, nil)
		env.Constraints.MaxNetworkBytes = 1 << 20

		e := netEvent("api.github.com", "140.82.121.5", 443)
		under := validate(t, env, e, fakeState{sent: 1024})
		if under.Verdict != decision.VerdictWithinEnvelope {
			t.Errorf("Verdict = %q under the egress budget, want within_envelope", under.Verdict)
		}
		over := validate(t, env, e, fakeState{sent: 1 << 20})
		if over.Verdict != decision.VerdictConstraintViolation {
			t.Errorf("Verdict = %q at the egress budget, want constraint_violation", over.Verdict)
		}
	})

	t.Run("a process event does not draw on the write budget", func(t *testing.T) {
		env := envelope([]capability.Grant{{Kind: capability.KindProcessExec}}, nil)
		env.Constraints.MaxFileWrites = 1

		res := validate(t, env, execEvent, fakeState{writes: 99})
		if res.Verdict != decision.VerdictWithinEnvelope {
			t.Errorf("Verdict = %q, want within_envelope", res.Verdict)
		}
	})
}

// TestValidateMismatchNamesWhatWasExpected: a violation that cannot say what
// the envelope did expect leaves a reader no better off than a bare "denied".
func TestValidateMismatchNamesWhatWasExpected(t *testing.T) {
	tests := []struct {
		name  string
		grant capability.Grant
		e     *event.Event
		want  string
	}{
		{
			"paths",
			pathGrantOf(capability.KindFileRead, "/ws/**"),
			fileEvent(capability.KindFileRead, "/etc/passwd"),
			"/ws/**",
		},
		{
			"hosts",
			capability.Grant{Kind: capability.KindNetConnect, Selector: capability.Selector{Hosts: []string{"api.github.com"}}},
			netEvent("evil.example.com", "1.2.3.4", 443),
			"api.github.com",
		},
		{
			"executables",
			capability.Grant{Kind: capability.KindProcessExec, Selector: capability.Selector{Executables: []string{"/usr/bin/git"}}},
			&event.Event{Capability: capability.KindProcessExec, Exec: &event.ExecPayload{Filename: "/bin/sh"}},
			"/usr/bin/git",
		},
		{
			"ports only, so the selector summary falls back to unconstrained",
			capability.Grant{Kind: capability.KindNetConnect, Selector: capability.Selector{Ports: []int{443}}},
			netEvent("api.github.com", "1.2.3.4", 22),
			"unconstrained",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := validate(t, envelope([]capability.Grant{tt.grant}, nil), tt.e, nil)
			if res.Verdict != decision.VerdictGrantExceeded {
				t.Fatalf("Verdict = %q, want grant_exceeded", res.Verdict)
			}
			var expected string
			for _, v := range res.Violations {
				if v.Type == ViolationSelectorMismatch {
					expected = v.Expected
				}
			}
			if !strings.Contains(expected, tt.want) {
				t.Errorf("Expected = %q, want it to mention %q", expected, tt.want)
			}
		})
	}
}

// TestValidateGrantBudgetOutranksSessionBudget: when both are spent, the
// grant-specific finding is reported, because it names the grant and is the
// more actionable of the two.
func TestValidateGrantBudgetOutranksSessionBudget(t *testing.T) {
	env := envelope([]capability.Grant{{
		Kind:     capability.KindFileWrite,
		Selector: capability.Selector{PathPatterns: []string{"/ws/**"}, MaxCount: 1},
	}}, nil)
	env.Constraints.MaxFileWrites = 1

	res := validate(t, env, fileEvent(capability.KindFileWrite, "/ws/main.go"),
		fakeState{grantUse: map[int]int{0: 1}, writes: 1})

	if res.Verdict != decision.VerdictGrantExceeded {
		t.Errorf("Verdict = %q, want grant_exceeded", res.Verdict)
	}
	if !hasViolation(res, ViolationCountExceeded) {
		t.Error("no count_exceeded violation")
	}
}

// TestValidateProducesEveryVerdict and TestValidateProducesEveryViolationType
// guard the mapping's completeness. A verdict or violation type nothing can
// produce is either dead vocabulary or a case the validator silently folds into
// another, and both are worth failing over.
func TestValidateProducesEveryVerdict(t *testing.T) {
	produced := map[decision.Verdict]bool{}
	for _, c := range everyOutcome(t) {
		produced[c.res.Verdict] = true
	}

	// Driven from the vocabulary rather than a local list, so a verdict added
	// to decision.AllVerdicts without a case here fails immediately.
	for _, want := range decision.AllVerdicts() {
		if !produced[want] {
			t.Errorf("no case produces verdict %q", want)
		}
	}
}

func TestValidateProducesEveryViolationType(t *testing.T) {
	produced := map[ViolationType]bool{}
	for _, c := range everyOutcome(t) {
		for _, v := range c.res.Violations {
			produced[v.Type] = true
		}
	}
	// ConstraintExceeded is produced by ValidateSession too, and by the
	// per-event path above; both are covered by the cases below.
	for _, want := range AllViolationTypes() {
		if !produced[want] {
			t.Errorf("no case produces violation %q", want)
		}
	}
}

type outcome struct {
	name string
	res  *Result
}

// everyOutcome exercises one case per verdict and per violation type.
func everyOutcome(t *testing.T) []outcome {
	t.Helper()

	base := func() *ece.Envelope {
		env := envelope([]capability.Grant{
			pathGrantOf(capability.KindFileWrite, "/ws/**"),
			{
				Kind:     capability.KindFileTruncate,
				Selector: capability.Selector{PathPatterns: []string{"/ws/**"}, MaxCount: 1},
			},
		}, []capability.Grant{
			pathGrantOf(capability.KindFileWrite, "/ws/.git/**"),
		})
		env.Constraints.WorkspaceRoot = "/ws"
		return env
	}

	expired := base()
	expired.ExpiresAt = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	expiredEvent := fileEvent(capability.KindFileWrite, "/ws/main.go")
	expiredEvent.WallClock = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	constrained := base()
	constrained.Constraints.MaxFileWrites = 1

	cases := []struct {
		name  string
		env   *ece.Envelope
		e     *event.Event
		state SessionState
	}{
		{"within", base(), fileEvent(capability.KindFileWrite, "/ws/main.go"), nil},
		{"denied", base(), fileEvent(capability.KindFileWrite, "/ws/.git/config"), nil},
		{"ungranted", base(), fileEvent(capability.KindFileRead, "/ws/main.go"), nil},
		{"mis-targeted and escaped", base(), fileEvent(capability.KindFileWrite, "/etc/passwd"), nil},
		{"count exceeded", base(), fileEvent(capability.KindFileTruncate, "/ws/main.go"),
			fakeState{grantUse: map[int]int{1: 1}}},
		{"session constraint", constrained, fileEvent(capability.KindFileWrite, "/ws/main.go"),
			fakeState{writes: 4}},
		{"expired", expired, expiredEvent, nil},
		{"unresolvable", base(), &event.Event{Capability: capability.KindFileWrite}, nil},
	}

	out := make([]outcome, 0, len(cases))
	for _, c := range cases {
		out = append(out, outcome{c.name, validate(t, c.env, c.e, c.state)})
	}
	return out
}

func TestValidateEnvelopeExpiry(t *testing.T) {
	expiry := time.Date(2026, 3, 2, 12, 0, 0, 0, time.UTC)
	env := envelope([]capability.Grant{pathGrantOf(capability.KindFileWrite, "/ws/**")}, nil)
	env.ExpiresAt = expiry

	e := fileEvent(capability.KindFileWrite, "/ws/main.go")
	e.WallClock = expiry.Add(time.Minute)

	res := validate(t, env, e, nil)
	if res.Verdict != decision.VerdictOutsideEnvelope {
		t.Errorf("Verdict = %q, want outside_envelope", res.Verdict)
	}
	if !hasViolation(res, ViolationEnvelopeExpired) {
		t.Error("no envelope_expired violation")
	}
	if res.MatchedGrant != nil {
		t.Error("a grant was reported as covering an operation under an expired envelope")
	}
}

// TestValidateExpiryUsesTheEventClock is what makes a recorded session
// replayable. Validating an archived event against the host clock would expire
// every corpus the moment its envelope's deadline passed, and the whole
// evaluation corpus would stop reproducing.
func TestValidateExpiryUsesTheEventClock(t *testing.T) {
	envTime := time.Date(2026, 3, 2, 12, 0, 0, 0, time.UTC)
	env := envelope([]capability.Grant{pathGrantOf(capability.KindFileWrite, "/ws/**")}, nil)
	env.ExpiresAt = envTime.Add(time.Hour)

	e := fileEvent(capability.KindFileWrite, "/ws/main.go")
	e.WallClock = envTime // recorded while the envelope was live

	// The host clock is years past the expiry, and must not matter.
	v := NewValidatorWith(nil, func() time.Time { return envTime.AddDate(3, 0, 0) })
	res, err := v.Validate(context.Background(), ValidateRequest{Envelope: env, Event: e})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != decision.VerdictWithinEnvelope {
		t.Errorf("Verdict = %q, want within_envelope; the replayed event was judged against the host clock", res.Verdict)
	}
}

func TestValidateExpiryFallsBackToTheHostClock(t *testing.T) {
	// A live event with no wall clock set still has to be judged against
	// something, and the alternative to the host clock is never expiring.
	envTime := time.Date(2026, 3, 2, 12, 0, 0, 0, time.UTC)
	env := envelope([]capability.Grant{pathGrantOf(capability.KindFileWrite, "/ws/**")}, nil)
	env.ExpiresAt = envTime

	v := NewValidatorWith(nil, func() time.Time { return envTime.Add(time.Hour) })
	res, err := v.Validate(context.Background(), ValidateRequest{
		Envelope: env, Event: fileEvent(capability.KindFileWrite, "/ws/main.go"),
	})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != decision.VerdictOutsideEnvelope {
		t.Errorf("Verdict = %q, want outside_envelope", res.Verdict)
	}
}

func TestValidateZeroExpiryNeverExpires(t *testing.T) {
	env := envelope([]capability.Grant{pathGrantOf(capability.KindFileWrite, "/ws/**")}, nil)
	res := validate(t, env, fileEvent(capability.KindFileWrite, "/ws/main.go"), nil)
	if res.Verdict != decision.VerdictWithinEnvelope {
		t.Errorf("Verdict = %q; an unset ExpiresAt must not read as expired at the zero time", res.Verdict)
	}
}

// --- severity, errors, determinism ------------------------------------------

// TestValidateSeverityRisesWithTheCapability: an ungranted kernel.bpfload and
// an ungranted fs.read are not the same event, and the catalog already records
// why.
func TestValidateSeverityRisesWithTheCapability(t *testing.T) {
	env := envelope(nil, nil)

	mild := validate(t, env, fileEvent(capability.KindFileRead, "/ws/main.go"), nil)
	severe := validate(t, env, &event.Event{Capability: capability.KindKernelBPFLoad}, nil)

	if mild.Violations[0].Severity != capability.SeverityMedium {
		t.Errorf("fs.read severity = %q, want the violation-type floor", mild.Violations[0].Severity)
	}
	if severe.Violations[0].Severity != capability.SeverityCritical {
		t.Errorf("kernel.bpfload severity = %q, want the catalog's baseline", severe.Violations[0].Severity)
	}
}

func TestValidateInputErrors(t *testing.T) {
	v := NewValidator()

	if _, err := v.Validate(context.Background(), ValidateRequest{Event: fileEvent(capability.KindFileRead, "/ws/x")}); !errors.Is(err, ErrNoEnvelope) {
		t.Errorf("err = %v, want ErrNoEnvelope", err)
	}
	if _, err := v.Validate(context.Background(), ValidateRequest{Envelope: envelope(nil, nil)}); !errors.Is(err, ErrNoEvent) {
		t.Errorf("err = %v, want ErrNoEvent", err)
	}
}

// TestValidateIsDeterministic is the property an audit depends on: the same
// inputs always produce the same verdict, the same matched grant, and the same
// explanation.
func TestValidateIsDeterministic(t *testing.T) {
	env := envelope([]capability.Grant{
		pathGrantOf(capability.KindFileWrite, "/**"),
		pathGrantOf(capability.KindFileWrite, "/ws/**"),
		pathGrantOf(capability.KindFileWrite, "/ws/src/**"),
	}, []capability.Grant{
		pathGrantOf(capability.KindFileWrite, "/ws/.git/**"),
	})

	for _, target := range []string{"/ws/src/main.go", "/ws/.git/config", "/etc/passwd"} {
		e := fileEvent(capability.KindFileWrite, target)
		first := validate(t, env, e, nil)

		for range 50 {
			got := validate(t, env, e, nil)
			if got.Verdict != first.Verdict {
				t.Fatalf("%s: verdict varied: %q then %q", target, first.Verdict, got.Verdict)
			}
			if (got.MatchedGrant == nil) != (first.MatchedGrant == nil) {
				t.Fatalf("%s: matched grant varied", target)
			}
			if got.MatchedGrant != nil && got.MatchedGrant != first.MatchedGrant {
				t.Fatalf("%s: a different grant was selected", target)
			}
			if len(got.Violations) != len(first.Violations) {
				t.Fatalf("%s: violation count varied", target)
			}
			if len(got.Reasoning) != len(first.Reasoning) ||
				got.Reasoning[len(got.Reasoning)-1] != first.Reasoning[len(first.Reasoning)-1] {
				t.Fatalf("%s: reasoning varied", target)
			}
		}
	}
}

func TestValidateDoesNotMutateTheEnvelope(t *testing.T) {
	// Implementations must not mutate the envelope: it is frozen once sealed,
	// and a validator that edited it could widen the thing constraining it.
	env := envelope([]capability.Grant{pathGrantOf(capability.KindFileWrite, "/ws/**")}, nil)
	before := *env
	beforeGrant := env.Grants[0]

	validate(t, env, fileEvent(capability.KindFileWrite, "/ws/main.go"), nil)

	if env.Sealed != before.Sealed || len(env.Grants) != len(before.Grants) {
		t.Error("the envelope was modified")
	}
	if env.Grants[0].Kind != beforeGrant.Kind || len(env.Grants[0].Selector.PathPatterns) != 1 {
		t.Error("a grant was modified")
	}
}

// --- ValidateSession --------------------------------------------------------

func TestValidateSession(t *testing.T) {
	env := envelope(nil, nil)
	env.Constraints = ece.Constraints{
		MaxDuration:     10 * time.Minute,
		MaxProcesses:    5,
		MaxFileWrites:   100,
		MaxNetworkBytes: 1 << 20,
	}

	v := NewValidator()

	within, err := v.ValidateSession(context.Background(), env, fakeState{
		seconds: 60, procs: 2, writes: 10, sent: 1024,
	})
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	if len(within) != 0 {
		t.Errorf("violations = %v, want none", within)
	}

	over, err := v.ValidateSession(context.Background(), env, fakeState{
		seconds: 3600, procs: 50, writes: 1000, sent: 1 << 30,
	})
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	if len(over) != 4 {
		t.Fatalf("violations = %d, want 4 (one per breached constraint): %v", len(over), over)
	}
	for _, viol := range over {
		if viol.Type != ViolationConstraintExceeded {
			t.Errorf("violation type = %q, want constraint_exceeded", viol.Type)
		}
		if viol.Expected == "" || viol.Observed == "" {
			t.Errorf("violation %v does not say what was expected or observed", viol)
		}
	}
}

func TestValidateSessionZeroMeansUnlimited(t *testing.T) {
	// The same rule empty selector lists follow: an unset budget is not a
	// budget of zero.
	env := envelope(nil, nil)

	got, err := v().ValidateSession(context.Background(), env, fakeState{
		seconds: 1e6, procs: 1e6, writes: 1e6, sent: 1e12,
	})
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("violations = %v, want none for an envelope with no constraints", got)
	}
}

func TestValidateSessionBoundaryIsInclusive(t *testing.T) {
	// Exactly at the limit is not over it.
	env := envelope(nil, nil)
	env.Constraints = ece.Constraints{MaxFileWrites: 10, MaxProcesses: 2}

	at, err := v().ValidateSession(context.Background(), env, fakeState{writes: 10, procs: 2})
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	if len(at) != 0 {
		t.Errorf("violations = %v at exactly the limit, want none", at)
	}

	over, err := v().ValidateSession(context.Background(), env, fakeState{writes: 11, procs: 2})
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	if len(over) != 1 {
		t.Errorf("violations = %v one past the limit, want one", over)
	}
}

func TestValidateSessionErrors(t *testing.T) {
	if _, err := v().ValidateSession(context.Background(), nil, fakeState{}); !errors.Is(err, ErrNoEnvelope) {
		t.Errorf("err = %v, want ErrNoEnvelope", err)
	}
	if _, err := v().ValidateSession(context.Background(), envelope(nil, nil), nil); !errors.Is(err, ErrNoState) {
		t.Errorf("err = %v, want ErrNoState", err)
	}
}

func v() *DefaultValidator { return NewValidator() }

// --- end to end over a recorded session -------------------------------------

// TestValidateReplayedSession runs a real recorded stream against a plausible
// envelope for the task it recorded. It is the closest thing available to the
// end-to-end path the daemon will run, and it exercises the bridge, the
// matcher, precedence, and the verdict mapping together.
func TestValidateReplayedSession(t *testing.T) {
	env := envelope([]capability.Grant{
		pathGrantOf(capability.KindFileRead, "/home/dev/project/**"),
		pathGrantOf(capability.KindFileWrite, "/home/dev/project/**"),
		pathGrantOf(capability.KindFileCreate, "/home/dev/project/**"),
		pathGrantOf(capability.KindFileRename, "/home/dev/project/**"),
		{
			Kind:     capability.KindProcessExec,
			Domain:   capability.DomainProcess,
			Selector: capability.Selector{Executables: []string{"/usr/bin/git"}},
		},
		{Kind: capability.KindProcessExit, Domain: capability.DomainProcess},
	}, []capability.Grant{
		// CI configuration is carved out of the workspace-wide write grant.
		pathGrantOf(capability.KindFileWrite, "/home/dev/project/.github/**"),
	})
	env.Constraints.WorkspaceRoot = "/home/dev/project"

	src := replay.New(replay.Config{
		Path: filepath.FromSlash("../../test/testdata/replay/git-operation.jsonl"),
	})
	defer src.Close()
	if err := src.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}

	val := NewValidator()
	verdicts := map[string]decision.Verdict{}
	escapes := map[string]bool{}

	for e := range src.Events() {
		res, err := val.Validate(context.Background(), ValidateRequest{Envelope: env, Event: &e})
		if err != nil {
			t.Fatalf("%s: Validate: %v", e.ID, err)
		}
		verdicts[e.ID] = res.Verdict
		escapes[e.ID] = hasViolation(res, ViolationWorkspaceEscape)
	}
	if err := src.Err(); err != nil {
		t.Fatalf("replay: %v", err)
	}

	want := map[string]decision.Verdict{
		"gt-001": decision.VerdictWithinEnvelope,   // exec git
		"gt-002": decision.VerdictWithinEnvelope,   // read .git/config
		"gt-003": decision.VerdictWithinEnvelope,   // read .git/HEAD
		"gt-004": decision.VerdictWithinEnvelope,   // read a source file
		"gt-005": decision.VerdictWithinEnvelope,   // create an object
		"gt-006": decision.VerdictWithinEnvelope,   // write the index
		"gt-007": decision.VerdictWithinEnvelope,   // rename the lock into place
		"gt-008": decision.VerdictExplicitlyDenied, // write CI config: denied
		"gt-009": decision.VerdictGrantExceeded,    // read ~/.ssh/id_rsa
		"gt-010": decision.VerdictWithinEnvelope,   // exit
	}
	if len(verdicts) != len(want) {
		t.Fatalf("validated %d events, want %d", len(verdicts), len(want))
	}
	for id, w := range want {
		if verdicts[id] != w {
			t.Errorf("%s: verdict = %q, want %q", id, verdicts[id], w)
		}
	}

	// The SSH key read is the only event that left the workspace.
	for id, escaped := range escapes {
		if want := id == "gt-009"; escaped != want {
			t.Errorf("%s: workspace escape = %v, want %v", id, escaped, want)
		}
	}
}

// --- invariants and cost ----------------------------------------------------

// FuzzValidateTarget asserts the invariants that must hold for every
// observation, not only the ones someone thought to write down.
func FuzzValidateTarget(f *testing.F) {
	for _, seed := range []string{
		"/ws/src/main.go", "/ws/.git/config", "/etc/passwd", "", "relative",
		"/ws/../etc/shadow", "/ws//x", "/ws/\x00", "/", "/ws",
	} {
		f.Add(seed)
	}

	env := envelope(
		[]capability.Grant{pathGrantOf(capability.KindFileWrite, "/ws/**")},
		[]capability.Grant{pathGrantOf(capability.KindFileWrite, "/ws/.git/**")},
	)
	env.Constraints.WorkspaceRoot = "/ws"
	val := NewValidator()

	f.Fuzz(func(t *testing.T, target string) {
		res, err := val.Validate(context.Background(), ValidateRequest{
			Envelope: env,
			Event:    fileEvent(capability.KindFileWrite, target),
		})
		if err != nil {
			t.Fatalf("Validate returned an error for target %q: %v", target, err)
		}

		if res.Verdict == "" {
			t.Fatalf("empty verdict for %q", target)
		}
		if len(res.Reasoning) == 0 {
			t.Fatalf("no reasoning for %q", target)
		}

		switch res.Verdict {
		case decision.VerdictWithinEnvelope:
			if res.MatchedGrant == nil {
				t.Fatalf("within_envelope with no matched grant for %q", target)
			}
			if len(res.Violations) != 0 {
				t.Fatalf("within_envelope with violations for %q: %v", target, res.Violations)
			}
			if !IsResolved(target) {
				t.Fatalf("an unresolved target was permitted: %q", target)
			}
		case decision.VerdictExplicitlyDenied:
			if res.MatchedDenial == nil {
				t.Fatalf("explicitly_denied with no matched denial for %q", target)
			}
			if res.MatchedGrant != nil {
				t.Fatalf("explicitly_denied with a matched grant for %q", target)
			}
		case decision.VerdictIndeterminate:
			if !hasViolation(res, ViolationUnresolvable) {
				t.Fatalf("indeterminate with no unresolvable violation for %q", target)
			}
			if res.MatchedGrant != nil {
				t.Fatalf("indeterminate with a matched grant for %q", target)
			}
		}

		for _, viol := range res.Violations {
			if viol.Type == "" {
				t.Fatalf("violation with no type for %q", target)
			}
			if viol.Severity == "" {
				t.Fatalf("violation %q with no severity for %q", viol.Type, target)
			}
		}
	})
}

func BenchmarkValidate(b *testing.B) {
	env := envelope([]capability.Grant{
		pathGrantOf(capability.KindFileRead, "/ws/**"),
		pathGrantOf(capability.KindFileWrite, "/ws/**"),
		pathGrantOf(capability.KindFileWrite, "/ws/src/**"),
		pathGrantOf(capability.KindFileWrite, "/ws/src/*.go"),
	}, []capability.Grant{
		pathGrantOf(capability.KindFileWrite, "/ws/.git/**"),
	})
	env.Constraints.WorkspaceRoot = "/ws"

	val := NewValidator()
	ctx := context.Background()

	cases := []struct {
		name string
		e    *event.Event
	}{
		{"within", fileEvent(capability.KindFileWrite, "/ws/src/main.go")},
		{"denied", fileEvent(capability.KindFileWrite, "/ws/.git/config")},
		{"outside", fileEvent(capability.KindFileWrite, "/etc/passwd")},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				if _, err := val.Validate(ctx, ValidateRequest{Envelope: env, Event: c.e}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
