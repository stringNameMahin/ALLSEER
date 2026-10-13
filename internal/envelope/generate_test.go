package envelope

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stringNameMahin/ALLSEER/internal/intent"
	"github.com/stringNameMahin/ALLSEER/internal/validator"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// observable is what the shipped BPF object can see on a healthy host.
var observable = capability.NewCatalog(
	capability.KindFileRead, capability.KindFileWrite, capability.KindFileCreate,
	capability.KindProcessExec, capability.KindProcessExit, capability.KindNetConnect,
)

func generate(t *testing.T, prompt string, langs ...string) *Result {
	t.Helper()
	an, err := intent.NewRuleAnalyzer().Analyze(context.Background(), intent.Request{
		Prompt:           prompt,
		WorkspaceRoot:    "/home/dev/proj",
		WorkspaceContext: intent.WorkspaceContext{Languages: langs},
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := RuleGenerator{Limits: Limits{MaxGrants: 64}}.Generate(context.Background(), an, observable, Params{
		SessionID: "s-1", WorkspaceRoot: "/home/dev/proj", Home: "/home/dev",
		Resolvers: []string{"127.0.0.53"}, Now: time.Unix(1_800_000_000, 0).UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func verdict(t *testing.T, env *ece.Envelope, kind capability.Kind, target string) decision.Verdict {
	t.Helper()
	d, _ := capability.DomainOf(kind)
	obs := capability.Observation{Kind: kind, Domain: d, Target: target}
	e := &event.Event{Capability: kind, Domain: d, Observation: obs, Result: event.Result{Succeeded: true}}
	r, err := validator.NewValidator().Validate(context.Background(), validator.ValidateRequest{Envelope: env, Event: e})
	if err != nil {
		t.Fatal(err)
	}
	return r.Verdict
}

func TestGeneratedEnvelopeIsAdmissibleAndHonest(t *testing.T) {
	res := generate(t, "run the go tests and fix the failing one", "go")
	env := res.Envelope

	if blocking := validator.BlockingIssues(validator.LintEnvelope(env)); len(blocking) != 0 {
		t.Fatalf("generated envelope is inadmissible: %+v", blocking)
	}
	if env.Constraints.WorkspaceRoot != "/home/dev/proj" || env.Sealed || env.Digest != "" {
		t.Fatalf("unexpected envelope header: %+v", env.Constraints)
	}
	for _, g := range env.Grants {
		if g.Rationale == "" {
			t.Errorf("grant %s has no rationale", g.Kind)
		}
	}

	cases := []struct {
		kind   capability.Kind
		target string
		want   decision.Verdict
	}{
		{capability.KindFileRead, "/home/dev/proj/main.go", decision.VerdictWithinEnvelope},
		{capability.KindFileWrite, "/home/dev/proj/main_test.go", decision.VerdictWithinEnvelope},
		{capability.KindFileRead, "/usr/lib/x86_64-linux-gnu/libc.so.6", decision.VerdictWithinEnvelope},
		{capability.KindFileRead, "/home/dev/go/pkg/mod/x/y.go", decision.VerdictWithinEnvelope},
		{capability.KindProcessExec, "/usr/bin/go", decision.VerdictWithinEnvelope},
		{capability.KindFileRead, "/home/dev/.ssh/id_rsa", decision.VerdictExplicitlyDenied},
		{capability.KindFileRead, "/home/dev/.aws/credentials", decision.VerdictExplicitlyDenied},
		{capability.KindFileRead, "/etc/shadow", decision.VerdictExplicitlyDenied},
		{capability.KindFileWrite, "/home/dev/proj/.git/hooks/pre-commit", decision.VerdictExplicitlyDenied},
		{capability.KindFileWrite, "/home/dev/proj/.github/workflows/ci.yml", decision.VerdictExplicitlyDenied},
		{capability.KindFileWrite, "/etc/hosts", decision.VerdictGrantExceeded},
	}
	for _, c := range cases {
		if got := verdict(t, env, c.kind, c.target); got != c.want {
			t.Errorf("%s %s = %s, want %s", c.kind, c.target, got, c.want)
		}
	}

	// A test task names no network, so egress is a departure.
	if got := verdict(t, env, capability.KindNetConnect, "1.2.3.4:443"); got == decision.VerdictWithinEnvelope {
		t.Errorf("egress from a test task was within the envelope")
	}
}

func TestDependencyInstallGrantsRegistryAndWarnsAboutCorrelation(t *testing.T) {
	res := generate(t, "install the dependencies with go mod download", "go")
	var hosts []string
	for _, g := range res.Envelope.Grants {
		if g.Kind == capability.KindNetConnect {
			hosts = append(hosts, g.Selector.Hosts...)
		}
	}
	joined := strings.Join(hosts, ",")
	for _, want := range []string{"proxy.golang.org", "sum.golang.org", "127.0.0.53"} {
		if !strings.Contains(joined, want) {
			t.Errorf("net.connect hosts %v lack %s", hosts, want)
		}
	}
	var warned bool
	for _, w := range res.Warnings {
		if strings.Contains(w, "does not correlate DNS") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("no correlation warning in %v", res.Warnings)
	}
	if got := verdict(t, res.Envelope, capability.KindNetConnect, "127.0.0.53:53"); got != decision.VerdictWithinEnvelope {
		t.Errorf("resolver connect = %s", got)
	}
}

func TestUnobservableGrantsAreDroppedAndReported(t *testing.T) {
	an, _ := intent.NewRuleAnalyzer().Analyze(context.Background(), intent.Request{Prompt: "build the project with make"})
	onlyExec := capability.NewCatalog(capability.KindProcessExec, capability.KindProcessExit)
	res, err := RuleGenerator{}.Generate(context.Background(), an, onlyExec, Params{WorkspaceRoot: "/w"})
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range res.Envelope.Grants {
		if !onlyExec.Observable(g.Kind) {
			t.Errorf("grant for unobservable %s survived", g.Kind)
		}
	}
	if len(res.Warnings) == 0 {
		t.Fatal("dropped grants were not reported")
	}
}

func TestGitPushOverSSHIsVisibleToTheApprover(t *testing.T) {
	res := generate(t, "commit the changes and git push to github.com", "go")
	env := res.Envelope
	if got := verdict(t, env, capability.KindFileRead, "/home/dev/.ssh/id_ed25519"); got != decision.VerdictWithinEnvelope {
		t.Errorf("ssh key read for git push = %s, want within (granted and shown)", got)
	}
	if got := verdict(t, env, capability.KindFileWrite, "/home/dev/.ssh/authorized_keys"); got != decision.VerdictExplicitlyDenied {
		t.Errorf("authorized_keys write = %s, want explicitly denied", got)
	}
}

func TestGenerateRefusesBadInputs(t *testing.T) {
	an, _ := intent.NewRuleAnalyzer().Analyze(context.Background(), intent.Request{Prompt: "build it now please"})
	for _, ws := range []string{"", "relative", "/"} {
		if _, err := (RuleGenerator{}).Generate(context.Background(), an, nil, Params{WorkspaceRoot: ws}); !errors.Is(err, ErrNoWorkspace) {
			t.Errorf("workspace %q: %v", ws, err)
		}
	}
	if _, err := (RuleGenerator{Limits: Limits{MaxGrants: 2}}).Generate(context.Background(), an, nil, Params{WorkspaceRoot: "/w"}); !errors.Is(err, ErrTooMany) {
		t.Errorf("MaxGrants not enforced: %v", err)
	}
	if _, err := (RuleGenerator{}).Generate(context.Background(), nil, nil, Params{WorkspaceRoot: "/w"}); !errors.Is(err, ErrNoAnalysis) {
		t.Errorf("nil analysis: %v", err)
	}
}

func TestSealVerifyAndTamper(t *testing.T) {
	env := generate(t, "run the go tests", "go").Envelope
	s := DigestSealer{}
	if err := s.Verify(env); !errors.Is(err, ErrNotSealed) {
		t.Fatalf("Verify unsealed = %v", err)
	}
	if err := s.Seal(env); err != nil {
		t.Fatal(err)
	}
	if err := s.Seal(env); !errors.Is(err, ErrAlreadySealed) {
		t.Fatalf("re-seal = %v", err)
	}
	if err := s.Verify(env); err != nil {
		t.Fatalf("Verify fresh = %v", err)
	}

	// Approval is recorded after sealing and does not break the digest.
	env.Approval = &ece.ApprovalRecord{ApprovedBy: "dev", Method: "shim"}
	if err := s.Verify(env); err != nil {
		t.Fatalf("Verify after approval = %v", err)
	}

	// Widening a sealed envelope is detected.
	env.Grants[0].Selector.PathPatterns = append(env.Grants[0].Selector.PathPatterns, "/**")
	if err := s.Verify(env); !errors.Is(err, ErrTampered) {
		t.Fatalf("Verify after widening = %v", err)
	}
}

func TestDigestIsReproducible(t *testing.T) {
	a := generate(t, "run the go tests", "go").Envelope
	b := generate(t, "run the go tests", "go").Envelope
	b.ID = a.ID
	da, _ := Digest(a)
	db, _ := Digest(b)
	if da != db {
		t.Fatalf("same content, different digests: %s %s", da, db)
	}
}

func TestNewSessionIDIsACgroupName(t *testing.T) {
	id := NewSessionID(time.Now())
	if !strings.HasPrefix(id, "s-") || strings.ContainsAny(id, "/ .") {
		t.Fatalf("session id %q", id)
	}
}

// A Go build runs toolchains from the module cache and writes its telemetry
// counters; both are part of the task, not departures.
func TestGoToolchainIsPartOfABuild(t *testing.T) {
	env := generate(t, "build the project and run the go tests", "go").Envelope
	cases := []struct {
		kind   capability.Kind
		target string
	}{
		{capability.KindProcessExec, "/home/dev/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.5.linux-amd64/pkg/tool/linux_amd64/compile"},
		{capability.KindProcessExit, "/home/dev/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.5.linux-amd64/bin/go"},
		{capability.KindFileCreate, "/home/dev/.config/go/telemetry/local/upload.token"},
	}
	for _, c := range cases {
		if got := verdict(t, env, c.kind, c.target); got != decision.VerdictWithinEnvelope {
			t.Errorf("%s %s = %s", c.kind, c.target, got)
		}
	}
	// Other configuration under ~/.config stays outside a build.
	if got := verdict(t, env, capability.KindFileRead, "/home/dev/.config/gh/hosts.yml"); got == decision.VerdictWithinEnvelope {
		t.Errorf("gh credentials readable by a build: %s", got)
	}
}
