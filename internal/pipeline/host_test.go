package pipeline

import (
	"path/filepath"
	"testing"

	"github.com/stringNameMahin/ALLSEER/internal/policy"
	"github.com/stringNameMahin/ALLSEER/internal/risk"
	"github.com/stringNameMahin/ALLSEER/internal/session"
	"github.com/stringNameMahin/ALLSEER/internal/validator"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// Host sensitivity is checked end to end for the two things internal/risk
// cannot check on its own: that the rating reaches policy and can change what
// would happen, and that adding it left every recording in the corpus exactly
// where it was.

// --- fixtures ------------------------------------------------------------------------

// metadataEnvelope is an honest envelope for a task that fetches dependencies:
// the workspace, and the one registry it is expected to talk to, named the way
// a human writes it.
//
// Nothing in it was arranged to make the rating fire. A connection to the
// instance metadata service is a departure because the envelope did not
// anticipate it, and it is *indeterminate* rather than a mismatch because the
// envelope names hosts and the connection carries only an address — which is
// the validator's own answer, and the case the shipped rule set already has a
// rule pair for.
func metadataEnvelope() *ece.Envelope {
	ws := "/home/dev/project"
	env := envelope(
		[]capability.Grant{
			pathGrant(capability.KindFileRead, 0, ws+"/**"),
			{Kind: capability.KindNetConnect, Domain: capability.DomainNetwork,
				Selector: capability.Selector{Hosts: []string{"registry.npmjs.org"}}},
		},
		nil,
		ece.Constraints{WorkspaceRoot: ws},
	)
	env.SessionID = "s-host"
	return env
}

// connectEvent builds an outbound connection with the enrichment a real capture
// would carry: the correlated name when DNS succeeded, the bare address and the
// correlation flag when it did not.
func connectEvent(id, addr string, port int, hostname string) *event.Event {
	target := addr
	if hostname != "" {
		target = hostname
	}
	target = joinPort(target, port)

	attrs := map[string]string{
		capability.AttrProtocol: "tcp",
		capability.AttrDestIP:   addr,
		capability.AttrPort:     itoa(port),
	}
	if hostname == "" {
		attrs[capability.AttrHostnameCorrelated] = "false"
	}

	return &event.Event{
		ID:         id,
		SessionID:  "s-host",
		Capability: capability.KindNetConnect,
		Domain:     capability.DomainNetwork,
		WallClock:  baseTime,
		Result:     event.Result{Succeeded: true},
		Network: &event.NetworkPayload{
			Protocol: "tcp", DestAddr: addr, DestPort: port, Hostname: hostname,
		},
		Observation: capability.Observation{
			Kind: capability.KindNetConnect, Domain: capability.DomainNetwork,
			Target: target, Attributes: attrs,
		},
	}
}

// joinPort builds the "host:port" target resolve.observeNetwork would produce,
// bracketing an IPv6 literal so the result can be split back apart.
func joinPort(host string, port int) string {
	if len(host) > 0 && host[0] != '[' && countColons(host) > 1 {
		return "[" + host + "]:" + itoa(port)
	}
	return host + ":" + itoa(port)
}

func countColons(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			n++
		}
	}
	return n
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func hostSensitivityFactor(a *decision.RiskAssessment) *decision.Factor {
	if a == nil {
		return nil
	}
	for i := range a.Factors {
		if a.Factors[i].Name == risk.FactorSensitiveHost {
			return &a.Factors[i]
		}
	}
	return nil
}

// pathsOnlyEngine is the shipped sensitivity list with its hosts section
// removed, and it is the *only* honest control for "what did host ratings
// change".
//
// Comparing against an engine with no oracle at all would answer a different
// question: that engine also loses sensitive_path and the credential-egress
// detector, so every difference the earlier milestones introduced would show up
// here as though this one had caused it. Dropping one section of the real file
// isolates the change to the thing under test.
func pathsOnlyEngine(t *testing.T) *risk.BaselineEngine {
	t.Helper()

	list, err := risk.LoadSensitivityList(filepath.Join("..", "..", "configs", "sensitivity.default.yaml"))
	if err != nil {
		t.Fatalf("loading the shipped sensitivity list: %v", err)
	}
	list.Hosts = nil

	o, err := risk.NewResourceOracle(list)
	if err != nil {
		t.Fatalf("NewResourceOracle: %v", err)
	}
	e, err := risk.NewEngineWithOracle(o)
	if err != nil {
		t.Fatalf("NewEngineWithOracle: %v", err)
	}
	return e
}

// buildHostPipeline is the full deterministic pipeline under the shipped rule
// set, with the shipped sensitivity list behind it either whole or with its
// hosts section removed.
func buildHostPipeline(t *testing.T, env *ece.Envelope, st State, rated bool) *EventPipeline {
	t.Helper()

	engine := risk.Engine(pathsOnlyEngine(t))
	if rated {
		engine = ratedEngine(t)
	}
	p, err := NewWithRisk(Config{
		Session: Session{Envelope: env, Mode: policy.ModeMonitor, State: st},
		Now:     frozen(),
	}, validator.NewValidator(), engine, defaultEngine(t))
	if err != nil {
		t.Fatalf("NewWithRisk: %v", err)
	}
	return p
}

// --- 1. the rating reaches policy ------------------------------------------------------

// The claim this milestone has to make good on: a host rating changes what
// would happen, through a rule that already shipped.
//
// An agent connects to the cloud instance metadata service by literal address.
// The envelope grants network access by hostname, so the validator cannot tell
// whether that address *is* the granted host and answers indeterminate rather
// than mismatch. Without host ratings the event scores 40 and matches
// indeterminate-low-risk, which warns. With them it scores 65 and matches
// indeterminate-high-risk, which asks a human.
//
// Neither rule was written for this feature — they ship in
// configs/rules.default.yaml with "unresolved is not the same as safe" as their
// stated reason, and a connection to the endpoint that vends cloud credentials
// is precisely when that should hold.
func TestHostRatingMovesAShippedRiskConditionedRule(t *testing.T) {
	env := metadataEnvelope()
	imds := connectEvent("h-imds", "169.254.169.254", 80, "")

	run := func(rated bool) *ProcessingContext {
		return process(t, buildHostPipeline(t, env, session.NewState(env.SessionID, env), rated), imds)
	}

	before, after := run(false), run(true)

	if before.Validation.Verdict != decision.VerdictIndeterminate {
		t.Fatalf("verdict = %q, want indeterminate; the envelope names hosts and this carries an address",
			before.Validation.Verdict)
	}
	if before.Outcome.RuleID != "indeterminate-low-risk" || before.Outcome.Action != ece.ActionWarn {
		t.Fatalf("without ratings the event matched %q / %q; want indeterminate-low-risk / warn",
			before.Outcome.RuleID, before.Outcome.Action)
	}
	if after.Outcome.RuleID != "indeterminate-high-risk" || after.Outcome.Action != ece.ActionRequestApproval {
		t.Errorf("with ratings the event matched %q / %q; want indeterminate-high-risk / request_approval",
			after.Outcome.RuleID, after.Outcome.Action)
	}

	// The score moved by exactly the grade, and by nothing else.
	if got := after.Risk.Score - before.Risk.Score; got != 25 {
		t.Errorf("score moved by %v, want exactly the critical grade's 25", got)
	}
	// And risk did not reach validation, which is the boundary the whole
	// architecture rests on.
	if after.Validation.Verdict != before.Validation.Verdict {
		t.Errorf("the verdict moved from %q to %q", before.Validation.Verdict, after.Validation.Verdict)
	}
}

// The evidence has to survive into the audit record, not just into the
// assessment the stage produced. A rating a human cannot read in the decision
// is a rating nobody can act on.
func TestHostEvidenceReachesTheDecision(t *testing.T) {
	env := metadataEnvelope()
	st := session.NewState(env.SessionID, env)
	p := buildHostPipeline(t, env, st, true)

	pc := process(t, p, connectEvent("h-imds", "169.254.169.254", 80, ""))
	f := hostSensitivityFactor(&pc.Decision.Risk)
	if f == nil {
		t.Fatalf("the decision carries no %s factor; factors were %+v",
			risk.FactorSensitiveHost, pc.Decision.Risk.Factors)
	}

	for k, want := range map[string]string{
		risk.EvidenceDimension:          risk.DimensionHost,
		risk.EvidenceTarget:             "169.254.169.254:80",
		risk.EvidenceHost:               "169.254.169.254",
		risk.EvidenceHostKind:           risk.HostKindLabelAddress,
		risk.EvidenceHostnameCorrelated: "false",
		risk.EvidenceSensitivity:        string(capability.SeverityCritical),
	} {
		if got := f.Evidence[k]; got != want {
			t.Errorf("evidence[%q] = %q, want %q", k, got, want)
		}
	}
	if f.Evidence[risk.EvidenceReason] == "" {
		t.Error("the sensitivity list's written reason did not reach the audit record")
	}
}

// The same destination reached by name, through an envelope that grants a
// different name. This is the mismatch case rather than the indeterminate one,
// and it is here to pin that a name entry rates a named destination — the other
// half of the name/address boundary.
func TestANamedDestinationIsRatedByName(t *testing.T) {
	env := metadataEnvelope()
	st := session.NewState(env.SessionID, env)
	p := buildHostPipeline(t, env, st, true)

	pc := process(t, p, connectEvent("h-name", "169.254.169.254", 80, "metadata.google.internal"))

	f := hostSensitivityFactor(pc.Risk)
	if f == nil {
		t.Fatal("no host factor on a named destination")
	}
	if got := f.Evidence[risk.EvidenceHostKind]; got != risk.HostKindLabelName {
		t.Errorf("host_kind = %q, want %q", got, risk.HostKindLabelName)
	}
	if got := f.Evidence[risk.EvidenceHost]; got != "metadata.google.internal" {
		t.Errorf("host = %q, want the correlated name", got)
	}
	if got := f.Evidence[risk.EvidenceSensitivity]; got != string(capability.SeverityCritical) {
		t.Errorf("sensitivity = %q, want critical", got)
	}
	// Correlation succeeded, so there is no correlation flag to carry.
	if _, ok := f.Evidence[risk.EvidenceHostnameCorrelated]; ok {
		t.Error("a correlated destination carries a correlation flag")
	}
}

// A granted connection to a rated destination keeps its exact zero and reports
// the finding anyway, which is the invariant sensitive_path already holds.
func TestAGrantedConnectionToARatedHostScoresZero(t *testing.T) {
	env := metadataEnvelope()
	st := session.NewState(env.SessionID, env)
	p := buildHostPipeline(t, env, st, true)

	// registry.npmjs.org is granted and is rated info, so both halves of the
	// invariant are exercised at once: a covered event scores zero, and a rated
	// destination is still reported.
	pc := process(t, p, connectEvent("h-reg", "104.16.24.35", 443, "registry.npmjs.org"))

	if pc.Validation.Verdict != decision.VerdictWithinEnvelope {
		t.Fatalf("verdict = %q, want within_envelope", pc.Validation.Verdict)
	}
	if pc.Risk.Score != 0 || pc.Risk.Level != decision.LevelNone {
		t.Errorf("a covered event scored %v (%q)", pc.Risk.Score, pc.Risk.Level)
	}

	f := hostSensitivityFactor(pc.Risk)
	if f == nil {
		t.Fatal("the rating went unreported on a covered event")
	}
	if f.Weight != 0 {
		t.Errorf("Weight = %v on a covered event", f.Weight)
	}
	if f.Evidence[risk.EvidenceNotCharged] == "" {
		t.Error("points were withheld without the record saying why")
	}
	if got := f.Evidence[risk.EvidenceSensitivity]; got != string(capability.SeverityInfo) {
		t.Errorf("sensitivity = %q, want info — rated, and unremarkable", got)
	}
}

// --- 2. the regression ------------------------------------------------------------------

// Adding host ratings must change nothing about the recordings that were
// already scored.
//
// Every fixture is run through the rated composition and every outcome compared
// against the same run without the sensitivity list, so a verdict, score, rule,
// or action that moved would fail here. The shipped list rates the corpus's only
// destinations — registry.npmjs.org as `info` and an unlisted address as
// unknown — and both are worth zero points, so the arithmetic is unchanged and
// only the *record* gained a line.
func TestHostRatingsLeaveTheCorpusWhereItWas(t *testing.T) {
	for _, fixture := range []string{
		"go-build.jsonl", "npm-install.jsonl", "git-operation.jsonl", "credential-egress.jsonl",
	} {
		t.Run(fixture, func(t *testing.T) {
			events := loadFixture(t, fixture)

			env := gitEnvelope()
			if fixture == "credential-egress.jsonl" {
				env = exfilEnvelope()
			}

			runAll := func(rated bool) []sequenceOutcome {
				st := session.NewState(env.SessionID, env)
				p := buildHostPipeline(t, env, st, rated)

				out := make([]sequenceOutcome, 0, len(events))
				for i := range events {
					e := events[i]
					pc := process(t, p, &e)
					if pc.Err != nil {
						t.Fatalf("%s: %v", e.ID, pc.Err)
					}
					out = append(out, sequenceOutcome{
						EventID: e.ID,
						Verdict: pc.Validation.Verdict,
						Rule:    pc.Outcome.RuleID,
						Action:  pc.Outcome.Action,
						Score:   pc.Risk.Score,
						Level:   pc.Risk.Level,
					})
				}
				return out
			}

			unrated, rated := runAll(false), runAll(true)
			for i := range rated {
				// Sensitivity may only raise, so a score that fell is a defect
				// regardless of whether anything else moved.
				if rated[i].Score < unrated[i].Score {
					t.Errorf("%s: score fell from %v to %v; a sensitivity list may only raise",
						rated[i].EventID, unrated[i].Score, rated[i].Score)
				}
				if rated[i] != unrated[i] {
					t.Errorf("%s: outcome moved\n got %+v\nwant %+v", rated[i].EventID, rated[i], unrated[i])
				}
			}
		})
	}
}

// Every network event in the corpus now carries a host rating, and every
// filesystem event still carries a path rating. The two never both speak, which
// is what keeps one event from producing two sentences about one resource.
func TestExactlyOneResourceFactorPerEvent(t *testing.T) {
	for _, fixture := range []string{
		"go-build.jsonl", "npm-install.jsonl", "git-operation.jsonl", "credential-egress.jsonl",
	} {
		t.Run(fixture, func(t *testing.T) {
			events := loadFixture(t, fixture)

			env := gitEnvelope()
			if fixture == "credential-egress.jsonl" {
				env = exfilEnvelope()
			}
			p := buildHostPipeline(t, env, session.NewState(env.SessionID, env), true)

			var sawHost, sawPath int
			for i := range events {
				e := events[i]
				pc := process(t, p, &e)

				host := hostSensitivityFactor(pc.Risk) != nil
				path := false
				for _, f := range pc.Risk.Factors {
					if f.Name == risk.FactorSensitivePath {
						path = true
					}
				}

				if host && path {
					t.Errorf("%s produced both resource factors", e.ID)
				}
				if !host && !path {
					t.Errorf("%s produced neither resource factor; every event touches something", e.ID)
				}

				if domain, ok := capability.DomainOf(e.Capability); ok && domain == capability.DomainNetwork {
					if !host {
						t.Errorf("%s is a %s event with no host rating", e.ID, e.Capability)
					}
					sawHost++
				} else if host {
					t.Errorf("%s is a %s event and was rated as a destination", e.ID, e.Capability)
				} else {
					sawPath++
				}
			}

			if sawHost+sawPath != len(events) {
				t.Errorf("counted %d rated events over %d", sawHost+sawPath, len(events))
			}
		})
	}
}
