package policy

import (
	"context"
	"strings"
	"testing"

	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
)

// The observability check is the only one here whose answer depends on the
// running build rather than on the file, so every case states the probe set
// explicitly rather than relying on a default.

// TestObservabilityCheckIsOptOut pins the compatibility guarantee. Every
// existing caller uses NewLinter, and none of them acquires an opinion about
// probes by upgrading.
func TestObservabilityCheckIsOptOut(t *testing.T) {
	rs := set(ece.ActionAllow, rule("r1", 10, ece.ActionBlock, Condition{
		Capabilities: []capability.Kind{capability.KindPrivEscalate},
	}))

	if issues := NewLinter().Lint(rs); len(issues) != 0 {
		t.Errorf("a catalogless linter reported %d issues:\n%s", len(issues), formatLint(issues))
	}
	if issues := LintRuleSet(rs); len(issues) != 0 {
		t.Errorf("LintRuleSet reported %d issues:\n%s", len(issues), formatLint(issues))
	}
	if issues := LintRuleSetWithCatalog(rs, nil); len(issues) != 0 {
		t.Errorf("a nil catalog reported %d issues:\n%s", len(issues), formatLint(issues))
	}
}

// TestShippedRuleSetLintsCleanWhenFullyObserved is the companion to
// TestShippedRuleSetLintsClean. On a build that sees everything, the check must
// stay silent -- otherwise it fires on the policy the project ships and every
// operator learns to ignore it on their first run.
func TestShippedRuleSetLintsCleanWhenFullyObserved(t *testing.T) {
	rs, err := NewLoader().Load(context.Background(), defaultRuleSetPath)
	if err != nil {
		t.Fatalf("load shipped rule set: %v", err)
	}

	linter := NewLinterWithCatalog(capability.NewCatalogAllObservable())
	if issues := linter.Lint(rs); len(issues) != 0 {
		t.Errorf("the shipped rule set produced %d lint issues on a fully observed build:\n%s",
			len(issues), formatLint(issues))
	}
}

// TestShippedRuleSetOnAPrivilegeBlindBuild is the case the check exists for,
// written against the shipped policy rather than a fixture. It is the situation
// a Windows build is in: privilege telemetry is uid-and-capability shaped on
// Linux and token, SID and integrity-level shaped on Windows, so no priv.* Kind
// has a probe. The rule that blocks privilege escalation is still in the file,
// still reads like protection, and cannot fire.
func TestShippedRuleSetOnAPrivilegeBlindBuild(t *testing.T) {
	rs, err := NewLoader().Load(context.Background(), defaultRuleSetPath)
	if err != nil {
		t.Fatalf("load shipped rule set: %v", err)
	}

	var observable []capability.Kind
	for _, k := range capability.AllKinds() {
		if d, _ := capability.Describe(k); d.Domain != capability.DomainPrivilege {
			observable = append(observable, k)
		}
	}

	issues := NewLinterWithCatalog(capability.NewCatalog(observable...)).Lint(rs)
	if len(issues) == 0 {
		t.Fatal("a build blind to every priv.* Kind produced no finding for the shipped policy")
	}
	for _, i := range issues {
		if i.Severity == capability.SeverityCritical {
			t.Errorf("observability produced a critical finding, which would refuse a portable rule set: %s", i.Message)
		}
		if !strings.Contains(i.Message, "no probe in this build observes") {
			t.Errorf("unexpected finding on a privilege-blind build: %s", i.Message)
		}
	}
}

func TestLintObservability(t *testing.T) {
	// A build that sees filesystem reads and nothing else. Chosen so that one
	// whole domain is observable in part, another not at all.
	partial := capability.NewCatalog(capability.KindFileRead)

	tests := []struct {
		name     string
		cond     Condition
		catalog  capability.Catalog
		want     []wantLint
		contains string
	}{
		{
			name:    "every capability observed",
			cond:    Condition{Capabilities: []capability.Kind{capability.KindFileRead}},
			catalog: partial,
		},
		{
			name:    "no capability observed",
			cond:    Condition{Capabilities: []capability.Kind{capability.KindPrivEscalate, capability.KindPrivSetuid}},
			catalog: partial,
			// High, not critical: the rule set is fine, this build is not.
			want:     []wantLint{{capability.SeverityHigh, "r1"}},
			contains: "can never fire in this build",
		},
		{
			name: "some capabilities observed",
			cond: Condition{Capabilities: []capability.Kind{
				capability.KindFileRead, capability.KindFileWrite,
			}},
			catalog: partial,
			// Medium, because OR within a list means the rule still fires on
			// the observable half -- narrower than written, not absent.
			want:     []wantLint{{capability.SeverityMedium, "r1"}},
			contains: "still fires on the rest",
		},
		{
			name:     "a domain with no observable capability",
			cond:     Condition{Domains: []capability.Domain{capability.DomainNetwork}},
			catalog:  partial,
			want:     []wantLint{{capability.SeverityHigh, "r1"}},
			contains: `domain "network"`,
		},
		{
			name:    "a domain with one observable capability is not reported",
			cond:    Condition{Domains: []capability.Domain{capability.DomainFilesystem}},
			catalog: partial,
		},
		{
			// The unknown Kind is lintClosedSets's finding, reported once as a
			// critical. Saying "and it is also unobservable" adds nothing.
			name:     "an unknown capability is not reported twice",
			cond:     Condition{Capabilities: []capability.Kind{"fs.teleport"}},
			catalog:  partial,
			want:     []wantLint{{capability.SeverityCritical, "r1"}},
			contains: "not in the catalog",
		},
		{
			name:    "an unknown domain is not reported as unobservable",
			cond:    Condition{Domains: []capability.Domain{"quantum"}},
			catalog: partial,
			want:    []wantLint{{capability.SeverityCritical, "r1"}},
		},
		{
			// A build with no probes at all: the honest answer for every
			// binary that has not attached a collector.
			name:    "nothing observable at all",
			cond:    Condition{Capabilities: []capability.Kind{capability.KindFileRead}},
			catalog: capability.NewCatalog(),
			want:    []wantLint{{capability.SeverityHigh, "r1"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs := set(ece.ActionAllow, rule("r1", 10, ece.ActionBlock, tt.cond))

			got := NewLinterWithCatalog(tt.catalog).Lint(rs)
			assertLint(t, got, tt.want)

			if tt.contains == "" {
				return
			}
			var found bool
			for _, i := range got {
				if strings.Contains(i.Message, tt.contains) {
					found = true
				}
			}
			if !found {
				t.Errorf("no issue mentioned %q:\n%s", tt.contains, formatLint(got))
			}
		})
	}
}

// TestObservabilityIsNeverBlocking is the property that keeps a portable rule
// set loadable. BlockingIssues is what callers refuse on, and an observability
// finding must never reach it.
func TestObservabilityIsNeverBlocking(t *testing.T) {
	rs := set(ece.ActionAllow,
		rule("r1", 10, ece.ActionBlock, Condition{
			Capabilities: []capability.Kind{capability.KindPrivEscalate},
		}),
		rule("r2", 20, ece.ActionBlock, Condition{
			Domains: []capability.Domain{capability.DomainKernel},
		}),
	)

	issues := NewLinterWithCatalog(capability.NewCatalog()).Lint(rs)
	if len(issues) == 0 {
		t.Fatal("expected findings on a build with no probes")
	}
	if blocking := BlockingIssues(issues); len(blocking) != 0 {
		t.Errorf("observability produced %d blocking issue(s):\n%s", len(blocking), formatLint(blocking))
	}
}

// TestObservabilitySkipsDisabledRules follows the rule the rest of the linter
// keeps: a rule that says it is inert cannot mislead anyone about what it does.
func TestObservabilitySkipsDisabledRules(t *testing.T) {
	r := rule("r1", 10, ece.ActionBlock, Condition{
		Capabilities: []capability.Kind{capability.KindPrivEscalate},
	})
	r.Enabled = false
	rs := set(ece.ActionAllow, r)

	if issues := NewLinterWithCatalog(capability.NewCatalog()).Lint(rs); len(issues) != 0 {
		t.Errorf("a disabled rule produced %d issues:\n%s", len(issues), formatLint(issues))
	}
}
