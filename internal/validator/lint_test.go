package validator

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
)

// --- helpers ----------------------------------------------------------------

// entry builds a grant or denial with the domain the catalog assigns, so a
// case that is not about domain drift does not trip the domain check.
func entry(kind capability.Kind, sel capability.Selector) capability.Grant {
	d, _ := capability.DomainOf(kind)
	return capability.Grant{Kind: kind, Domain: d, Selector: sel}
}

func envWith(grants, denials []capability.Grant) *ece.Envelope {
	return &ece.Envelope{
		SchemaVersion: ece.SchemaVersion,
		Grants:        grants,
		Denials:       denials,
		Constraints:   ece.Constraints{WorkspaceRoot: "/home/dev/project"},
		DefaultAction: ece.ActionRequestApproval,
	}
}

// wantIssue is the part of an Issue a case asserts: what it is and where it
// points. The message is prose and would make the table unreadable; the cases
// that turn on wording check it separately.
type wantIssue struct {
	severity capability.Severity
	field    string
}

func assertIssues(t *testing.T, got []ece.Issue, want []wantIssue) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d issues, want %d:\n%s", len(got), len(want), formatIssues(got))
	}
	for i := range want {
		if got[i].Severity != want[i].severity || got[i].Field != want[i].field {
			t.Errorf("issue %d = %s at %q, want %s at %q",
				i, got[i].Severity, got[i].Field, want[i].severity, want[i].field)
		}
		if got[i].Message == "" {
			t.Errorf("issue %d at %q has no message; an issue nobody can act on is noise", i, got[i].Field)
		}
	}
}

func formatIssues(issues []ece.Issue) string {
	var b strings.Builder
	for _, i := range issues {
		b.WriteString("  ")
		b.WriteString(string(i.Severity))
		b.WriteString(" ")
		b.WriteString(i.Field)
		b.WriteString(": ")
		b.WriteString(i.Message)
		b.WriteString("\n")
	}
	if b.Len() == 0 {
		return "  (none)\n"
	}
	return b.String()
}

// --- the table --------------------------------------------------------------

func TestLintEnvelope(t *testing.T) {
	cases := []struct {
		name string
		env  *ece.Envelope
		want []wantIssue
	}{
		// --- the producing case: a plausible envelope lints clean -------------
		{
			name: "well-formed envelope",
			env: envWith(
				[]capability.Grant{
					entry(capability.KindFileWrite, capability.Selector{
						PathPatterns: []string{"/home/dev/project/internal/**"},
					}),
					entry(capability.KindNetConnect, capability.Selector{
						Hosts: []string{"proxy.golang.org", "*.github.com", "10.0.0.0/8"},
						Ports: []int{443},
					}),
					entry(capability.KindProcessExec, capability.Selector{
						Executables: []string{"/usr/bin/go", "/usr/bin/git"},
						ArgPatterns: []string{"test", "build"},
					}),
				},
				[]capability.Grant{
					entry(capability.KindFileRead, capability.Selector{
						PathPatterns: []string{"/home/dev/.ssh/**", "/home/dev/project/**/.env"},
					}),
				},
			),
			want: nil,
		},

		// --- the asymmetry the whole file exists for --------------------------
		{
			name: "invalid pattern in a grant is not fatal",
			env: envWith([]capability.Grant{
				entry(capability.KindFileWrite, capability.Selector{
					PathPatterns: []string{"/ws/**.go"},
				}),
			}, nil),
			want: []wantIssue{{capability.SeverityMedium, "grants[0].selector.path_patterns[0]"}},
		},
		{
			name: "invalid pattern in a denial is fatal",
			env: envWith(nil, []capability.Grant{
				entry(capability.KindFileRead, capability.Selector{
					PathPatterns: []string{"/ws/**.go"},
				}),
			}),
			want: []wantIssue{{capability.SeverityCritical, "denials[0].selector.path_patterns[0]"}},
		},
		{
			name: "relative pattern in a denial is fatal",
			env: envWith(nil, []capability.Grant{
				entry(capability.KindFileRead, capability.Selector{
					PathPatterns: []string{"**/.env"},
				}),
			}),
			want: []wantIssue{{capability.SeverityCritical, "denials[0].selector.path_patterns[0]"}},
		},
		{
			name: "only the invalid pattern is reported",
			env: envWith(nil, []capability.Grant{
				entry(capability.KindFileRead, capability.Selector{
					PathPatterns: []string{"/ws/.ssh/**", "/ws/[abc", "/ws/**"},
				}),
			}),
			want: []wantIssue{{capability.SeverityCritical, "denials[0].selector.path_patterns[1]"}},
		},

		// --- kinds ------------------------------------------------------------
		{
			name: "unknown kind in a grant",
			env: envWith([]capability.Grant{
				{Kind: "fs.wrte", Domain: capability.DomainFilesystem},
			}, nil),
			want: []wantIssue{{capability.SeverityCritical, "grants[0].kind"}},
		},
		{
			name: "unknown kind in a denial",
			env: envWith(nil, []capability.Grant{
				{Kind: "fs.readall", Domain: capability.DomainFilesystem},
			}),
			want: []wantIssue{{capability.SeverityCritical, "denials[0].kind"}},
		},
		{
			name: "empty kind",
			env:  envWith([]capability.Grant{{Domain: capability.DomainFilesystem}}, nil),
			want: []wantIssue{{capability.SeverityCritical, "grants[0].kind"}},
		},
		{
			name: "an unknown kind suppresses selector checks it cannot interpret",
			env: envWith([]capability.Grant{{
				Kind:     "fs.wrte",
				Domain:   capability.DomainNetwork,
				Selector: capability.Selector{PathPatterns: []string{"relative/**"}},
			}}, nil),
			want: []wantIssue{{capability.SeverityCritical, "grants[0].kind"}},
		},
		{
			name: "domain disagrees with the catalog",
			env: envWith([]capability.Grant{{
				Kind:     capability.KindFileWrite,
				Domain:   capability.DomainNetwork,
				Selector: capability.Selector{PathPatterns: []string{"/ws/**"}},
			}}, nil),
			want: []wantIssue{{capability.SeverityLow, "grants[0].domain"}},
		},

		// --- dimensions the matcher does not read -----------------------------
		{
			name: "hosts on a filesystem grant widen it silently",
			env: envWith([]capability.Grant{{
				Kind:     capability.KindFileWrite,
				Domain:   capability.DomainFilesystem,
				Selector: capability.Selector{Hosts: []string{"api.github.com"}},
			}}, nil),
			want: []wantIssue{{capability.SeverityHigh, "grants[0].selector.hosts"}},
		},
		{
			name: "path patterns on a network denial widen it",
			env: envWith(nil, []capability.Grant{
				entry(capability.KindNetConnect, capability.Selector{
					PathPatterns: []string{"/ws/**"},
					Hosts:        []string{"evil.example.com"},
				}),
			}),
			want: []wantIssue{{capability.SeverityMedium, "denials[0].selector.path_patterns"}},
		},
		{
			name: "path patterns narrow an ipc grant",
			env: envWith([]capability.Grant{
				entry(capability.KindIPCUnixSock, capability.Selector{
					PathPatterns: []string{"/run/user/1000/**"},
				}),
			}, nil),
			want: nil,
		},

		// --- hosts, ports, protocols ------------------------------------------
		{
			name: "host:port in a grant host list",
			env: envWith([]capability.Grant{
				entry(capability.KindNetConnect, capability.Selector{
					Hosts: []string{"api.github.com:443"},
				}),
			}, nil),
			want: []wantIssue{{capability.SeverityMedium, "grants[0].selector.hosts[0]"}},
		},
		{
			name: "homoglyph host in a denial",
			env: envWith(nil, []capability.Grant{
				entry(capability.KindNetConnect, capability.Selector{
					Hosts: []string{"gіthub.com"}, // Cyrillic i
				}),
			}),
			want: []wantIssue{{capability.SeverityCritical, "denials[0].selector.hosts[0]"}},
		},
		{
			name: "unusable port in a denial",
			env: envWith(nil, []capability.Grant{
				entry(capability.KindNetConnect, capability.Selector{
					Hosts: []string{"evil.example.com"},
					Ports: []int{0, 443, 70000},
				}),
			}),
			want: []wantIssue{
				{capability.SeverityCritical, "denials[0].selector.ports[0]"},
				{capability.SeverityCritical, "denials[0].selector.ports[2]"},
			},
		},
		{
			name: "empty protocol entry",
			env: envWith([]capability.Grant{
				entry(capability.KindNetConnect, capability.Selector{
					Hosts:     []string{"api.github.com"},
					Protocols: []string{"tcp", " "},
				}),
			}, nil),
			want: []wantIssue{{capability.SeverityMedium, "grants[0].selector.protocols[1]"}},
		},

		// --- process ----------------------------------------------------------
		{
			name: "invalid executable pattern in a grant",
			env: envWith([]capability.Grant{
				entry(capability.KindProcessExec, capability.Selector{
					Executables: []string{"go"},
				}),
			}, nil),
			want: []wantIssue{{capability.SeverityMedium, "grants[0].selector.executables[0]"}},
		},
		{
			name: "empty argument pattern in a denial",
			env: envWith(nil, []capability.Grant{
				entry(capability.KindProcessExec, capability.Selector{
					Executables: []string{"/usr/bin/git"},
					ArgPatterns: []string{""},
				}),
			}),
			want: []wantIssue{{capability.SeverityCritical, "denials[0].selector.arg_patterns[0]"}},
		},

		// --- unbounded selectors ----------------------------------------------
		{
			name: "unbounded grant",
			env:  envWith([]capability.Grant{entry(capability.KindFileWrite, capability.Selector{})}, nil),
			want: []wantIssue{{capability.SeverityMedium, "grants[0].selector"}},
		},
		{
			name: "unbounded denial is a deliberate blanket prohibition",
			env:  envWith(nil, []capability.Grant{entry(capability.KindNetConnect, capability.Selector{})}),
			want: nil,
		},
		{
			name: "a privilege grant has nothing to narrow it with",
			env:  envWith([]capability.Grant{entry(capability.KindPrivSetuid, capability.Selector{})}, nil),
			want: nil,
		},
		{
			name: "an inapplicable dimension is not also reported as unbounded",
			env: envWith([]capability.Grant{{
				Kind:     capability.KindFileWrite,
				Domain:   capability.DomainFilesystem,
				Selector: capability.Selector{Ports: []int{443}},
			}}, nil),
			want: []wantIssue{{capability.SeverityHigh, "grants[0].selector.ports"}},
		},

		// --- byte-exactness ambiguities ---------------------------------------
		{
			name: "non-ASCII pattern in a grant",
			env: envWith([]capability.Grant{
				entry(capability.KindFileWrite, capability.Selector{
					PathPatterns: []string{"/ws/caf\u00e9/**"},
				}),
			}, nil),
			want: []wantIssue{{capability.SeverityLow, "grants[0].selector.path_patterns[0]"}},
		},
		{
			name: "non-ASCII pattern in a denial",
			env: envWith(nil, []capability.Grant{
				entry(capability.KindFileRead, capability.Selector{
					PathPatterns: []string{"/ws/p\u0430ckage.json"}, // Cyrillic a
				}),
			}),
			want: []wantIssue{{capability.SeverityMedium, "denials[0].selector.path_patterns[0]"}},
		},
		{
			name: "mixed case in a denial is evadable",
			env: envWith(nil, []capability.Grant{
				entry(capability.KindFileWrite, capability.Selector{
					PathPatterns: []string{"/ws/Makefile"},
				}),
			}),
			want: []wantIssue{{capability.SeverityLow, "denials[0].selector.path_patterns[0]"}},
		},
		{
			name: "mixed case in a grant is not reported",
			env: envWith([]capability.Grant{
				entry(capability.KindFileWrite, capability.Selector{
					PathPatterns: []string{"/ws/Makefile", "/ws/README.md"},
				}),
			}, nil),
			want: nil,
		},

		// --- counts and constraints -------------------------------------------
		{
			name: "negative max count",
			env: envWith([]capability.Grant{
				entry(capability.KindFileWrite, capability.Selector{
					PathPatterns: []string{"/ws/**"}, MaxCount: -1,
				}),
			}, nil),
			want: []wantIssue{{capability.SeverityLow, "grants[0].selector.max_count"}},
		},
		{
			name: "max count on a denial",
			env: envWith(nil, []capability.Grant{
				entry(capability.KindFileRead, capability.Selector{
					PathPatterns: []string{"/ws/.env"}, MaxCount: 3,
				}),
			}),
			want: []wantIssue{{capability.SeverityLow, "denials[0].selector.max_count"}},
		},
		{
			name: "max count on a grant is ordinary",
			env: envWith([]capability.Grant{
				entry(capability.KindProcessExec, capability.Selector{
					Executables: []string{"/usr/bin/go"}, MaxCount: 20,
				}),
			}, nil),
			want: nil,
		},
		{
			name: "unresolved workspace root",
			env: &ece.Envelope{
				Constraints: ece.Constraints{WorkspaceRoot: "/home/dev/../project"},
			},
			want: []wantIssue{{capability.SeverityMedium, "constraints.workspace_root"}},
		},
		{
			name: "no workspace root is a coherent choice",
			env:  &ece.Envelope{},
			want: nil,
		},

		// --- ordering and field paths -----------------------------------------
		{
			name: "issues are reported in document order",
			env: &ece.Envelope{
				Constraints: ece.Constraints{WorkspaceRoot: "relative/root"},
				Grants: []capability.Grant{
					entry(capability.KindFileRead, capability.Selector{PathPatterns: []string{"/ws/**"}}),
					entry(capability.KindFileWrite, capability.Selector{PathPatterns: []string{"/ws/a**b"}}),
				},
				Denials: []capability.Grant{
					entry(capability.KindFileRead, capability.Selector{PathPatterns: []string{"/ws/.env"}}),
					entry(capability.KindFileRead, capability.Selector{PathPatterns: []string{"/ws/**", "bad"}}),
				},
			},
			want: []wantIssue{
				{capability.SeverityMedium, "constraints.workspace_root"},
				{capability.SeverityMedium, "grants[1].selector.path_patterns[0]"},
				{capability.SeverityCritical, "denials[1].selector.path_patterns[1]"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertIssues(t, LintEnvelope(tc.env), tc.want)
		})
	}
}

// --- the interface ----------------------------------------------------------

func TestEnvelopeLinterValidate(t *testing.T) {
	l := NewEnvelopeLinter()

	if _, err := l.Validate(context.Background(), nil); !errors.Is(err, ErrNoEnvelope) {
		t.Fatalf("Validate(nil) error = %v, want ErrNoEnvelope", err)
	}

	env := envWith(nil, []capability.Grant{
		entry(capability.KindFileRead, capability.Selector{PathPatterns: []string{"/ws/[abc"}}),
	})
	issues, err := l.Validate(context.Background(), env)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(issues) != 1 {
		t.Fatalf("got %d issues, want 1:\n%s", len(issues), formatIssues(issues))
	}
	if issues[0].Suggestion == "" {
		t.Error("issue carries no suggestion; a reviewer needs to know what to write instead")
	}
	if !strings.Contains(issues[0].Message, "protects nothing") {
		t.Errorf("denial message %q does not say the denial protects nothing, which is the whole finding", issues[0].Message)
	}
}

func TestBlockingIssues(t *testing.T) {
	issues := []ece.Issue{
		{Severity: capability.SeverityLow, Field: "a"},
		{Severity: capability.SeverityCritical, Field: "b"},
		{Severity: capability.SeverityHigh, Field: "c"},
		{Severity: capability.SeverityMedium, Field: "d"},
		{Severity: capability.SeverityCritical, Field: "e"},
	}

	blocking := BlockingIssues(issues)
	if len(blocking) != 2 || blocking[0].Field != "b" || blocking[1].Field != "e" {
		t.Fatalf("BlockingIssues = %v, want the two critical issues in order", blocking)
	}
	if got := BlockingIssues(nil); got != nil {
		t.Errorf("BlockingIssues(nil) = %v, want nil", got)
	}
}

// TestLintBlocksNothingFailClosed pins the direction of the severity scale: a
// grant defect never refuses admission, because a grant that matches nothing
// costs false positives and never silent permission. If this fails, the
// asymmetry documented at the top of lint.go has been inverted.
func TestLintBlocksNothingFailClosed(t *testing.T) {
	env := envWith([]capability.Grant{
		{Kind: capability.KindFileWrite, Domain: capability.DomainNetwork, Selector: capability.Selector{
			PathPatterns: []string{"/ws/**.go", "relative", ""},
			Hosts:        []string{"not a host"},
			Ports:        []int{99999},
			MaxCount:     -3,
		}},
		entry(capability.KindNetConnect, capability.Selector{Hosts: []string{"api.github.com:443"}}),
	}, nil)

	issues := LintEnvelope(env)
	if len(issues) == 0 {
		t.Fatal("a thoroughly broken set of grants produced no issues")
	}
	if blocking := BlockingIssues(issues); len(blocking) != 0 {
		t.Errorf("grant defects blocked admission:\n%s", formatIssues(blocking))
	}
}

// --- agreement with the matchers --------------------------------------------

// TestLintAgreesWithPathMatcher is the drift guard the co-location argument
// rests on. Every pattern the corpus marks invalid must be blocked in a denial,
// and every pattern the corpus expects to work must be admitted -- otherwise the
// linter and the matcher disagree about which envelopes are usable, and the gap
// between them is exactly where a denial that denies nothing lives.
func TestLintAgreesWithPathMatcher(t *testing.T) {
	m := NewPathMatcher()

	for _, c := range loadCorpus(t, pathCorpusPath, "match", "nomatch", "invalid", "unresolved") {
		env := envWith(nil, []capability.Grant{
			entry(capability.KindFileRead, capability.Selector{PathPatterns: []string{c.pattern}}),
		})
		blocking := BlockingIssues(LintEnvelope(env))

		switch c.expect {
		case "invalid":
			if len(blocking) == 0 {
				t.Errorf("line %d: pattern %q is unusable by the matcher but was admitted", c.line, c.pattern)
			}
			if m.Match(c.pattern, c.path) {
				t.Errorf("line %d: pattern %q matched %q despite being invalid", c.line, c.pattern, c.path)
			}
		default:
			if len(blocking) != 0 {
				t.Errorf("line %d: pattern %q is usable by the matcher but was blocked:\n%s",
					c.line, c.pattern, formatIssues(blocking))
			}
		}
	}
}

// TestLintAgreesWithNetworkMatcher is the same guard for host patterns.
func TestLintAgreesWithNetworkMatcher(t *testing.T) {
	for _, c := range loadCorpus(t, networkCorpusPath, "match", "nomatch", "invalid", "uncorrelated") {
		env := envWith(nil, []capability.Grant{
			entry(capability.KindNetConnect, capability.Selector{Hosts: []string{c.pattern}}),
		})
		blocking := BlockingIssues(LintEnvelope(env))

		switch c.expect {
		case "invalid":
			if len(blocking) == 0 {
				t.Errorf("line %d: host pattern %q is unusable by the matcher but was admitted", c.line, c.pattern)
			}
			if MatchHost(c.pattern, c.path) {
				t.Errorf("line %d: host pattern %q matched %q despite being invalid", c.line, c.pattern, c.path)
			}
		default:
			if len(blocking) != 0 {
				t.Errorf("line %d: host pattern %q is usable by the matcher but was blocked:\n%s",
					c.line, c.pattern, formatIssues(blocking))
			}
		}
	}
}

// TestApplicableDimensionsCoversEveryDomain guards the other half of the
// agreement: applicableDimensions must track SelectorMatcher's dispatch. A new
// domain landing in the catalog without a case here would silently fall to the
// default and report its selector dimensions as ignored.
func TestApplicableDimensionsCoversEveryDomain(t *testing.T) {
	known := map[string]bool{
		dimPaths: true, dimHosts: true, dimPorts: true,
		dimProtocols: true, dimExecutables: true, dimArgs: true,
	}

	for _, d := range capability.AllDomains() {
		dims := applicableDimensions(d)
		if len(dims) == 0 {
			t.Errorf("domain %q has no applicable selector dimension", d)
		}
		for _, dim := range dims {
			if !known[dim] {
				t.Errorf("domain %q names unknown dimension %q", d, dim)
			}
		}
	}
}

// TestLintedDenialWouldHaveDeniedNothing is the motivating case stated as a
// test: an envelope whose credential denial is mistyped validates every read of
// the file it was written to protect as within envelope. The linter is the only
// thing standing between that envelope and a session.
func TestLintedDenialWouldHaveDeniedNothing(t *testing.T) {
	env := envWith(
		[]capability.Grant{
			entry(capability.KindFileRead, capability.Selector{PathPatterns: []string{"/home/dev/**"}}),
		},
		[]capability.Grant{
			// "**" only means a whole segment, so this denies nothing at all.
			entry(capability.KindFileRead, capability.Selector{PathPatterns: []string{"/home/dev/**.ssh/**"}}),
		},
	)

	blocking := BlockingIssues(LintEnvelope(env))
	if len(blocking) != 1 {
		t.Fatalf("got %d blocking issues, want 1:\n%s", len(blocking), formatIssues(LintEnvelope(env)))
	}

	// And confirm the finding is real rather than pedantic: with the envelope
	// admitted, the read the denial named is within envelope.
	res, err := NewValidator().Validate(context.Background(), ValidateRequest{
		Envelope: env,
		Event:    fileEvent(capability.KindFileRead, "/home/dev/.ssh/id_rsa"),
		State:    fakeState{},
	})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != "within_envelope" {
		t.Fatalf("verdict = %q, want within_envelope; if this changed, the motivating case for admission linting has changed too", res.Verdict)
	}
}
