package risk

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/stringNameMahin/ALLSEER/internal/validator"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/decision"
	"github.com/stringNameMahin/ALLSEER/pkg/event"
)

// Host sensitivity is tested at two levels, and the split is deliberate.
//
// The vocabulary tests assert that this list means exactly what an identically
// written network grant means. They are written against the same confusions
// test/testdata/network/corpus.tsv is written against — suffix lookalikes,
// wildcard depth, the apex, IPv4-mapped addresses — because a sensitivity list
// that disagreed with the matcher about what `*.github.com` covers would be a
// second network model, which is the thing this feature exists not to be.
//
// The factor tests assert the three states and the invariants: unknown is not
// info, a covered event keeps its zero, and the list may only raise.

// --- fixtures ---------------------------------------------------------------------

// hostListYAML builds a hosts-only list, so a host test exercises the host
// vocabulary and nothing else.
func hostListYAML(entries string) []byte {
	return []byte("name: t\nversion: \"1\"\nhosts:\n" + entries)
}

func hostOracleFrom(t *testing.T, entries string) *ResourceOracle {
	t.Helper()
	list, err := ParseSensitivityList(hostListYAML(entries), "test")
	if err != nil {
		t.Fatalf("ParseSensitivityList: %v", err)
	}
	o, err := NewResourceOracle(list)
	if err != nil {
		t.Fatalf("NewResourceOracle: %v", err)
	}
	return o
}

// hostEntry is the boilerplate of a single graded entry, so a test names only
// the patterns and the grade it cares about.
func hostEntry(grade string, patterns ...string) string {
	return "  - patterns: [" + strings.Join(quoteAll(patterns), ", ") + "]\n" +
		"    sensitivity: " + grade + "\n" +
		"    reason: a reason, because every entry needs one\n"
}

func quoteAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, `"`+s+`"`)
	}
	return out
}

// netEvent builds a network event with a resolved observation and the
// correlation attribute enrichment would have written.
func netEvent(kind capability.Kind, target string, correlated bool) *event.Event {
	e := observedEvent(kind, target)
	e.Result = event.Result{Succeeded: true}
	if !correlated {
		e.Observation.Attributes = map[string]string{
			capability.AttrHostnameCorrelated: "false",
		}
	}
	return e
}

// hostDeparture is the shape most of these score: an ungranted connection, so
// the factor is charged rather than merely reported.
func hostDeparture(target string) ScoreRequest {
	return ScoreRequest{
		Event: netEvent(capability.KindNetConnect, target, true),
		Validation: result(decision.VerdictOutsideEnvelope,
			viol(validator.ViolationUngrantedCapability, capability.SeverityHigh)),
		Envelope: envelope(),
		History:  history(),
	}
}

func hostFactor(a *decision.RiskAssessment) *decision.Factor {
	return factor(a, FactorSensitiveHost)
}

// --- 1. the shipped list -------------------------------------------------------------

// The defaults ALLSEER ships are a security claim the project owns, so the file
// it ships is loaded and exercised rather than assumed good.
func TestShippedHostListLoads(t *testing.T) {
	list, err := LoadSensitivityList(defaultListPath())
	if err != nil {
		t.Fatalf("the shipped list does not load: %v", err)
	}
	if len(list.Hosts) == 0 {
		t.Fatal("the shipped list grades no hosts")
	}

	for i, e := range list.Hosts {
		if e.Reason == "" {
			t.Errorf("host entry #%d ships without a reason", i)
		}
		if !KnownSensitivity(e.Sensitivity) {
			t.Errorf("host entry #%d ships grade %q, which is not a grade", i, e.Sensitivity)
		}
		for _, p := range e.Patterns {
			// The vocabulary claim, checked against the real file: every shipped
			// pattern is one the envelope's own matcher accepts.
			if err := validator.ValidateHostPattern(p); err != nil {
				t.Errorf("host entry #%d ships an unusable pattern: %v", i, err)
			}
			// And none of them is a filesystem glob that happens to parse.
			if strings.Contains(p, "**") || strings.HasPrefix(p, "/") {
				t.Errorf("host entry #%d ships %q, which reads as a path pattern", i, p)
			}
		}
	}
}

// The ratings the project is actually claiming about destinations, one at a
// time. This table is the reviewable form of the claim: changing a grade should
// require changing this test, deliberately.
func TestShippedHostRatings(t *testing.T) {
	o := defaultOracle(t)

	for _, c := range []struct {
		host string
		want capability.Severity
		note string
	}{
		// The flagship case, by address and by name, because a destination is
		// rated by the identity the observation carries.
		{"169.254.169.254", capability.SeverityCritical, "cloud metadata, by address"},
		{"metadata.google.internal", capability.SeverityCritical, "cloud metadata, by name"},
		{"169.254.42.7", capability.SeverityCritical, "link-local block catches the rest"},

		{"10.4.2.9", capability.SeverityHigh, "private space, lateral movement"},
		{"192.168.1.1", capability.SeverityHigh, ""},
		{"172.16.0.5", capability.SeverityHigh, "the awkward /12 boundary"},

		{"127.0.0.1", capability.SeverityMedium, "loopback: dev servers and local daemons alike"},
		{"::1", capability.SeverityMedium, "loopback, v6"},

		{"github.com", capability.SeverityLow, "the apex, listed explicitly"},
		{"api.github.com", capability.SeverityLow, "one label under the wildcard"},

		{"registry.npmjs.org", capability.SeverityInfo, "rated, and unremarkable"},
		{"pypi.org", capability.SeverityInfo, ""},

		// Genuinely unknown: the list has never heard of these. Unknown is not
		// info, and this is the row that says so.
		{"evil.example", SensitivityUnknown, "an unlisted name"},
		{"93.184.216.34", SensitivityUnknown, "an unlisted public address"},
		{"8.8.8.8", SensitivityUnknown, "a public resolver is not on the list"},
	} {
		t.Run(c.host, func(t *testing.T) {
			got, reason := o.HostSensitivityReason(c.host)
			if got != c.want {
				t.Errorf("HostSensitivity(%q) = %q, want %q (%s)", c.host, got, c.want, c.note)
			}
			if KnownSensitivity(got) && reason == "" {
				t.Errorf("%q is graded %q with no reason behind it", c.host, got)
			}
			if !KnownSensitivity(got) && reason != "" {
				t.Errorf("%q is unrated but carries a reason %q", c.host, reason)
			}
		})
	}

	// 172.32 is outside the /12 and 192.167 is outside the /16. Both are the
	// mistakes a hand-written block check makes, and neither is this one's,
	// because containment is netip's.
	for _, outside := range []string{"172.32.0.1", "192.167.1.1", "11.0.0.1"} {
		if got := o.HostSensitivity(outside); got != SensitivityUnknown {
			t.Errorf("%q rated %q; it is outside every shipped block", outside, got)
		}
	}
}

// --- 2. the vocabulary is the validator's ---------------------------------------------

// Exact names are whole names, case-insensitively, with the root's trailing dot
// ignored. The near-misses are the ones a suffix comparison would wave through,
// and they are the reason host allowlists fail in the wild.
func TestExactHostNames(t *testing.T) {
	o := hostOracleFrom(t, hostEntry("critical", "api.github.com"))

	for _, m := range []string{"api.github.com", "API.GitHub.COM", "api.github.com."} {
		if got := o.HostSensitivity(m); got != capability.SeverityCritical {
			t.Errorf("%q = %q, want critical; DNS is case-insensitive and the root dot is not a label", m, got)
		}
	}
	for _, n := range []string{
		"evil-api.github.com",     // not a label boundary
		"api.github.com.evil.tld", // the name as a prefix of another
		"notapi.github.com",
		"github.com",       // the apex is not the name
		"x.api.github.com", // a subdomain is not the name
		"api.github.co",
	} {
		if got := o.HostSensitivity(n); got != SensitivityUnknown {
			t.Errorf("%q = %q, want unknown; an exact name matches whole names only", n, got)
		}
	}
}

// A wildcard covers exactly one additional label — the TLS certificate
// convention — and never the apex. Both halves are asserted, because covering
// the apex would silently widen every entry an operator writes.
func TestWildcardHosts(t *testing.T) {
	o := hostOracleFrom(t, hostEntry("high", "*.github.com"))

	for _, m := range []string{"api.github.com", "raw.github.com", "API.GitHub.com"} {
		if got := o.HostSensitivity(m); got != capability.SeverityHigh {
			t.Errorf("%q = %q, want high", m, got)
		}
	}
	for _, n := range []string{
		"github.com",      // the apex
		"a.b.github.com",  // two labels
		"evil-github.com", // not a label boundary
		"github.com.evil.io",
	} {
		if got := o.HostSensitivity(n); got != SensitivityUnknown {
			t.Errorf("%q = %q, want unknown", n, got)
		}
	}

	// An entry meaning both writes both, exactly as an envelope granting both
	// writes both. That is the documented answer to "should the apex match".
	both := hostOracleFrom(t, hostEntry("high", "github.com", "*.github.com"))
	for _, m := range []string{"github.com", "api.github.com"} {
		if got := both.HostSensitivity(m); got != capability.SeverityHigh {
			t.Errorf("%q = %q, want high once both spellings are listed", m, got)
		}
	}
}

// Addresses are compared as parsed values, so every spelling of one address is
// that address, and the families stay distinct.
func TestAddressAndBlockHosts(t *testing.T) {
	o := hostOracleFrom(t,
		hostEntry("critical", "2001:db8::1")+
			hostEntry("high", "10.0.0.0/8")+
			hostEntry("medium", "93.184.216.34"))

	for _, c := range []struct {
		host string
		want capability.Severity
		note string
	}{
		{"2001:db8::1", capability.SeverityCritical, ""},
		{"2001:0db8:0000:0000:0000:0000:0000:0001", capability.SeverityCritical, "a longer spelling of one address"},
		{"2001:DB8::1", capability.SeverityCritical, "case in hex"},
		{"10.1.2.3", capability.SeverityHigh, "inside the block"},
		{"93.184.216.34", capability.SeverityMedium, ""},
		{"::ffff:93.184.216.34", capability.SeverityMedium, "IPv4-mapped IPv6 is the IPv4 address"},

		{"11.0.0.1", SensitivityUnknown, "outside the block"},
		{"93.184.216.35", SensitivityUnknown, "one address along"},
		{"127.0.0.1", SensitivityUnknown, "::1 is not 127.0.0.1 and neither is listed"},
	} {
		if got := o.HostSensitivity(c.host); got != c.want {
			t.Errorf("%q = %q, want %q (%s)", c.host, got, c.want, c.note)
		}
	}

	// Host bits in a block are masked away rather than making the entry
	// unmatchable, which is the universal reading of the notation.
	masked := hostOracleFrom(t, hostEntry("high", "10.1.2.3/8"))
	if got := masked.HostSensitivity("10.9.9.9"); got != capability.SeverityHigh {
		t.Errorf("10.9.9.9 = %q under 10.1.2.3/8, want high; host bits are masked", got)
	}
}

// The rule that matters, restated as a sensitivity claim: a name and an address
// are never assumed to be the same thing, in either direction.
func TestTheNameAddressBoundaryHolds(t *testing.T) {
	byName := hostOracleFrom(t, hostEntry("critical", "metadata.google.internal"))
	if got := byName.HostSensitivity("169.254.169.254"); got != SensitivityUnknown {
		t.Errorf("an address matched a name entry (%q); nothing here reverse-resolves", got)
	}

	byAddr := hostOracleFrom(t, hostEntry("critical", "169.254.169.254"))
	if got := byAddr.HostSensitivity("metadata.google.internal"); got != SensitivityUnknown {
		t.Errorf("a name matched an address entry (%q)", got)
	}

	// Which is exactly why the shipped list writes both, and why this is the
	// documented instruction to whoever edits it.
	both := hostOracleFrom(t, hostEntry("critical", "metadata.google.internal", "169.254.169.254"))
	for _, m := range []string{"metadata.google.internal", "169.254.169.254"} {
		if got := both.HostSensitivity(m); got != capability.SeverityCritical {
			t.Errorf("%q = %q once both spellings are listed, want critical", m, got)
		}
	}
}

// Highest grade wins when several entries match, so a narrower entry added
// later can only ever raise a destination's grade. Asserted in both declaration
// orders, because a rule that depended on file order would not be reviewable.
func TestHighestHostGradeWins(t *testing.T) {
	forward := hostOracleFrom(t,
		hostEntry("low", "*.corp.example")+hostEntry("critical", "vault.corp.example"))
	backward := hostOracleFrom(t,
		hostEntry("critical", "vault.corp.example")+hostEntry("low", "*.corp.example"))

	for name, o := range map[string]*ResourceOracle{"narrow last": forward, "narrow first": backward} {
		if got := o.HostSensitivity("vault.corp.example"); got != capability.SeverityCritical {
			t.Errorf("%s: vault = %q, want critical", name, got)
		}
		if got := o.HostSensitivity("wiki.corp.example"); got != capability.SeverityLow {
			t.Errorf("%s: wiki = %q, want low", name, got)
		}
	}
}

// A destination the matcher cannot interpret is unknown, not unremarkable — the
// same refusal PathSensitivity makes about an unresolved path.
func TestAnUninterpretableDestinationIsUnrated(t *testing.T) {
	o := hostOracleFrom(t, hostEntry("critical", "*.example.com"))

	for _, bad := range []string{
		"",
		"host:443",         // a target that was never split
		"10.0.0.0/8",       // a block in the observed position
		"*.example.com",    // a pattern in the observed position
		"exam ple.com",     // whitespace
		"-leading.example", // a hyphen where DNS forbids one
		"exämple.com",      // non-ASCII: the kernel sees the A-label
	} {
		if got := o.HostSensitivity(bad); got != SensitivityUnknown {
			t.Errorf("HostSensitivity(%q) = %q, want unknown", bad, got)
		}
	}
}

// bareHost is the caller-splits half of MatchHost's contract, and the IPv6
// cases are where a naive split loses the destination entirely.
func TestBareHostSplitsTheTarget(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"registry.npmjs.org:443", "registry.npmjs.org"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"2001:db8::1", "2001:db8::1"},
		{"registry.npmjs.org", "registry.npmjs.org"},
		{"169.254.169.254:80", "169.254.169.254"},
		{"", ""},
	} {
		if got := bareHost(c.in); got != c.want {
			t.Errorf("bareHost(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// --- 3. admission ----------------------------------------------------------------------

// Loading fails closed, and every rejection covers a defect that is otherwise
// invisible at runtime. The path-vocabulary entries are the interesting half:
// they parse as YAML and would match nothing.
func TestHostListRejections(t *testing.T) {
	for _, c := range []struct {
		name    string
		entries string
		want    string
	}{
		{"a filesystem glob", hostEntry("high", "/**/.ssh/**"), "leading"},
		{"a bare path", hostEntry("high", "/etc/shadow"), "not a hostname"},
		{"a port in the pattern", hostEntry("high", "github.com:443"), "host:port"},
		{"a URL", hostEntry("high", "https://github.com"), "not a hostname"},
		{"an interior wildcard", hostEntry("high", "api-*.github.com"), "leading"},
		{"a doubled wildcard", hostEntry("high", "*.*.github.com"), "leading"},
		{"a path-style wildcard", hostEntry("high", "**.github.com"), "leading"},
		{"a bare wildcard", hostEntry("high", "*"), "leading"},
		{"a non-ASCII name", hostEntry("high", "exämple.com"), "not a hostname"},
		{"a zoned address", hostEntry("high", "fe80::1%eth0"), "zone"},
		{"whitespace", hostEntry("high", "git hub.com"), "whitespace"},
		{"an empty pattern", hostEntry("high", ""), "empty"},
		{"no patterns", "  - patterns: []\n    sensitivity: high\n    reason: r\n", "no patterns"},
		{"no grade", "  - patterns: [\"github.com\"]\n    reason: r\n", "does not set sensitivity"},
		{"an unknown grade", "  - patterns: [\"github.com\"]\n    sensitivity: severe\n    reason: r\n", "unknown sensitivity"},
		{"no reason", "  - patterns: [\"github.com\"]\n    sensitivity: high\n", "no reason"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseSensitivityList(hostListYAML(c.entries), "test")
			if err == nil {
				t.Fatalf("accepted %s", c.name)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not mention %q", err, c.want)
			}
		})
	}

	// A misspelled section key is an entry nobody will notice is missing, so it
	// refuses the file rather than decoding to nothing.
	if _, err := ParseSensitivityList([]byte("name: t\nversion: \"1\"\nhost:\n"+hostEntry("high", "github.com")), "test"); err == nil {
		t.Error("accepted a list with a misspelled 'hosts' key")
	}
}

// The two sections are independent, and a list carrying only one of them is
// legal. That is what lets a deployment rate destinations without inheriting
// this project's opinions about files, and the reverse.
func TestEitherSectionAloneIsALegalList(t *testing.T) {
	pathsOnly, err := ParseSensitivityList(listYAML(
		"  - patterns: [/etc/shadow]\n    sensitivity: critical\n    reason: r\n"), "test")
	if err != nil {
		t.Fatalf("a paths-only list was refused: %v", err)
	}
	if len(pathsOnly.Hosts) != 0 {
		t.Error("a paths-only list decoded hosts from nowhere")
	}

	hostsOnly, err := ParseSensitivityList(hostListYAML(hostEntry("critical", "169.254.169.254")), "test")
	if err != nil {
		t.Fatalf("a hosts-only list was refused: %v", err)
	}
	if len(hostsOnly.Paths) != 0 {
		t.Error("a hosts-only list decoded paths from nowhere")
	}

	// A list that grades nothing at all is still refused, which is the rule the
	// two-section form had to preserve rather than relax.
	if _, err := ParseSensitivityList([]byte("name: t\nversion: \"1\"\n"), "test"); !errors.Is(err, ErrNoSensitivityEntries) {
		t.Errorf("an empty list returned %v, want ErrNoSensitivityEntries", err)
	}
}

// --- 4. the three states -----------------------------------------------------------------

// The distinction the whole module refuses to collapse, asserted across all
// three states at once.
func TestHostSensitivityKeepsItsThreeStates(t *testing.T) {
	t.Run("no host ratings means no factor at all", func(t *testing.T) {
		// An oracle built from a paths-only list. It answers unknown to every
		// destination, and that is exactly why it must not emit a factor: nobody
		// was ever taught a host, so "we asked and do not know" would be a claim
		// about a lookup that never had anything to look in.
		o := oracleFrom(t, "  - patterns: [/etc/shadow]\n    sensitivity: critical\n    reason: r\n")
		if o.RatesHosts() {
			t.Fatal("a paths-only oracle claims to rate hosts")
		}
		a := scoreWith(t, engineWith(t, o), hostDeparture("evil.example:443"))
		if f := hostFactor(a); f != nil {
			t.Errorf("a build with no host ratings produced %+v", *f)
		}
	})

	t.Run("asked and unlisted means unknown", func(t *testing.T) {
		a := scoreWith(t, engineWith(t, defaultOracle(t)), hostDeparture("evil.example:443"))
		f := hostFactor(a)
		if f == nil {
			t.Fatal("no sensitive_host factor; the oracle rates hosts and was asked")
		}
		if got := f.Evidence[EvidenceSensitivity]; got != SensitivityUnknownLabel {
			t.Errorf("sensitivity = %q, want the literal %q", got, SensitivityUnknownLabel)
		}
		if f.Weight != 0 {
			t.Errorf("an unrated destination contributed %v", f.Weight)
		}
	})

	t.Run("listed means a grade and the author's reason", func(t *testing.T) {
		a := scoreWith(t, engineWith(t, defaultOracle(t)), hostDeparture("169.254.169.254:80"))
		f := hostFactor(a)
		if f == nil {
			t.Fatal("no sensitive_host factor")
		}
		if got := f.Evidence[EvidenceSensitivity]; got != string(capability.SeverityCritical) {
			t.Errorf("sensitivity = %q, want critical", got)
		}
		if f.Evidence[EvidenceReason] == "" {
			t.Error("the list author's reason did not reach the record")
		}
		if f.Weight != sensitivityPoints[capability.SeverityCritical] {
			t.Errorf("Weight = %v, want %v", f.Weight, sensitivityPoints[capability.SeverityCritical])
		}
	})
}

// An `info` rating is an explicit statement that a destination is ordinary. It
// scores nothing and it is emphatically not unknown, which is the whole reason
// the registries are in the shipped list.
func TestAnInfoHostIsRatedNotUnknown(t *testing.T) {
	a := scoreWith(t, engineWith(t, defaultOracle(t)), hostDeparture("registry.npmjs.org:443"))
	f := hostFactor(a)
	if f == nil {
		t.Fatal("no sensitive_host factor")
	}
	if got := f.Evidence[EvidenceSensitivity]; got != string(capability.SeverityInfo) {
		t.Errorf("sensitivity = %q, want info", got)
	}
	if f.Weight != 0 {
		t.Errorf("an info destination contributed %v points", f.Weight)
	}
	if f.Evidence[EvidenceReason] == "" {
		t.Error("an info rating with no reason is not a rating")
	}
}

// --- 5. the factor ------------------------------------------------------------------------

// The evidence a reader needs to check the finding by hand, on a destination
// reached by name and on one reached only by address.
func TestHostFactorEvidence(t *testing.T) {
	t.Run("by name", func(t *testing.T) {
		a := scoreWith(t, engineWith(t, defaultOracle(t)), hostDeparture("metadata.google.internal:80"))
		f := hostFactor(a)
		if f == nil {
			t.Fatal("no sensitive_host factor")
		}
		want := map[string]string{
			EvidenceDimension:   DimensionHost,
			EvidenceTarget:      "metadata.google.internal:80",
			EvidenceHost:        "metadata.google.internal",
			EvidenceHostKind:    HostKindLabelName,
			EvidenceSensitivity: string(capability.SeverityCritical),
		}
		for k, v := range want {
			if got := f.Evidence[k]; got != v {
				t.Errorf("evidence[%q] = %q, want %q", k, got, v)
			}
		}
		// Correlation succeeded, so enrichment wrote nothing and neither does
		// the record. An absent key reads as "not recorded", which is the truth.
		if _, ok := f.Evidence[EvidenceHostnameCorrelated]; ok {
			t.Error("a correlated destination carries a correlation flag")
		}
	})

	t.Run("by address, uncorrelated", func(t *testing.T) {
		req := hostDeparture("169.254.169.254:80")
		req.Event = netEvent(capability.KindNetConnect, "169.254.169.254:80", false)

		f := hostFactor(scoreWith(t, engineWith(t, defaultOracle(t)), req))
		if f == nil {
			t.Fatal("no sensitive_host factor")
		}
		if got := f.Evidence[EvidenceHostKind]; got != HostKindLabelAddress {
			t.Errorf("host_kind = %q, want %q", got, HostKindLabelAddress)
		}
		// The correlation gap is reported so an operator can see why a name
		// entry never got a chance. It qualifies the answer; it does not change
		// it, and it charges nothing — an uncorrelated destination is
		// novel_network_destination's signal, not this factor's.
		if got := f.Evidence[EvidenceHostnameCorrelated]; got != "false" {
			t.Errorf("hostname_correlated = %q, want %q", got, "false")
		}
		if f.Weight != sensitivityPoints[capability.SeverityCritical] {
			t.Errorf("Weight = %v; the address is on the list and correlation is beside the point", f.Weight)
		}
	})
}

// Every network capability reaches a destination, so every one is rated. A
// sensitive host is sensitive whichever way the socket points.
func TestEveryNetworkCapabilityIsRated(t *testing.T) {
	e := engineWith(t, defaultOracle(t))

	for _, kind := range []capability.Kind{
		capability.KindNetConnect, capability.KindNetSend, capability.KindNetReceive,
		capability.KindNetBind, capability.KindNetListen, capability.KindNetAccept,
		capability.KindNetDNS, capability.KindNetRawSock,
	} {
		req := hostDeparture("169.254.169.254:80")
		req.Event = netEvent(kind, "169.254.169.254:80", false)
		if f := hostFactor(scoreWith(t, e, req)); f == nil {
			t.Errorf("%s produced no host factor", kind)
		}
	}

	// A DNS query names a host and carries no port, which is the one target
	// shape that arrives bare. It still rates.
	req := hostDeparture("metadata.google.internal")
	req.Event = netEvent(capability.KindNetDNS, "metadata.google.internal", true)
	f := hostFactor(scoreWith(t, e, req))
	if f == nil {
		t.Fatal("a DNS query produced no host factor")
	}
	if got := f.Evidence[EvidenceHost]; got != "metadata.google.internal" {
		t.Errorf("host = %q, want the bare queried name", got)
	}
}

// A non-network event has no destination, so asking about one would be
// answering a question nobody put. sensitive_path owns those, and the two never
// both speak.
func TestNonNetworkEventsGetNoHostFactor(t *testing.T) {
	e := engineWith(t, defaultOracle(t))

	for _, kind := range []capability.Kind{
		capability.KindFileRead, capability.KindFileWrite, capability.KindProcessExec,
		capability.KindPrivSetuid, capability.KindKernelBPFLoad, capability.KindIPCUnixSock,
	} {
		a := scoreWith(t, e, ScoreRequest{
			Event:      observedEvent(kind, "/some/target"),
			Validation: result(decision.VerdictOutsideEnvelope, viol(validator.ViolationUngrantedCapability, capability.SeverityMedium)),
			Envelope:   envelope(),
			History:    history(),
		})
		if f := hostFactor(a); f != nil {
			t.Errorf("%s produced a host factor: %+v", kind, *f)
		}
	}
}

// A covered event keeps its exact zero and loses its silence, the same
// arrangement sensitive_path makes and for the same invariant.
func TestACoveredConnectionKeepsItsZeroButNotItsSilence(t *testing.T) {
	req := hostDeparture("169.254.169.254:80")
	req.Validation = result(decision.VerdictWithinEnvelope)

	a := scoreWith(t, engineWith(t, defaultOracle(t)), req)
	if a.Score != 0 || a.Level != decision.LevelNone {
		t.Errorf("a covered event scored %v (%q); the zero invariant is load-bearing", a.Score, a.Level)
	}

	f := hostFactor(a)
	if f == nil {
		t.Fatal("the rating went unreported on a covered event")
	}
	if f.Weight != 0 {
		t.Errorf("Weight = %v on a covered event, want 0", f.Weight)
	}
	if f.Evidence[EvidenceNotCharged] == "" {
		t.Error("points were withheld without the record saying why")
	}
	if f.Evidence[EvidenceSensitivity] != string(capability.SeverityCritical) {
		t.Error("the withheld finding lost its grade")
	}
}

// --- 6. the invariants ---------------------------------------------------------------------

// Host sensitivity may only raise, and it must move nothing else. A factor that
// perturbed its neighbours would be indistinguishable from one that was simply
// worth more.
func TestHostSensitivityOnlyRaisesAndDisturbsNothing(t *testing.T) {
	e := engineWith(t, defaultOracle(t))

	unlisted := scoreWith(t, e, hostDeparture("evil.example:443"))
	rated := scoreWith(t, e, hostDeparture("169.254.169.254:80"))

	if rated.Score <= unlisted.Score {
		t.Errorf("a critical destination scored %v against an unrated %v", rated.Score, unlisted.Score)
	}
	if rated.Score-unlisted.Score != sensitivityPoints[capability.SeverityCritical] {
		t.Errorf("score moved by %v, want exactly the grade's %v",
			rated.Score-unlisted.Score, sensitivityPoints[capability.SeverityCritical])
	}

	for _, name := range names(unlisted) {
		if name == FactorSensitiveHost {
			continue
		}
		a, b := factor(unlisted, name), factor(rated, name)
		if b == nil {
			t.Errorf("factor %q disappeared when the host was rated", name)
			continue
		}
		if a.Weight != b.Weight {
			t.Errorf("factor %q moved from %v to %v", name, a.Weight, b.Weight)
		}
	}
	if rated.Confidence != unlisted.Confidence {
		t.Errorf("confidence moved from %v to %v", unlisted.Confidence, rated.Confidence)
	}

	// No grade is negative and none can be configured to be, so no destination
	// can be listed as a way to lower a score.
	for _, g := range []capability.Severity{
		capability.SeverityInfo, capability.SeverityLow, capability.SeverityMedium,
		capability.SeverityHigh, capability.SeverityCritical,
	} {
		if sensitivityPointsFor(g) < 0 {
			t.Errorf("grade %q prices at %v", g, sensitivityPointsFor(g))
		}
	}
}

// Host sensitivity shares sensitive_path's point table, which is a decision
// rather than an omission: the grades answer one question about two kinds of
// resource, and the higher consequence of egress is already carried by
// violation_severity through the capability catalog's baseline.
func TestHostGradesArePricedLikePathGrades(t *testing.T) {
	for _, g := range []capability.Severity{
		capability.SeverityInfo, capability.SeverityLow, capability.SeverityMedium,
		capability.SeverityHigh, capability.SeverityCritical,
	} {
		o := hostOracleFrom(t, hostEntry(string(g), "graded.example"))
		hostPoints := hostFactor(scoreWith(t, engineWith(t, o), hostDeparture("graded.example:443"))).Weight

		if want := sensitivityPoints[g]; hostPoints != want {
			t.Errorf("grade %q on a host contributes %v, want the shared %v", g, hostPoints, want)
		}
	}

	// And the two capabilities carry their own weight separately: net.connect is
	// `high` in the catalog and fs.read is `low`, so the difference between
	// reaching a destination and reading a file is charged by violation_severity
	// rather than a second sensitivity table.
	if severityPoints[capability.SeverityHigh] <= severityPoints[capability.SeverityLow] {
		t.Error("the severity table no longer separates a connect from a read")
	}
}

// Repeated scoring against one oracle produces one answer. The host scan walks
// a slice and builds an evidence map, both places an ordering bug hides.
func TestHostScoringIsDeterministic(t *testing.T) {
	e := engineWith(t, defaultOracle(t))
	req := hostDeparture("169.254.169.254:80")

	first := scoreWith(t, e, req)
	for i := 0; i < 50; i++ {
		if got := scoreWith(t, e, req); !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d diverged\n got %+v\nwant %+v", i, got, first)
		}
	}
}

// --- 7. admission and metadata ---------------------------------------------------------------

func TestHostScorerAdmission(t *testing.T) {
	if _, err := NewSensitiveHostScorer(nil); err == nil {
		t.Error("a nil oracle was accepted")
	}

	var bare SensitiveHostScorer
	if _, err := bare.Evaluate(context.Background(), hostDeparture("github.com:443")); err == nil {
		t.Error("a scorer with no oracle reported no rating instead of refusing")
	}

	s, err := NewSensitiveHostScorer(defaultOracle(t))
	if err != nil {
		t.Fatalf("NewSensitiveHostScorer: %v", err)
	}
	if s.Name() != FactorSensitiveHost {
		t.Errorf("Name = %q", s.Name())
	}
	if s.Weight() != sensitivityPoints[capability.SeverityCritical] {
		t.Errorf("Weight = %v", s.Weight())
	}

	f, err := s.Evaluate(context.Background(), hostDeparture("169.254.169.254:80"))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if f == nil {
		t.Fatal("no factor")
	}
	if f.Name != s.Name() || f.Weight > s.Weight() || f.Description == "" {
		t.Errorf("factor %+v disagrees with its scorer", *f)
	}

	if _, err := s.Evaluate(context.Background(), ScoreRequest{
		Event: netEvent(capability.KindNetConnect, "github.com:443", true),
	}); !errors.Is(err, ErrNoValidation) {
		t.Errorf("Evaluate returned %v on an unvalidated request, want ErrNoValidation", err)
	}
}

// The scorer set reflects what the oracle actually knows, which is the record
// that host rating is configured at all.
func TestTheScorerSetFollowsTheList(t *testing.T) {
	has := func(e *BaselineEngine, name string) bool {
		for _, s := range e.Scorers() {
			if s.Name() == name {
				return true
			}
		}
		return false
	}

	pathsOnly := engineWith(t, oracleFrom(t, "  - patterns: [/etc/shadow]\n    sensitivity: critical\n    reason: r\n"))
	if has(pathsOnly, FactorSensitiveHost) {
		t.Error("a paths-only list produced a host scorer")
	}
	if !has(pathsOnly, FactorSensitivePath) {
		t.Error("a paths-only list produced no path scorer")
	}

	hostsOnly := engineWith(t, hostOracleFrom(t, hostEntry("critical", "169.254.169.254")))
	if !has(hostsOnly, FactorSensitiveHost) {
		t.Error("a hosts-only list produced no host scorer")
	}
	if has(hostsOnly, FactorSensitivePath) {
		t.Error("a hosts-only list produced a path scorer, which could only ever say unknown")
	}

	both := engineWith(t, defaultOracle(t))
	if !has(both, FactorSensitiveHost) || !has(both, FactorSensitivePath) {
		t.Error("the shipped list did not produce both resource scorers")
	}

	// An oracle that cannot state its own emptiness is assumed to rate both,
	// which is the safe direction: the factor is emitted and reports whatever
	// the oracle actually said.
	if !ratesHosts(stubOracle{}) || !ratesPaths(stubOracle{}) {
		t.Error("a third-party oracle was assumed to rate nothing")
	}
	if ratesHosts(nil) || ratesPaths(nil) {
		t.Error("a nil oracle was assumed to rate something")
	}
}

// stubOracle is a third-party oracle: it implements the interface and nothing
// else, with no way to state what it does and does not know.
type stubOracle struct{}

func (stubOracle) PathSensitivity(string) capability.Severity       { return SensitivityUnknown }
func (stubOracle) HostSensitivity(string) capability.Severity       { return capability.SeverityHigh }
func (stubOracle) ExecutableSensitivity(string) capability.Severity { return SensitivityUnknown }

// A third-party oracle with no reason method still produces a graded factor;
// the reason is simply absent rather than fabricated.
func TestAThirdPartyHostOracleIsUsed(t *testing.T) {
	f := hostFactor(scoreWith(t, engineWith(t, stubOracle{}), hostDeparture("anything.example:443")))
	if f == nil {
		t.Fatal("no host factor from a third-party oracle")
	}
	if got := f.Evidence[EvidenceSensitivity]; got != string(capability.SeverityHigh) {
		t.Errorf("sensitivity = %q, want high", got)
	}
	if _, ok := f.Evidence[EvidenceReason]; ok {
		t.Error("a reason was invented for an oracle that offers none")
	}
}

// --- 8. benchmarks --------------------------------------------------------------------------

// The common case: a destination the list has never heard of, which is what
// almost every connection is. The scan runs to the end, so this is also the
// worst case for a list of this size.
func BenchmarkScoreHostUnrated(b *testing.B) {
	benchmarkHost(b, "93.184.216.34:443")
}

// A destination the list rates, which stops at the first matching rule — and
// because the rules are ordered highest-grade first, a critical destination is
// the earliest exit there is.
func BenchmarkScoreHostRated(b *testing.B) {
	benchmarkHost(b, "169.254.169.254:80")
}

// A named destination, which walks past every address and block rule before
// reaching a name it can compare.
func BenchmarkScoreHostRatedByName(b *testing.B) {
	benchmarkHost(b, "registry.npmjs.org:443")
}

func benchmarkHost(b *testing.B, target string) {
	b.Helper()

	o, err := LoadResourceOracle(defaultListPath())
	if err != nil {
		b.Fatal(err)
	}
	e, err := NewEngineWithOracle(o)
	if err != nil {
		b.Fatal(err)
	}

	req := ScoreRequest{
		Event: netEvent(capability.KindNetConnect, target, true),
		Validation: result(decision.VerdictOutsideEnvelope,
			viol(validator.ViolationUngrantedCapability, capability.SeverityHigh)),
		Envelope: envelope(),
		History:  history(),
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
