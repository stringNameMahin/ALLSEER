package validator

import (
	"strings"
	"testing"

	"github.com/stringNameMahin/ALLSEER/pkg/capability"
)

func fileWriteObs(path string) capability.Observation {
	return capability.Observation{
		Kind:   capability.KindFileWrite,
		Domain: capability.DomainFilesystem,
		Target: path,
	}
}

func connectObs(target string, attrs map[string]string) capability.Observation {
	return capability.Observation{
		Kind:       capability.KindNetConnect,
		Domain:     capability.DomainNetwork,
		Target:     target,
		Attributes: attrs,
	}
}

func execObs(binary, argv string) capability.Observation {
	obs := capability.Observation{
		Kind:   capability.KindProcessExec,
		Domain: capability.DomainProcess,
		Target: binary,
	}
	if argv != "" {
		obs.Attributes = map[string]string{capability.AttrArgv: argv}
	}
	return obs
}

// want describes an expected MatchResult without pinning the reason wording.
type want int

const (
	wantMatch want = iota
	wantMismatch
	wantUnevaluable
)

func (w want) String() string {
	switch w {
	case wantMatch:
		return "match"
	case wantMismatch:
		return "mismatch"
	default:
		return "unevaluable"
	}
}

func check(t *testing.T, got MatchResult, w want) {
	t.Helper()

	var actual want
	switch {
	case got.Matched:
		actual = wantMatch
	case got.Unevaluable:
		actual = wantUnevaluable
	default:
		actual = wantMismatch
	}
	if actual != w {
		t.Errorf("got %s (%q), want %s", actual, got.Reason, w)
	}
	if got.Reason == "" {
		t.Error("Reason is empty; an outcome reaches the audit log unexplained")
	}
	if got.Matched && got.Unevaluable {
		t.Error("Matched and Unevaluable are both set")
	}
}

func TestMatchKindMustAgree(t *testing.T) {
	m := NewMatcher()

	g := capability.Grant{Kind: capability.KindFileWrite, Domain: capability.DomainFilesystem}
	check(t, m.Match(g, fileWriteObs("/ws/main.go")), wantMatch)
	check(t, m.Match(g, capability.Observation{
		Kind:   capability.KindFileRead,
		Domain: capability.DomainFilesystem,
		Target: "/ws/main.go",
	}), wantMismatch)
}

func TestMatchUnknownKindIsUnevaluable(t *testing.T) {
	// An unknown Kind should have been rejected at envelope admission. If one
	// reaches matching, guessing how to interpret its target would be
	// inventing a selector.
	unknown := capability.Kind("fs.teleport")
	g := capability.Grant{Kind: unknown}
	obs := capability.Observation{Kind: unknown, Target: "/ws/main.go"}

	check(t, NewMatcher().Match(g, obs), wantUnevaluable)
}

func TestMatchFilesystem(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		target   string
		w        want
	}{
		{"covered by pattern", []string{"/ws/**"}, "/ws/src/main.go", wantMatch},
		{"second pattern covers", []string{"/etc/**", "/ws/**"}, "/ws/main.go", wantMatch},
		{"outside every pattern", []string{"/ws/**"}, "/etc/passwd", wantMismatch},
		{"no constraint covers everything", nil, "/etc/passwd", wantMatch},

		// The distinction the whole type exists for.
		{"unresolved path is not a mismatch", []string{"/ws/**"}, "/ws/../etc/passwd", wantUnevaluable},
		{"relative path is not a mismatch", []string{"/ws/**"}, "main.go", wantUnevaluable},
		{"empty path is not a mismatch", []string{"/ws/**"}, "", wantUnevaluable},

		// An unconstrained dimension covers everything, including what could
		// not be resolved: the uncertainty cannot change coverage.
		{"no constraint covers an unresolved path", nil, "/ws/../etc/passwd", wantMatch},

		// An invalid pattern matches nothing, so it is a mismatch rather than
		// an error here; envelope admission is where it should have been
		// caught.
		{"invalid pattern covers nothing", []string{"/ws/**.go"}, "/ws/main.go", wantMismatch},
	}

	m := NewMatcher()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := capability.Grant{
				Kind:     capability.KindFileWrite,
				Domain:   capability.DomainFilesystem,
				Selector: capability.Selector{PathPatterns: tt.patterns},
			}
			check(t, m.Match(g, fileWriteObs(tt.target)), tt.w)
		})
	}
}

func TestMatchNetworkHosts(t *testing.T) {
	tests := []struct {
		name   string
		hosts  []string
		target string
		attrs  map[string]string
		w      want
	}{
		{
			"correlated name matches a name grant",
			[]string{"api.github.com"}, "api.github.com:443", nil, wantMatch,
		},
		{
			"correlated name misses a different name grant",
			[]string{"proxy.golang.org"}, "api.github.com:443", nil, wantMismatch,
		},
		{
			// The address is a fact the kernel is certain of, so matching it
			// against a block grant is not a hopeful equivalence.
			"address matches a CIDR grant",
			[]string{"10.0.0.0/8"}, "10.1.2.3:443", nil, wantMatch,
		},
		{
			"address outside a CIDR grant is a real mismatch",
			[]string{"10.0.0.0/8"}, "11.1.2.3:443", nil, wantMismatch,
		},
		{
			// Both facts are known, so both are compared.
			"correlated name plus address matches whichever the grant names",
			[]string{"10.0.0.0/8"}, "build.internal:443",
			map[string]string{capability.AttrDestIP: "10.1.2.3"}, wantMatch,
		},
		{
			"name grant matches the name when the address is also known",
			[]string{"build.internal"}, "build.internal:443",
			map[string]string{capability.AttrDestIP: "10.1.2.3"}, wantMatch,
		},
		{
			// The case the network spec exists for: a name grant against a
			// destination known only by address.
			"uncorrelated address against a name grant",
			[]string{"api.github.com"}, "140.82.121.5:443", nil, wantUnevaluable,
		},
		{
			"uncorrelated address against a wildcard grant",
			[]string{"*.github.com"}, "140.82.121.5:443", nil, wantUnevaluable,
		},
		{
			// One granted host is comparable and missed, the other could not be
			// compared at all. The connection may have been to the second, so
			// the honest answer is uncertainty, not a violation.
			"a mix of comparable and uncomparable grants is uncertain",
			[]string{"10.0.0.0/8", "api.github.com"}, "140.82.121.5:443", nil, wantUnevaluable,
		},
		{
			"fully comparable grants produce a clean mismatch",
			[]string{"10.0.0.0/8", "192.168.0.0/16"}, "140.82.121.5:443", nil, wantMismatch,
		},
		{
			"no host constraint covers any destination",
			nil, "140.82.121.5:443", nil, wantMatch,
		},
		{
			"a destination with neither name nor address is uncertain",
			[]string{"api.github.com"}, ":443", nil, wantUnevaluable,
		},
	}

	m := NewMatcher()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := capability.Grant{
				Kind:     capability.KindNetConnect,
				Domain:   capability.DomainNetwork,
				Selector: capability.Selector{Hosts: tt.hosts},
			}
			check(t, m.Match(g, connectObs(tt.target, tt.attrs)), tt.w)
		})
	}
}

// TestMatchNetworkIPv6Target is the parsing trap: a bare IPv6 literal is full
// of colons and looks like host:port to a naive split.
func TestMatchNetworkIPv6Target(t *testing.T) {
	m := NewMatcher()

	tests := []struct {
		name   string
		hosts  []string
		ports  []int
		target string
		w      want
	}{
		{"bracketed IPv6 with port", []string{"2001:db8::1"}, []int{443}, "[2001:db8::1]:443", wantMatch},
		{"bare IPv6, no port", []string{"2001:db8::1"}, nil, "2001:db8::1", wantMatch},
		{"bare IPv6 in a block", []string{"2001:db8::/32"}, nil, "2001:db8::1", wantMatch},
		{"bare IPv6 outside a block", []string{"2001:db9::/32"}, nil, "2001:db8::1", wantMismatch},
		{"bare hostname, no port", []string{"api.github.com"}, nil, "api.github.com", wantMatch},
		{
			// Not a mismatch: nothing here says the port was wrong, only that
			// it is unknown.
			"port constrained but target carries none",
			nil, []int{443}, "api.github.com", wantUnevaluable,
		},
		{"unparseable target", []string{"api.github.com"}, nil, "not a host:::", wantUnevaluable},
		{"non-numeric port", nil, []int{443}, "api.github.com:https", wantUnevaluable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := capability.Grant{
				Kind:     capability.KindNetConnect,
				Domain:   capability.DomainNetwork,
				Selector: capability.Selector{Hosts: tt.hosts, Ports: tt.ports},
			}
			check(t, m.Match(g, connectObs(tt.target, nil)), tt.w)
		})
	}
}

func TestMatchNetworkPortsAndProtocols(t *testing.T) {
	m := NewMatcher()

	sel := func(ports []int, protocols []string) capability.Grant {
		return capability.Grant{
			Kind:   capability.KindNetConnect,
			Domain: capability.DomainNetwork,
			Selector: capability.Selector{
				Hosts:     []string{"api.github.com"},
				Ports:     ports,
				Protocols: protocols,
			},
		}
	}
	tcp := map[string]string{capability.AttrProtocol: "tcp"}

	check(t, m.Match(sel([]int{443}, nil), connectObs("api.github.com:443", nil)), wantMatch)
	check(t, m.Match(sel([]int{443}, nil), connectObs("api.github.com:22", nil)), wantMismatch)

	// Empty means any, the rule that must never be read as deny-all.
	check(t, m.Match(sel(nil, nil), connectObs("api.github.com:31337", nil)), wantMatch)

	check(t, m.Match(sel(nil, []string{"tcp"}), connectObs("api.github.com:443", tcp)), wantMatch)
	check(t, m.Match(sel(nil, []string{"TCP"}), connectObs("api.github.com:443", tcp)), wantMatch)
	check(t, m.Match(sel(nil, []string{"udp"}), connectObs("api.github.com:443", tcp)), wantMismatch)
	check(t, m.Match(sel(nil, []string{"tcp"}), connectObs("api.github.com:443", nil)), wantUnevaluable)
}

// TestMatchDimensionsAreConjunctive pins the AND across dimensions. Getting
// this backwards would make a grant of "this host on this port" cover the host
// on every port.
func TestMatchDimensionsAreConjunctive(t *testing.T) {
	g := capability.Grant{
		Kind:   capability.KindNetConnect,
		Domain: capability.DomainNetwork,
		Selector: capability.Selector{
			Hosts:     []string{"api.github.com"},
			Ports:     []int{443},
			Protocols: []string{"tcp"},
		},
	}
	tcp := map[string]string{capability.AttrProtocol: "tcp"}
	udp := map[string]string{capability.AttrProtocol: "udp"}

	m := NewMatcher()
	check(t, m.Match(g, connectObs("api.github.com:443", tcp)), wantMatch)
	check(t, m.Match(g, connectObs("proxy.golang.org:443", tcp)), wantMismatch)
	check(t, m.Match(g, connectObs("api.github.com:22", tcp)), wantMismatch)
	check(t, m.Match(g, connectObs("api.github.com:443", udp)), wantMismatch)
}

func TestMatchProcess(t *testing.T) {
	tests := []struct {
		name        string
		executables []string
		argPatterns []string
		binary      string
		argv        string
		w           want
	}{
		{"executable covered", []string{"/usr/bin/*"}, nil, "/usr/bin/git", "git status", wantMatch},
		{"executable not covered", []string{"/usr/bin/git"}, nil, "/bin/sh", "sh -c x", wantMismatch},
		{"no executable constraint", nil, nil, "/bin/sh", "sh -c x", wantMatch},
		{"unresolved binary path", []string{"/usr/bin/*"}, nil, "git", "git status", wantUnevaluable},

		{"argument matches a single arg", nil, []string{"clone"}, "/usr/bin/git", "git clone https://x", wantMatch},
		{"argument matches with a wildcard", nil, []string{"https://*"}, "/usr/bin/git", "git clone https://x", wantMatch},
		{"argument matches the whole command line", nil, []string{"git clone *"}, "/usr/bin/git", "git clone https://x", wantMatch},
		{"no argument pattern covers", nil, []string{"push"}, "/usr/bin/git", "git clone https://x", wantMismatch},
		{"missing argv is not a mismatch", nil, []string{"push"}, "/usr/bin/git", "", wantUnevaluable},
		{"no argument constraint", nil, nil, "/usr/bin/git", "", wantMatch},

		// Both dimensions apply, and the executable is checked first because a
		// wrong binary makes the arguments irrelevant.
		{"executable wins over arguments", []string{"/usr/bin/git"}, []string{"clone"}, "/bin/sh", "git clone x", wantMismatch},
	}

	m := NewMatcher()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := capability.Grant{
				Kind:   capability.KindProcessExec,
				Domain: capability.DomainProcess,
				Selector: capability.Selector{
					Executables: tt.executables,
					ArgPatterns: tt.argPatterns,
				},
			}
			check(t, m.Match(g, execObs(tt.binary, tt.argv)), tt.w)
		})
	}
}

func TestMatchSelectorlessDomains(t *testing.T) {
	m := NewMatcher()

	// Privilege and kernel capabilities carry no selector dimension, so the
	// Kind alone decides.
	for _, kind := range []capability.Kind{
		capability.KindPrivSetuid,
		capability.KindKernelModuleLoad,
		capability.KindIPCSharedMem,
	} {
		g := capability.Grant{Kind: kind}
		obs := capability.Observation{Kind: kind}
		check(t, m.Match(g, obs), wantMatch)
	}

	// A unix socket is named by a path, and a grant narrowing PathPatterns
	// plainly means it.
	g := capability.Grant{
		Kind:     capability.KindIPCUnixSock,
		Selector: capability.Selector{PathPatterns: []string{"/run/allseer/**"}},
	}
	check(t, m.Match(g, capability.Observation{
		Kind:   capability.KindIPCUnixSock,
		Target: "/run/allseer/control.sock",
	}), wantMatch)
	check(t, m.Match(g, capability.Observation{
		Kind:   capability.KindIPCUnixSock,
		Target: "/run/docker.sock",
	}), wantMismatch)
}

// TestMatchesAgreesWithMatch guards the interface wrapper against drifting from
// the richer result it delegates to.
func TestMatchesAgreesWithMatch(t *testing.T) {
	m := NewMatcher()
	cases := []struct {
		g   capability.Grant
		obs capability.Observation
	}{
		{
			capability.Grant{Kind: capability.KindFileWrite, Selector: capability.Selector{PathPatterns: []string{"/ws/**"}}},
			fileWriteObs("/ws/main.go"),
		},
		{
			capability.Grant{Kind: capability.KindFileWrite, Selector: capability.Selector{PathPatterns: []string{"/ws/**"}}},
			fileWriteObs("/etc/passwd"),
		},
		{
			capability.Grant{Kind: capability.KindNetConnect, Selector: capability.Selector{Hosts: []string{"api.github.com"}}},
			connectObs("140.82.121.5:443", nil),
		},
	}

	for _, c := range cases {
		full := m.Match(c.g, c.obs)
		ok, reason := m.Matches(c.g, c.obs)
		if ok != full.Matched || reason != full.Reason {
			t.Errorf("Matches = (%v, %q), Match = (%v, %q)", ok, reason, full.Matched, full.Reason)
		}
	}
}

// TestMatchUnevaluableIsNeverAMatch is the safety property: nothing the matcher
// could not evaluate is ever reported as covered.
func TestMatchUnevaluableIsNeverAMatch(t *testing.T) {
	m := NewMatcher()
	cases := []struct {
		g   capability.Grant
		obs capability.Observation
	}{
		{
			capability.Grant{Kind: capability.KindFileWrite, Selector: capability.Selector{PathPatterns: []string{"/**"}}},
			fileWriteObs("/ws/../etc/passwd"),
		},
		{
			capability.Grant{Kind: capability.KindNetConnect, Selector: capability.Selector{Hosts: []string{"*.github.com"}}},
			connectObs("140.82.121.5:443", nil),
		},
		{
			capability.Grant{Kind: capability.KindProcessExec, Selector: capability.Selector{ArgPatterns: []string{"*"}}},
			execObs("/usr/bin/git", ""),
		},
	}

	for _, c := range cases {
		got := m.Match(c.g, c.obs)
		if got.Matched {
			t.Errorf("unevaluable input reported as covered: %q", got.Reason)
		}
		if !got.Unevaluable {
			t.Errorf("expected Unevaluable for %v, got mismatch: %q", c.obs.Target, got.Reason)
		}
	}
}

func TestSplitTarget(t *testing.T) {
	tests := []struct {
		target  string
		host    string
		port    int
		hasPort bool
		ok      bool
	}{
		{"api.github.com:443", "api.github.com", 443, true, true},
		{"10.1.2.3:80", "10.1.2.3", 80, true, true},
		{"[2001:db8::1]:443", "2001:db8::1", 443, true, true},
		{"2001:db8::1", "2001:db8::1", 0, false, true},
		{"::1", "::1", 0, false, true},
		{"api.github.com", "api.github.com", 0, false, true},
		{"api.github.com:", "api.github.com", 0, false, true},
		{"", "", 0, false, false},
		{"api.github.com:https", "", 0, false, false},
		{"not a host:::", "", 0, false, false},
	}

	for _, tt := range tests {
		host, port, hasPort, ok := splitTarget(tt.target)
		if host != tt.host || port != tt.port || hasPort != tt.hasPort || ok != tt.ok {
			t.Errorf("splitTarget(%q) = (%q, %d, %v, %v), want (%q, %d, %v, %v)",
				tt.target, host, port, hasPort, ok, tt.host, tt.port, tt.hasPort, tt.ok)
		}
	}
}

func BenchmarkMatch(b *testing.B) {
	m := NewMatcher()

	fs := capability.Grant{
		Kind:     capability.KindFileWrite,
		Selector: capability.Selector{PathPatterns: []string{"/ws/src/**", "/ws/testdata/**"}},
	}
	fsObs := fileWriteObs("/ws/src/internal/pkg/main.go")

	net := capability.Grant{
		Kind: capability.KindNetConnect,
		Selector: capability.Selector{
			Hosts: []string{"*.github.com", "proxy.golang.org"},
			Ports: []int{443},
		},
	}
	netObs := connectObs("api.github.com:443", map[string]string{capability.AttrDestIP: "140.82.121.5"})

	b.Run("filesystem", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			m.Match(fs, fsObs)
		}
	})
	b.Run("network", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			m.Match(net, netObs)
		}
	})
}

func TestReasonNamesTheOffendingValue(t *testing.T) {
	// A reason that does not name what failed is useless in an audit log.
	m := NewMatcher()

	g := capability.Grant{
		Kind:     capability.KindFileWrite,
		Selector: capability.Selector{PathPatterns: []string{"/ws/**"}},
	}
	got := m.Match(g, fileWriteObs("/etc/passwd"))
	if !strings.Contains(got.Reason, "/etc/passwd") {
		t.Errorf("Reason = %q, want it to name the path", got.Reason)
	}
}
