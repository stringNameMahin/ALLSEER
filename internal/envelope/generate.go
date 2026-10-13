package envelope

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/stringNameMahin/ALLSEER/internal/intent"
	"github.com/stringNameMahin/ALLSEER/pkg/capability"
	"github.com/stringNameMahin/ALLSEER/pkg/ece"
)

// Errors reported by generation.
var (
	ErrNoAnalysis  = errors.New("envelope: an analysis is required")
	ErrNoWorkspace = errors.New("envelope: an absolute workspace root is required")
	ErrTooMany     = errors.New("envelope: generated grants exceed the configured maximum")
)

// Params are the per-request inputs to generation beyond the analysis.
type Params struct {
	SessionID     string
	WorkspaceRoot string
	// Home is the requesting user's home directory. Credential denials are
	// written under it.
	Home string
	// Resolvers are DNS server addresses the agent is expected to query.
	Resolvers []string
	TTL       time.Duration
	Now       time.Time
}

// Result is a generated envelope plus what generation could not honour.
type Result struct {
	Envelope *ece.Envelope
	// Warnings are surfaced to the approver. Each names a grant that was
	// dropped or one that cannot be matched as written.
	Warnings []string
}

// RuleGenerator builds envelopes from a deterministic analysis and the
// built-in profiles.
type RuleGenerator struct {
	Limits Limits
}

// Generate builds an unsealed envelope. Grants for capabilities the catalog
// cannot observe are dropped and reported, because a grant with no probe
// behind it reads as a control and enforces nothing.
func (g RuleGenerator) Generate(_ context.Context, an *intent.Analysis, cat capability.Catalog, p Params) (*Result, error) {
	if an == nil {
		return nil, ErrNoAnalysis
	}
	ws := filepath.Clean(p.WorkspaceRoot)
	if p.WorkspaceRoot == "" || !filepath.IsAbs(ws) || ws == "/" {
		return nil, fmt.Errorf("%w: %q", ErrNoWorkspace, p.WorkspaceRoot)
	}
	home := ""
	if p.Home != "" && filepath.IsAbs(p.Home) && filepath.Clean(p.Home) != "/" {
		home = filepath.Clean(p.Home)
	}
	now := p.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	ttl := p.TTL
	if ttl <= 0 {
		ttl = time.Hour
	}

	b := &builder{ws: ws, home: home}
	b.base()
	b.task(an)
	b.network(an, p.Resolvers)
	b.denials(an)

	res := &Result{}
	var grants []capability.Grant
	for _, gr := range b.grants {
		if g.forbidden(gr.Kind) {
			res.Warnings = append(res.Warnings, fmt.Sprintf("dropped %s grant: the kind is forbidden by configuration", gr.Kind))
			continue
		}
		if cat != nil && !cat.Observable(gr.Kind) {
			res.Warnings = append(res.Warnings, fmt.Sprintf("dropped %s grant: no probe in this build observes it", gr.Kind))
			continue
		}
		grants = append(grants, gr)
	}
	var denials []capability.Grant
	for _, d := range b.denials_ {
		if cat != nil && !cat.Observable(d.Kind) {
			res.Warnings = append(res.Warnings, fmt.Sprintf("denial of %s is unenforceable: no probe in this build observes it", d.Kind))
			continue
		}
		denials = append(denials, d)
	}
	if g.Limits.MaxGrants > 0 && len(grants) > g.Limits.MaxGrants {
		return nil, fmt.Errorf("%w: %d > %d", ErrTooMany, len(grants), g.Limits.MaxGrants)
	}
	if hasHostnameGrant(grants) {
		res.Warnings = append(res.Warnings, "network grants name hosts, but this build does not correlate DNS answers; "+
			"connections to them reach policy as indeterminate rather than as matched")
	}
	if an.Record.Confidence < g.Limits.MinConfidence {
		res.Warnings = append(res.Warnings, fmt.Sprintf("analysis confidence %.2f is below the configured minimum %.2f",
			an.Record.Confidence, g.Limits.MinConfidence))
	}

	res.Envelope = &ece.Envelope{
		SchemaVersion: ece.SchemaVersion,
		ID:            newID(),
		SessionID:     p.SessionID,
		CreatedAt:     now,
		ExpiresAt:     now.Add(ttl),
		Intent:        an.Record,
		Grants:        grants,
		Denials:       denials,
		Constraints: ece.Constraints{
			WorkspaceRoot: ws,
			MaxDuration:   ttl,
		},
		DefaultAction: ece.ActionRequestApproval,
	}
	return res, nil
}

func (g RuleGenerator) forbidden(k capability.Kind) bool {
	for _, f := range g.Limits.ForbiddenKinds {
		if f == k {
			return true
		}
	}
	return false
}

type builder struct {
	ws, home string
	grants   []capability.Grant
	denials_ []capability.Grant
}

func (b *builder) add(kind capability.Kind, sel capability.Selector, why string) {
	d, _ := capability.DomainOf(kind)
	for i := range b.grants {
		if b.grants[i].Kind == kind && sameDims(b.grants[i].Selector, sel) {
			b.grants[i].Selector.PathPatterns = union(b.grants[i].Selector.PathPatterns, sel.PathPatterns)
			b.grants[i].Selector.Hosts = union(b.grants[i].Selector.Hosts, sel.Hosts)
			b.grants[i].Selector.Executables = union(b.grants[i].Selector.Executables, sel.Executables)
			return
		}
	}
	b.grants = append(b.grants, capability.Grant{Kind: kind, Domain: d, Selector: sel, Rationale: why})
}

func (b *builder) deny(kind capability.Kind, paths []string, why string) {
	d, _ := capability.DomainOf(kind)
	b.denials_ = append(b.denials_, capability.Grant{Kind: kind, Domain: d,
		Selector: capability.Selector{PathPatterns: paths}, Rationale: why})
}

func (b *builder) homePaths(rel ...string) []string {
	if b.home == "" {
		return nil
	}
	out := make([]string, 0, len(rel))
	for _, r := range rel {
		out = append(out, b.home+"/"+r)
	}
	return out
}

func paths(p ...string) capability.Selector { return capability.Selector{PathPatterns: p} }

// systemReads are files every toolchain reads: the loader, locale, name
// service, TLS roots. Credential files are deliberately absent.
var systemReads = []string{
	"/usr/**", "/lib/**", "/lib64/**", "/bin/**", "/sbin/**", "/opt/**", "/snap/**",
	"/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d/**", "/etc/localtime",
	"/etc/nsswitch.conf", "/etc/passwd", "/etc/group", "/etc/hosts", "/etc/host.conf",
	"/etc/resolv.conf", "/etc/gai.conf", "/etc/ssl/**", "/etc/ca-certificates/**",
	"/etc/alternatives/**", "/etc/os-release", "/etc/lsb-release", "/etc/mime.types",
	"/etc/locale.alias", "/etc/inputrc", "/etc/bash.bashrc", "/etc/profile", "/etc/profile.d/**",
	"/etc/environment", "/etc/gitconfig", "/etc/timezone", "/run/systemd/resolve/**",
	"/proc/**", "/sys/**", "/dev/null", "/dev/zero", "/dev/urandom", "/dev/random",
	"/dev/tty", "/dev/pts/**", "/tmp/**", "/var/tmp/**",
}

var systemExecs = []string{
	"/usr/bin/**", "/bin/**", "/usr/local/bin/**", "/usr/lib/**", "/usr/libexec/**",
	"/usr/local/go/**", "/usr/local/lib/**", "/snap/**", "/tmp/**",
}

func (b *builder) base() {
	ws := b.ws + "/**"
	reads := append([]string{ws}, systemReads...)
	reads = append(reads, b.homePaths(".gitconfig", ".config/git/**", ".cache/**", ".bashrc", ".profile")...)
	b.add(capability.KindFileRead, paths(reads...),
		"The workspace, system libraries, and the configuration every toolchain reads. Credential stores are excluded.")

	writes := append([]string{ws, "/tmp/**", "/var/tmp/**", "/dev/null", "/dev/tty", "/dev/pts/**"},
		b.homePaths(".cache/**")...)
	b.add(capability.KindFileWrite, paths(writes...), "Changes stay in the workspace, temporary directories and caches.")
	b.add(capability.KindFileCreate, paths(writes...), "New files stay in the workspace, temporary directories and caches.")

	execs := append([]string{ws}, systemExecs...)
	execs = append(execs, b.homePaths("go/bin/**", ".local/bin/**", ".cargo/bin/**")...)
	b.add(capability.KindProcessExec, capability.Selector{Executables: execs},
		"System and user toolchain binaries, and programs built in the workspace.")
	b.add(capability.KindProcessExit, capability.Selector{Executables: execs}, "Exit of the same programs.")
}

func (b *builder) task(an *intent.Analysis) {
	switch an.Record.TaskType {
	case intent.TaskTypeBuild, intent.TaskTypeTest, intent.TaskTypeDependencyInstall:
		caches := b.homePaths("go/**", ".npm/**", ".cargo/**", ".rustup/**", ".local/lib/**", ".m2/**", ".gradle/**",
			".config/go/**")
		if len(caches) > 0 {
			b.add(capability.KindFileRead, paths(caches...), "Language toolchains read their module and package caches.")
			b.add(capability.KindFileWrite, paths(caches...), "Language toolchains populate their module and package caches.")
			b.add(capability.KindFileCreate, paths(caches...), "Language toolchains populate their module and package caches.")
		}
		if tools := b.homePaths("go/pkg/mod/golang.org/toolchain@*/**", ".rustup/toolchains/**"); len(tools) > 0 {
			sel := capability.Selector{Executables: tools}
			b.add(capability.KindProcessExec, sel, "Toolchains the language's version manager downloaded into its cache.")
			b.add(capability.KindProcessExit, sel, "Exit of the same toolchain binaries.")
		}
	case intent.TaskTypeGitOperation:
		if an.RequiresNetwork {
			if ssh := b.homePaths(".ssh/**"); len(ssh) > 0 {
				b.add(capability.KindFileRead, paths(ssh...),
					"Git over SSH reads keys and known_hosts. Review: this grants credential access.")
			}
		}
	}
}

// registryHosts are the hosts a dependency install reaches beyond the index
// named by the analyzer.
var registryHosts = map[string][]string{
	"proxy.golang.org":   {"proxy.golang.org", "sum.golang.org", "storage.googleapis.com"},
	"registry.npmjs.org": {"registry.npmjs.org"},
	"pypi.org":           {"pypi.org", "files.pythonhosted.org"},
	"crates.io":          {"crates.io", "index.crates.io", "static.crates.io"},
}

func (b *builder) network(an *intent.Analysis, resolvers []string) {
	if !an.RequiresNetwork {
		return
	}
	var hosts []string
	for _, h := range an.Scope.NetworkHints {
		if more, ok := registryHosts[h]; ok {
			hosts = append(hosts, more...)
		} else {
			hosts = append(hosts, h)
		}
	}
	if len(resolvers) > 0 {
		b.add(capability.KindNetConnect, capability.Selector{Hosts: dedupe(resolvers), Ports: []int{53}},
			"Name resolution through the configured resolvers.")
	}
	if len(hosts) > 0 {
		b.add(capability.KindNetConnect, capability.Selector{Hosts: dedupe(hosts)},
			"Hosts the task names or implies.")
	}
}

func (b *builder) denials(an *intent.Analysis) {
	gitNet := an.Record.TaskType == intent.TaskTypeGitOperation && an.RequiresNetwork
	creds := []string{".aws/**", ".gnupg/**", ".kube/**", ".docker/config.json", ".netrc",
		".config/gh/**", ".git-credentials", ".password-store/**", ".pgpass"}
	if !gitNet {
		creds = append(creds, ".ssh/**")
	}
	reads := append(b.homePaths(creds...), "/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/sudoers.d/**")
	if b.home != "/root" && !strings.HasPrefix(b.ws, "/root/") {
		reads = append(reads, "/root/**")
	}
	b.deny(capability.KindFileRead, reads, "Credential stores are never part of a coding task.")

	persist := append([]string{b.ws + "/.git/hooks/**"},
		b.homePaths(".ssh/**", ".bashrc", ".profile", ".bash_profile", ".zshrc", ".config/autostart/**")...)
	if an.Record.TaskType != intent.TaskTypeGitOperation {
		persist = append(persist, b.ws+"/.github/workflows/**")
	}
	for _, k := range []capability.Kind{capability.KindFileWrite, capability.KindFileCreate} {
		b.deny(k, persist, "Hooks, CI workflows and shell startup files are persistence points.")
	}
}

func hasHostnameGrant(gs []capability.Grant) bool {
	for _, g := range gs {
		for _, h := range g.Selector.Hosts {
			if strings.ContainsAny(h, "abcdefghijklmnopqrstuvwxyz") && !strings.Contains(h, ":") {
				return true
			}
		}
	}
	return false
}

func sameDims(a, b capability.Selector) bool {
	return (len(a.PathPatterns) > 0) == (len(b.PathPatterns) > 0) &&
		(len(a.Hosts) > 0) == (len(b.Hosts) > 0) &&
		(len(a.Executables) > 0) == (len(b.Executables) > 0) &&
		len(a.Ports) == 0 && len(b.Ports) == 0 && len(a.Protocols) == 0 && len(b.Protocols) == 0
}

func union(a, b []string) []string { return dedupe(append(append([]string(nil), a...), b...)) }

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// NewSessionID returns a fresh session identifier that is also a safe cgroup
// name.
func NewSessionID(now time.Time) string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("s-%s-%s", now.UTC().Format("20060102t150405"), hex.EncodeToString(b[:]))
}

// GrantedKinds lists the distinct kinds an envelope grants, sorted.
func GrantedKinds(env *ece.Envelope) []capability.Kind {
	seen := map[capability.Kind]bool{}
	var out []capability.Kind
	for _, g := range env.Grants {
		if !seen[g.Kind] {
			seen[g.Kind] = true
			out = append(out, g.Kind)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
